import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomInt } from 'node:crypto';
import test from 'node:test';

// Load browser modules without adding a package.json to the .NET app.
const source = await readFile(new URL('../wwwroot/js/crypto.js', import.meta.url), 'utf8');
const cryptoUrl = 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
const {
    ALPHABET, normalize, parseCodebookLine, encryptText, decryptText,
    encryptMessage, decryptMessage, isEncrypted, rememberKey,
} = await import(cryptoUrl);
const newKey = () => Array.from({ length: 40 }, () => ALPHABET[randomInt(37)]).join('');
const line = (number, key = newKey()) => `    ${number}\t${key}`;
const HMAC_KEY = 'Hmac_sleutel_voor_de_test_0123456789';

test('mod37 with the example from the slides: HELLO + AI8OP = HMIZ3', () => {
    assert.equal(ALPHABET.length, 37);
    assert.equal(encryptText('HELLO', 'AI8OP'), 'HMIZ3');
    assert.equal(decryptText('HMIZ3', 'AI8OP'), 'HELLO');
});

test('lowercase becomes uppercase, a space becomes _, other characters are refused', () => {
    assert.equal(normalize('Hallo Jasper 2'), 'HALLO_JASPER_2');
    assert.throws(() => normalize('Hallo!'), /!/);
    assert.throws(() => normalize('café'), /É/);
});

test('a codebook line needs a number and exactly 40 characters', () => {
    const key = newKey();
    assert.deepEqual(parseCodebookLine(line(7, key)), { number: 7, key });
    assert.deepEqual(parseCodebookLine('12 ' + key), { number: 12, key });
    for (const invalid of [key, line(0, key), '3 ' + key.slice(1), '3 ' + key.toLowerCase().replace(/[^a-z]/, 'a')]) {
        assert.throws(() => parseCodebookLine(invalid), /codeboek/);
    }
});

test('only ciphertext, line number and MAC leave the browser; the receiver decrypts', async () => {
    const codebookLine = line(7);
    const message = await encryptMessage('Hallo Jasper', codebookLine, HMAC_KEY, 'Mohammed', 'Jasper');
    assert.equal(message.subject, 'MOD37:1');
    assert.match(message.body, /^MOD37:1:7:[A-Z0-9_]{12}:[a-f0-9]{64}$/);
    assert.ok(!message.body.includes('HALLO'));
    const stored = { ...message, sender: 'Mohammed', recipient: 'Jasper' };
    assert.ok(isEncrypted(stored));
    assert.equal(await decryptMessage(stored, codebookLine, HMAC_KEY), 'HALLO JASPER');
    await assert.rejects(encryptMessage('A'.repeat(41), codebookLine, HMAC_KEY, 'Mohammed', 'Jasper'), /40/);
    await assert.rejects(encryptMessage('Hallo', codebookLine, 'kort', 'Mohammed', 'Jasper'), /HMAC/);
});

test('the MAC detects a changed ciphertext, line number, sender or HMAC key', async () => {
    const key = newKey();
    const message = await encryptMessage('Om acht uur', line(3, key), HMAC_KEY, 'Mohammed', 'Jasper');
    const stored = { ...message, sender: 'Mohammed', recipient: 'Jasper' };
    const [, , number, ciphertext, tag] = stored.body.split(':');
    const changed = ciphertext.slice(0, -1) + (ciphertext.endsWith('A') ? 'B' : 'A');
    const tampered = { ...stored, body: `MOD37:1:${number}:${changed}:${tag}` };
    await assert.rejects(decryptMessage(tampered, line(3, key), HMAC_KEY), /Integriteitscontrole mislukt/);
    const otherLine = { ...stored, body: `MOD37:1:4:${ciphertext}:${tag}` };
    await assert.rejects(decryptMessage(otherLine, line(4, key), HMAC_KEY), /Integriteitscontrole mislukt/);
    await assert.rejects(decryptMessage({ ...stored, sender: 'Eve' }, line(3, key), HMAC_KEY), /Integriteitscontrole mislukt/);
    await assert.rejects(decryptMessage(stored, line(3, key), HMAC_KEY + 'x'), /Integriteitscontrole mislukt/);
    await assert.rejects(decryptMessage(stored, line(5, key), HMAC_KEY), /lijn 3/);
});

test('local reuse history stores only fingerprints; decrypting remains repeatable', async () => {
    const storage = new Map();
    globalThis.localStorage = { getItem: name => storage.get(name), setItem: (name, value) => storage.set(name, value) };
    const key = line(1);
    await rememberKey(key, true);
    await assert.rejects(rememberKey(key, true), /al gebruikt/);
    await rememberKey(key);
    assert.equal(storage.size, 1);
    assert.ok(!JSON.stringify([...storage]).includes(key.trim()));
    assert.match([...storage.keys()][0], /^unbreakable_used_key_[a-f0-9]{64}$/);
    globalThis.localStorage.setItem = () => { throw new Error('Storage disabled'); };
    await assert.rejects(rememberKey(line(2), true), /Lokale opslag/);
});

test('API sends only ciphertext and routing metadata, even with extra key/plaintext properties', async () => {
    const apiSource = (await readFile(new URL('../wwwroot/js/api.js', import.meta.url), 'utf8'))
        .replace("'./crypto.js'", JSON.stringify(cryptoUrl));
    const { api } = await import('data:text/javascript;base64,' + Buffer.from(apiSource).toString('base64'));
    globalThis.localStorage = { getItem: () => 'Anna' };
    const requests = [];
    globalThis.fetch = async (url, options) => {
        requests.push({ url, ...options });
        return { ok: true, headers: new Headers({ 'Content-Type': 'application/json' }), json: async () => ({ id: 1 }) };
    };
    const key = line(9);
    const encrypted = await encryptMessage('Geheim', key, HMAC_KEY, 'Anna', 'Bram');
    await api.send({ recipient: 'Bram', ...encrypted, key, plaintext: 'GEHEIM' });
    assert.deepEqual(JSON.parse(requests[0].body), { recipient: 'Bram', ...encrypted });
    assert.ok(!JSON.stringify(requests).includes(key.trim().split('\t')[1]));
    assert.ok(!JSON.stringify(requests).includes('GEHEIM'));
    assert.throws(() => api.send({ recipient: 'Bram', subject: 'Plain', body: 'GEHEIM' }));
    assert.equal(requests.length, 1);
});

test('compose encrypts before sending; reading decrypts locally and renders plaintext as text', async () => {
    // Minimal DOM stand-in to exercise the actual form handlers without a browser dependency.
    const elements = new Map();
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            value: '', textContent: '', innerHTML: '', disabled: false, isConnected: true,
            listeners: {},
            addEventListener(type, handler) { this.listeners[type] = handler; },
            querySelector() { return element('submit'); },
        });
        return elements.get(id);
    }
    const storage = new Map([['unbreakable_user', 'Anna']]);
    globalThis.localStorage = { getItem: name => storage.get(name), setItem: (name, value) => storage.set(name, value) };
    globalThis.document = { getElementById: element };
    globalThis.window = { addEventListener() {} };
    globalThis.location = { hash: '#/nieuw' };
    const requests = [];
    let saved;
    globalThis.fetch = async (url, options) => {
        requests.push({ url, ...options });
        if (options.method === 'POST') saved = {
            ...JSON.parse(options.body), id: 1, sender: 'Anna', sentAt: new Date().toISOString(),
        };
        return {
            ok: true, headers: new Headers({ 'Content-Type': 'application/json' }),
            json: async () => url === '/api/users' ? ['Anna', 'Bram'] : saved,
        };
    };
    const apiSource = (await readFile(new URL('../wwwroot/js/api.js', import.meta.url), 'utf8'))
        .replace("'./crypto.js'", JSON.stringify(cryptoUrl));
    const apiUrl = 'data:text/javascript;base64,' + Buffer.from(apiSource).toString('base64');
    const appSource = (await readFile(new URL('../wwwroot/js/app.js', import.meta.url), 'utf8'))
        .replace("'./api.js'", JSON.stringify(apiUrl)).replace("'./crypto.js'", JSON.stringify(cryptoUrl))
        .replace(/\nroute\(\);\s*$/, '\nawait route();\nexport { route };');
    const { route } = await import('data:text/javascript;base64,' + Buffer.from(appSource).toString('base64'));
    const key = line(11);
    element('recipient').value = 'Bram';
    element('text').value = 'Tot morgen';
    element('message-key').value = key;
    element('hmac-key').value = HMAC_KEY;
    await element('compose').listeners.submit({ preventDefault() {}, currentTarget: element('compose') });
    assert.equal(location.hash, '#/inbox');
    assert.equal(element('message-key').value, '');
    assert.equal(element('text').value, '');
    assert.ok(isEncrypted(saved));
    assert.ok(!JSON.stringify(requests).includes(key.trim().split('\t')[1]));
    assert.ok(!JSON.stringify(requests).includes('TOT_MORGEN'));

    storage.set('unbreakable_user', 'Bram');
    location.hash = '#/bericht/1';
    await route();
    assert.equal(element('body').textContent, saved.body);
    const beforeDecrypt = requests.length;
    element('message-key').value = key;
    element('hmac-key').value = HMAC_KEY;
    await element('decrypt').listeners.submit({ preventDefault() {}, currentTarget: element('decrypt') });
    assert.equal(element('decrypt-error').textContent, '');
    assert.equal(element('body').textContent, 'TOT MORGEN');
    assert.match(element('integrity-status').textContent, /HMAC/);
    assert.equal(requests.length, beforeDecrypt);

    location.hash = '#/nieuw';
    await route();
    element('recipient').value = 'Anna';
    element('text').value = 'Opnieuw';
    element('message-key').value = key;
    element('hmac-key').value = HMAC_KEY;
    const beforeReuse = requests.length;
    await element('compose').listeners.submit({ preventDefault() {}, currentTarget: element('compose') });
    assert.match(element('compose-error').textContent, /al gebruikt/);
    assert.equal(requests.length, beforeReuse);
});
