import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomInt } from 'node:crypto';
import test from 'node:test';

// Load browser modules without adding a package.json to the .NET app.
const source = await readFile(new URL('../wwwroot/js/crypto.js', import.meta.url), 'utf8');
const cryptoUrl = 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
const { ALPHABET, encryptMessage, decryptMessage, isEncrypted, requiredKeyLength, rememberKey } = await import(cryptoUrl);
const newKey = (length = 80) => Array.from({ length }, () => ALPHABET[randomInt(63)]).join('');

test('mod63 preserves case, punctuation, spaces, Unicode and line breaks', () => {
    const subject = 'Hé 👋';
    const body = '<script> & "\' _\n你好\n\u0000';
    const key = newKey(Math.max(80, requiredKeyLength(subject, body)));
    const message = encryptMessage(subject, body, key);
    assert.ok(isEncrypted(message));
    assert.deepEqual(decryptMessage(message, key), { subject, body });
    assert.equal(message.subject, 'MOD63:1');
    assert.equal(message.body.length, 8 + requiredKeyLength(subject, body));
    assert.ok(!message.body.includes(subject));
    assert.ok(!message.body.includes(body));
});

test('known mod63 arithmetic, wraparound, exact capacity and no repeated key', () => {
    // UTF-8 A/newline/B -> base63 BC AK BD; adding _ (62) wraps by one.
    const key = '_'.repeat(80);
    assert.equal(encryptMessage('A', 'B', key).body, 'MOD63:1:AB_JAC');
    assert.deepEqual(decryptMessage(encryptMessage('A', 'B', key), key), { subject: 'A', body: 'B' });
    assert.equal(requiredKeyLength('A', 'b'.repeat(38)), 80);
    encryptMessage('A', 'b'.repeat(38), key);
    assert.throws(() => encryptMessage('A', 'b'.repeat(39), key), /82/);
    for (const invalid of ['', 'A'.repeat(79), 'A'.repeat(80) + '\n', 'A'.repeat(79) + '!']) {
        assert.throws(() => encryptMessage('A', 'B', invalid), /sleutel/);
    }
    assert.throws(() => encryptMessage('A\nB', 'C', key));
    assert.throws(() => encryptMessage('A', 'b'.repeat(1000), newKey(3000)), /te lang/);
});

test('rejects malformed ciphertext and invalid decoded bytes', () => {
    for (const body of ['plain text', 'MOD63:1:', 'MOD63:1:A', 'MOD63:1:AA\n', 'MOD63:1:AA!_']) {
        assert.equal(isEncrypted({ subject: 'MOD63:1', body }), false);
    }
    assert.throws(() => decryptMessage({ subject: 'MOD63:1', body: 'MOD63:1:__' }, 'A'.repeat(80)));
    assert.throws(() => decryptMessage({ subject: 'MOD63:1', body: 'MOD63:1:EC' }, 'A'.repeat(80)));
});

test('local reuse history stores only fingerprints; decrypting remains repeatable', async () => {
    const storage = new Map();
    globalThis.localStorage = { getItem: name => storage.get(name), setItem: (name, value) => storage.set(name, value) };
    const key = newKey();
    await rememberKey(key, true);
    await assert.rejects(rememberKey(key, true), /al gebruikt/);
    await rememberKey(key);
    assert.equal(storage.size, 1);
    assert.ok(!JSON.stringify([...storage]).includes(key));
    assert.match([...storage.keys()][0], /^unbreakable_used_key_[a-f0-9]{64}$/);
    const secondKey = newKey();
    await rememberKey(secondKey, true);
    globalThis.localStorage.setItem = () => { throw new Error('Storage disabled'); };
    await assert.rejects(rememberKey(newKey(), true), /Lokale opslag/);
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
    const key = newKey();
    const encrypted = encryptMessage('Hello', 'Secret text!', key);
    await api.send({ recipient: 'Bram', ...encrypted, key, plaintext: 'Secret text!' });
    assert.deepEqual(JSON.parse(requests[0].body), { recipient: 'Bram', ...encrypted });
    assert.ok(!JSON.stringify(requests).includes(key));
    assert.ok(!JSON.stringify(requests).includes('Secret text!'));
    assert.throws(() => api.send({ recipient: 'Bram', subject: 'Plain', body: 'Secret text!' }));
    assert.equal(requests.length, 1);
    await api.exportJson();
    assert.equal(requests[1].url, '/api/messages/export');
    assert.equal(requests[1].body, undefined);
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
    const key = newKey();
    const subject = '<img src=x>';
    const body = 'Private 👋';
    element('recipient').value = 'Bram';
    element('subject').value = subject;
    element('text').value = body;
    element('message-key').value = key;
    await element('compose').listeners.submit({ preventDefault() {}, currentTarget: element('compose') });
    assert.equal(location.hash, '#/inbox');
    assert.equal(element('message-key').value, '');
    assert.equal(element('text').value, '');
    assert.ok(isEncrypted(saved));
    assert.ok(!JSON.stringify(requests).includes(key));
    assert.ok(!JSON.stringify(requests).includes(body));

    storage.set('unbreakable_user', 'Bram');
    location.hash = '#/bericht/1';
    await route();
    assert.equal(element('body').textContent, saved.body);
    const beforeDecrypt = requests.length;
    element('message-key').value = key;
    await element('decrypt').listeners.submit({ preventDefault() {}, currentTarget: element('decrypt') });
    assert.equal(element('message-subject').textContent, subject);
    assert.equal(element('body').textContent, body);
    assert.equal(element('message-key').value, '');
    assert.equal(requests.length, beforeDecrypt);
    assert.ok(!JSON.stringify([...storage]).includes(key));

    location.hash = '#/nieuw';
    await route();
    element('recipient').value = 'Anna';
    element('subject').value = 'Reuse';
    element('text').value = 'Blocked';
    element('message-key').value = key;
    const beforeReuse = requests.length;
    await element('compose').listeners.submit({ preventDefault() {}, currentTarget: element('compose') });
    assert.match(element('compose-error').textContent, /al gebruikt/);
    assert.equal(requests.length, beforeReuse);
});
