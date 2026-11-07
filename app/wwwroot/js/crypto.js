// One-time pad in modulo 37 met een codeboek, plus HMAC-SHA-256.
// Alfabet: A-Z = 0-25, 0-9 = 26-35 en _ (een spatie) = 36.
export const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
export const MARKER = 'MOD37:1';
const KEY_LENGTH = 40;
const INTEGRITY_ERROR = 'Integriteitscontrole mislukt: verkeerde HMAC-sleutel of gewijzigd bericht.';
const encoder = new TextEncoder();

// Kleine letters worden hoofdletters, een spatie wordt _. Andere tekens weigeren we.
export function normalize(text) {
    const normalized = text.trim().toUpperCase().replace(/\s/g, '_');
    const invalid = [...new Set(normalized.replace(/[A-Z0-9_]/g, ''))];
    if (invalid.length > 0) throw new Error('Deze tekens kan je niet versturen: ' + invalid.join(' '));
    return normalized;
}

// Een lijn uit het codeboek zoals nl ze toont: het nummer en dan 40 tekens.
export function parseCodebookLine(line) {
    const match = /^\s*(\d{1,4})\s+([A-Z0-9_]{40})\s*$/.exec(line);
    if (!match || Number(match[1]) < 1) {
        throw new Error('Plak een volledige lijn uit het codeboek: het nummer en de 40 tekens.');
    }
    return { number: Number(match[1]), key: match[2] };
}

// C = (P + K) mod 37
export function encryptText(plaintext, key) {
    let ciphertext = '';
    for (let i = 0; i < plaintext.length; i++) {
        const p = ALPHABET.indexOf(plaintext[i]);
        const k = ALPHABET.indexOf(key[i]);
        ciphertext += ALPHABET[(p + k) % 37];
    }
    return ciphertext;
}

// P = (C - K) mod 37. De + 37 zorgt dat het getal nooit negatief wordt.
export function decryptText(ciphertext, key) {
    let plaintext = '';
    for (let i = 0; i < ciphertext.length; i++) {
        const c = ALPHABET.indexOf(ciphertext[i]);
        const k = ALPHABET.indexOf(key[i]);
        plaintext += ALPHABET[(c - k + 37) % 37];
    }
    return plaintext;
}

async function importHmacKey(hmacKey, key) {
    if (typeof hmacKey !== 'string' || hmacKey.length < 32 || /[^A-Za-z0-9_]/.test(hmacKey)) {
        throw new Error('Gebruik een aparte HMAC-sleutel van minstens 32 tekens: A–Z, a–z, 0–9 en _.');
    }
    if (hmacKey === key) throw new Error('De HMAC-sleutel moet verschillen van de sleutel uit het codeboek.');
    if (!globalThis.crypto?.subtle) throw new Error('Open de app via HTTPS of localhost.');
    return crypto.subtle.importKey('raw', encoder.encode(hmacKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// De MAC beschermt de ciphertext, het lijnnummer, de afzender en de ontvanger.
function authenticatedData(sender, recipient, number, ciphertext) {
    return encoder.encode(JSON.stringify([MARKER, sender, recipient, number, ciphertext]));
}

// MOD37:1:<lijnnummer>:<ciphertext>:<hmac>
export function parseEnvelope(message) {
    const match = /^MOD37:1:([1-9]\d{0,3}):([A-Z0-9_]{1,40}):([a-f0-9]{64})$/.exec(message.body ?? '');
    if (message.subject !== MARKER || !match) return null;
    return { number: Number(match[1]), ciphertext: match[2], tag: match[3] };
}

export function isEncrypted(message) {
    return parseEnvelope(message) !== null;
}

// Ook een beschadigd bericht gaat naar het ontsleutelformulier, nooit naar de gewone weergave.
export function isEncryptedEnvelope(message) {
    return message.subject === MARKER || (typeof message.body === 'string' && message.body.startsWith('MOD37:'));
}

export async function encryptMessage(text, codebookLine, hmacKey, sender, recipient) {
    const plaintext = normalize(text);
    const { number, key } = parseCodebookLine(codebookLine);
    if (plaintext.length < 1 || plaintext.length > KEY_LENGTH) {
        throw new Error(`Een bericht heeft 1 tot ${KEY_LENGTH} tekens, zo lang als een lijn uit het codeboek.`);
    }
    const ciphertext = encryptText(plaintext, key);
    const hmac = await importHmacKey(hmacKey, key);
    const tag = await crypto.subtle.sign('HMAC', hmac, authenticatedData(sender, recipient, number, ciphertext));
    const hex = Array.from(new Uint8Array(tag), byte => byte.toString(16).padStart(2, '0')).join('');
    return { subject: MARKER, body: `${MARKER}:${number}:${ciphertext}:${hex}` };
}

export async function decryptMessage(message, codebookLine, hmacKey) {
    const envelope = parseEnvelope(message);
    if (!envelope) throw new Error(INTEGRITY_ERROR);
    const { number, key } = parseCodebookLine(codebookLine);
    if (number !== envelope.number) {
        throw new Error(`Dit bericht gebruikt lijn ${envelope.number} uit het codeboek, niet lijn ${number}.`);
    }
    const hmac = await importHmacKey(hmacKey, key);
    const tag = Uint8Array.from(envelope.tag.match(/../g), hex => parseInt(hex, 16));
    // verify vergelijkt zelf, in constante tijd. Pas als de MAC klopt, ontsleutelen we.
    const data = authenticatedData(message.sender, message.recipient, envelope.number, envelope.ciphertext);
    if (!await crypto.subtle.verify('HMAC', hmac, tag, data)) throw new Error(INTEGRITY_ERROR);
    return decryptText(envelope.ciphertext, key).replaceAll('_', ' ');
}

// Alleen een vingerafdruk blijft lokaal bewaard, nooit de sleutel zelf.
// Dit kan hergebruik op andere apparaten of na het wissen van opslag niet voorkomen.
export async function rememberKey(key, rejectUsed = false) {
    if (!globalThis.crypto?.subtle) throw new Error('Open de app via HTTPS of localhost.');
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(key));
    const fingerprint = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    try {
        const name = 'unbreakable_used_key_' + fingerprint;
        if (rejectUsed && localStorage.getItem(name)) {
            throw new Error('Deze lijn uit het codeboek werd al gebruikt in deze browser. Neem een nieuwe lijn.');
        }
        localStorage.setItem(name, '1');
    } catch (error) {
        if (error.message.includes('al gebruikt')) throw error;
        throw new Error('Lokale opslag is nodig om hergebruik van sleutels te blokkeren.');
    }
}