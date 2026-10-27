// Elke sleutelpositie wordt precies eenmaal gebruikt, zonder herhalen.
export const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_';
export const MARKER = 'MOD63:2';
const PREFIX = MARKER + ':';
const LEGACY_MARKER = 'MOD63:1';
const LEGACY_PREFIX = LEGACY_MARKER + ':';
const INTEGRITY_ERROR = 'Integriteitscontrole mislukt: verkeerde sleutel of gewijzigd bericht.';
const encoder = new TextEncoder();

export function requiredKeyLength(subject, body) {
    return encoder.encode(subject + '\n' + body).length * 2;
}

function validateKey(key, length) {
    if (key.length < 80 || /[^A-Za-z0-9_]/.test(key)) {
        throw new Error('Gebruik een sleutel van minstens 80 tekens: A–Z, a–z, 0–9 en _.');
    }
    if (key.length < length) {
        throw new Error(`Dit bericht heeft ${length} sleuteltekens nodig; je sleutel heeft er ${key.length}. De sleutel wordt nooit herhaald.`);
    }
}

export function isEncrypted(message) {
    if (typeof message.body !== 'string' || message.body.length > 2000) return false;
    if (message.subject === MARKER) {
        return /^MOD63:2:(?:[A-Za-z0-9_]{2})+:[a-f0-9]{64}$/.test(message.body)
            && !message.body.endsWith('\n');
    }
    return message.subject === LEGACY_MARKER
        && /^MOD63:1:(?:[A-Za-z0-9_]{2})+$/.test(message.body)
        && !message.body.endsWith('\n');
}

// Ook beschadigde enveloppen moeten naar het ontsleutelformulier, nooit naar plaintext-weergave.
export function isEncryptedEnvelope(message) {
    return [MARKER, LEGACY_MARKER].includes(message.subject)
        || (typeof message.body === 'string' && message.body.startsWith('MOD63:'));
}

export function isAuthenticatedEnvelope(message) {
    return message.subject === MARKER
        || (typeof message.body === 'string' && message.body.startsWith(PREFIX));
}

function validateHmacKey(key, encryptionKey) {
    if (typeof key !== 'string' || key.length < 80 || /[^A-Za-z0-9_]/.test(key)) {
        throw new Error('Gebruik een aparte HMAC-sleutel van minstens 80 tekens: A–Z, a–z, 0–9 en _.');
    }
    if (key === encryptionKey) throw new Error('De HMAC-sleutel moet verschillen van de mod63-sleutel.');
}

async function importHmacKey(key, encryptionKey) {
    validateHmacKey(key, encryptionKey);
    if (!globalThis.crypto?.subtle) throw new Error('Open de app via HTTPS of localhost.');
    return crypto.subtle.importKey('raw', encoder.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

function authenticatedData(ciphertext) {
    return encoder.encode(JSON.stringify([MARKER, ciphertext]));
}

export async function encryptMessage(subject, body, key, hmacKey) {
    if (!subject || subject.length > 100 || /[\r\n]/.test(subject) || !body || body.length > 2000) {
        throw new Error('Vul een onderwerp (maximaal 100 tekens) en een bericht (maximaal 2000 tekens) in.');
    }
    const bytes = encoder.encode(subject + '\n' + body);
    validateKey(key, bytes.length * 2);
    if (PREFIX.length + bytes.length * 2 + 65 > 2000) {
        throw new Error('Het versleutelde bericht is te lang (maximaal 2000 tekens).');
    }
    let ciphertext = '';
    for (const byte of bytes) {
        for (const value of [Math.floor(byte / 63), byte % 63]) {
            ciphertext += ALPHABET[(value + ALPHABET.indexOf(key[ciphertext.length])) % 63];
        }
    }
    const authenticationKey = await importHmacKey(hmacKey, key);
    const tag = await crypto.subtle.sign('HMAC', authenticationKey, authenticatedData(ciphertext));
    const hex = Array.from(new Uint8Array(tag), byte => byte.toString(16).padStart(2, '0')).join('');
    return { subject: MARKER, body: PREFIX + ciphertext + ':' + hex };
}

export async function decryptMessage(message, key, hmacKey) {
    const authenticated = isAuthenticatedEnvelope(message);
    if (!isEncrypted(message)) throw new Error(authenticated ? INTEGRITY_ERROR : 'Dit is geen ondersteund mod63-bericht.');
    let ciphertext;
    if (authenticated) {
        const authenticationKey = await importHmacKey(hmacKey, key);
        const parts = message.body.slice(PREFIX.length).split(':');
        ciphertext = parts[0];
        const tag = Uint8Array.from(parts[1].match(/../g), hex => parseInt(hex, 16));
        if (!await crypto.subtle.verify('HMAC', authenticationKey, tag, authenticatedData(ciphertext))) {
            throw new Error(INTEGRITY_ERROR);
        }
    } else {
        ciphertext = message.body.slice(LEGACY_PREFIX.length);
    }
    validateKey(key, ciphertext.length);
    const values = Array.from(ciphertext, (char, i) =>
        (ALPHABET.indexOf(char) - ALPHABET.indexOf(key[i]) + 63) % 63);
    const bytes = [];
    for (let i = 0; i < values.length; i += 2) {
        const byte = values[i] * 63 + values[i + 1];
        if (byte > 255) throw new Error('Ontsleutelen mislukt. Controleer de sleutel en het bericht.');
        bytes.push(byte);
    }
    try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
        const separator = text.indexOf('\n');
        if (separator < 1 || separator > 100 || separator === text.length - 1) throw new Error();
        return { subject: text.slice(0, separator), body: text.slice(separator + 1) };
    } catch {
        throw new Error('Ontsleutelen mislukt. Controleer de sleutel en het bericht.');
    }
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
            throw new Error('Deze sleutel werd al gebruikt in deze browser. Gebruik een nieuwe sleutel.');
        }
        localStorage.setItem(name, '1');
    } catch (error) {
        if (error.message.includes('Deze sleutel')) throw error;
        throw new Error('Lokale opslag is nodig om hergebruik van sleutels te blokkeren.');
    }
}
