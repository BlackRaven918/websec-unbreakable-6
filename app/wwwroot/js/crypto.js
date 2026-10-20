// Elke sleutelpositie wordt precies eenmaal gebruikt, zonder herhalen.
export const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_';
export const MARKER = 'MOD63:1';
const PREFIX = MARKER + ':';
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
    if (message.subject !== MARKER || typeof message.body !== 'string' || !message.body.startsWith(PREFIX)) return false;
    const ciphertext = message.body.slice(PREFIX.length);
    return ciphertext.length > 0 && ciphertext.length % 2 === 0 && !/[^A-Za-z0-9_]/.test(ciphertext);
}

export function encryptMessage(subject, body, key) {
    if (!subject || subject.length > 100 || /[\r\n]/.test(subject) || !body || body.length > 2000) {
        throw new Error('Vul een onderwerp (maximaal 100 tekens) en een bericht (maximaal 2000 tekens) in.');
    }
    const bytes = encoder.encode(subject + '\n' + body);
    validateKey(key, bytes.length * 2);
    if (PREFIX.length + bytes.length * 2 > 2000) {
        throw new Error('Het versleutelde bericht is te lang (maximaal 2000 tekens).');
    }
    let ciphertext = '';
    for (const byte of bytes) {
        for (const value of [Math.floor(byte / 63), byte % 63]) {
            ciphertext += ALPHABET[(value + ALPHABET.indexOf(key[ciphertext.length])) % 63];
        }
    }
    return { subject: MARKER, body: PREFIX + ciphertext };
}

export function decryptMessage(message, key) {
    if (!isEncrypted(message)) throw new Error('Dit is geen ondersteund mod63-bericht.');
    const ciphertext = message.body.slice(PREFIX.length);
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
