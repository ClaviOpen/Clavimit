// Clavimit message wire format.
// Serializes encrypted payloads into the "-----BEGIN/END CLAVIMIT
// MAIL-----" text block embedded in Gmail messages, and parses/
// validates that format back into structured data on decryption.
// Used by content.js between cryptography.js (raw encrypted data)
// and emailParser.js (Gmail text content).

import {
    MESSAGE_BEGIN,
    MESSAGE_END,
    PAYLOAD_VERSION,
    ALGORITHM,
    KEY_ALGORITHM,
} from "../config.js";

export function createMessageBody(encrypted) {
    return {
        version: PAYLOAD_VERSION,
        algorithm: ALGORITHM,
        keyAlgorithm: KEY_ALGORITHM,
        encryptedKeys: encrypted.encryptedKeys,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
    };
}

export function createMessage(encrypted) {
    const message = createMessageBody(encrypted);

    return `${MESSAGE_BEGIN}

${serializeMessage(message)}

${MESSAGE_END}`;
}

export function serializeMessage(message) {
    return JSON.stringify(message);
}

export function composeMessage(encrypted) {
    return createMessage(encrypted);
}

export class MessageFormat {
    constructor({ version, scheme, label }) {
        if (new.target === MessageFormat) {
            throw new TypeError("MessageFormat is abstract; subclass it.");
        }
        this.version = version;
        this.scheme = scheme;
        this.label = label;
        Object.freeze(this);
    }

    encryptMessage(message, publicKeyPem, senderPublicKeyPem) {}

    decryptMessage(message, privateKeyPem) {}

    validate(message) {}
}
