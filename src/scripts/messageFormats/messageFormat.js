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
import { ClavimitError } from "../exeptions.js";

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

export function deserializeMessage(text) {
    let message;

    try {
        message = JSON.parse(text);
    } catch (error) {
        throw new ClavimitError(
            "INVALID_MESSAGE",
            "The Clavimit message contains invalid JSON.",
        );
    }

    if (!validateMessage(message)) {
        throw new ClavimitError(
            "INVALID_MESSAGE",
            "The Clavimit message does not satisfy the expected format.",
        );
    }

    return message;
}

export function validateMessage(message) {
    if (!message) {
        return false;
    }
    return (
        message.version === PAYLOAD_VERSION &&
        message.algorithm === ALGORITHM &&
        message.keyAlgorithm === KEY_ALGORITHM &&
        typeof message.encryptedKeys === "object" &&
        typeof message.encryptedKeys.recipient === "string" &&
        (message.encryptedKeys.sender === null ||
            typeof message.encryptedKeys.sender === "string") &&
        typeof message.iv === "string" &&
        typeof message.ciphertext === "string"
    );
}

export function composeMessage(encrypted) {
    return createMessage(encrypted);
}

export function parseMessage(text) {
    if (!text) {
        throw new ClavimitError(
            "INVALID_MESSAGE",
            "No Clavimit message was found",
        );
    }
    const start = text.indexOf(MESSAGE_BEGIN);
    const finish = text.indexOf(MESSAGE_END);

    if (start === -1 || finish === -1) {
        throw new ClavimitError("INVALID_MESSAGE", "Not a Clavimit message");
    }

    const json = text.slice(start + MESSAGE_BEGIN.length, finish).trim();

    return deserializeMessage(json);
}

export class MessageFormat {
    constructor({ version, label }) {
        if (new.target === MessageFormat) {
            throw new TypeError("MessageFormat is abstract; subclass it.");
        }
        this.version = version;
        this.label = label;
        Object.freeze(this);
    }

    encryptMessage(message, publicKeyPem, senderPublicKeyPem) {}

    decryptMessage(message, privateKeyPem) {}

    validate(message) {}
}
