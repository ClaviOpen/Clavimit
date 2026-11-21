import { MessageFormat } from "./messageFormat.js";
import { RsaOap, aesGcm } from "../cryptography.js";
import { PAYLOAD_VERSION, ALGORITHM, KEY_ALGORITHM } from "../config.js";

export class V1Format extends MessageFormat {
    constructor() {
        const scheme = new RsaOap(aesGcm);
        super({
            version: 1,
            scheme: scheme,
            label: "Clavimit 0.1 and later",
        });
    }

    async encryptMessage(message, publicKeyPem, senderPublicKeyPem) {
        const enc = await this.scheme.encryptMessage(
            message,
            publicKeyPem,
            senderPublicKeyPem,
        );
        return {
            version: this.version,
            algorithm: "AES-256-GCM",
            keyAlgorithm: "RSA-OAEP-SHA256",
            encryptedKeys: enc.encryptedKeys,
            iv: enc.iv,
            ciphertext: enc.ciphertext,
        };
    }

    async decryptMessage(message, privateKeyPem) {
        const dec = await this.scheme.decryptMessage(message, privateKeyPem);
        return dec;
    }

    validateMessage(message) {
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
}
