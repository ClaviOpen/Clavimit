import { MessageFormat } from "./messageFormat.js";
import { RsaOap, aesGcm } from "../cryptography.js";

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

    decryptMesage(message, keys) {}

    validate(message) {}
}
