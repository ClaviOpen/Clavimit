import { MessageFormat } from "./messageFormat.js";
import {
    constuctEncryptedAESKey,
    encrypt,
    validateRsaKeyForEncryption,
    generateAESKey,
} from "../cryptography.js";

export class V1Format extends MessageFormat {
    constructor() {
        super({
            version: 1,
            label: "Clavimit 0.1 and later",
        });
    }

    async encryptMessage(message, publicKeyPem, senderPublicKeyPem) {
        let recipientRsaKey;
        try {
            recipientRsaKey = await importPublicKey(publicKeyPem);
            validateRsaKeyForEncryption(recipientRsaKey);
        } catch {
            throw new ClavimitError(
                "INVALID_RECIPIENT_PUBLIC_KEY",
                "The recipient's public key could not be read.",
            );
        }
        const aesKey = await generateAESKey();
        const { ciphertext, iv } = await encrypt(message, aesKey);
        const encryptedKey = await constuctEncryptedAESKey(
            aesKey,
            recipientRsaKey,
        );
        let senderEncKey = null;
        if (senderPublicKeyPem) {
            let senderRsaKey;
            try {
                senderRsaKey = await importPublicKey(senderPublicKeyPem);
                validateRsaKeyForEncryption(senderRsaKey);
            } catch {
                throw new ClavimitError(
                    "INVALID_SENDER_PUBLIC_KEY",
                    "The sender's public key could not be read.",
                );
            }
            senderEncKey = await constuctEncryptedAESKey(aesKey, senderRsaKey);
        }

        return {
            encryptedKeys: {
                recipient: encryptedKey,
                sender: senderEncKey,
            },
            ciphertext: ciphertext,
            iv: iv,
        };
    }

    decryptMesage(message, keys) {}

    validate(message) {}
}
