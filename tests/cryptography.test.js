import { describe, it, expect } from "vitest";
import {
    encryptMessage,
    decryptMessage,
    importPublicKey,
    computeFingerprint,
} from "#src/scripts/cryptography";

function pemToDer(pem) {
    const base64 = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/\s+/g, "");

    const binary = atob(base64);

    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function generateKeyPair() {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"],
    );

    const publicKeyBuffer = await crypto.subtle.exportKey("spki", publicKey);

    const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", privateKey);

    return {
        publicKey: toPem(publicKeyBuffer, "PUBLIC KEY"),
        privateKey: toPem(privateKeyBuffer, "PRIVATE KEY"),
    };
}

function toPem(buffer, label) {
    const bytes = new Uint8Array(buffer);

    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    const base64 = btoa(binary);
    const lines = base64.match(/.{1,64}/g).join("\n");

    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

describe("encryption and decryption", () => {
    it("encrypts and decrypts a message with the recipient key", async () => {
        const { publicKey, privateKey } = await generateKeyPair();

        const message = "This is a dummy message";
        const encrypted = await encryptMessage(message, publicKey);
        const decrypted = await decryptMessage(encrypted, privateKey);

        expect(decrypted).toBe(message);
    });

    it("encrypts and decrypts an empty message", async () => {
        const { publicKey, privateKey } = await generateKeyPair();

        const message = "";
        const encrypted = await encryptMessage(message, publicKey);
        const decrypted = await decryptMessage(encrypted, privateKey);

        expect(decrypted).toBe(message);
    });

    it("allows the sender to decrypt with the sender private key", async () => {
        const recipient = await generateKeyPair();
        const sender = await generateKeyPair();

        const message = "Message readable by sender";

        const encrypted = await encryptMessage(
            message,
            recipient.publicKey,
            sender.publicKey,
        );

        const decrypted = await decryptMessage(encrypted, sender.privateKey);

        expect(decrypted).toBe(message);
    });

    it("allows the recipient to decrypt when a sender copy exists", async () => {
        const recipient = await generateKeyPair();
        const sender = await generateKeyPair();

        const message = "Message readable by recipient";

        const encrypted = await encryptMessage(
            message,
            recipient.publicKey,
            sender.publicKey,
        );

        const decrypted = await decryptMessage(encrypted, recipient.privateKey);

        expect(decrypted).toBe(message);
    });

    it("throws INVALID_RECIPIENT_PUBLIC_KEY when recipient key is empty", async () => {
        await expect(encryptMessage("dummy message", "")).rejects.toMatchObject(
            {
                code: "INVALID_RECIPIENT_PUBLIC_KEY",
            },
        );
    });

    it("throws INVALID_RECIPIENT_PUBLIC_KEY when recipient key is invalid", async () => {
        await expect(
            encryptMessage("dummy message", "dummy key"),
        ).rejects.toMatchObject({
            code: "INVALID_RECIPIENT_PUBLIC_KEY",
        });
    });

    it("throws INVALID_SENDER_PUBLIC_KEY when sender key is invalid", async () => {
        const recipient = await generateKeyPair();

        await expect(
            encryptMessage(
                "dummy message",
                recipient.publicKey,
                "dummy sender key",
            ),
        ).rejects.toMatchObject({
            code: "INVALID_SENDER_PUBLIC_KEY",
        });
    });

    it("does not create a sender key when none is provided", async () => {
        const recipient = await generateKeyPair();

        const encrypted = await encryptMessage(
            "dummy message",
            recipient.publicKey,
        );

        expect(encrypted.encryptedKeys.recipient).toBeTypeOf("string");

        expect(encrypted.encryptedKeys.sender).toBeNull();
    });

    it("creates both encrypted key copies when sender key is provided", async () => {
        const recipient = await generateKeyPair();
        const sender = await generateKeyPair();

        const encrypted = await encryptMessage(
            "dummy message",
            recipient.publicKey,
            sender.publicKey,
        );

        expect(encrypted.encryptedKeys.recipient).toBeTypeOf("string");

        expect(encrypted.encryptedKeys.sender).toBeTypeOf("string");
    });

    it("rejects a private key that belongs to neither sender nor recipient", async () => {
        const recipient = await generateKeyPair();
        const sender = await generateKeyPair();
        const stranger = await generateKeyPair();

        const encrypted = await encryptMessage(
            "secret message",
            recipient.publicKey,
            sender.publicKey,
        );

        await expect(
            decryptMessage(encrypted, stranger.privateKey),
        ).rejects.toMatchObject({
            code: "DECRYPTION_FAILED",
        });
    });
});

describe("Public key fingerprint", () => {
    it("computes the expected SHA-256 SPKI fingerprint", async () => {
        const PK_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwgWcmFpy9HtVEjpytJ8
Z9jyZetgT40RHi1UZkiFBQur1R1AyweDfTnf1MIcF3GME9lhb+UREMJtYOpTxrta
RErLMy3681CbAQrLb8IFit31kbE/lPduXcY+7fXKaW3MkdjNwR5w+swADZsqM50E
VU1VwB/9PhQMpfZFpayJauY8lwIiK/6XF7bLe+6PamVE2HXWyerX3whszpjvSKvF
I5KUuyE4Qe1LZrD33pbPC3axUmMDpRCjxctpgKGOLEbQu654ZpLm3sTLRchW6OOM
jyvJMIhIhO3QzRHWINXlPLlP9M4Y7GdtSHmTCxLctd/Zh7aNpJvskM1y8DlCLfGQ
QwIDAQAB
-----END PUBLIC KEY-----`;
        const expectedDigest =
            "5eef6637277a452cdae279cdb3ccefd47c6107c35a0af0a426a907fc57c75e45";
        const key = await importPublicKey(PK_PEM);
        const fingerprint = await computeFingerprint(key);
        expect(fingerprint).toBe(expectedDigest);
    });

    it("produces different fingerprints for different public keys", async () => {
        const PK_PEM_1 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwgWcmFpy9HtVEjpytJ8
Z9jyZetgT40RHi1UZkiFBQur1R1AyweDfTnf1MIcF3GME9lhb+UREMJtYOpTxrta
RErLMy3681CbAQrLb8IFit31kbE/lPduXcY+7fXKaW3MkdjNwR5w+swADZsqM50E
VU1VwB/9PhQMpfZFpayJauY8lwIiK/6XF7bLe+6PamVE2HXWyerX3whszpjvSKvF
I5KUuyE4Qe1LZrD33pbPC3axUmMDpRCjxctpgKGOLEbQu654ZpLm3sTLRchW6OOM
jyvJMIhIhO3QzRHWINXlPLlP9M4Y7GdtSHmTCxLctd/Zh7aNpJvskM1y8DlCLfGQ
QwIDAQAB
-----END PUBLIC KEY-----`;
        const PK_PEM_2 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjHj3SNo6I4uhcmgketLx
qa2Ill9sjbSK9ZNXcyjHUIF7iCWT1W3YS5Xsn5xDDlLL2bdjo5Ig68xkzr8QNbqM
M28QbommqodR8FMXnJD0OqnrtVSWNMjScSQ4CT1XtwxPS6mkl306qwxONqP48j7H
sU65VmhCtntjzFX5JIKt3JpwbJy7z2qsvXfJvlVwZ74oA4uPQh2iuBAMWyNOcmM4
geUUY3YDo0KW3eLGmp65pGsij5ZWKiDD6Qs+iQAzxMZsCLpDCh0YwxbMK9IbPlr9
Bcj5AqORdfuTSKASrXXd5usXt3PKKwMAaJNDQ7W6Ag3MkN5UQ1UDW0G/IszLmCVF
RQIDAQAB
-----END PUBLIC KEY-----`;
        const publicKey1 = await importPublicKey(PK_PEM_1);
        const publicKey2 = await importPublicKey(PK_PEM_2);

        const fingerprint1 = await computeFingerprint(publicKey1);
        const fingerprint2 = await computeFingerprint(publicKey2);

        expect(fingerprint1).not.toBe(fingerprint2);
    });
    it("rejects a non-extractable public key", async () => {
        const PK_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwgWcmFpy9HtVEjpytJ8
Z9jyZetgT40RHi1UZkiFBQur1R1AyweDfTnf1MIcF3GME9lhb+UREMJtYOpTxrta
RErLMy3681CbAQrLb8IFit31kbE/lPduXcY+7fXKaW3MkdjNwR5w+swADZsqM50E
VU1VwB/9PhQMpfZFpayJauY8lwIiK/6XF7bLe+6PamVE2HXWyerX3whszpjvSKvF
I5KUuyE4Qe1LZrD33pbPC3axUmMDpRCjxctpgKGOLEbQu654ZpLm3sTLRchW6OOM
jyvJMIhIhO3QzRHWINXlPLlP9M4Y7GdtSHmTCxLctd/Zh7aNpJvskM1y8DlCLfGQ
QwIDAQAB
-----END PUBLIC KEY-----`;
        const der = pemToDer(PK_PEM);

        const publicKey = await crypto.subtle.importKey(
            "spki",
            der,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"],
        );

        await expect(computeFingerprint(publicKey)).rejects.toThrow();
    });
});
