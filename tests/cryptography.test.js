import { describe, it, expect } from "vitest";
import {
    encryptMessage,
    decryptMessage,
    importPublicKey,
    importPrivateKey,
} from "#src/scripts/cryptography";

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
