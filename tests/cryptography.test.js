import { describe, it, expect } from "vitest";
import {
    encryptMessage,
    decryptMessage,
    importPrivateKey,
    validateRsaKeyForEncryption,
} from "#src/scripts/cryptography";
import { ClavimitError } from "#src/scripts/exeptions";

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

    it("decrypts messages encrypted with legacy 1024-bit RSA keys", async () => {
        // Encrypt using weak RAS key.
        // - construct message manually
        // - encrypt manually (Clavimit encryption would fail due to the weak key).
        // - decrypt with Clavimit decrytion.

        const keyPair = await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 1024,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"],
        );
        const plaintext = "Legacy encrypted message";
        const aesKey = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256,
            },
            true,
            ["encrypt", "decrypt"],
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv,
            },
            aesKey,
            new TextEncoder().encode(plaintext),
        );

        const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);

        const encryptedAesKey = await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            keyPair.publicKey,
            rawAesKey,
        );

        // Export the legacy RSA private key
        const privateKeyDer = await crypto.subtle.exportKey(
            "pkcs8",
            keyPair.privateKey,
        );
        const privateKeyPem = toPem(privateKeyDer, "PRIVATE KEY");
        // Construct a Clavimit-compatible encrypted message
        const encryptedMessage = {
            encryptedKeys: {
                recipient: btoa(
                    String.fromCharCode(...new Uint8Array(encryptedAesKey)),
                ),
                sender: null,
            },
            ciphertext: btoa(
                String.fromCharCode(...new Uint8Array(ciphertext)),
            ),
            iv: btoa(String.fromCharCode(...iv)),
        };

        // Decrypt using Clavimit
        const decrypted = await decryptMessage(encryptedMessage, privateKeyPem);
        expect(decrypted).toBe(plaintext);
    });
});

describe("RSA public key validation", () => {
    const createMockKey = ({
        modulusLength = 2048,
        publicExponent = [0x01, 0x00, 0x01],
        hash = "SHA-256",
        name = "RSA-OAEP",
        type = "public",
    } = {}) => ({
        type,
        algorithm: {
            name,
            modulusLength,
            publicExponent: new Uint8Array(publicExponent),
            hash: { name: hash },
        },
    });

    it("accepts a valid RSA public key", () => {
        const key = createMockKey();
        expect(() => validateRsaKeyForEncryption(key)).not.toThrow();
    });

    it("rejects RSA moduli smaller than 2048 bits", () => {
        const key = createMockKey({ modulusLength: 1024 });
        expect(() => validateRsaKeyForEncryption(key)).toThrow(ClavimitError);
    });

    it("rejects public exponents smaller than 65537", () => {
        const key = createMockKey({ publicExponent: [0x03] });
        expect(() => validateRsaKeyForEncryption(key)).toThrow(ClavimitError);
    });

    it("rejects even public exponents", () => {
        const key = createMockKey({ publicExponent: [0x01, 0x00, 0x02] });
        expect(() => validateRsaKeyForEncryption(key)).toThrow(ClavimitError);
    });

    it("rejects public exponents greater than or equal to 2^256", () => {
        const key = createMockKey({
            publicExponent: [0x01, ...Array(32).fill(0)],
        });
        expect(() => validateRsaKeyForEncryption(key)).toThrow(ClavimitError);
    });

    it("rejects keys using an algorithm other than RSA-OAEP", () => {
        const key = createMockKey({ name: "RSA-PSS" });
        expect(() => validateRsaKeyForEncryption(key)).toThrow(Error);
    });

    it("rejects private keys", () => {
        const key = createMockKey({ type: "private" });
        expect(() => validateRsaKeyForEncryption(key)).toThrow(Error);
    });

    it("rejects RSA-OAEP keys using a hash other than SHA-256", () => {
        const key = createMockKey({ hash: "SHA-1" });
        expect(() => validateRsaKeyForEncryption(key)).toThrow(Error);
    });

    it("accepts a 2048-bit RSA modulus", () => {
        const key = createMockKey({ modulusLength: 2048 });

        expect(() => validateRsaKeyForEncryption(key)).not.toThrow();
    });

    it("rejects a 2047-bit RSA modulus", () => {
        const key = createMockKey({ modulusLength: 2047 });

        expect(() => validateRsaKeyForEncryption(key)).toThrow(ClavimitError);
    });
});
