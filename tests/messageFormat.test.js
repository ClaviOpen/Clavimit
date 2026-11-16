import { describe, it, expect } from "vitest";

import {
    parseMessage,
    deserializeMessage,
    validateMessage,
} from "#src/scripts/messageFormats/messageFormat.js";

import {
    MESSAGE_BEGIN,
    MESSAGE_END,
    PAYLOAD_VERSION,
    ALGORITHM,
    KEY_ALGORITHM,
} from "#src/scripts/config.js";

const validMessage = {
    version: PAYLOAD_VERSION,
    algorithm: ALGORITHM,
    keyAlgorithm: KEY_ALGORITHM,

    encryptedKeys: {
        recipient: "dummyRecipientEncryptedKey",
        sender: null,
    },

    iv: "dummyIv",
    ciphertext: "dummyCiphertext",
};

describe("deserialize", () => {
    it("throws INVALID_MESSAGE for invalid JSON", () => {
        expect.assertions(1);

        try {
            deserializeMessage("dummyMessage");
        } catch (error) {
            expect(error.code).toBe("INVALID_MESSAGE");
        }
    });

    it("throws INVALID_MESSAGE when the message format is invalid", () => {
        const invalidMessage = JSON.stringify({
            version: PAYLOAD_VERSION,
        });

        expect(() => {
            deserializeMessage(invalidMessage);
        }).toThrow(
            "The Clavimit message does not satisfy the expected format.",
        );
    });

    it("deserializes a valid message", () => {
        const result = deserializeMessage(JSON.stringify(validMessage));

        expect(result).toEqual(validMessage);
    });
});

describe("validateMessage", () => {
    it("accepts a valid message without a sender copy", () => {
        expect(validateMessage(validMessage)).toBe(true);
    });

    it("accepts a valid message with a sender copy", () => {
        const message = {
            ...validMessage,

            encryptedKeys: {
                recipient: "recipientKey",
                sender: "senderKey",
            },
        };

        expect(validateMessage(message)).toBe(true);
    });

    it("rejects null", () => {
        expect(validateMessage(null)).toBe(false);
    });

    it("rejects a message with missing encryptedKeys", () => {
        const message = {
            ...validMessage,
        };

        delete message.encryptedKeys;

        expect(validateMessage(message)).toBe(false);
    });

    it("rejects a message with missing recipient encrypted key", () => {
        const message = {
            ...validMessage,

            encryptedKeys: {
                sender: null,
            },
        };

        expect(validateMessage(message)).toBe(false);
    });

    it("rejects an invalid sender encrypted key", () => {
        const message = {
            ...validMessage,

            encryptedKeys: {
                recipient: "recipientKey",
                sender: 123,
            },
        };

        expect(validateMessage(message)).toBe(false);
    });

    it("rejects a message with a missing ciphertext", () => {
        const message = {
            ...validMessage,
        };

        delete message.ciphertext;

        expect(validateMessage(message)).toBe(false);
    });

    it("rejects a message with an invalid version", () => {
        const message = {
            ...validMessage,
            version: 999,
        };

        expect(validateMessage(message)).toBe(false);
    });

    it("rejects a message with an invalid algorithm", () => {
        const message = {
            ...validMessage,
            algorithm: "AES-128-CBC",
        };

        expect(validateMessage(message)).toBe(false);
    });

    it("rejects a message with an invalid key algorithm", () => {
        const message = {
            ...validMessage,
            keyAlgorithm: "RSA-PKCS1",
        };

        expect(validateMessage(message)).toBe(false);
    });
});

describe("parseMessage", () => {
    it("throws INVALID_MESSAGE for empty text", () => {
        expect(() => {
            parseMessage("");
        }).toThrow("No Clavimit message was found");
    });

    it("throws INVALID_MESSAGE when message markers are missing", () => {
        expect(() => {
            parseMessage("Hello, this is just a normal email");
        }).toThrow("Not a Clavimit message");
    });

    it("throws when the end marker is missing", () => {
        const text = `
${MESSAGE_BEGIN}
${JSON.stringify(validMessage)}
`;

        expect(() => {
            parseMessage(text);
        }).toThrow("Not a Clavimit message");
    });

    it("throws when the begin marker is missing", () => {
        const text = `
${JSON.stringify(validMessage)}
${MESSAGE_END}
`;

        expect(() => {
            parseMessage(text);
        }).toThrow("Not a Clavimit message");
    });

    it("parses a valid Clavimit message", () => {
        const text = `
${MESSAGE_BEGIN}

${JSON.stringify(validMessage)}

${MESSAGE_END}
`;

        const result = parseMessage(text);

        expect(result).toEqual(validMessage);
    });

    it("parses a Clavimit message surrounded by other text", () => {
        const text = `
Dummy wrapper begin

${MESSAGE_BEGIN}
${JSON.stringify(validMessage)}
${MESSAGE_END}

Dummy wrapper end
`;

        const result = parseMessage(text);

        expect(result).toEqual(validMessage);
    });

    it("throws INVALID_MESSAGE when enclosed JSON is invalid", () => {
        const text = `
${MESSAGE_BEGIN}
this is not JSON
${MESSAGE_END}
`;

        expect(() => {
            parseMessage(text);
        }).toThrow("The Clavimit message contains invalid JSON.");
    });

    it("throws INVALID_MESSAGE when enclosed message has an invalid format", () => {
        const text = `
${MESSAGE_BEGIN}
${JSON.stringify({ version: 1 })}
${MESSAGE_END}
`;

        expect(() => {
            parseMessage(text);
        }).toThrow(
            "The Clavimit message does not satisfy the expected format.",
        );
    });

    it("parses message containing a sender encrypted key", () => {
        const message = {
            ...validMessage,

            encryptedKeys: {
                recipient: "recipientEncryptedKey",
                sender: "senderEncryptedKey",
            },
        };

        const text = `
${MESSAGE_BEGIN}
${JSON.stringify(message)}
${MESSAGE_END}
`;

        expect(parseMessage(text)).toEqual(message);
    });
});
