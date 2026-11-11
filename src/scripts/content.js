// Main UI controller for Clavimit's side panel.
// Wires up all user interactions: encrypt/decrypt buttons, RSA key
// pair generation, key file imports, and Gmail compose/secure-compose
// mode toggling. Coordinates cryptography.js (encryption/decryption),
// emailParser.js (reading/writing Gmail content), and
// messageFormat.js (wrapping/unwrapping the Clavimit message format).

import {
    encryptMessage,
    decryptMessage,
    generateKeyPair,
    validateRsaKeyForEncryption,
    computeFingerprint,
    importPublicKey,
} from "./cryptography.js";
import {
    getReceivedEmailText,
    setEmailText,
    getInputEmailText,
    openComposeWindow,
} from "./emailParser.js";
import { parseMessage, composeMessage } from "./messageFormat.js";
import { ClavimitError } from "./exeptions.js";

function setStatus(element, message, success = false) {
    element.textContent = message;
    element.hidden = false;
    element.classList.toggle("operation-status--success", success);
}

function clearStatus(element) {
    element.textContent = "";
    element.hidden = true;
    element.classList.remove("operation-status--success");
}

const encryptStatus = document.getElementById("encryptStatus");
const decryptStatus = document.getElementById("decryptStatus");
const keyGenerationStatus = document.getElementById("keyGenerationStatus");

const decryptError = document.getElementById("decryptError");

function showDecryptError(message) {
    decryptError.textContent = message;
    decryptError.hidden = false;
}

function clearDecryptError() {
    decryptError.textContent = "";
    decryptError.hidden = true;
}

const encryptError = document.getElementById("encryptError");
const senderPKError = document.getElementById("senderPKError");

function showEncryptError(message) {
    encryptError.textContent = message;
    encryptError.hidden = false;
}

function clearEncryptError() {
    encryptError.textContent = "";
    encryptError.hidden = true;
}

function showSenderPKError(message) {
    senderPKError.textContent = message;
    senderPKError.hidden = false;
}

function clearSenderPKError() {
    senderPKError.textContent = "";
    senderPKError.hidden = true;
}

function downloadPem(filename, pem) {
    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
}

const button = document.getElementById("enc");
const publicKeyInput = document.getElementById("publicKey");
const privateKeyInput = document.getElementById("privateKey");
const senderPublicKeyInput = document.getElementById("senderPublicKey");

const decryptButton = document.getElementById("dec");
const decryptedText = document.getElementById("decryptedText");

const encryptWithSenderKeyCheckBox = document.getElementById(
    "encryptWithSenderPublicKey",
);
const publicKeyFingerprint = document.getElementById("publicKeyFingerPrint");

// -------- Key generation
const generateRsaKeyPairButton = document.getElementById("generateKeyPair");
const generatedKeys = document.getElementById("generatedKeys");
const generatedPublicKey = document.getElementById("generatedPublicKey");
const generatedPrivateKey = document.getElementById("generatedPrivateKey");

generateRsaKeyPairButton.addEventListener("click", async () => {
    clearStatus(keyGenerationStatus);

    generateRsaKeyPairButton.disabled = true;
    generateRsaKeyPairButton.textContent = "Generating key pair…";
    try {
        const keyPair = await generateKeyPair();
        generatedPublicKey.value = keyPair.publicKey;
        generatedPrivateKey.value = keyPair.privateKey;
        document.getElementById("generatePublicKeyDiv").hidden = false;
        document.getElementById("generatePrivateKeyDiv").hidden = false;
        setStatus(keyGenerationStatus, "✓ Key pair generated", true);
    } finally {
        generateRsaKeyPairButton.disabled = false;
        generateRsaKeyPairButton.textContent = "Generate RSA key pair";
    }
});

document.getElementById("downloadPublicKey").addEventListener("click", () => {
    downloadPem("clavimit-public.pem", generatedPublicKey.value);
    generatedPublicKey.value = "";
    document.getElementById("generatePublicKeyDiv").hidden = true;
});

document.getElementById("downloadPrivateKey").addEventListener("click", () => {
    downloadPem("clavimit-private.pem", generatedPrivateKey.value);
    generatedPrivateKey.value = "";
    document.getElementById("generatePrivateKeyDiv").hidden = true;
});
// --------

// Emails writing modes
const secureCompose = document.getElementById("secureCompose");
const secureMessageInput = document.getElementById("secureMessage");
const secureComposeDiv = document.getElementById("secureComposeDiv");
secureCompose.addEventListener("change", () => {
    secureComposeDiv.hidden = !secureCompose.checked;
});

gmailCompose.addEventListener("change", () => {
    secureComposeDiv.hidden = !secureCompose.checked;
});
//

// Encryption with sender public key
encryptWithSenderKeyCheckBox.addEventListener("change", () => {
    const encryptWithSenderKeyDiv = document.getElementById(
        "encryptWithSenderPublicKeyDiv",
    );
    encryptWithSenderKeyDiv.hidden = !encryptWithSenderKeyCheckBox.checked;
});

// Import RSA keys
const privateKeyFile = document.getElementById("privateKeyFile");
const publicKeyFile = document.getElementById("publicKeyFile");
const senderPublicKeyFile = document.getElementById("senderPublicKeyFile");

privateKeyFile.addEventListener("change", async () => {
    const file = privateKeyFile.files[0];
    if (!file) {
        return;
    }
    const text = await file.text();
    privateKeyInput.value = text;
});

publicKeyFile.addEventListener("change", async () => {
    clearEncryptError();
    const file = publicKeyFile.files[0];
    if (!file) return;
    try {
        const text = await file.text();
        if (!text) return;
        publicKeyInput.value = text;
        publicKeyInput.dispatchEvent(new Event("input", { bubbles: true }));
    } catch (error) {
        console.error("Could not read public key file:", error);
        showEncryptError("Could not read the selected public key file.");
    }
});

senderPublicKeyFile.addEventListener("change", async () => {
    const file = senderPublicKeyFile.files[0];
    if (!file) {
        return;
    }
    const text = await file.text();
    senderPublicKeyInput.value = text;
    senderPublicKeyInput.dispatchEvent(new Event("input", { bubbles: true }));
});

senderPublicKeyInput.addEventListener("input", async () => {
    clearEncryptError();
    clearSenderPKError();
    const text = senderPublicKeyInput.value;
    if (!text.trim()) return;

    let key;
    try {
        key = await importPublicKey(text);
        if (senderPublicKeyInput.value !== text) return;
    } catch (error) {
        if (senderPublicKeyInput.value !== text) return;
        console.log("Invalid or incomplete public key:", error);
        showSenderPKError("Could not import public key.");
        return;
    }
    try {
        validateRsaKeyForEncryption(key);
    } catch (error) {
        if (senderPublicKeyInput.value !== text) return;

        console.error("Public key import or validation failed:", error);
        if (error instanceof ClavimitError) {
            showSenderPKError(error.message);
        } else {
            showSenderPKError("Could not import or validate public key.");
        }
    }
});

publicKeyInput.addEventListener("input", async () => {
    clearEncryptError();
    publicKeyFingerprint.textContent = "";
    publicKeyFingerprint.hidden = true;
    const text = publicKeyInput.value;
    if (!text.trim()) return;

    let key;
    try {
        key = await importPublicKey(text);
        if (publicKeyInput.value !== text) return;
    } catch (error) {
        if (publicKeyInput.value !== text) return;
        console.log("Invalid or incomplete public key:", error);
        showEncryptError("Could not import public key.");
        return;
    }
    try {
        validateRsaKeyForEncryption(key);
        try {
            const fingerprint = await computeFingerprint(key);
            if (publicKeyInput.value !== text) return;
            publicKeyFingerprint.textContent = `SHA-256 fingerprint: ${fingerprint}`;
            publicKeyFingerprint.hidden = false;
        } catch (error) {
            if (publicKeyInput.value !== text) return;
            console.log("Invalid or incomplete public key:", error);
            showEncryptError(
                "Could not compute the fingerprint. Please check that the public key is valid.",
            );
        }
    } catch (error) {
        if (publicKeyInput.value !== text) return;
        console.error("Public key import or validation failed:", error);
        if (error instanceof ClavimitError) {
            showEncryptError(error.message);
        } else {
            showEncryptError("Could not import or validate public key.");
        }
    }
});

//

// Email decryption handler
const copyDecryptedTextButton = document.getElementById("copyDecryptedText");

copyDecryptedTextButton.addEventListener("click", async () => {
    await navigator.clipboard.writeText(decryptedText.value);
});
decryptButton.addEventListener("click", async () => {
    clearDecryptError();
    document.getElementById("decryptionResultArea").hidden = true;
    clearStatus(decryptStatus);
    try {
        const privateKey = privateKeyInput.value.trim();

        if (!privateKey) {
            throw new ClavimitError(
                "EMPTY_PRIVATE_KEY",
                "Please enter your private key.",
            );
        }
        const text = await getReceivedEmailText();
        const message = parseMessage(text);
        const plaintext = await decryptMessage(message, privateKey);
        decryptedText.value = plaintext;
        document.getElementById("decryptionResultArea").hidden = false;
        setStatus(decryptStatus, "✓ Message decrypted", true);
    } catch (error) {
        console.error("Decryption error:", error);

        if (error instanceof ClavimitError) {
            showDecryptError(error.message);
        } else {
            showDecryptError(
                "Something went wrong while decrypting the message.",
            );
        }
    } finally {
        decryptButton.disabled = false;
        decryptButton.textContent = "Decrypt Email";
        privateKeyInput.value = "";
        privateKeyFile.value = "";
    }
});

// Email encryption handler
button.addEventListener("click", async () => {
    clearEncryptError();
    clearStatus(encryptStatus);
    try {
        const publicKey = publicKeyInput.value.trim();
        if (!publicKey) {
            throw new ClavimitError(
                "EMPTY_PUBLIC_KEY",
                "Please enter the recipient's public key.",
            );
        }

        let senderPublicKey = null;
        if (encryptWithSenderKeyCheckBox.checked) {
            senderPublicKey = senderPublicKeyInput.value.trim();

            if (!senderPublicKey) {
                throw new ClavimitError(
                    "EMPTY_SENDER_PUBLIC_KEY",
                    "Please enter the sender's public key.",
                );
            }
        }
        let text;
        if (secureCompose.checked) {
            text = secureMessageInput.value;
            const opened = await openComposeWindow();

            if (!opened) {
                throw new ClavimitError(
                    "COMPOSE_NOT_FOUND",
                    "Clavimit could not open a Gmail compose window.",
                );
            }
        } else {
            text = await getInputEmailText();
        }
        setStatus(
            encryptStatus,
            "✓ Encrypted message inserted into Gmail",
            true,
        );

        if (!text?.trim()) {
            throw new ClavimitError(
                "EMPTY_MESSAGE",
                "No message to encrypt provided.",
            );
        }
        const enc = await encryptMessage(text, publicKey, senderPublicKey);
        const message = composeMessage(enc);
        await setEmailText(message);
    } catch (error) {
        console.error("Encryption error:", error);

        if (error instanceof ClavimitError) {
            showEncryptError(error.message);
        } else {
            showEncryptError("Something unexpected went wrong.");
        }
    } finally {
        button.disabled = false;
        button.textContent = "Encrypt Email";
        publicKeyInput.value = "";
        publicKeyFile.value = "";
        publicKeyFingerprint.textContent = "";
        publicKeyFingerprint.hidden = true;
        if (senderPublicKeyInput.value) {
            senderPublicKeyInput.value = "";
            senderPublicKeyFile.value = "";
        }
    }
});
