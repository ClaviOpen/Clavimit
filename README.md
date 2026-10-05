<h1>
  <img src="src/icons/icon128.png" width="48" align="center" alt="Clavimit icon">
  Clavimit
</h1>

Clavimit is a browser extension for encrypting and decrypting Gmail messages using client-side cryptography.

It uses hybrid encryption with **AES-256-GCM** and **RSA-OAEP with SHA-256**. Encryption and decryption are performed locally in the browser using the Web Crypto API.

Clavimit does not require an account or a Clavimit server.

## Screenshots

<p align="center">
  <img src="images/clavimitInit.png" alt="Clavimit initial view" width="23%" />
  <img src="images/ClavimitEncrpt.png" alt="Clavimit encryption view" width="23%" />
  <img src="images/ClavimitDecrypt.png" alt="Clavimit decryption view" width="23%" />
  <img src="images/ClavimitKeyGeneration.png" alt="Clavimit key generation view" width="23%" />
</p>

<p aligh="center"> 
   <img src="images/encryptingEmail.png" alt="Clavimit encrypting email view" width="100%">
</p>





## Features
* 🔐 Encrypt Gmail messages
* 🔓 Decrypt Clavimit messages directly from Gmail
* ✍️ Secure compose mode keeps plaintext out of Gmail's compose field
* 👤 Optional sender-side decryption for messages in Sent
* 🔑 Use your own RSA keys or generate a key pair locally
* 🌐 Available for Chrome and Firefox
* 🚫 No Clavimit account or backend required
* 🧩 Built using the browser-native Web Crypto API

## Installation

### Google Chrome
Clavimit is available on the Chrome Web Store. [Install Clavimit from the Chrome Web Store](https://chromewebstore.google.com/detail/clavimit/iicgeaiojengjpccnjcchkkokiagkihd)

### Mozilla Firefox
Clavimit is available on the Firefox Add-Ons. [Install Clavimit from Firefox Add-Ons](https://addons.mozilla.org/en-US/firefox/addon/clavimit/)

## 🤝 Contributing

Contributors are welcome — including first-time open-source contributors.

Clavimit is a small project that touches several interesting areas:
* browser extension development
* JavaScript
* Gmail/DOM integration
* Web Crypto
* testing
* privacy and security
* UI/UX

UI improvements, tests, documentation, validation, browser compatibility, and Gmail integration are all valuable areas to work on.

### Good first contributions

If this is your first contribution, these are good places to start:

* [#16 — Improve README.md and CONTRIBUTING.md files](https://github.com/ClaviOpen/Clavimit/issues/16)
* [#1 — Keep package and manifest versions synchronized](https://github.com/ClaviOpen/Clavimit/issues/1)
* [See all good first issues](https://github.com/claviOpen/Clavimit/issues?q=is%3Aissue+state%3Aopen+label%3A%22good+first+issue%22)

For larger tasks, see the [open issues](https://github.com/ClaviOpen/Clavimit/issues).

Read `CONTRIBUTING.md` for development setup, testing, contribution guidelines, and pull-request instructions.

If you're unsure whether an issue is suitable for you, leave a comment on it. I'm happy to point you toward the relevant parts of the codebase.

## How it works

### Encrypting
When encrypting a message:

1. Open Clavimit.
2. Open the encryption section.
3. Provide the recipient's RSA public key by:
   * pasting the key, or
   * selecting a public-key file.
4. Choose a compose mode:
   * **Gmail compose** - encrypt the message currently written in Gmail.
   * **Secure compose** - write the plaintext message directly inside Clavimit. Clavimit opens a Gmail compose window automatically and inserts only the encrypted message. 
5. Optionally enable **Keep a decryptable copy for the sender** and provide the sender's RSA public key.
6. Click **Encrypt**.

Clavimit generates a new AES-256 key for each message and encrypts the email content using AES-GCM.

The AES key is encrypted using the recipient's RSA public key with RSA-OAEP. If **Keep a decryptable copy for the sender** is enabled, the same AES key is also encrypted using the sender's RSA public key. Encrypting the AES key separately for the recipient and sender allows either party to decrypt the same encrypted message using their own RSA private key.

The encrypted email contains the information required for the recipient to decrypt it, including:

* the encrypted AES key
* the encrypted AES key for the sender, when enabled
* the initialization vector (IV)
* the encrypted message
* the algorithm identifiers
* the Clavimit message-format version

Encrypted messages are wrapped in a Clavimit message block:

```text
-----BEGIN CLAVIMIT MAIL-----
...
-----END CLAVIMIT MAIL-----
```

### Decryption
To decrypt a Clavimit message:

1. Open the encrypted email in Gmail.
2. Open Clavimit.
3. Provide your RSA private key by:

   * pasting the key, or
   * selecting a private-key file.
4. Click **Decrypt**.

Clavimit attempts to decrypt the message AES key using the provided RSA private key. If the message contains both recipient and sender encrypted-key copies, Clavimit automatically uses the one that can be decrypted with the supplied private key.

The recovered AES key is then used to decrypt the email content.

The resulting plaintext is displayed by the extension.

The **Keep a decryptable copy for the sender** feature allows the senders to decrypt their own messages from Gmail's Sent section.

### RSA key generation
Clavimit can optionally generate an RSA key pair for you. This is not required; you can also use your existing compatible RSA keys.

## Cryptography

Clavimit currently uses:

* **AES-256-GCM** for message encryption
* **RSA-OAEP with SHA-256** for encrypting the AES key
* a newly generated AES key for every encrypted message
* a new random initialization vector for every encryption operation
* the browser's native **Web Crypto API**

Clavimit does not implement cryptographic primitives itself.

## Key ownership

For encryption, Clavimit requires the recipient's **public key**. The sender may optionally provide their own public key to keep a decryptable copy of the message.

For decryption, Clavimit requires a **private key** corresponding to one of the public keys used during encryption.

Users remain responsible for storing, backing up, exchanging, and verifying their own RSA keys. Keys can be generated independently or optionally generated locally using Clavimit.

Keys are provided to Clavimit only when they are needed, either by pasting them into the extension or selecting a key file.

Clavimit does not intentionally:

* upload keys to a server
* synchronize keys between devices
* permanently store private keys in the browser
* provide key recovery
* distribute public keys
* verify that a public key belongs to a particular person

Key ownership and key distribution remain under the user's control.

## Privacy

Encryption and decryption are performed locally in the browser.

Clavimit does not require a backend service for message encryption or decryption.

The email content and cryptographic keys are processed by the extension only when required to perform the requested operation.

For more details, see [Privacy Policy](PRIVACY.md).

### Gmail draft limitation

When using **Gmail compose**, Clavimit encrypts the message after it has already been written in Gmail's compose window.

Gmail may automatically save the plaintext message as a draft before Clavimit applies encryption. Therefore, Gmail compose mode does **not** protect the plaintext message from Gmail while it is being composed.

Therefore, the current version of Clavimit does **not** protect the plaintext message from Gmail itself while the message is being composed.

When using **Secure compose**, the plaintext is written inside Clavimit instead. Clavimit encrypts the message locally, opens a Gmail compose window if necessary, and inserts only the encrypted message into Gmail.

## Security limitations

Clavimit is currently an experimental project and has **not been independently security audited**.

It should not currently be relied upon for highly sensitive or production-critical communication.

Clavimit also does not currently provide:

* public-key identity verification
* digital signatures
* sender authentication
* automatic public-key discovery
* protection against a malicious or compromised browser
* protection against a compromised device
* protection against plaintext drafts created by Gmail before encryption

Users should independently verify that a public key really belongs to the intended recipient before using it.

## Current status

Clavimit is under active development.

The current implementation supports:

* Gmail message encryption
* Gmail message decryption
* Gmail and secure compose modes
* Optional sender-side decryption by encrypting the AES key for both recipient and sender
* RSA public keys provided as pasted text or files
* RSA private keys provided as pasted text or files
* AES-256-GCM message encryption
* RSA-OAEP key encryption
* Clavimit-formatted encrypted email messages
* local browser-based cryptographic operations

## Project scope

Clavimit is intended to provide a simple encryption layer for Gmail while keeping cryptographic key ownership in the hands of the user.

The project deliberately does not aim to become a full cryptographic key-management system.

Future versions may improve usability around public keys and identity verification without requiring Clavimit to take ownership of users' private keys.

## Roadmap

### Near-term improvements

The next planned improvements focus on extending the current email workflow and improving privacy:

* **Attachment encryption** — encrypt email attachments together with the message content.
* **Formatted decrypted messages** — correctly display decrypted HTML and structured message content instead of showing the raw representation.
* **Symmetric encryption mode** — optionally allow encryption using a user-provided symmetric key for situations where both parties already share a secret.

### Potential future features

Longer-term features that may be explored include:

* public-key fingerprint display
* digital signatures
* signature verification using user-provided public keys
* support for additional cryptographic algorithms

Clavimit will continue to leave key ownership, distribution, and identity verification to the user rather than acting as a key-management or identity service.

## Contributing

Contributions are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, contribution guidelines, issue reporting, and current areas for contribution.

## Install Development version
To install the development version manually:
1. Clone or download this repository.
2. Check out the develop branch: 
```bash 
git checkout develop
```
3. Install the project dependencies: 
```bash
npm install
```

### Build requirements

The extension build requires:
* Node.js
* npm
* No external or web-based build tools

package-lock.json is included to reproduce dependency versions.

The build script copies the extension source files, selects the browser-specific implementation, and generates the final manifest.json by combining the common manifest with the browser-specific manifest.

### Build for Chrome
Run
```bash
npm run build:chrome
```
The generated Chrome extension is written to: `dist/chrome`

To load it manually:
1. Open Chrome.
2. Navigate to `chrome://extensions`. 
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the `dist/chrome` directory.
6. Open Gmail.
7. Open Clavimit from Chrome and use the side panel to encrypt or decrypt messages.

### Build for Firefox
Run
```bash
npm run build:firefox
```
The generated Firefox extension is written to: `dist/firefox`

To load it manually:
1. Open Firefox.
2. Navigate to `about:debugging`. 
3. Select **This Firefox**.
4. Click **Load Temporary Add-on**.
5.Select the `dist/firefox/manifest.json` file.
6. Open Gmail.
7. Open Clavimit from Chrome and use the side panel to encrypt or decrypt messages.

Extensions loaded through `about:debugging` are temporary and must be loaded again after restarting Firefox.



## License

Clavimit is licensed under the **GNU General Public License v3.0**.

See the [LICENSE](LICENSE) file for details.
