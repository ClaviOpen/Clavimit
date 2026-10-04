# Contributing to Clavimit

Thank you for your interest in contributing to Clavimit.

Clavimit is under active development, and contributions such as bug reports, documentation improvements, testing, feature proposals, and code changes are welcome.

## Before contributing

For small fixes, documentation improvements, or straightforward bug fixes, feel free to open an issue or pull request directly.

For larger features, cryptographic changes, or architectural changes, please open an issue first so the proposed approach can be discussed before significant work is started.

## How to contribute

To contribute code to Clavimit:

1. Fork the repository and set up your development environment as described below.
2. Create a branch in your fork for your changes.
3. Make and test your changes.
4. Push your branch to your fork.
5. Open a pull request targeting the `develop` branch of `ClaviOpen/Clavimit`.

For larger features, cryptographic changes, or architectural changes, please open an issue before starting implementation so the proposed approach can be discussed.

## Development setup

1. Fork the `ClaviOpen/Clavimit` repository.

2. Clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/Clavimit.git
cd Clavimit
```

3. Check out the `develop` branch:

```bash
git checkout develop
```

4. Install the project dependencies:

```bash
npm install
```

Before starting your changes, create a dedicated branch:

```bash
git checkout -b your-branch-name
```

#### Build for Chrome
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

#### Build for Firefox
Run
```bash
npm run build:firefox
```
The generated Chrome extension is written to: `dist/firefox`

To load it manually:
1. Open Firefox.
2. Navigate to `about:debugging`. 
3. Select **This Firefox**.
4. Click **Load Temporary Add-on**.
5. Select the `dist/firefox/manifest.json` file.
6. Open Gmail.
7. Open Clavimit from Chrome and use the side panel to encrypt or decrypt messages.

Extensions loaded through `about:debugging` are temporary and must be loaded again after restarting Firefox.


## Reporting issues

Clavimit provides dedicated GitHub issue templates to help keep reports clear and consistent.

### Bug reports

Use the **Bug report** template when something does not behave as expected.

Please provide enough information to reproduce the issue, including the relevant environment details.

When reporting the environment, distinguish between:

* the development version installed using **Load unpacked**
* the published Chrome Web Store extension

The extension version can be found in `chrome://extensions`.

Do not include private keys, sensitive email content, or other confidential information in bug reports.

### Feature requests

Use the **Feature request** template to propose new functionality or improvements.

For substantial features, please describe:

* the problem the feature would solve
* the proposed behavior
* possible alternatives
* any security or privacy implications

Clavimit aims to remain focused on client-side email encryption and does not intend to become a key-management or identity service.

### Documentation

Use the **Documentation** template to report documentation that is:

* missing
* unclear
* outdated
* incorrect

Documentation issues may concern the README, Privacy Policy, contributing guide, installation instructions, extension UI text, or other user-facing explanations.

## Pull requests

Pull requests are welcome.

Pull requests should target the `develop` branch. The `main` branch is reserved for stable releases.

A pull request may target main if this has been agreed in advance, during discussion of the related issue, or when the issue explicitly specifies it. This may be appropriate for certain documentation changes, urgent bug fixes, or other changes that need to be included in the current stable release without waiting for the next development merge.

Please use the provided pull request template and keep each pull request focused on a single issue, feature, or improvement whenever possible.

When submitting a pull request:

* explain what changed and why
* keep unrelated changes out of the same pull request
* test the affected functionality
* add or update automated tests where appropriate
* update documentation if behavior changes
* avoid introducing unnecessary dependencies
* clearly explain any new permissions or external services

Changes affecting cryptography, message parsing, Gmail access, or key handling should be kept particularly small and reviewable.

## Current areas for contribution

Some areas currently planned for development include:

* **Attachment encryption** — support encryption and decryption of email attachments.
* **Formatted decrypted messages** — correctly render decrypted HTML and structured message content.
* **Symmetric encryption mode** — support encryption using user-provided symmetric keys.
* **Improved Gmail integration** — make message and compose-window detection more robust.
* **Automated tests** — expand coverage for cryptographic operations, message formatting, invalid input, and edge cases.
* **UI and accessibility improvements**
* **Documentation improvements**

Potential longer-term features include:

* public-key fingerprint display
* digital signatures
* signature verification using user-provided public keys
* support for additional cryptographic algorithms

## Security-related changes

Clavimit handles cryptographic operations, cryptographic keys, and email content.

Contributions should therefore avoid unnecessary complexity in security-sensitive parts of the project.

Please avoid:

* implementing custom cryptographic primitives
* storing private keys without prior design discussion
* adding network requests or external services without discussion
* weakening cryptographic parameters for compatibility or convenience
* adding permissions that are not required for Clavimit's functionality

Clavimit currently relies on the browser's Web Crypto API for cryptographic operations.

Changes involving cryptography should include automated tests whenever possible.

## Testing

Changes should be tested according to the functionality they affect.

Important cryptographic and message-format test cases include:

* encryption/decryption round trips
* Unicode content
* empty messages
* malformed Clavimit messages
* corrupted ciphertext
* modified initialization vectors
* incorrect public or private keys
* invalid key formats

Changes affecting Gmail integration should also be tested manually using the development version of the extension.

Documentation-only changes do not require Gmail testing.

## Code style

Try to follow the style already used throughout the project.

Before submitting a pull request, format the project with:

```bash
npm run format
```

Formatting is also checked automatically by CI.

In addition:

* use clear function and variable names
* keep functions focused on a single responsibility
* prefer browser-native APIs over unnecessary dependencies
* keep cryptographic logic separate from Gmail DOM handling
* use Clavimit's application-level error handling for expected failures
* remove debugging code before submitting a pull request
* never commit real private keys or sensitive email content

## Privacy

Contributions must respect Clavimit's privacy principles.

Clavimit should not transmit email content or cryptographic keys to external services unless such a change has been explicitly discussed, justified, and documented.

For more details, see the [Privacy Policy](PRIVACY.md).

## License

By contributing to Clavimit, you agree that your contributions will be licensed under the same license as the project: the **GNU General Public License v3.0**.

See the [LICENSE](LICENSE) file for details.
