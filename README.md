# Secure File Vault

A robust, production-ready web application built with Python and Flask for encrypted temporary file sharing and password-based file encryption.

## Features

- **Encrypted Online Clipboard**: Join the website lobby, see active users, and send encrypted files directly to one or more receivers.
- **Self-Destruct Policies**: Clips can be destroyed after 1 or 2 downloads and expire after 5 minutes, 10 minutes, 2 hours, or 3 hours.
- **Browser-Side Public-Key Crypto**: The clipboard uses Web Crypto in the browser with ECDH, HKDF-SHA256, and AES-256-GCM.
- **Encrypted Server Storage Only**: The server stores ciphertext and metadata, never plaintext clipboard files or private keys.
- **Rate Limited APIs**: Flask-Limiter protects lobby, presence, upload, download, and classic encrypt/decrypt endpoints.
- **Upload & Encrypt**: Secure files using AES-256 GCM authenticated encryption.
- **Upload & Decrypt**: Safely decrypt previously secured files.
- **Graceful Error Handling**: Detects incorrect passwords and corrupted files via tag validation.
- **Secure by Design**: Minimal dependencies, CSRF protection, and path traversal prevention.
- **File Size Limits**: Built-in mechanisms blocking files larger than 20MB.

## Cryptography Details

This application uses the `cryptography` library to adhere to modern cryptography standards.

### Encrypted Online Clipboard
The live clipboard flow is handled in the browser through `static/channel.js`:

1. A temporary user enters a username and joins the website lobby. No room code or outside invite is required.
2. The browser generates an ECDH P-256 key pair and registers only the public key with Flask.
3. The sender selects one or more active receivers. The sender browser encrypts the file separately for each selected receiver.
4. For each receiver, the browser generates a random AES file key and encrypts the file locally with AES-256-GCM.
5. For each receiver, the browser creates an ephemeral ECDH key pair, derives a wrapping key with HKDF-SHA256, and wraps that AES file key to the selected receiver's public key.
6. Flask stores only encrypted payloads, wrapped key metadata, lobby metadata, expiry time, and remaining download count.
7. Each receiver downloads their own encrypted clip. Their browser unwraps the AES file key with their in-tab private key and decrypts the file locally.

The clipboard private key only lives in the browser tab. If the tab is closed or refreshed, that temporary user cannot decrypt pending files anymore. Because usernames are still not verified identity, users should compare the displayed key fingerprint before sharing sensitive files.

### How AES-GCM Works
AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) acts as both an encryption mode and an authenticator. It ensures that the file content hasn't been tampered with while simultaneously encrypting the confidentiality of the contents.

During encryption, a 12-byte random nonce is generated and appended with the final encryption process that yields an Authentication Tag. We output: `[16-byte salt][12-byte nonce][ciphertext + 16-byte tag]`.

### Why PBKDF2HMAC is Used
To derive a 256-bit secure key from a human-readable password, PBKDF2HMAC (Password-Based Key Derivation Function 2) stretches the chosen password through HMAC-SHA256, alongside a 16-byte random salt, iterated 210,000 times. This provides a strong defense against dictionary and brute-force attacks.

## Threat Model

1. **Stolen Encrypted File**: An attacker cannot unearth the encryption key without knowing the exact chosen password and computing the costly PBKDF2 function.
2. **File Tampering**: Because AES-GCM tags all cipher payload integrity, if an attacker flips a bit in the encrypted string to inject malicious routines, the decrypt attempt will inherently and gracefully crash via `InvalidTag`.
3. **Cross-Site Request Forgery**: All forms natively deploy and validate standard CSRF cookies securely isolated via `Flask-WTF`.
4. **Shared Package Exposure**: A stored clipboard clip cannot be opened without the receiver's temporary in-browser private key.
5. **Clipboard Exposure**: A stored clipboard blob is encrypted before upload. A server compromise exposes ciphertext, public keys, sender/receiver names, timing metadata, expiry policy, and file names, but not plaintext file contents.

### Security Limitations
- Files are kept in internal application memory using `io.BytesIO` during cryptographic processing to keep raw unencrypted segments entirely decoupled from the system disk. For extreme multi-GB sizes, you must switch to chunked streaming pipelines; which is why the system caps at 20MB payload.
- As the deployment bridges direct HTML/HTTP interactions: ensure the platform runs via HTTPS. Otherwise, credentials are exposed in cleartext transit.
- Temporary usernames are not verified identity. Use the displayed fingerprint to confirm the intended receiver when identity matters.
- The default rate-limit storage is in-memory. For multi-worker or multi-instance production deployments, set `RATELIMIT_STORAGE_URI` to Redis or another Flask-Limiter supported backend.

## How to Run the Project

1. Keep a stable Python 3.9+ runtime locally.
2. Clone/change working directory to this application.
3. Use pip to install constraints.
   ```bash
   pip install -r requirements.txt
   ```
4. Start the service.
   ```bash
   python app.py
   ```
5. Navigate to `http://localhost:5000` via web browser.

## Deployment

This app is now ready for common Python web hosts and Docker platforms.

### Required Environment Variables

Set a stable secret key in production:

```bash
FLASK_SECRET_KEY=replace-with-a-long-random-secret
```

You can generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Most hosts also provide `PORT` automatically. If yours does not, set:

```bash
PORT=5000
```

Recommended production settings:

```bash
RATELIMIT_STORAGE_URI=redis://redis:6379/0
SECURE_VAULT_DATA_DIR=/app/instance/clipboard
SESSION_COOKIE_SECURE=true
```

### Deploy With Gunicorn

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the app:

```bash
gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120
```

The included `Procfile` uses that same command for platforms that support Procfile-based Python apps.

### Deploy With Docker

Build the image:

```bash
docker build -t secure-vault .
```

Run it locally:

```bash
docker run --rm -p 5000:5000 -e FLASK_SECRET_KEY=replace-this secure-vault
```

Open:

```bash
http://localhost:5000
```

### Hosted Platform Checklist

1. Push this folder to a Git repository.
2. Create a new Python web service or Docker web service on your host.
3. Set `FLASK_SECRET_KEY` in the service environment.
4. Use `pip install -r requirements.txt` as the build command for Python builds.
5. Use the Procfile command or `gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120` as the start command.
6. Enable HTTPS. The public-key sharing channel uses browser Web Crypto, which requires a secure context outside localhost.
7. For multiple Gunicorn workers or multiple app instances, configure shared `SECURE_VAULT_DATA_DIR` storage and a shared `RATELIMIT_STORAGE_URI`.

Health checks can point to:

```bash
/healthz
```

## Future Improvements

- Stream-based bulk chunk proxy encryption logic.
- Secure, hardware-based KMS wrappers or integrations.
- Rate-limiting (via `Flask-Limiter`) for excessive decryption attempts.
- Progress bars reflecting processing stages.
