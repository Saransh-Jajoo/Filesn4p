# Secure File Vault - Workflow Explanation

Secure File Vault now has two file protection modes:

- **Encrypted Online Clipboard:** temporary lobby users share files through the server, but files are encrypted in the sender's browser before upload.
- **Password Vault:** classic password-based AES-GCM encryption and decryption through Flask.

---

## 1. Encrypted Online Clipboard

The clipboard is designed for short-lived sharing between people who are currently active on the website.

### Step 1: User Goes Online

- **What happens:** A user enters a temporary username and clicks **Go Online**.
- **Behind the scenes:** Flask creates a temporary active user in the website lobby. No room code, passkey, or outside invite is needed.

### Step 2: Browser Creates Temporary Keys

- **What happens:** Each joined user gets a temporary cryptographic identity for that browser tab.
- **Behind the scenes:** The browser generates an ECDH P-256 public/private key pair. The public key is sent to Flask. The private key stays only in the current browser tab.

### Step 3: Server Tracks Active Users

- **What happens:** Everyone online in the website lobby can see active users and each user's key fingerprint.
- **Behind the scenes:** The browser sends heartbeat requests. Users disappear from the active list when they stop sending heartbeats.

### Step 4: Sender Chooses Receivers And Policy

- **What happens:** The sender chooses one or more active receivers, selects a file, and chooses a destroy policy.
- **Available policies:** The clip can be destroyed after 1 or 2 downloads, and it expires after 5 minutes, 10 minutes, 2 hours, or 3 hours.

### Step 5: Sender Browser Encrypts The File

- **What happens:** The plaintext file is encrypted before it reaches Flask.
- **Behind the scenes:** The browser encrypts separately for each selected receiver. For every receiver, it creates a random AES-256-GCM file key, encrypts the file locally, creates a fresh ephemeral ECDH key pair, derives a wrapping key with HKDF-SHA256 using that receiver's public key, and encrypts the AES file key for that receiver.

### Step 6: Server Stores Only Ciphertext

- **What happens:** Flask receives and stores the encrypted file blob.
- **Behind the scenes:** SQLite stores metadata such as sender name, receiver id, encrypted key metadata, expiry time, and views left. The encrypted payload is stored on disk under the configured clipboard data directory. Flask never receives the plaintext file or receiver private key.

### Step 7: Receiver Opens Incoming File

- **What happens:** The receiver clicks **Open** in the incoming file list.
- **Behind the scenes:** Flask checks the receiver id, expiry time, and remaining views. It returns the encrypted blob and metadata. The receiver browser uses its in-tab private key to unwrap the AES file key and decrypt the file locally.

### Step 8: Self-Destruction

- **What happens:** The clip is removed after the selected number of downloads or after the selected time window.
- **Behind the scenes:** Flask decrements the view counter on download. When the counter reaches zero or the clip expires, the encrypted blob is deleted and the metadata is marked deleted. Expired users and their pending clips are also cleaned up.

---

## 2. Important Clipboard Security Notes

### Plaintext Is Not Stored

The server stores encrypted files only. A server compromise can expose ciphertext, filenames, usernames, lobby metadata, timestamps, and public keys, but not plaintext file contents.

### Usernames Are Not Identity

Temporary usernames are convenient, but anyone can type any username. For sensitive files, compare the displayed key fingerprint with the receiver through another channel before sending.

### Private Keys Are Temporary

The receiver private key exists only in the browser tab. If the receiver refreshes or closes the page, that temporary identity is gone and pending files for that identity cannot be opened.

### HTTPS Is Required In Production

Browser Web Crypto works on localhost during development. Real deployments should use HTTPS so app code, room traffic, and classic password forms are protected in transit.

---

## 3. Password Vault: Encrypt A File

This is the classic flow using `/encrypt`.

### Step 1: User Uploads The File

- **What happens:** The user selects a file, enters a password, and clicks **Encrypt & Download**.
- **Behind the scenes:** Flask rejects files larger than 20MB and keeps the file in memory instead of saving it to disk.

### Step 2: Creating The Encryption Key

- **What happens:** The password is not used directly as the AES key.
- **Behind the scenes:** Flask creates a random 16-byte salt and runs PBKDF2-HMAC-SHA256 for 210,000 iterations to derive a 32-byte AES key.

### Step 3: Encrypting And Downloading

- **What happens:** The file downloads as something like `document.pdf.enc`.
- **Behind the scenes:** AES-256-GCM encrypts and authenticates the file. The output format is:

```text
[16-byte salt][12-byte nonce][ciphertext + 16-byte tag]
```

---

## 4. Password Vault: Decrypt A File

### Step 1: User Uploads The `.enc` File

- **What happens:** The user selects the encrypted file and enters the same password.

### Step 2: Rebuilding The Key

- **What happens:** Flask extracts the salt and nonce.
- **Behind the scenes:** The entered password and stored salt go through PBKDF2 again. The same password recreates the same AES key.

### Step 3: Verifying And Decrypting

- **What happens:** The original file downloads if the password and file are valid.
- **Behind the scenes:** AES-GCM checks the authentication tag. Wrong passwords and tampered files fail cleanly.

---

## 5. Why These Cryptographic Choices?

### AES-GCM

AES-GCM provides encryption and tamper detection together. If encrypted data or metadata is changed, decryption fails.

### PBKDF2

PBKDF2 slows down password guessing by forcing many hash operations for every password attempt.

### ECDH

ECDH lets the sender and receiver derive matching secret material without sending that secret to the server.

### HKDF

ECDH output should not be used directly as an AES key. HKDF turns it into a clean, purpose-specific wrapping key.

### Hybrid Encryption

Large files are encrypted with AES-GCM. The small AES file key is wrapped for the receiver using the ECDH-derived wrapping key. This is faster and safer than trying to encrypt file bytes directly with asymmetric crypto.

---

## 6. Server-Side Security Measures

The app includes:

- CSRF protection for forms and clipboard API writes.
- Content Security Policy.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: no-referrer`.
- `Cache-Control: no-store`.
- Optional HSTS when the request is HTTPS.
- Upload size limits.
- Filename sanitization.
- Temporary encrypted blob cleanup.
- Rate limiting through Flask-Limiter.
- `/healthz` for deployment health checks.

For production with multiple workers or multiple instances, use shared encrypted-blob storage through `SECURE_VAULT_DATA_DIR` and shared rate-limit storage through `RATELIMIT_STORAGE_URI`, such as Redis.

---

## 7. Deployment Workflow

### Required Environment Variables

```text
FLASK_SECRET_KEY=<long random secret>
```

Recommended production settings:

```text
RATELIMIT_STORAGE_URI=redis://redis:6379/0
SECURE_VAULT_DATA_DIR=/app/instance/clipboard
SESSION_COOKIE_SECURE=true
```

### Health Check

```text
/healthz
```

Response:

```json
{"status":"ok"}
```

### Gunicorn Start Command

```bash
gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120
```

### Docker Flow

```bash
docker build -t secure-vault .
docker run --rm -p 5000:5000 -e FLASK_SECRET_KEY=replace-this secure-vault
```
