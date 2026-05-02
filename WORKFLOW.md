# FileSn4p Workflow

This document explains the current Next.js/Vercel workflow for secure multi-recipient file sharing.

## 1. User Enters The Lobby

1. The browser generates an ECDH P-256 key pair with Web Crypto.
2. The browser sends only the public key, username, and fingerprint to `POST /api/rooms`.
3. The API stores the temporary active user in Redis with a short TTL.
4. The private key stays in the browser tab.

## 2. Active Users Stay Fresh

1. The browser calls `POST /api/rooms/[roomId]/heartbeat` every 15 seconds.
2. The app does not display a public online roster.
3. Users that stop heartbeating disappear from recipient search results.

## 3. Sender Selects File And Policy

1. The UI accepts one file up to 50 MB.
2. Files above 50 MB show an in-app alert before upload.
3. The sender enters:
   - Download limit: minimum 1, no product cap.
   - Expiry time: 10 to 180 minutes.
4. Both values are validated again in `POST /api/rooms/[roomId]/clips`.

## 4. Sender Selects Recipients

1. Recipient search calls `GET /api/rooms/[roomId]/users/search`.
2. Results show username and key fingerprint.
3. The sender can select multiple active users, including 10+ recipients.
4. Recipient selection is sent as structured JSON, not string-concatenated data.
5. `GET /api/rooms/[roomId]/users` returns only the current user so a client cannot enumerate everyone in the lobby through the normal API.

## 5. Browser Encrypts The Share

1. The browser creates one random AES-256-GCM file key.
2. The file is encrypted once with that key.
3. For each recipient:
   - Import recipient ECDH public key.
   - Create an ephemeral ECDH key pair.
   - Derive a wrapping key with HKDF-SHA256.
   - Wrap the AES file key with AES-GCM.
   - Build per-recipient metadata.
4. Plaintext never leaves the browser.

## 6. Browser Uploads Ciphertext Directly To Blob

1. The browser calls the Vercel Blob client upload helper.
2. `/api/upload` validates the active user before issuing an upload token.
3. The encrypted Blob uploads directly from the browser to private Vercel Blob.
4. This avoids Vercel Function request body limits for 50 MB files.
5. If `BLOB_READ_WRITE_TOKEN` is missing, `/api/upload` returns a clear configuration error and `/api/health` reports `blobConfigured:false`.

## 7. API Registers The Share

1. The browser sends Blob URL/pathname, file sizes, policy, and per-recipient metadata to `POST /api/rooms/[roomId]/clips`.
2. The API verifies sender and recipients are active.
3. The API creates one share record and one clip record per recipient.
4. Redis stores:
   - Share metadata
   - Per-recipient clip metadata
   - Recipient inbox IDs
   - Atomic download counter

## 8. Recipient Opens A File

1. Recipient inbox calls `GET /api/rooms/[roomId]/clips`.
2. Clicking Open calls `GET /api/clips/[clipId]/download?userId=...`.
3. The API verifies:
   - Clip exists
   - User is the intended recipient
   - Recipient is active
   - Share is not expired
   - Downloads remain
4. The API decrements the Redis counter before streaming encrypted bytes.
5. Metadata is returned in the `X-Clip-Metadata` header.
6. The browser unwraps the AES key and decrypts locally.

## 9. Self-Destruction

1. Time expiry blocks access after 10 to 180 minutes.
2. Download expiry blocks access once the counter reaches zero.
3. On the final download, the API schedules Blob and metadata cleanup.
4. Expired shares are also cleaned opportunistically when touched by inbox or download routes.

## 10. Theme Workflow

1. CSS variables define all app colors.
2. If no stored preference exists, system preference controls the initial theme.
3. The theme toggle writes `filesn4p-theme` to local storage.
4. The UI switches between `public/logo-light.svg` and `public/logo-dark.svg`.
5. Inputs, selected states, hover states, focus rings, and select elements all use theme variables to avoid the white-text-on-white-background issue.

## 11. Deployment Workflow

1. Install dependencies with `npm install`.
2. Create a private Vercel Blob store.
3. Set `BLOB_READ_WRITE_TOKEN`.
4. Add Upstash Redis and set:
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`
5. Run:

```bash
npm run typecheck
npm run build
npm audit --audit-level=moderate
```

6. Deploy to Vercel using the Next.js framework preset.
7. Confirm `/api/health` returns `{"status":"ok","durableStore":true,"blobConfigured":true}`.
