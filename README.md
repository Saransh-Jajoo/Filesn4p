# FileSn4p

FileSn4p is a production-oriented, browser-encrypted file-sharing app built with Next.js for Vercel. It supports light and dark themes, multi-recipient sharing, expiring access, flexible download limits, and direct private Vercel Blob uploads so large files do not pass through serverless request bodies.

## Features

- Light and dark mode with CSS variables, system preference detection, persistent theme selection, and separate optimized SVG logos in `public/logo-light.svg` and `public/logo-dark.svg`.
- Framer Motion transitions for page, step, recipient, alert, and inbox state changes.
- 50 MB maximum file size with browser-side alerting and server-side upload token limits.
- User-entered download limit with minimum `1` and no product-level cap.
- User-entered expiry from 10 minutes to 3 hours.
- Multi-user sharing to 10+ active recipients in one flow.
- No public online roster. Recipients are only discovered through explicit username search.
- Browser-side E2E encryption using Web Crypto ECDH P-256, HKDF-SHA256, and AES-256-GCM.
- Private Vercel Blob storage for encrypted payloads.
- Redis/Upstash metadata storage for Vercel serverless durability.
- Serverless Next.js route handlers only. No long-running backend process.
- Rate limits, input validation, expiring metadata, high-entropy IDs, and recipient-only downloads.

## Architecture

```text
Browser
  - Generates temporary ECDH identity
  - Encrypts file once with AES-256-GCM
  - Wraps the AES key separately for each recipient
  - Uploads ciphertext directly to private Vercel Blob

Next.js API routes
  - Track active lobby users in Redis
  - Authorize direct Blob upload tokens
  - Store share metadata and per-recipient wrapped keys
  - Enforce recipient access, expiry, and download counts
  - Stream encrypted downloads through an authorized route

Vercel services
  - Vercel Blob stores encrypted payloads
  - Upstash Redis stores temporary users, inboxes, shares, and counters
```

The server never receives plaintext files, private keys, or raw AES file keys.

## Local Setup

Install dependencies:

```bash
npm install
```

Create `.env.local`:

```bash
cp .env.example .env.local
```

For UI and API smoke tests, Redis and Blob are optional. Without Redis, the app uses in-memory local state and reports `durableStore:false` from `/api/health`.

Start the app:

```bash
npm run dev
```

Open:

```text
http://127.0.0.1:3000
```

Run production checks:

```bash
npm run typecheck
npm run build
npm audit --audit-level=moderate
```

## Environment Variables

Required for production:

```text
BLOB_READ_WRITE_TOKEN=vercel_blob_read_write_token
UPSTASH_REDIS_REST_URL=https://your-redis-url.upstash.io
UPSTASH_REDIS_REST_TOKEN=your_redis_rest_token
```

Optional for local callback testing:

```text
VERCEL_BLOB_CALLBACK_URL=https://your-ngrok-url
```

Legacy Flask variables in older versions are not used by the Next.js/Vercel app.

## Vercel Deployment

1. Create a Vercel project from this repository.
2. Create a Vercel Blob store with **Private** access.
3. Connect the Blob store to the project so `BLOB_READ_WRITE_TOKEN` is added.
4. Add an Upstash Redis database from Vercel Marketplace or Upstash, then set `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
5. Use the default Vercel Next.js settings:
   - Install command: `npm install`
   - Build command: `npm run build`
   - Framework: Next.js
6. Deploy.
7. Health-check `/api/health`; production should return `durableStore:true`.

If sharing shows `Vercel Blob: Failed to retrieve the client token`, the deployment is missing `BLOB_READ_WRITE_TOKEN` or the Blob store is not connected to the Vercel project. The app also checks this at login and `/api/health` reports `blobConfigured:false` when uploads are not ready.

## Security Design

- **Encryption in transit:** Vercel provides HTTPS in production. Browser Web Crypto also requires a secure context outside localhost.
- **Encryption at rest:** Only AES-GCM ciphertext is stored in Blob.
- **E2E key model:** Private ECDH keys live only in the current browser tab.
- **Access control:** Downloads require the active recipient user ID for the clip.
- **Recipient privacy:** The UI does not show an online user list, and the all-users route returns only the current active user. Recipient lookup is explicit search only.
- **Private storage:** Blob reads are performed through the authorized download route using `BLOB_READ_WRITE_TOKEN`.
- **Expiring links:** Redis metadata expires and download routes reject expired shares.
- **Download limits:** A Redis-backed counter decrements atomically before a download is served.
- **URL guessing prevention:** User, share, and clip IDs are high-entropy random values; Blob paths include random UUIDs and private storage blocks public reads.
- **Input validation:** Usernames, fingerprints, public keys, metadata, recipient lists, file sizes, expiry, and download limits are validated server-side.
- **Rate limiting:** API routes use Redis or local-memory request buckets.

## Important Limitations

- Temporary usernames are not verified identities. Compare displayed fingerprints through another channel for high-sensitivity transfers.
- If a browser tab closes or refreshes, its private key is lost and pending files for that temporary identity cannot be decrypted.
- Without Redis environment variables, local memory mode is not suitable for Vercel production.
- Blob cleanup is opportunistic after expiry and immediate after the final allowed download. Expired Blob objects are removed when the share is touched again.

## Legacy Flask Files

The previous Flask implementation remains in the repository for reference, but Vercel deployment now targets the Next.js app through `package.json`, `next.config.ts`, and `vercel.json`.
