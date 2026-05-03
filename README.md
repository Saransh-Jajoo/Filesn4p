# FileSn4p

FileSn4p is a browser-encrypted sharing app built on Next.js. It supports secure transfer of files, clipboard text, or both in one share, with per-share lifecycle controls and automatic cleanup.

## Core Capabilities

- End-to-end encryption in browser (ECDH P-256 + HKDF-SHA256 + AES-256-GCM)
- Share modes:
  - `file`
  - `clipboard`
  - `both` (files + clipboard together)
- Multi-file support with total session cap of **50 MB**
- Multi-recipient send (single encrypted payload for all recipients)
- Deletion/lifecycle triggers:
  - `download` (N downloads, max 5)
  - `open` (single open)
  - `copy` (single copy/open event)
  - `time` (time expiry)
- Time expiry up to **4 hours** from client policy; backend hard-caps to **24 hours**
- Inbox sender identity with unknown-sender warning
- No public online user count / no system-wide activity disclosure
- Logout lifecycle with optional user-data purge
- Periodic cleanup for expired shares, stale users, orphaned clips, and blob objects

## Security Controls

- Strict input validation for user IDs, policy values, metadata, sizes, blob URL/path
- Strong per-route rate limiting
- Private blob upload/download path
- CSP + security headers in `next.config.ts`
- Cleanup endpoint secret (`CLEANUP_SECRET`) required in production
- CI workflow gates for lint/type/build/audit/basic secret-pattern scanning

## Architecture

- Frontend: `components/SecureShareApp.tsx`
- API routes: `app/api/**`
- State store:
  - Upstash Redis in production
  - In-memory fallback for local dev only
- Binary storage: Vercel Blob private store

## Environment Variables

Create `.env.local` from `.env.example`:

```bash
cp .env.example .env.local
```

Required for production:

```text
BLOB_READ_WRITE_TOKEN=vercel_blob_read_write_token
UPSTASH_REDIS_REST_URL=https://your-redis-url.upstash.io
UPSTASH_REDIS_REST_TOKEN=your_redis_rest_token
CLEANUP_SECRET=replace_with_random_cleanup_secret
```

Optional:

```text
VERCEL_BLOB_CALLBACK_URL=
```

## Local Run

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:3000`.

## Deployment Gates

```bash
npm run lint
npm run typecheck
npm run build
npm audit --audit-level=moderate
```

## Cleanup Endpoint

- Route: `GET /api/cleanup`
- In production, `CLEANUP_SECRET` must be set and header must be passed:
  - `x-cleanup-secret: <your-secret>`

Set a scheduled job (Vercel Cron or external scheduler) to call this endpoint regularly (recommended every 5-15 minutes).

## Notes

- Legacy Flask files are still present for reference but are not the production runtime path.
- For current lifecycle and security behavior, see [WORKFLOW.md](./WORKFLOW.md) and [security.md](./security.md).
