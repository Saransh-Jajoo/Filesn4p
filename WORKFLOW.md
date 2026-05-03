# FileSn4p Workflow

This document defines the production behavior for share creation, delivery, lifecycle controls, and cleanup.

## 1. Join Lobby

1. Client generates ECDH key pair locally.
2. Client sends `username`, `publicKey`, `fingerprint` to `POST /api/rooms`.
3. Backend creates temporary user session in Redis/in-memory store.
4. Private key never leaves browser runtime.

## 2. Keep Session Alive

1. Client sends heartbeat every 15 seconds to `POST /api/rooms/[roomId]/heartbeat`.
2. Stale users are invalidated after timeout.
3. Lobby does not expose public online counts.

## 3. Compose Share

Sender can choose:

- content: `file`, `clipboard`, or `both`
- deletion trigger: `download`, `open`, `copy`, `time`
- expiry mode: `downloads` or `time` (validated with trigger compatibility)

Limits:

- Total content per share/session: 50 MB (files + clipboard plaintext bytes)
- Download limit max: 5
- Time expiry max from client: 4 hours
- Backend hard cap: 24 hours

## 4. Encryption

1. Files are encrypted once with AES-256-GCM.
2. Clipboard text (if present) is encrypted under same share key with separate nonce.
3. For each recipient:
   - derive wrap key via ECDH + HKDF
   - wrap AES key
   - store recipient-specific metadata

## 5. Upload

1. For file-containing shares, client uploads encrypted payload directly to Vercel Blob using `/api/upload`.
2. Upload token route validates active room/user and max size.
3. Clipboard-only shares skip Blob upload and store only encrypted clipboard payload.

## 6. Register Share

`POST /api/rooms/[roomId]/clips` stores:

- one share record
- one recipient clip record per recipient
- lifecycle policy and expiry timestamps
- reference indexes for cleanup (`users`, `shares`, `clips`)

Policy normalization:

- `download` -> uses user-supplied download limit (1..5)
- `open` / `copy` -> forced single access
- `time` -> access count ignored; expiry-only lifecycle

## 7. Inbox Listing

`GET /api/rooms/[roomId]/clips` returns active clips for recipient only.

Each item includes:

- sender name and sender fingerprint
- sender verification status (unknown sender warning if no longer verifiable)
- content type, file info, clipboard flag
- lifecycle metadata (`expiryMode`, `deletionTrigger`, `viewsLeft`)

## 8. Open/Download

`GET /api/clips/[clipId]/download?userId=...`:

1. Validates recipient ownership and active session.
2. Enforces expiry and lifecycle policy.
3. For `download/open/copy` triggers, decrements server-side counter atomically.
4. For `time` trigger, skips counter decrement.
5. Returns encrypted payload and metadata headers, or clipboard payload JSON for clipboard-only shares.
6. On final allowed access, schedules cleanup.

## 9. Logout Lifecycle

`POST /api/rooms/[roomId]/logout`:

- invalidates current user session
- optional `purgeData=true` removes:
  - sender’s owned shares
  - recipient inbox clips
  - share/clip index references

## 10. Cleanup Lifecycle

`GET /api/cleanup`:

- in production, requires `CLEANUP_SECRET` and header: `x-cleanup-secret`
- removes stale users
- removes expired/exhausted/orphaned shares
- removes orphaned clip records
- deletes referenced Blob objects
- prunes index pointers for missing records

Recommended cron schedule: every 5-15 minutes.

## 11. Privacy Model

- No system-wide activity counters in UI
- No public roster endpoint for all active users
- Search-based recipient discovery only
- Sender identity shown in inbox with unknown warning fallback
