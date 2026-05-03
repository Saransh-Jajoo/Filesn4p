# FileSn4p Security Report

**Report date:** May 3, 2026  
**Scope:** Next.js app (`app/`, `components/`, `lib/`) and deployment workflow  
**Environment:** Node 22, Next.js 16.2.4

## Executive Summary

The current implementation enforces consistent lifecycle controls for files and clipboard shares, validates high-risk inputs server-side, and includes scheduled cleanup logic for expired and orphaned data.  

Primary residual risk is operational: if cleanup scheduling is not configured or secrets are mismanaged in deployment, retention/privacy guarantees can degrade.

## Security Controls Implemented

1. **Consistent lifecycle enforcement for file + clipboard**
   - `download`: bounded access count (max 5)
   - `open` / `copy`: forced single-access lifecycle
   - `time`: expiry-only lifecycle
   - Same backend enforcement path for all content types

2. **Input and policy validation**
   - Size caps: 50 MB total content per share
   - Max expiry from client: 4h
   - Backend hard expiry cap: 24h
   - Strict validation of blob URL/path, recipient metadata, policy combinations

3. **Access control and privacy**
   - Recipient-bound download access checks
   - Active-session checks on sensitive routes
   - No public global online-user exposure
   - Inbox shows sender identity and unknown-sender warning state

4. **Cleanup and anti-orphan logic**
   - Indexed user/share/clip tracking
   - Periodic cleanup removes stale users, expired/exhausted shares, orphan clips
   - Blob deletion tied to share cleanup

5. **Transport and browser hardening**
   - CSP with reduced script permissions in production
   - Security headers (`HSTS`, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, COOP/CORP, Permissions-Policy)

6. **Cleanup endpoint protection**
   - Shared-secret gate (`CLEANUP_SECRET`) via `x-cleanup-secret`
   - Endpoint disabled in production if secret is not configured

## Tool-Based Verification

## 1) Build/Type/Lint Integrity

```bash
npm run typecheck
npm run lint
npm run build
```

Result: **pass**.

## 2) Dependency Audit

```bash
npm audit --audit-level=moderate
```

Result: **0 vulnerabilities found** (at scan time).

## 3) Dangerous Pattern Sweep

```bash
rg -n "dangerouslySetInnerHTML|eval\\(|new Function\\(|document\\.write\\(" app components lib
```

Result: no unsafe browser code execution patterns in app code.  
One expected `redis.eval` usage exists in server store for atomic counter decrement (controlled static script, not user-influenced).

## Threat Simulation Matrix

1. **IDOR / unauthorized file read**
   - Attempt: access clip with another user ID
   - Defense: clip recipient binding + active-user validation
   - Status: blocked by route logic

2. **Replay/download-abuse**
   - Attempt: repeated calls after limit
   - Defense: atomic decrement; cleanup on exhaustion
   - Status: blocked after counter reaches zero

3. **Clipboard exfiltration via inconsistent policy path**
   - Attempt: bypass file lifecycle by using clipboard-only mode
   - Defense: same `claimDownload` lifecycle enforcement for all content types
   - Status: enforced

4. **Oversize payload abuse**
   - Attempt: exceed per-share size
   - Defense: total-size validation + upload max enforcement
   - Status: rejected

5. **Orphaned data retention**
   - Attempt: stale records left after user/session expiry
   - Defense: global indexes + periodic cleanup + purge on logout
   - Status: addressed

6. **Cleanup endpoint abuse**
   - Attempt: external trigger spam
   - Defense: rate limiting + optional secret gate
   - Status: mitigated (requires `CLEANUP_SECRET` in production)

## Deployment Security Requirements

1. Use private Vercel Blob store.
2. Configure:
   - `BLOB_READ_WRITE_TOKEN`
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`
   - `CLEANUP_SECRET` (mandatory in production)
3. Schedule `/api/cleanup` every 5-15 minutes with `x-cleanup-secret`.
4. Enable CI workflow `.github/workflows/security-ci.yml`.
5. Keep `npm audit` in release gate.

## Residual Risks and Recommendations

1. Add dedicated integration tests for lifecycle modes (`download/open/copy/time`) across `file`, `clipboard`, and `both`.
2. Add anomaly alerting (rate-limit spikes, repeated invalid clip fetches).
3. Consider signed ephemeral session tokens instead of raw user ID usage for stronger session theft resistance.
4. Add regular external DAST in staging before release.

## Conclusion

The app now has consistent file/clipboard lifecycle handling, stronger cleanup guarantees, and a deployment-ready security baseline. With cron cleanup and secret/config hygiene in place, it is suitable for production rollout.
