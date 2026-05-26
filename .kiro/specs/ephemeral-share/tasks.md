# Implementation Plan: EphemeralShare

## Overview

EphemeralShare is implemented in two phases:

- **Phase 1 — Core MVP** (tasks 1–20): The shippable product. Covers auth, upload, download, destroy queue, cleanup worker, basic security hardening, and full Docker Compose deployment. All tasks are required.
- **Phase 2 — Hardened** (tasks 21–31): Optional hardening layer. Adds honeypot tokens, cryptographic erasure, property-based tests, advanced metrics, geo fingerprinting, log minimization, fuzzing, and a disaster recovery runbook. All tasks are marked `*` (optional) and can be skipped for initial deployment.

## Tasks

---

## Phase 1 — Core MVP

- [x] 1. Project scaffolding
  - Create monorepo directory structure: `backend/`, `frontend/`, `infra/`, `nginx/`
  - Initialize Go module (`go.mod`) for backend with Fiber, Redis client, AWS SDK v2, JWT, bcrypt, TOTP dependencies
  - Initialize Next.js 14 App Router project for frontend
  - Define shared config structs and environment variable loading (backend)
  - Define all core data model types: `FileMetadata`, `AuditEvent`, `AdminClaims`, `DestroyJob`, `HealthResponse`
  - Define Redis key constants including: `token:`, `lock:`, `destroyed:`, `rl:`, `failed:`, `cleanup:`, `session:`, `enum:`, `honeypot:`, `upload:`, `quota:uploads:`, `quota:bytes:`, `destroy_queue`, `uploads_pending`, `uploads_unconfirmed`, `cleanup_by_expiry`, `destroy_dlq`, `refresh:`, `cleanup_lock`, `KeyDestroyJobID`
  - _Requirements: 1.1, 1.2, 2.1_

- [x] 2. Redis data layer
  - Implement Redis client wrapper with connection pooling and health check
  - Implement `GetRedisServerTime(ctx) (int64, error)` using Redis `TIME` command
  - Implement Lua CAS token state machine script: `ACTIVE → CONSUMING` with atomic `destruction_scheduled_at` and `destroy_job_id` (UUID v4) set
  - Implement ZSET secondary index helpers: ZADD/ZRANGEBYSCORE/ZREM for `uploads_pending`, `uploads_unconfirmed`, `cleanup_by_expiry`, `destroy_queue`, `destroy_dlq`
  - Enforce explicit TTL on all keys:
    - `enum:{ip}` → EXPIRE 3600
    - `failed:{ip}` → EXPIRE 600
    - `quota:uploads:{YYYY-MM-DD}` and `quota:bytes:{YYYY-MM-DD}` → EXPIREAT midnight
  - Implement periodic ZSET stale entry cleanup via `ZREMRANGEBYSCORE` (run hourly by cleanup worker):
    - `destroy_queue`: remove scores < now−86400
    - `destroy_dlq`: remove scores < now−604800
    - `uploads_pending`: remove scores < now−3600
    - `uploads_unconfirmed`: remove scores < now−3600
    - `cleanup_by_expiry`: remove scores < now−86400
  - _Requirements: 3.1, 3.2, 4.9, 5.1_

- [x] 3. S3/R2 client
  - Implement S3 client wrapper using AWS SDK v2 (compatible with Cloudflare R2)
  - Implement `GeneratePresignedUploadURL(ctx, objectKey, contentType, sizeBytes, ttl)` with `x-amz-meta-expected-size` embedded
  - Implement `GeneratePresignedDownloadURL(ctx, objectKey, filename, contentType, ttl)` with `response-content-disposition: attachment; filename="{sanitized_filename}"` and `response-content-type` parameters
  - After generating any presigned URL: parse URL host and validate it matches `S3_ENDPOINT` host → return `SSRF_ENDPOINT_MISMATCH` error if mismatch
  - Implement `HeadObjectWithRetry(ctx, objectKey, maxAttempts=4)` with delays: 0 ms, 100 ms, 300 ms, 1000 ms
  - Implement `DeleteObject(ctx, objectKey)` treating 404 as success
  - _Requirements: 2.2, 2.3, 4.5, 7.2_

- [x] 4. Token generation & MIME utilities
  - Implement `GenerateToken(entropyBytes int) (token, tokenHash string, err error)` using `crypto/rand` + SHA-256
  - Implement `ValidateMIME(header []byte, declaredType string) error` — sniff first 512 bytes, check against allowed list
  - Implement `ValidateOfficeDocument(r io.Reader) error` — detect Office ZIP structure; add zip bomb protection:
    - Max 1000 ZIP entries
    - Max 100× compression ratio per entry
    - Max 3 nested ZIP levels
    - Max 2× declared file size uncompressed
    - Return `ZIP_BOMB_DETECTED` if any limit exceeded
  - Implement `SanitizeFilename(filename string) (string, error)`:
    - NFC normalization via `golang.org/x/text/unicode/norm`
    - Strip RTL override characters: U+202E, U+200F, U+202B
    - Strip invisible characters: U+200B, U+FEFF, U+00AD
    - Strip control characters and path separators
    - Enforce max 255 bytes
  - Add dependency: `golang.org/x/text`
  - _Requirements: 2.4, 2.7, 2.8, 2.9_

- [x] 5. Audit logging
  - Implement structured stdout JSON logger emitting `AuditEvent` structs
  - Define event constants: `upload_initiated`, `upload_confirmed`, `download_accessed`, `file_destroyed`, `orphan_cleaned`, `admin_login_success`, `admin_login_failure`, `suspicious_activity`, `honeypot_hit`, `refresh_token_replay_detected`, `malware_detected`, `destroy_job_failed`, `destroy_job_dlq`
  - Ensure no sensitive data (file content, raw tokens, passwords) appears in log output
  - _Requirements: 13.1, 13.2, 13.3_

- [x] 6. Auth service
  - Implement `POST /api/admin/login`: bcrypt password verify, optional TOTP check, issue access JWT + HttpOnly refresh token cookie
  - Implement `POST /api/admin/refresh`: validate refresh token cookie, JTI rotation with replay detection (`refresh:{jti}` Redis key TTL=8h); on replay: revoke session chain + emit `refresh_token_replay_detected` CRITICAL event
  - Implement `POST /api/admin/logout`: clear refresh token cookie, DEL session key
  - Implement JWT middleware: validate `AdminClaims` (exp, role, session_id, GeoRegion); geo anomaly → require re-auth; DeviceFingerprint change → log suspicious activity
  - Implement IP whitelist middleware: hard reject if `ADMIN_ALLOWED_IPS` set and IP not in list
  - Implement CSRF Origin check for cookie-authenticated endpoints (`/api/admin/refresh`, `/api/admin/logout`): Origin mismatch or absent → 403 `CSRF_DETECTED`
  - Implement brute-force lockout: 5 failed attempts → 15-minute lockout via `failed:{ip}` Redis key (EXPIRE 600)
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

- [x] 7. Upload service
  - Implement `POST /api/admin/request-upload`: validate JWT, check `quota:uploads:daily` + `quota:bytes:daily`, check `MAX_PENDING_UPLOADS_PER_ADMIN`, generate presigned PUT URL with `x-amz-meta-expected-size`, SETEX `upload:{upload_id}` (status: PENDING_UPLOAD, TTL 30 min), ZADD `uploads_pending`
  - Implement `POST /api/admin/confirm-upload`: update `upload:{upload_id}` status → UPLOADED_UNCONFIRMED, call `HeadObjectWithRetry` (4 attempts with backoff), run synchronous ClamAV scan (wait for result), on clean: generate token, SETEX `token:{hash}`, SADD `cleanup:{date}`, ZADD `cleanup_by_expiry`, INCR quota keys, return share URL; on infected: DELETE S3 object, return 400 `MALWARE_DETECTED`
  - IAM-enforced single PUT: create `infra/iam-policy.json` with Allow PutObject/GetObject/DeleteObject/HeadObject and explicit DENY CreateMultipartUpload/UploadPart/CompleteMultipartUpload/AbortMultipartUpload — do NOT add code-level multipart detection
  - Implement `GET /api/admin/tokens`: list active tokens from Redis
  - Implement `DELETE /api/admin/tokens/{token_hash}`: revoke token
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.9, 2.10, 7.1, 7.2_

- [x] 8. Download service
  - Implement `GET /d/{token}`: SHA-256 hash token, GET `token:{hash}` from Redis, render SSR Download_Page (or 302 `/expired` if not found/destroyed); respect `MINIMAL_DISCLOSURE_MODE`
  - Implement `POST /api/download/{token}`: run Lua CAS script (ACTIVE → CONSUMING), set `destruction_scheduled_at` and `destroy_job_id` (UUID v4) atomically; on `ALREADY_CONSUMING` → 423; verify checksum via HEAD; generate presigned download URL; before ZADD: check `destruction_scheduled_at != nil` in token metadata → skip ZADD if already scheduled (deduplication); use `GetRedisServerTime` for grace period score: `redis_server_time + PRESIGNED_URL_TTL_SECONDS + DESTRUCTION_GRACE_SECONDS`; ZADD `destroy_queue`; return 302 redirect with `Cache-Control: no-store, private`
  - Handle object existence race: if S3 HEAD returns 404 after lock acquired, treat as already destroyed and proceed with destruction pipeline
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.9, 4.10, 4.13, 4.14, 11.1, 11.3_

- [x] 9. Security middleware
  - Implement security headers middleware: `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Cache-Control: no-store`, empty `Server`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`
  - Implement rate limiting middleware using Redis: download zone (5 r/m), upload zone (2 r/m), API zone (30 r/m), request-upload zone (5 r/m)
  - Implement token enumeration detection: `enum:{ip}` count > 10 in 1 min → block IP 1 hour (EXPIRE 3600) + 429 `TOKEN_ENUMERATION_DETECTED`
  - Implement error sanitization middleware: strip stack traces, internal paths, Redis/S3 keys from all error responses
  - Implement global backpressure: `ZCARD uploads_pending >= MAX_TOTAL_PENDING_UPLOADS` (default 50, env var `MAX_TOTAL_PENDING_UPLOADS`) → return 429 `SYSTEM_OVERLOADED`
  - _Requirements: 9.1, 9.2, 9.5, 9.6, 9.7, 9.8, 10.1, 10.2_

- [x] 10. Cleanup worker
  - Implement destroy queue polling goroutine (every `DESTROY_QUEUE_POLL_INTERVAL_SECONDS`, default 5s):
    - Use `GetRedisServerTime` for ZRANGEBYSCORE dequeue: `ZRANGEBYSCORE destroy_queue 0 {redis_now}`
    - For each `DestroyJob`: execute destruction pipeline (DELETE S3, DEL `token:{hash}`, DEL `lock:{hash}`, SETEX `destroyed:{hash}` 86400), ZREM after complete, emit audit log
    - On S3 delete failure: increment `job.Attempt`, re-ZADD with exponential backoff score (`now + base_delay * 2^attempt`, base_delay=30s)
    - If `attempt >= MAX_DESTROY_RETRIES`: ZADD `destroy_dlq`, emit CRITICAL audit event `destroy_job_dlq`
  - Implement orphan scan goroutine (every 15 min):
    - Before each cycle: `SET cleanup_lock {hostname+pid} NX EX 60` → skip cycle if lock not acquired
    - DEL `cleanup_lock` after cycle completes
    - ZRANGEBYSCORE `uploads_pending 0 {now}` + `uploads_unconfirmed 0 {now}` + `cleanup_by_expiry 0 {now}` → process expired entries
    - For each object_key: check token status; if CONSUMING and within MAX_GRACE_PERIOD → skip; if CONSUMING and stale → delete; if no token → delete (orphan); if ACTIVE and age > max TTL → delete
    - SREM `cleanup:{date_bucket}` after delete
  - Implement periodic ZSET stale entry cleanup (every 1 hour) via `ZREMRANGEBYSCORE` for all ZSET indexes (see Task 2)
  - _Requirements: 6.1, 6.2, 6.3_

- [x] 11. Health check & core metrics
  - Implement `GET /health`: ping Redis + S3, return `HealthResponse` JSON
  - Implement Prometheus metrics endpoint `GET /metrics` (internal only):
    - `ephemeral_downloads_total` Counter (status label)
    - `ephemeral_destruction_duration_seconds` Histogram
    - `ephemeral_orphan_cleanup_total` Counter (status label)
    - `ephemeral_lock_contention_total` Counter
    - `ephemeral_active_tokens_gauge` Gauge
    - `ephemeral_destroy_queue_size` Gauge
    - `ephemeral_destroy_dlq_size` Gauge
    - `ephemeral_malware_detections_total` Counter
    - `ephemeral_s3_failures_total` Counter (operation label)
    - `ephemeral_destroy_oldest_job_seconds` Gauge: `ZRANGE destroy_queue 0 0 WITHSCORES` → age = `now − score`; 0 if queue empty
  - _Requirements: 12.1, 12.2_

- [x] 12. Wire backend
  - Configure Fiber app with hardened settings: `BodyLimit 500MB`, `ReadTimeout`, `WriteTimeout`, `DisableStartupMessage`, `StrictRouting`
  - Register all middleware (security headers, rate limiting, error sanitization)
  - Register all routes: auth, upload, download, health, metrics
  - Implement graceful shutdown: SIGTERM/SIGINT → drain in-flight requests → stop cleanup worker goroutines
  - _Requirements: 1.1, 9.1_

- [x] 13. Frontend — CSP nonce middleware + shared API client
  - Implement Next.js 14 `middleware.ts`: generate per-request nonce (`crypto.randomBytes(16).toString('base64')`), set `Content-Security-Policy` header with `nonce-{N}` and `strict-dynamic`, pass nonce via `x-nonce` response header to layout
  - Implement shared API client (`lib/api.ts`): typed fetch wrapper for all backend endpoints, handle 401 → redirect to login, attach access token from React context
  - _Requirements: 9.2, 9.7_

- [x] 14. Frontend — Admin login page
  - Implement `app/admin/page.tsx`: login form (password + optional TOTP), call `POST /api/admin/login`, store access token in React context (not localStorage), redirect to dashboard on success
  - Handle 401 (invalid credentials), 429 (rate limited), 423 (locked out) with user-friendly error messages
  - _Requirements: 8.1, 11.2_

- [x] 15. Frontend — Admin dashboard
  - Implement `app/admin/dashboard/page.tsx` (protected route): drag-and-drop `UploadZone` component with progress bar, TTL selector, admin note field
  - Implement `ShareLinkCard`: copyable share URL + expiry countdown
  - Implement `TokenList`: list active tokens with revoke button (calls `DELETE /api/admin/tokens/{hash}`)
  - Call `POST /api/admin/request-upload` → PUT directly to S3 presigned URL → `POST /api/admin/confirm-upload`
  - _Requirements: 2.1, 2.5, 11.2_

- [x] 16. Frontend — Download page (SSR)
  - Implement `app/d/[token]/page.tsx` as SSR page: fetch token metadata from backend via `BACKEND_INTERNAL_URL` (avoids public Nginx loop), render `DownloadCard` with filename (or generic message if `MINIMAL_DISCLOSURE_MODE`), file size, content type, expiry countdown, one-time warning, download button
  - Download button calls `POST /api/download/{token}` → follow 302 redirect to presigned URL
  - _Requirements: 4.1, 4.3, 11.1, 11.3_

- [x] 17. Frontend — Expired page
  - Implement `app/expired/page.tsx`: display explanation that link has expired or been used, contact options
  - Implement `app/contact/page.tsx`: contact information page
  - _Requirements: 11.4_

- [x] 18. Nginx config
  - Write `nginx/nginx.conf` with:
    - `client_max_body_size 500m`, `client_body_timeout 60s`, `client_header_timeout 10s`
    - Rate limiting zones: `download` (5 r/m), `upload` (2 r/m), `api` (30 r/m), `request_upload` (5 r/m)
    - Security headers (X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy, Cache-Control, Server, Permissions-Policy, COOP, CORP)
    - CDN cache bypass for `/d/*`, `/api/*`, `/admin/*` routes
    - TLS termination (Let's Encrypt / self-signed for dev)
    - Internal-only `/metrics` location (allow 10.0.0.0/8, 172.16.0.0/12; deny all)
    - Pass through CSP header set by Next.js middleware (do not override)
  - _Requirements: 9.1, 9.3, 9.4_

- [x] 19. Docker Compose + IAM policy
  - Write `docker-compose.yml` with all services: `backend`, `frontend`, `redis`, `clamav`, `nginx`
  - Write `Dockerfile` for backend (multi-stage Go build) and frontend (Next.js standalone)
  - Write `.env.example` with all environment variables including `MAX_TOTAL_PENDING_UPLOADS=50`
  - Write `infra/iam-policy.json`: Allow PutObject/GetObject/DeleteObject/HeadObject; DENY CreateMultipartUpload/UploadPart/CompleteMultipartUpload/AbortMultipartUpload
  - Write `infra/s3-lifecycle.json`: lifecycle rule to delete objects older than max TTL + 1 day (safety net)
  - Write `infra/setup-s3.sh`: create bucket, apply lifecycle policy, apply IAM policy
  - _Requirements: 1.1, 7.1_

- [x] 20. Phase 1 checkpoint — core integration tests
  - Write integration tests covering:
    1. Full upload → download → destroy cycle (verify state machine ACTIVE→CONSUMING→DESTROYED)
    2. Concurrent download: two simultaneous POST → exactly one 302, one 423
    3. Orphan cleanup: upload → expire token → run cleanup worker → verify S3 object deleted
    4. Grace period: verify S3 object exists during grace period, deleted after
    5. ClamAV clean file: token activated
    6. ClamAV infected file: S3 deleted, 400 returned
    7. Token enumeration blocking: 11th invalid request → 429
    8. Destroy queue retry + DLQ: simulate S3 delete failure → verify exponential backoff → DLQ after max retries
    9. Distributed lock: two cleanup worker instances → only one acquires `cleanup_lock`
    10. Redis TIME grace period: verify ZADD score uses Redis server time, not `time.Now()`
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: all Phase 1 requirements_

---

## Phase 2 — Hardened

- [ ] 21. Honeypot token system
  - Implement honeypot token namespace: store under `honeypot:{hash}` prefix (never routes to real S3 object)
  - Implement background goroutine: generate N honeypot tokens at random interval (`HONEYPOT_BASE_INTERVAL_SECONDS + random(0, HONEYPOT_JITTER_SECONDS)`), random count between `HONEYPOT_MIN_COUNT` and `HONEYPOT_MAX_COUNT`, with realistic fake metadata (random TTL 1–48h, common filenames, realistic sizes)
  - Implement timing jitter: honeypot token lookup must have identical latency to real token lookup (Redis pipeline, no short-circuit)
  - Implement fake responses: `GET /d/{honeypot_token}` renders identical Download_Page structure with fake metadata; `POST /api/download/{honeypot_token}` returns fake 423 (expired) response after jitter delay
  - On honeypot POST hit: emit CRITICAL audit event `honeypot_hit`, increment `ephemeral_honeypot_hits_total` metric
  - _Requirements: 10.3, 10.4_

- [ ] 22. Cryptographic erasure + streaming proxy
  - Implement `DOWNLOAD_MODE=stream` backend streaming proxy: acquire token lock → call S3 GetObject → stream bytes via `io.Copy` to client → run destruction pipeline after stream completes; handle stream cancellation via `ctx.Done()`
  - Implement per-file DEK encryption (XChaCha20-Poly1305, `golang.org/x/crypto/chacha20poly1305`):
    - Upload: generate DEK (32 bytes) + nonce_prefix (16 bytes) per file; encrypt in 64 KB chunks; encrypt DEK with master key; store `encrypted_dek` + `nonce_prefix` in `FileMetadata`
    - Download (requires `DOWNLOAD_MODE=stream`): retrieve + decrypt DEK; stream-decrypt S3 object; stream decrypted bytes to client
    - Destruction: DEL `token:{hash}` destroys DEK → cryptographic erasure
  - Add env vars: `ENCRYPTION_ENABLED`, `MASTER_ENCRYPTION_KEY`
  - _Requirements: 7.6_

- [ ] 23. Property-based tests (17 properties)
  - Add `pgregory.net/rapid` dependency
  - Implement all 17 property-based tests using `rapid` generators:
    - [ ] 23.1 P1: `TestObjectKeyFormat` — random filenames/content types
    - [ ] 23.2 P2: `TestTokenGenerationAndStorage` — N token generations, varying entropy
    - [ ] 23.3 P3: `TestMetadataRoundTrip` — random `FileMetadata` structs
    - [ ] 23.4 P4: `TestTTLConfiguration` — random TTL in [1, 168] hours
    - [ ] 23.5 P5: `TestGETDoesNotConsumeToken` — random tokens, random N GET requests
    - [ ] 23.6 P6: `TestDestructionIdempotence` — random tokens, verify ACTIVE→CONSUMING→DESTROYED
    - [ ] 23.7 P7: `TestDestroyedTokenRejection` — random consumed tokens
    - [ ] 23.8 P8: `TestNoInternalIdentifiersInResponses` — random tokens, all endpoint types
    - [ ] 23.9 P9: `TestConcurrentDownloadExclusivity` — N=2..10 concurrent requests
    - [ ] 23.10 P10: `TestOrphanCleanupCompleteness` — random orphaned objects
    - [ ] 23.11 P11: `TestSecurityHeadersOnAllResponses` — random endpoints, verify nonce uniqueness
    - [ ] 23.12 P12: `TestAuditLogCompletenessAndNoSensitiveData` — random events, both disclosure modes
    - [ ] 23.13 P13: `TestTokenUniqueness` — N=10,000 generations, both entropy levels
    - [ ] 23.14 P14: `TestMIMEValidationRejectsMismatches` — random file content + declared MIME pairs
    - [ ] 23.15 P15: `TestDownloadPageMetadataDisplay` — random `FileMetadata`, both disclosure modes
    - [ ] 23.16 P16: `TestPresignedURLTTLBound` — random presigned URLs, verify expiry within TTL
    - [ ] 23.17 P17: `TestCryptographicErasure` — random file content + DEK pairs (requires Task 22)
  - Each test runs minimum 100 iterations; tag format: `// Feature: ephemeral-share, Property {N}: {property_text}`
  - _Requirements: all correctness properties_

- [ ] 24. Advanced ClamAV
  - Implement ClamAV semaphore: `CLAMAV_MAX_CONCURRENT_SCANS` (default 3) — reject with 503 `SCAN_QUEUE_FULL` if limit reached
  - Implement DLQ retry strategy for scan failures: retry up to `MAX_DESTROY_RETRIES` with exponential backoff before moving to DLQ
  - Add `ephemeral_clamav_scan_duration_seconds` Histogram and `ephemeral_clamav_concurrent_scans` Gauge metrics
  - _Requirements: 2.10_

- [ ] 25. Advanced metrics
  - Add remaining Prometheus metrics:
    - `ephemeral_presigned_url_generation_failures_total` Counter
    - `ephemeral_token_consumption_latency_seconds` Histogram
    - `ephemeral_active_uploads_gauge` Gauge
    - `ephemeral_orphan_cleanup_duration_seconds` Histogram
    - `ephemeral_redis_lua_contention_total` Counter
    - `ephemeral_presigned_url_generation_latency_seconds` Histogram
    - `ephemeral_destroy_retries_total` Counter
  - _Requirements: 12.2_

- [ ] 26. CSP nonce injection (Next.js 14 middleware nonce)
  - Enhance `middleware.ts` to inject nonce into all `<script>` tags in the rendered HTML via Next.js App Router `headers()` API
  - Verify nonce present in both CSP header and all `<script nonce={nonce}>` tags in layout
  - Write unit test: 10 requests to HTML endpoints → each response has unique nonce in CSP header matching script tags
  - _Requirements: 9.2, 9.7_

- [ ] 27. Geo fingerprinting
  - Add `GeoRegion` (country code at login time) and `DeviceFingerprint` (hash of User-Agent + Accept-Language) to `AdminClaims`
  - Implement geo anomaly detection: if `GeoRegion` changes between requests → log geo anomaly + require re-authentication
  - Implement device fingerprint change logging: if `DeviceFingerprint` changes → log suspicious activity (no hard reject)
  - _Requirements: 8.4_

- [ ] 28. Log minimization mode
  - Implement `LOG_MINIMIZATION_MODE=true` behavior in `AuditEvent` emission:
    - Hash IP addresses: `SHA-256(ip + daily_salt)`
    - Truncate `object_key` to prefix only: `ep/{YYYY}/{MM}/`
    - Truncate `token_hash` to first 12 characters
    - Round timestamps to nearest hour
  - Write unit tests verifying minimization applied correctly when mode enabled
  - _Requirements: 13.4_

- [ ] 29. HTTP parser fuzzing tests
  - Write Go fuzz tests (`go test -fuzz`) for HTTP request parsing, token extraction, MIME sniffing, and filename sanitization
  - Target: `FuzzTokenExtraction`, `FuzzMIMEValidation`, `FuzzSanitizeFilename`, `FuzzOfficeDocumentValidation`
  - _Requirements: 9.1_

- [ ] 30. Disaster recovery runbook
  - Write `docs/disaster-recovery.md` covering:
    - Redis AOF failure mode: `appendfsync everysec` = accept up to 1s token state loss on crash; active tokens become invalid (broken links) — acceptable failure mode, not data loss; recipients see `/expired` page
    - S3 object orphan recovery procedure
    - Cleanup worker DLQ drain procedure
    - Master key rotation procedure (when `ENCRYPTION_ENABLED=true`)
    - Scaling replicas: `cleanup_lock` prevents duplicate orphan scan cycles; destroy queue polling is safe without lock (ZREM ensures exactly-once)
  - _Requirements: 6.3_

- [ ] 31. Phase 2 checkpoint — full test suite
  - Run full test suite: `go test ./... -count=1 -race`
  - Verify all property-based tests pass (minimum 100 iterations each)
  - Verify all integration tests pass
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: all Phase 2 requirements_

## Notes

- Tasks marked with `*` are optional (Phase 2) and can be skipped for initial deployment
- Phase 1 is the shippable MVP: auth, upload, download, destroy queue, cleanup, basic security, Docker Compose
- Phase 2 adds hardening: honeypot, crypto erasure, PBT, advanced metrics, geo fingerprinting
- Each task references specific requirements for traceability
- Checkpoints (tasks 20 and 31) ensure incremental validation
- Property tests (task 23) validate universal correctness properties defined in the design document
- Unit tests validate specific examples and edge cases
