# Requirements Document — EphemeralShare

## Introduction

EphemeralShare là hệ thống chia sẻ file bảo mật cao theo triết lý **zero-retention**: mỗi file chỉ tồn tại trong hệ thống đúng khoảng thời gian tối thiểu cần thiết để chuyển giao đến người nhận, sau đó bị xóa hoàn toàn và không thể phục hồi.

Hệ thống phục vụ một admin duy nhất upload và chia sẻ file nhạy cảm (hợp đồng, credentials, file thiết kế, tài liệu nội bộ, software license). Người nhận chỉ được tải file đúng một lần duy nhất thông qua một link có thời hạn. Sau khi tải xong — hoặc khi TTL hết — file bị xóa khỏi object storage và token bị thu hồi khỏi Redis.

Pipeline cốt lõi: `Upload → Encrypt → Store (temp) → Generate Token → Share Link → Download → Destroy`

### Scope và Assumptions

- **One-time delivery guarantee:** THE System đảm bảo file chỉ được giao đúng một lần thông qua cơ chế share link. THE System KHÔNG đảm bảo ngăn chặn exfiltration sau khi file đã được Recipient nhận (ví dụ: sao chép, chụp màn hình, hoặc chia sẻ lại file đã tải là ngoài phạm vi threat model của hệ thống).
- **Presigned URL window:** THE System đảm bảo Presigned_Download_URL chỉ có hiệu lực trong tối đa TTL đã cấu hình (mặc định 30 giây) kể từ thời điểm phát hành. Bất kỳ bên nào có được Presigned_Download_URL trong khoảng thời gian này đều có thể tải file trực tiếp từ Object_Storage.
- **Logical deletion:** Object_Storage deletion là xóa logic (object không còn truy cập được qua API ngay sau khi DELETE). Việc ghi đè vật lý trên phương tiện lưu trữ nằm ngoài phạm vi đảm bảo của hệ thống và phải được xử lý ở cấp độ nhà cung cấp hạ tầng nếu có yêu cầu compliance.

---

## Glossary

- **System**: Toàn bộ hệ thống EphemeralShare bao gồm backend, frontend, Redis và Object Storage.
- **Upload_Service**: Backend service (Go Fiber) xử lý upload, tạo token, và orchestrate pipeline.
- **Download_Service**: Backend service (Go Fiber) xử lý download request, acquire lock, và trigger destruction.
- **Cleanup_Worker**: Background process chạy định kỳ để phát hiện và xóa orphaned S3 objects.
- **Admin**: Người dùng duy nhất có quyền upload file và quản lý hệ thống.
- **Admin_Panel**: Frontend Next.js dành riêng cho Admin, bao gồm trang login và dashboard upload.
- **Recipient**: Người nhận link chia sẻ, không có tài khoản trong hệ thống.
- **Download_Page**: Trang frontend hiển thị thông tin file và nút tải xuống cho Recipient.
- **Token**: Chuỗi ngẫu nhiên 256-bit (base64url, ~43 ký tự) được tạo sau mỗi upload thành công, dùng để xác thực download request.
- **Token_Hash**: SHA-256 hash của Token, được lưu trong Redis thay vì Token gốc.
- **Share_URL**: URL công khai dạng `https://domain/d/{token}` được Admin chia sẻ cho Recipient.
- **Redis**: Cache layer lưu trữ token metadata với TTL, distributed lock, và rate limiting state.
- **Object_Storage**: Cloudflare R2 hoặc AWS S3 lưu trữ file tạm thời, private, không public access.
- **Presigned_Upload_URL**: URL có chữ ký HMAC cho phép frontend upload trực tiếp lên Object_Storage trong 15 phút.
- **Presigned_Download_URL**: URL có chữ ký HMAC cho phép Recipient tải file trực tiếp từ Object_Storage. TTL có thể cấu hình qua environment variable `PRESIGNED_URL_TTL_SECONDS`, mặc định 30 giây, tối đa 60 giây.
- **Distributed_Lock**: Redis lock (SET NX EX 30) ngăn concurrent download của cùng một Token.
- **TTL**: Time-To-Live — thời gian tồn tại tối đa của một Token trong Redis (mặc định 24 giờ, cấu hình được từ 1 giờ đến 7 ngày).
- **Orphaned_Object**: S3 object còn tồn tại sau khi Token tương ứng đã hết hạn hoặc bị xóa.
- **Destroyed_Token_List**: Danh sách Token_Hash đã bị thu hồi, lưu trong Redis 24 giờ để ngăn replay attack.
- **MIME_Type**: Loại nội dung file được phát hiện từ byte header thực tế, không phải từ extension.
- **Admin_JWT**: JSON Web Token có thời hạn 15 phút, gắn với IP address của Admin, dùng để xác thực mọi admin request.
- **TOTP**: Time-based One-Time Password (RFC 6238) — xác thực hai yếu tố tùy chọn cho Admin login.

---

## Requirements

### Requirement 1: Admin Authentication

**User Story:** As an Admin, I want to authenticate securely before accessing the upload dashboard, so that unauthorized users cannot upload or manage files.

#### Acceptance Criteria

1. WHEN an unauthenticated request reaches any `/admin/*` route, THE Admin_Panel SHALL redirect the request to `/admin` login page.
2. WHEN Admin submits a login request with a valid password, THE Upload_Service SHALL issue an Admin_JWT with a 15-minute expiry and a refresh token with an 8-hour expiry.
3. WHEN Admin submits a login request with an invalid password, THE Upload_Service SHALL return HTTP 401 and add a 500-millisecond artificial delay before responding.
4. WHEN Admin submits 5 consecutive failed login attempts from the same IP within 10 minutes, THE Upload_Service SHALL block further login attempts from that IP for 15 minutes and return HTTP 429.
5. WHERE TOTP is enabled, WHEN Admin submits a valid password, THE Upload_Service SHALL require a valid 6-digit TOTP code before issuing the Admin_JWT.
6. WHEN an Admin_JWT is used from an IP address different from the IP at login time, THE Upload_Service SHALL reject the request with HTTP 401 and log a suspicious activity event.
7. WHERE ADMIN_ALLOWED_IPS is configured, WHEN a request reaches any `/admin/*` route from an IP not in the whitelist, THE Upload_Service SHALL return HTTP 403 without processing the request.
8. THE Upload_Service SHALL store the Admin password as a bcrypt hash with cost factor 12 or higher and SHALL NOT store or log the plaintext password.

---

### Requirement 2: File Upload Pipeline

**User Story:** As an Admin, I want to upload a file and receive a shareable link, so that I can securely deliver the file to a Recipient.

#### Acceptance Criteria

1. WHEN Admin requests a presigned upload URL, THE Upload_Service SHALL validate the Admin_JWT before generating the URL.
2. WHEN Admin requests a presigned upload URL with a valid Admin_JWT, THE Upload_Service SHALL generate a Presigned_Upload_URL with a 15-minute expiry and an unguessable Object_Storage key in the format `ep/{YYYY}/{MM}/{uuid-v4}`.
3. WHEN Admin requests a presigned upload URL with a file size exceeding 500 MB, THE Upload_Service SHALL return HTTP 400 with error code `FILE_TOO_LARGE`.
4. WHEN Admin requests a presigned upload URL with a MIME_Type not in the allowed list, THE Upload_Service SHALL return HTTP 400 with error code `INVALID_CONTENT_TYPE` and the list of allowed types.
5. WHEN Admin confirms upload completion with a valid token, THE Upload_Service SHALL verify the object exists in Object_Storage before activating the Token.
6. WHEN Admin confirms upload completion successfully, THE Upload_Service SHALL store Token metadata in Redis using the key `token:{Token_Hash}` with the configured TTL and return the Share_URL.
7. THE Upload_Service SHALL generate each Token using a cryptographically secure random number generator producing 32 bytes (256-bit entropy) encoded as URL-safe base64.
8. THE Upload_Service SHALL store only the Token_Hash (SHA-256) in Redis and SHALL NOT store the raw Token value anywhere in the system.
9. THE Upload_Service SHALL detect the actual MIME_Type from the first 512 bytes of file content and SHALL reject files where the detected MIME_Type does not match the declared content type.
10. WHEN an upload pipeline step fails after the object is stored in Object_Storage but before the Token is activated, THE Upload_Service SHALL delete the orphaned object from Object_Storage.

---

### Requirement 3: Token & Metadata Management

**User Story:** As an Admin, I want each shared file to have a configurable expiry time, so that files are automatically invalidated if not downloaded within the allowed window.

#### Acceptance Criteria

1. THE Upload_Service SHALL store file metadata in Redis with the following fields: `object_key`, `original_filename`, `content_type`, `size_bytes`, `uploaded_at`, `expires_at`, `max_downloads`, `download_count`, `checksum_sha256`, and `admin_note`.
2. WHEN Admin specifies a TTL between 1 hour and 168 hours (7 days) inclusive, THE Upload_Service SHALL set the Redis key TTL to the specified value.
3. IF Admin does not specify a TTL, THEN THE Upload_Service SHALL apply a default TTL of 24 hours.
4. WHEN a Token's Redis TTL expires, THE System SHALL treat the Token as invalid for all subsequent download requests without requiring explicit deletion.
5. WHEN Admin requests to revoke a Token via the dashboard, THE Upload_Service SHALL delete the Redis key `token:{Token_Hash}` immediately and return HTTP 200.

---

### Requirement 4: One-Time Download with Atomic Destruction

**User Story:** As a Recipient, I want to download the file exactly once using the Share_URL, so that the file is immediately destroyed after I receive it.

#### Acceptance Criteria

1. WHEN a Recipient navigates to `GET /d/{token}`, THE Download_Service SHALL validate the Token exists in Redis and render the Download_Page WITHOUT consuming the Token or acquiring the Distributed_Lock.
2. WHEN a Recipient submits `POST /api/download/{token}` (explicit download confirmation), THE Download_Service SHALL atomically acquire the Distributed_Lock using a Redis Lua script that performs GET and SET NX in a single atomic operation, then generate the Presigned_Download_URL, and trigger destruction.
3. THE System SHALL NOT consume a Token or trigger destruction on a GET request to any endpoint.
4. WHEN the Distributed_Lock is already held by another request for the same Token, THE Download_Service SHALL return HTTP 423 with error code `DOWNLOAD_IN_PROGRESS` and a `retry_after` value of 30 seconds.
5. WHEN the Distributed_Lock is acquired successfully, THE Download_Service SHALL generate a Presigned_Download_URL with a TTL equal to the value of `PRESIGNED_URL_TTL_SECONDS` (default 30 seconds, maximum 60 seconds) and redirect the Recipient with HTTP 302.
6. WHEN Download_Service generates a Presigned_Download_URL, THE Download_Service SHALL verify the stored `checksum_sha256` in Token metadata matches the ETag or checksum reported by Object_Storage before issuing the redirect.
7. IF the checksum verification fails, THE Download_Service SHALL abort the download, log an integrity error event, and return HTTP 500 with error code `INTEGRITY_CHECK_FAILED`.
8. WHEN the Distributed_Lock is acquired successfully, THE Download_Service SHALL schedule asynchronous destruction of the Token and Object_Storage object within 5 seconds of issuing the redirect.
9. WHEN destruction is triggered, THE Download_Service SHALL delete the S3 object first, then delete `token:{Token_Hash}` from Redis, then delete `lock:{Token_Hash}` from Redis, then add `{Token_Hash}` to the Destroyed_Token_List with a 24-hour TTL.
10. THE destruction pipeline SHALL be idempotent: if the Object_Storage object does not exist at destruction time (e.g., already deleted in a previous partial attempt), THE Download_Service SHALL treat the missing object as a successful deletion and continue with Redis key cleanup.
11. IF any step of the destruction pipeline fails, THE Download_Service SHALL log the failure and continue executing remaining destruction steps rather than aborting the entire pipeline.
12. WHEN a Recipient requests `GET /d/{token}` and the Token is not found in Redis, THE Download_Service SHALL redirect to `/expired` with HTTP 302.
13. WHEN a Recipient requests `GET /d/{token}` and the Token_Hash is present in the Destroyed_Token_List, THE Download_Service SHALL redirect to `/expired` with HTTP 302.
14. THE Download_Service SHALL NOT expose the Object_Storage key, bucket name, or any internal identifiers in the HTTP response to the Recipient.

---

### Requirement 5: Race Condition Prevention

**User Story:** As a system operator, I want concurrent download attempts on the same link to be safely handled, so that the file is never delivered more than once.

#### Acceptance Criteria

1. WHEN two or more `POST /api/download/{token}` requests for the same Token arrive within the Distributed_Lock window, THE Download_Service SHALL guarantee that exactly one request acquires the lock and proceeds to generate the Presigned_Download_URL.
2. THE Download_Service SHALL implement the Distributed_Lock check and Token metadata retrieval as a single atomic Redis Lua script to eliminate time-of-check/time-of-use race conditions.
3. WHEN a Recipient submits `POST /api/download/{token}` from multiple browser tabs simultaneously, THE Download_Service SHALL return HTTP 423 for all requests after the first lock acquisition.
4. WHEN the Distributed_Lock expires after 30 seconds without destruction completing (e.g., due to a crash), THE System SHALL allow the next request to re-acquire the lock and re-attempt destruction.

---

### Requirement 6: Orphan Cleanup

**User Story:** As a system operator, I want orphaned Object_Storage objects to be automatically removed, so that no file data persists beyond its intended lifetime even in failure scenarios.

#### Acceptance Criteria

1. THE Cleanup_Worker SHALL run every 15 minutes to scan for Orphaned_Objects in Object_Storage.
2. WHEN the Cleanup_Worker finds an object in Object_Storage whose age exceeds the maximum configured TTL and whose corresponding Redis key does not exist, THE Cleanup_Worker SHALL delete the object from Object_Storage.
3. WHEN the Cleanup_Worker deletes an Orphaned_Object, THE Cleanup_Worker SHALL emit a structured log event containing the object key and deletion timestamp.
4. IF the Cleanup_Worker encounters an error deleting an object, THEN THE Cleanup_Worker SHALL log the error and continue processing remaining objects without stopping.

---

### Requirement 7: Object Storage Security

**User Story:** As a system operator, I want the Object_Storage bucket to be completely private, so that files cannot be accessed directly without a valid Presigned_Download_URL.

#### Acceptance Criteria

1. THE System SHALL configure the Object_Storage bucket with all public access blocked, allowing only the backend IAM role to generate presigned URLs.
2. THE Upload_Service SHALL generate Object_Storage keys using the format `ep/{YYYY}/{MM}/{uuid-v4}` with no correlation to the original filename.
3. THE System SHALL disable Object_Storage versioning on the bucket to prevent version-based file recovery after deletion.
4. WHEN THE Upload_Service deletes an object, THE Upload_Service SHALL verify the deletion by performing a HEAD request and SHALL log an error if the object still exists after deletion.
5. THE System SHALL configure an Object_Storage lifecycle rule to permanently delete any remaining objects older than the maximum TTL plus 1 day as a safety net.
6. THE System assumes Object_Storage provider logical deletion semantics (object inaccessible via API immediately after DELETE) are sufficient for the defined threat model. Physical media overwrite is outside the scope of this system's guarantees.
7. THE System documentation SHALL explicitly state that Object_Storage deletion is logical, not physical, and that compliance requirements demanding physical media destruction must be addressed at the infrastructure provider level.
8. THE System SHALL configure Redis with `appendonly yes` and `appendfsync everysec` for crash recovery, with the explicit understanding that persisted data represents tokens that were active at crash time and will expire per their TTL.
9. THE System SHALL document that Redis persistence (AOF/RDB) is used solely for crash recovery of in-flight tokens and SHALL NOT be considered long-term data storage.
10. THE System SHALL NOT disable Redis persistence entirely, as doing so would cause all active tokens to become invalid on Redis restart, resulting in broken share links.

---

### Requirement 8: Rate Limiting

**User Story:** As a system operator, I want rate limiting applied at multiple layers, so that the download endpoint and admin panel are protected against brute force and abuse.

#### Acceptance Criteria

1. THE System SHALL enforce a rate limit of 5 download requests per minute per IP address on the `/d/` endpoint at the Nginx layer, returning HTTP 429 when exceeded.
2. THE System SHALL enforce a rate limit of 2 upload requests per minute per IP address on the `/api/admin/request-upload` endpoint at the Nginx layer.
3. THE System SHALL enforce a rate limit of 30 API requests per minute per IP address on all `/api/` endpoints at the Nginx layer.
4. THE Download_Service SHALL enforce an application-level sliding window rate limit of 10 download requests per minute per IP address using Redis, independent of the Nginx layer.
5. WHEN a rate limit is exceeded, THE System SHALL return HTTP 429 with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers.

---

### Requirement 9: Security Headers & Transport Security

**User Story:** As a system operator, I want all HTTP responses to include security headers and enforce HTTPS, so that the system is protected against common web vulnerabilities.

#### Acceptance Criteria

1. THE System SHALL include the following headers on all HTTP responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store, no-cache, must-revalidate`, and an empty `Server` header.
2. THE System SHALL include a `Content-Security-Policy` header with `default-src 'self'` on all HTML responses.
3. WHEN a request arrives over HTTP, THE System SHALL redirect to HTTPS with HTTP 301.
4. THE System SHALL use TLS 1.2 or higher for all connections and SHALL NOT support TLS 1.0 or TLS 1.1.
5. THE System SHALL NOT include stack traces, internal error messages, or system information in HTTP error responses to clients.
6. THE System SHALL configure Cloudflare (or CDN provider) to bypass cache for all `/d/*`, `/api/*`, and `/admin/*` routes using `Cache-Control: no-store` headers and CDN page rules.
7. THE Download_Service SHALL include `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache` on all responses from the `/d/` endpoint, including the 302 redirect response.
8. THE System SHALL NOT allow CDN edge nodes to cache Presigned_Download_URL redirect responses.

---

### Requirement 10: Admin Dashboard UX

**User Story:** As an Admin, I want a clean dashboard to upload files and copy share links, so that I can complete the file delivery workflow in under 30 seconds.

#### Acceptance Criteria

1. THE Admin_Panel SHALL provide a drag-and-drop file upload interface that displays upload progress as a percentage.
2. WHEN an upload completes successfully, THE Admin_Panel SHALL display the Share_URL in a copyable text field and show the expiry time.
3. WHEN Admin selects a file exceeding 500 MB or with a disallowed MIME_Type, THE Admin_Panel SHALL display an inline validation error before initiating the upload request.
4. THE Admin_Panel SHALL allow Admin to configure TTL (1 hour to 7 days) and an optional admin note per upload.
5. WHEN Admin is on the dashboard and the Admin_JWT expires, THE Admin_Panel SHALL automatically attempt to refresh the token using the refresh token without interrupting the current session.
6. THE Admin_Panel SHALL display a list of active tokens with their expiry times and provide a revoke button for each token.

---

### Requirement 11: Download Page UX

**User Story:** As a Recipient, I want a clear download page that shows file information and a prominent download button, so that I understand the one-time nature of the link before clicking.

#### Acceptance Criteria

1. WHEN a Recipient navigates to a valid Share_URL, THE Download_Page SHALL display the original filename, file size, file type, and remaining time until link expiry.
2. THE Download_Page SHALL display a prominent warning that the link can only be used once before the download button.
3. WHEN a Recipient clicks the download button, THE Download_Page SHALL send a POST request to `/api/download/{token}` to initiate the download, preventing accidental token consumption by browser prefetch or link crawlers.
4. WHEN a Recipient clicks the download button, THE Download_Page SHALL initiate the download and display a confirmation message that the link has been consumed.
5. WHEN a Recipient navigates to an expired or already-used Share_URL, THE System SHALL redirect to `/expired` with HTTP 302.
6. THE Download_Page SHALL be server-side rendered to validate Token existence before sending HTML to the client.

---

### Requirement 12: Expired Link Page

**User Story:** As a Recipient who encounters an expired link, I want a clear explanation and contact options, so that I can request a new link from the Admin.

#### Acceptance Criteria

1. WHEN a Recipient is redirected to `/expired`, THE System SHALL display a page explaining that the file has been downloaded or the link has expired for security reasons.
2. THE System SHALL display contact options (configurable: Telegram, Zalo, Email) on the `/expired` page to allow the Recipient to request a new link.
3. THE System SHALL NOT reveal whether the link expired due to TTL timeout or because the file was already downloaded.

---

### Requirement 13: Audit Logging

**User Story:** As a system operator, I want structured audit logs for key events, so that I can investigate security incidents without storing sensitive file content.

#### Acceptance Criteria

1. THE System SHALL emit a structured JSON log event to stdout for each of the following events: upload initiated, upload confirmed, download link accessed, file destroyed, orphan cleaned, admin login success, admin login failure, and suspicious activity detected.
2. THE System SHALL include the following fields in each audit log event: `ts` (ISO 8601 timestamp), `event` (event type), `object_key` (not filename), `token_hash` (not raw token), `success` (boolean), and optionally `admin_ip` or `recipient_ip`.
3. THE System SHALL NOT include file content, original filenames, raw tokens, or admin passwords in any log event.
4. THE System SHALL write all logs to stdout only and SHALL NOT write logs to persistent files on disk.

---

### Requirement 14: Health Check Endpoint

**User Story:** As a system operator, I want a health check endpoint, so that monitoring tools can verify system availability and dependency connectivity.

#### Acceptance Criteria

1. THE System SHALL expose a `GET /health` endpoint that returns HTTP 200 with `{"status":"ok","redis":"ok","storage":"ok","version":"<version>"}` when all dependencies are healthy.
2. WHEN Redis is unavailable, THE System SHALL return HTTP 503 with `{"status":"degraded","redis":"unavailable"}` from the `/health` endpoint.
3. WHEN Object_Storage is unavailable, THE System SHALL return HTTP 503 with `{"status":"degraded","storage":"unavailable"}` from the `/health` endpoint.
4. THE `/health` endpoint SHALL NOT require authentication and SHALL be excluded from rate limiting.

---

### Requirement 15: Token Round-Trip Integrity

**User Story:** As a system operator, I want token generation and validation to be verifiably correct, so that no token can be forged, replayed, or collide with another token.

#### Acceptance Criteria

1. THE Upload_Service SHALL generate tokens such that for any two independently generated tokens, the probability of collision is less than 1 in 2^128.
2. FOR ALL valid tokens generated by THE Upload_Service, hashing the token with SHA-256 and looking up `token:{hash}` in Redis SHALL return the original metadata stored at upload time (round-trip property).
3. WHEN a token is consumed and added to the Destroyed_Token_List, THE Download_Service SHALL reject all subsequent requests using that token, including requests that arrive before the 24-hour Destroyed_Token_List TTL expires.
4. THE Upload_Service SHALL generate tokens using only `crypto/rand` (Go) or equivalent cryptographically secure source and SHALL NOT use `math/rand` or any deterministic source.
