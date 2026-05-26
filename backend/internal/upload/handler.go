// Package upload implements HTTP handlers for the EphemeralShare upload pipeline.
// It covers presigned URL generation, upload confirmation with ClamAV scanning,
// token listing, and token revocation.
package upload

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"ephemeral-share/backend/internal/audit"
	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/models"
	"ephemeral-share/backend/internal/rediskeys"
	"ephemeral-share/backend/internal/storage"
	"ephemeral-share/backend/internal/store"
	"ephemeral-share/backend/internal/util"
)

// Handler holds dependencies for upload HTTP handlers.
type Handler struct {
	cfg    *config.Config
	redis  *store.RedisClient
	s3     *storage.S3Client
	audit  *audit.Logger
	clamav *ClamAVClient
}

// NewHandler creates a new upload Handler.
func NewHandler(
	cfg *config.Config,
	redis *store.RedisClient,
	s3 *storage.S3Client,
	auditLogger *audit.Logger,
) *Handler {
	return &Handler{
		cfg:    cfg,
		redis:  redis,
		s3:     s3,
		audit:  auditLogger,
		clamav: NewClamAVClient(cfg.ClamAVAddress),
	}
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

// requestUploadBody is the JSON body for POST /api/admin/request-upload.
type requestUploadBody struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	TTLHours    int    `json:"ttl_hours"`
	AdminNote   string `json:"admin_note"`
}

// requestUploadResponse is the JSON response for a successful request-upload.
type requestUploadResponse struct {
	PresignedUploadURL string `json:"presigned_upload_url"`
	ObjectKey          string `json:"object_key"`
	UploadID           string `json:"upload_id"`
	ExpiresIn          int    `json:"expires_in"`
}

// confirmUploadBody is the JSON body for POST /api/admin/confirm-upload.
type confirmUploadBody struct {
	ObjectKey   string `json:"object_key"`
	ETag        string `json:"etag"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	TTLHours    int    `json:"ttl_hours"`
	AdminNote   string `json:"admin_note"`
	UploadID    string `json:"upload_id"`
}

// confirmUploadResponse is the JSON response for a successful confirm-upload.
type confirmUploadResponse struct {
	ShareURL  string    `json:"share_url"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

// tokenListItem is a single entry in the GET /api/admin/tokens response.
type tokenListItem struct {
	TokenHash   string    `json:"token_hash"`
	Filename    string    `json:"filename"`
	ExpiresAt   time.Time `json:"expires_at"`
	SizeBytes   int64     `json:"size_bytes"`
	ContentType string    `json:"content_type"`
}

// ---------------------------------------------------------------------------
// POST /api/admin/request-upload
// ---------------------------------------------------------------------------

// RequestUpload handles POST /api/admin/request-upload.
//
// Flow:
//  1. Parse and validate request body.
//  2. Check daily quota (uploads + bytes).
//  3. Check pending upload limits (per-admin and global).
//  4. Validate file size and content type.
//  5. Sanitize filename.
//  6. Generate object key and upload ID.
//  7. Generate presigned PUT URL.
//  8. Store upload session in Redis.
//  9. Add to uploads_pending ZSET.
//  10. Emit audit event.
//  11. Return presigned URL.
func (h *Handler) RequestUpload(c *fiber.Ctx) error {
	ctx := context.Background()
	ip := c.IP()

	var req requestUploadBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "INVALID_REQUEST",
		})
	}

	// Validate required fields.
	if req.Filename == "" || req.ContentType == "" || req.SizeBytes <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "INVALID_REQUEST",
			"details": "filename, content_type, and size_bytes are required",
		})
	}

	// Validate file size.
	if req.SizeBytes > h.cfg.MaxFileSizeBytes {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "FILE_TOO_LARGE",
			"max_bytes": h.cfg.MaxFileSizeBytes,
		})
	}

	// Validate content type against allowed list.
	if !h.isAllowedContentType(req.ContentType) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":         "INVALID_CONTENT_TYPE",
			"allowed_types": h.cfg.AllowedMIMETypes,
		})
	}

	// Sanitize filename.
	sanitized, err := util.SanitizeFilename(req.Filename)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "INVALID_FILENAME",
		})
	}

	// Resolve TTL.
	ttlHours := h.resolveTTL(req.TTLHours)

	// Check daily upload quota.
	today := time.Now().UTC().Format("2006-01-02")
	if h.cfg.MaxDailyUploads > 0 {
		quotaUploadsKey := rediskeys.QuotaUploads(today)
		quotaStr, err := h.redis.Get(ctx, quotaUploadsKey)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
		}
		var currentUploads int64
		if quotaStr != "" {
			fmt.Sscanf(quotaStr, "%d", &currentUploads)
		}
		if int(currentUploads) >= h.cfg.MaxDailyUploads {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "DAILY_UPLOAD_QUOTA_EXCEEDED",
			})
		}
	}

	// Check daily bytes quota.
	if h.cfg.MaxDailyBytes > 0 {
		quotaBytesKey := rediskeys.QuotaBytes(today)
		quotaStr, err := h.redis.Get(ctx, quotaBytesKey)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
		}
		var currentBytes int64
		if quotaStr != "" {
			fmt.Sscanf(quotaStr, "%d", &currentBytes)
		}
		if currentBytes+req.SizeBytes > h.cfg.MaxDailyBytes {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "DAILY_BYTES_QUOTA_EXCEEDED",
			})
		}
	}

	// Check per-admin pending upload limit.
	pendingCount, err := h.redis.ZCard(ctx, rediskeys.KeyUploadsPending)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}
	if h.cfg.MaxPendingUploadsPerAdmin > 0 && int(pendingCount) >= h.cfg.MaxPendingUploadsPerAdmin {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": "TOO_MANY_PENDING_UPLOADS",
		})
	}

	// Check global pending upload limit.
	if h.cfg.MaxTotalPendingUploads > 0 && int(pendingCount) >= h.cfg.MaxTotalPendingUploads {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": "SYSTEM_OVERLOADED",
		})
	}

	// Generate object key: ep/{YYYY}/{MM}/{uuid-v4}
	now := time.Now().UTC()
	objectKey := fmt.Sprintf("ep/%d/%02d/%s", now.Year(), now.Month(), uuid.New().String())

	// Generate upload ID.
	uploadID := uuid.New().String()

	// Generate presigned upload URL (15 minute TTL).
	presignedURL, err := h.s3.GeneratePresignedUploadURL(
		ctx,
		objectKey,
		req.ContentType,
		req.SizeBytes,
		15*time.Minute,
	)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "PRESIGN_FAILED")
	}

	// Build upload session.
	session := models.UploadSession{
		UploadID:    uploadID,
		ObjectKey:   objectKey,
		Status:      models.FileStatusPendingUpload,
		Filename:    sanitized,
		ContentType: req.ContentType,
		SizeBytes:   req.SizeBytes,
		TTLHours:    ttlHours,
		AdminNote:   req.AdminNote,
		CreatedAt:   now,
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// SETEX upload:{upload_id} with 30-minute TTL.
	uploadKey := rediskeys.Upload(uploadID)
	if err := h.redis.Set(ctx, uploadKey, string(sessionJSON), 30*time.Minute); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// ZADD uploads_pending with score = now + 1800 (30 min expiry).
	expiryScore := float64(now.Unix() + 1800)
	if err := h.redis.ZAddWithScore(ctx, rediskeys.KeyUploadsPending, expiryScore, uploadID); err != nil {
		// Non-fatal: clean up the upload key.
		_ = h.redis.Del(ctx, uploadKey)
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// Emit audit event.
	h.audit.Emit(ctx, audit.EventUploadInitiated, true,
		audit.WithObjectKey(objectKey),
		audit.WithAdminIP(ip),
		audit.WithDetails(map[string]interface{}{
			"upload_id":    uploadID,
			"size_bytes":   req.SizeBytes,
			"content_type": req.ContentType,
			"ttl_hours":    ttlHours,
		}),
	)

	return c.Status(fiber.StatusOK).JSON(requestUploadResponse{
		PresignedUploadURL: presignedURL,
		ObjectKey:          objectKey,
		UploadID:           uploadID,
		ExpiresIn:          900, // 15 minutes
	})
}

// ---------------------------------------------------------------------------
// POST /api/admin/confirm-upload
// ---------------------------------------------------------------------------

// ConfirmUpload handles POST /api/admin/confirm-upload.
//
// Flow:
//  1. Parse and validate request body.
//  2. Validate upload session exists in Redis.
//  3. Update session status to UPLOADED_UNCONFIRMED.
//  4. HEAD object to verify existence.
//  5. Run ClamAV scan.
//  6. Generate token and store metadata.
//  7. Update quota counters.
//  8. Clean up upload session.
//  9. Emit audit event.
//  10. Return share URL.
func (h *Handler) ConfirmUpload(c *fiber.Ctx) error {
	ctx := context.Background()
	ip := c.IP()

	var req confirmUploadBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "INVALID_REQUEST",
		})
	}

	if req.ObjectKey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "INVALID_REQUEST",
			"details": "object_key is required",
		})
	}

	// Validate upload session if upload_id provided.
	var session *models.UploadSession
	if req.UploadID != "" {
		uploadKey := rediskeys.Upload(req.UploadID)
		sessionStr, err := h.redis.Get(ctx, uploadKey)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
		}
		if sessionStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "UPLOAD_SESSION_NOT_FOUND",
			})
		}
		var s models.UploadSession
		if err := json.Unmarshal([]byte(sessionStr), &s); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
		}
		session = &s

		// Update status to UPLOADED_UNCONFIRMED.
		s.Status = models.FileStatusUploadedUnconfirmed
		updatedJSON, err := json.Marshal(s)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
		}
		if err := h.redis.Set(ctx, uploadKey, string(updatedJSON), 30*time.Minute); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
		}
	}

	// Resolve fields: prefer request body, fall back to session.
	filename := req.Filename
	contentType := req.ContentType
	sizeBytes := req.SizeBytes
	ttlHours := req.TTLHours
	adminNote := req.AdminNote

	if session != nil {
		if filename == "" {
			filename = session.Filename
		}
		if contentType == "" {
			contentType = session.ContentType
		}
		if sizeBytes == 0 {
			sizeBytes = session.SizeBytes
		}
		if ttlHours == 0 {
			ttlHours = session.TTLHours
		}
		if adminNote == "" {
			adminNote = session.AdminNote
		}
	}

	// Sanitize filename.
	sanitized, err := util.SanitizeFilename(filename)
	if err != nil {
		sanitized = "file"
	}

	// Resolve TTL.
	ttlHours = h.resolveTTL(ttlHours)

	// HEAD object to verify existence (with retry).
	_, err = h.s3.HeadObjectWithRetry(ctx, req.ObjectKey, 4)
	if err != nil {
		// Object not found — clean up and return error.
		_ = h.s3.DeleteObject(ctx, req.ObjectKey)
		if req.UploadID != "" {
			_ = h.redis.Del(ctx, rediskeys.Upload(req.UploadID))
			_ = h.redis.ZRem(ctx, rediskeys.KeyUploadsPending, req.UploadID)
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "UPLOAD_NOT_FOUND",
		})
	}

	// ClamAV scan: download from S3 and stream to clamd.
	scanCtx, scanCancel := context.WithTimeout(ctx,
		time.Duration(h.cfg.ClamAVScanTimeoutSeconds)*time.Second,
	)
	defer scanCancel()

	clean, virusName, scanErr := h.scanObject(scanCtx, req.ObjectKey)
	if scanErr != nil {
		// Scan unavailable — return 503.
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "SCAN_UNAVAILABLE",
		})
	}
	if !clean {
		// Infected — delete S3 object and return error.
		_ = h.s3.DeleteObject(ctx, req.ObjectKey)
		if req.UploadID != "" {
			_ = h.redis.Del(ctx, rediskeys.Upload(req.UploadID))
			_ = h.redis.ZRem(ctx, rediskeys.KeyUploadsPending, req.UploadID)
		}
		h.audit.Emit(ctx, audit.EventMalwareDetected, false,
			audit.WithObjectKey(req.ObjectKey),
			audit.WithAdminIP(ip),
			audit.WithDetails(map[string]interface{}{
				"virus_name": virusName,
			}),
		)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":      "MALWARE_DETECTED",
			"virus_name": virusName,
		})
	}

	// Generate token (32 bytes = 256-bit entropy).
	token, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "TOKEN_GENERATION_FAILED")
	}
	_ = token // token is returned in share_url, not stored

	// Compute token hash from the raw token bytes for storage.
	// util.GenerateToken already returns the SHA-256 hash.
	// tokenHash is the hex-encoded SHA-256 of the raw token bytes.

	// Build FileMetadata.
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(ttlHours) * time.Hour)

	// Compute checksum: use ETag if provided, otherwise use a placeholder.
	// In production, the ETag from S3 is the MD5 of the object content.
	checksumSHA256 := computeChecksumFromETag(req.ETag)

	meta := models.FileMetadata{
		ObjectKey:        req.ObjectKey,
		OriginalFilename: sanitized,
		ContentType:      contentType,
		SizeBytes:        sizeBytes,
		UploadedAt:       now,
		ExpiresAt:        expiresAt,
		MaxDownloads:     1,
		DownloadCount:    0,
		ChecksumSHA256:   checksumSHA256,
		AdminNote:        adminNote,
		Status:           models.FileStatusActive,
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// SETEX token:{token_hash} with TTL.
	tokenKey := rediskeys.Token(tokenHash)
	tokenTTL := time.Duration(ttlHours) * time.Hour
	if err := h.redis.Set(ctx, tokenKey, string(metaJSON), tokenTTL); err != nil {
		// Cleanup S3 object on failure.
		_ = h.s3.DeleteObject(ctx, req.ObjectKey)
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// SADD cleanup:{YYYY-MM-DD} object_key.
	today := now.Format("2006-01-02")
	cleanupKey := rediskeys.Cleanup(today)
	if err := h.redis.SAdd(ctx, cleanupKey, req.ObjectKey); err != nil {
		// Non-fatal: log but continue.
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithObjectKey(req.ObjectKey),
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to add to cleanup set",
				"error":  err.Error(),
			}),
		)
	}

	// ZADD cleanup_by_expiry with score = expires_at unix timestamp.
	if err := h.redis.ZAddWithScore(ctx, rediskeys.KeyCleanupByExpiry,
		float64(expiresAt.Unix()), req.ObjectKey); err != nil {
		// Non-fatal.
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithObjectKey(req.ObjectKey),
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to add to cleanup_by_expiry",
				"error":  err.Error(),
			}),
		)
	}

	// Move from uploads_pending to uploads_unconfirmed (ZREM pending, ZADD unconfirmed).
	if req.UploadID != "" {
		_ = h.redis.ZRem(ctx, rediskeys.KeyUploadsPending, req.UploadID)
		_ = h.redis.ZRem(ctx, rediskeys.KeyUploadsUnconfirmed, req.UploadID)
	}

	// Increment quota counters.
	if _, err := h.redis.IncrQuotaUploads(ctx, today); err != nil {
		// Non-fatal.
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to increment quota uploads",
				"error":  err.Error(),
			}),
		)
	}
	if _, err := h.redis.IncrByQuotaBytes(ctx, today, sizeBytes); err != nil {
		// Non-fatal.
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to increment quota bytes",
				"error":  err.Error(),
			}),
		)
	}

	// DEL upload:{upload_id}.
	if req.UploadID != "" {
		_ = h.redis.Del(ctx, rediskeys.Upload(req.UploadID))
	}

	// Build share URL: https://{PublicBaseURL}/d/{token}
	shareURL := fmt.Sprintf("%s/d/%s", strings.TrimRight(h.cfg.PublicBaseURL, "/"), token)

	// Emit audit event.
	h.audit.Emit(ctx, audit.EventUploadConfirmed, true,
		audit.WithObjectKey(req.ObjectKey),
		audit.WithTokenHash(tokenHash),
		audit.WithAdminIP(ip),
		audit.WithDetails(map[string]interface{}{
			"size_bytes":   sizeBytes,
			"content_type": contentType,
			"ttl_hours":    ttlHours,
			"expires_at":   expiresAt.Format(time.RFC3339),
		}),
	)

	return c.Status(fiber.StatusOK).JSON(confirmUploadResponse{
		ShareURL:  shareURL,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
}

// ---------------------------------------------------------------------------
// GET /api/admin/tokens
// ---------------------------------------------------------------------------

// ListTokens handles GET /api/admin/tokens.
// It scans Redis for token:* keys and returns metadata for each active token.
func (h *Handler) ListTokens(c *fiber.Ctx) error {
	ctx := context.Background()

	tokens, err := h.scanTokenKeys(ctx)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	return c.Status(fiber.StatusOK).JSON(tokens)
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/tokens/{token_hash}
// ---------------------------------------------------------------------------

// RevokeToken handles DELETE /api/admin/tokens/{token_hash}.
func (h *Handler) RevokeToken(c *fiber.Ctx) error {
	ctx := context.Background()
	ip := c.IP()

	tokenHash := c.Params("token_hash")
	if tokenHash == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "INVALID_REQUEST",
		})
	}

	tokenKey := rediskeys.Token(tokenHash)
	if err := h.redis.Del(ctx, tokenKey); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	h.audit.Emit(ctx, audit.EventFileDestroyed, true,
		audit.WithTokenHash(tokenHash),
		audit.WithAdminIP(ip),
		audit.WithDetails(map[string]interface{}{
			"reason": "admin_revoked",
		}),
	)

	return c.SendStatus(fiber.StatusOK)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// isAllowedContentType checks whether the given content type is in the allowed list.
func (h *Handler) isAllowedContentType(contentType string) bool {
	// Normalize: strip parameters (e.g., "text/plain; charset=utf-8" → "text/plain").
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	for _, allowed := range h.cfg.AllowedMIMETypes {
		if strings.ToLower(strings.TrimSpace(allowed)) == ct {
			return true
		}
	}
	return false
}

// resolveTTL returns the TTL in hours, clamped to [MinTTLHours, MaxTTLHours].
// If ttlHours is 0, the default TTL is used.
func (h *Handler) resolveTTL(ttlHours int) int {
	if ttlHours <= 0 {
		return h.cfg.DefaultTTLHours
	}
	if ttlHours < h.cfg.MinTTLHours {
		return h.cfg.MinTTLHours
	}
	if ttlHours > h.cfg.MaxTTLHours {
		return h.cfg.MaxTTLHours
	}
	return ttlHours
}

// scanObject downloads the object from S3 via a short-lived presigned URL and
// streams it to ClamAV for scanning.
//
// Returns:
//   - clean=true, virusName="", err=nil  → file is clean
//   - clean=false, virusName="...", err=nil → file is infected
//   - clean=false, virusName="", err=...  → scan error
func (h *Handler) scanObject(ctx context.Context, objectKey string) (clean bool, virusName string, err error) {
	// Generate a short-lived presigned download URL (60 seconds).
	presignedURL, err := h.s3.GeneratePresignedDownloadURL(
		ctx,
		objectKey,
		"scan",
		"application/octet-stream",
		60*time.Second,
	)
	if err != nil {
		return false, "", fmt.Errorf("upload: failed to generate presigned download URL for scan: %w", err)
	}

	// Download the file via HTTP.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, presignedURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("upload: failed to create HTTP request for scan: %w", err)
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return false, "", fmt.Errorf("upload: failed to download object for scan: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("upload: unexpected HTTP status %d when downloading for scan", resp.StatusCode)
	}

	// Stream to ClamAV.
	return h.clamav.ScanReader(ctx, resp.Body)
}

// scanTokenKeys uses Redis SCAN to find all token:* keys and returns their metadata.
func (h *Handler) scanTokenKeys(ctx context.Context) ([]tokenListItem, error) {
	// Use the underlying Redis client via the store's generic Get method.
	// We need to scan for keys matching "token:*" pattern.
	// Since store.RedisClient doesn't expose SCAN directly, we use a workaround
	// by calling the internal client via a helper method.
	keys, err := h.redis.ScanKeys(ctx, rediskeys.KeyPrefixToken+"*")
	if err != nil {
		return nil, err
	}

	items := make([]tokenListItem, 0, len(keys))
	for _, key := range keys {
		val, err := h.redis.Get(ctx, key)
		if err != nil || val == "" {
			continue
		}

		var meta models.FileMetadata
		if err := json.Unmarshal([]byte(val), &meta); err != nil {
			continue
		}

		// Extract token hash from key (strip "token:" prefix).
		tokenHash := strings.TrimPrefix(key, rediskeys.KeyPrefixToken)

		items = append(items, tokenListItem{
			TokenHash:   tokenHash,
			Filename:    meta.OriginalFilename,
			ExpiresAt:   meta.ExpiresAt,
			SizeBytes:   meta.SizeBytes,
			ContentType: meta.ContentType,
		})
	}

	return items, nil
}

// computeChecksumFromETag derives a SHA-256 hex string from the ETag.
// S3 ETags are typically MD5 hashes (or multipart composites). Since we don't
// have the raw file content here, we store the ETag-derived value as a
// placeholder checksum. The download service will verify against S3 HEAD.
func computeChecksumFromETag(etag string) string {
	// Strip surrounding quotes from ETag if present.
	etag = strings.Trim(etag, `"`)
	if etag == "" {
		return ""
	}
	// Hash the ETag to produce a consistent hex string.
	sum := sha256.Sum256([]byte(etag))
	return fmt.Sprintf("%x", sum)
}


