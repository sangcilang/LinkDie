// Package download implements HTTP handlers for the EphemeralShare download pipeline.
// It covers the SSR metadata endpoint (GET /d/{token}) and the token-consuming
// download endpoint (POST /api/download/{token}).
package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
)

// Handler holds dependencies for download HTTP handlers.
type Handler struct {
	cfg   *config.Config
	redis *store.RedisClient
	s3    *storage.S3Client
	audit *audit.Logger
}

// NewHandler creates a new download Handler.
func NewHandler(
	cfg *config.Config,
	redis *store.RedisClient,
	s3 *storage.S3Client,
	auditLogger *audit.Logger,
) *Handler {
	return &Handler{
		cfg:   cfg,
		redis: redis,
		s3:    s3,
		audit: auditLogger,
	}
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// tokenMetadataResponse is the JSON response for GET /d/{token}.
// In normal mode it includes filename; in minimal disclosure mode it omits it.
type tokenMetadataResponse struct {
	Filename    string    `json:"filename,omitempty"`
	SizeBytes   int64     `json:"size_bytes"`
	ContentType string    `json:"content_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	TokenHash   string    `json:"token_hash"`
}

// ---------------------------------------------------------------------------
// GET /d/{token} — SSR metadata endpoint
// ---------------------------------------------------------------------------

// GetTokenMetadata handles GET /d/{token}.
//
// This endpoint is called by the Next.js SSR page to retrieve token metadata
// for rendering the Download_Page. It does NOT consume the token or acquire
// the Distributed_Lock.
//
// Flow:
//  1. SHA-256 hash the token from the URL param.
//  2. Check destroyed:{hash} in Redis → 302 /expired if found.
//  3. GET token:{hash} from Redis → 302 /expired if not found.
//  4. Return 200 JSON with metadata (respecting MINIMAL_DISCLOSURE_MODE).
func (h *Handler) GetTokenMetadata(c *fiber.Ctx) error {
	ctx := context.Background()

	// Set cache-control headers to prevent caching of this response.
	setCacheControlNoStore(c)

	// Extract and hash the token.
	rawToken := c.Params("token")
	if rawToken == "" {
		return c.Redirect("/expired", fiber.StatusFound)
	}
	tokenHash := hashToken(rawToken)

	// Check destroyed:{hash} — if found, the token has already been consumed.
	destroyedVal, err := h.redis.Get(ctx, rediskeys.Destroyed(tokenHash))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}
	if destroyedVal != "" {
		return c.Redirect("/expired", fiber.StatusFound)
	}

	// GET token:{hash} from Redis.
	metaStr, err := h.redis.Get(ctx, rediskeys.Token(tokenHash))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}
	if metaStr == "" {
		return c.Redirect("/expired", fiber.StatusFound)
	}

	// Unmarshal metadata.
	var meta models.FileMetadata
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// Build response respecting MINIMAL_DISCLOSURE_MODE.
	resp := tokenMetadataResponse{
		SizeBytes:   meta.SizeBytes,
		ContentType: meta.ContentType,
		ExpiresAt:   meta.ExpiresAt,
		TokenHash:   tokenHash,
	}

	if h.cfg.MinimalDisclosureMode {
		// Minimal mode: hide filename, report zero size, generic content type.
		resp.SizeBytes = 0
		resp.ContentType = "application/octet-stream"
		// resp.Filename is omitted (zero value, omitempty)
	} else {
		resp.Filename = meta.OriginalFilename
	}

	return c.Status(fiber.StatusOK).JSON(resp)
}

// ---------------------------------------------------------------------------
// POST /api/download/{token} — Consume token and get download URL
// ---------------------------------------------------------------------------

// ConsumeToken handles POST /api/download/{token}.
//
// This is the critical endpoint that atomically acquires the lock and triggers
// destruction. It returns a 302 redirect to the presigned download URL.
//
// Flow:
//  1. SHA-256 hash the token.
//  2. Check destroyed:{hash} → 302 /expired if found.
//  3. Get Redis server time via GetRedisServerTime.
//  4. Generate destroy_job_id = UUID v4.
//  5. Call redis.CASTokenConsume → handle not found / already consuming.
//  6. Verify checksum via s3.HeadObjectWithRetry.
//  7. Generate presigned download URL.
//  8. Deduplication check: skip ZADD if destruction already scheduled.
//  9. ZADD destroy_queue with grace period score.
//  10. Emit download_accessed audit event.
//  11. Return 302 redirect to presigned URL.
func (h *Handler) ConsumeToken(c *fiber.Ctx) error {
	ctx := context.Background()
	ip := c.IP()

	// Set cache-control headers.
	c.Set("Cache-Control", "no-store, private")
	c.Set("Pragma", "no-cache")

	// 1. Extract and hash the token.
	rawToken := c.Params("token")
	if rawToken == "" {
		return c.Redirect("/expired", fiber.StatusFound)
	}
	tokenHash := hashToken(rawToken)

	// 2. Check destroyed:{hash}.
	destroyedVal, err := h.redis.Get(ctx, rediskeys.Destroyed(tokenHash))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}
	if destroyedVal != "" {
		return c.Redirect("/expired", fiber.StatusFound)
	}

	// 3. Get Redis server time.
	redisNow, err := h.redis.GetRedisServerTime(ctx)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// 4. Generate destroy_job_id.
	jobID := uuid.New().String()

	// 5. Call CASTokenConsume — atomically transition ACTIVE → CONSUMING.
	meta, alreadyConsuming, err := h.redis.CASTokenConsume(ctx, tokenHash, redisNow, jobID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}
	if meta == nil {
		// Token not found in Redis.
		return c.Redirect("/expired", fiber.StatusFound)
	}
	if alreadyConsuming {
		// Another request is already consuming this token.
		return c.Status(fiber.StatusLocked).JSON(fiber.Map{
			"error":       "DOWNLOAD_IN_PROGRESS",
			"retry_after": 30,
		})
	}

	// 6. Verify checksum via HeadObjectWithRetry (1 attempt — fast path).
	headOut, headErr := h.s3.HeadObjectWithRetry(ctx, meta.ObjectKey, 1)
	if headErr != nil {
		// Check if this is a 404 (object not found — race condition).
		if isS3NotFound(headErr) {
			// Object already deleted — proceed with cleanup and return expired.
			h.cleanupAfterMissingObject(ctx, tokenHash)
			return c.Redirect("/expired", fiber.StatusFound)
		}
		// Other S3 error — return 500.
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// Checksum verification (best-effort: ETag is MD5, stored checksum may be SHA-256).
	// Only perform strict comparison if both values are in the same format.
	if headOut != nil && headOut.ETag != nil && meta.ChecksumSHA256 != "" {
		etag := strings.Trim(*headOut.ETag, `"`)
		// ETag is typically MD5 hex (32 chars); SHA-256 is 64 chars.
		// Only compare if both appear to be the same format (same length).
		if len(etag) == len(meta.ChecksumSHA256) && etag != meta.ChecksumSHA256 {
			h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
				audit.WithTokenHash(tokenHash),
				audit.WithObjectKey(meta.ObjectKey),
				audit.WithRecipientIP(ip),
				audit.WithDetails(map[string]interface{}{
					"reason":            "integrity_check_failed",
					"etag":              etag,
					"stored_checksum":   meta.ChecksumSHA256,
				}),
			)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "INTEGRITY_CHECK_FAILED",
			})
		}
	}

	// 7. Generate presigned download URL.
	presignedTTL := time.Duration(h.cfg.PresignedURLTTLSeconds) * time.Second
	presignedURL, err := h.s3.GeneratePresignedDownloadURL(
		ctx,
		meta.ObjectKey,
		meta.OriginalFilename,
		meta.ContentType,
		presignedTTL,
	)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "PRESIGN_FAILED")
	}

	// 8. Deduplication check: skip ZADD if destruction already scheduled.
	if meta.DestructionScheduledAt == nil {
		// 9. ZADD destroy_queue with score = redisNow + presignedURLTTL + graceSeconds.
		destroyScore := float64(redisNow) +
			float64(h.cfg.PresignedURLTTLSeconds) +
			float64(h.cfg.DestructionGraceSeconds)

		destroyJob := models.DestroyJob{
			JobID:       jobID,
			ObjectKey:   meta.ObjectKey,
			TokenHash:   tokenHash,
			Attempt:     0,
			ScheduledAt: redisNow,
		}

		jobJSON, err := json.Marshal(destroyJob)
		if err != nil {
			// Non-fatal: log but continue — the cleanup worker will handle orphans.
			h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
				audit.WithTokenHash(tokenHash),
				audit.WithObjectKey(meta.ObjectKey),
				audit.WithDetails(map[string]interface{}{
					"reason": "failed to marshal destroy job",
					"error":  err.Error(),
				}),
			)
		} else {
			if err := h.redis.ZAddWithScore(ctx, rediskeys.KeyDestroyQueue, destroyScore, string(jobJSON)); err != nil {
				// Non-fatal: log but continue.
				h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
					audit.WithTokenHash(tokenHash),
					audit.WithObjectKey(meta.ObjectKey),
					audit.WithDetails(map[string]interface{}{
						"reason": "failed to enqueue destroy job",
						"error":  err.Error(),
					}),
				)
			}
		}
	}

	// 10. Emit download_accessed audit event.
	h.audit.Emit(ctx, audit.EventDownloadAccessed, true,
		audit.WithTokenHash(tokenHash),
		audit.WithObjectKey(meta.ObjectKey),
		audit.WithRecipientIP(ip),
		audit.WithDetails(map[string]interface{}{
			"job_id": jobID,
		}),
	)

	// 11. Return 302 redirect to presigned URL.
	// Cache-control headers are already set above.
	return c.Redirect(presignedURL, fiber.StatusFound)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// hashToken computes the SHA-256 hash of the raw token and returns it as a
// lowercase hex string. This is the Token_Hash stored in Redis.
func hashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// setCacheControlNoStore sets the Cache-Control and Pragma headers to prevent
// caching of the response, as required by Requirement 9.7.
func setCacheControlNoStore(c *fiber.Ctx) {
	c.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Set("Pragma", "no-cache")
}

// isS3NotFound returns true if the error represents an S3 404 (object not found).
func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	// Check for HTTP 404 status code in the error chain.
	var apiErr interface{ HTTPStatusCode() int }
	if errors.As(err, &apiErr) && apiErr.HTTPStatusCode() == 404 {
		return true
	}
	// Also check the error message as a fallback for S3-compatible providers.
	msg := err.Error()
	return strings.Contains(msg, "404") ||
		strings.Contains(msg, "NoSuchKey") ||
		strings.Contains(msg, "NotFound")
}

// cleanupAfterMissingObject handles the race condition where the S3 object is
// missing after the CAS lock was acquired. This can happen if a previous partial
// destruction deleted the object but didn't complete Redis cleanup.
//
// Cleanup steps:
//  1. DEL token:{hash}
//  2. SETEX destroyed:{hash} 86400
//  3. DEL lock:{hash}
func (h *Handler) cleanupAfterMissingObject(ctx context.Context, tokenHash string) {
	// DEL token:{hash}
	if err := h.redis.Del(ctx, rediskeys.Token(tokenHash)); err != nil {
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithTokenHash(tokenHash),
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to DEL token key during missing object cleanup",
				"error":  err.Error(),
			}),
		)
	}

	// SETEX destroyed:{hash} 86400 — mark as destroyed to prevent replay.
	if err := h.redis.Set(ctx, rediskeys.Destroyed(tokenHash), "1", 86400*time.Second); err != nil {
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithTokenHash(tokenHash),
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to SETEX destroyed key during missing object cleanup",
				"error":  err.Error(),
			}),
		)
	}

	// DEL lock:{hash}
	if err := h.redis.Del(ctx, rediskeys.Lock(tokenHash)); err != nil {
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithTokenHash(tokenHash),
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to DEL lock key during missing object cleanup",
				"error":  err.Error(),
			}),
		)
	}

	h.audit.Emit(ctx, audit.EventFileDestroyed, true,
		audit.WithTokenHash(tokenHash),
		audit.WithDetails(map[string]interface{}{
			"reason": "object_not_found_race_condition",
		}),
	)
}

// formatObjectKey is a helper used in audit events to avoid leaking the full
// object key in error messages. Returns only the prefix portion.
func formatObjectKey(objectKey string) string {
	// Return only the ep/{YYYY}/{MM}/ prefix, not the full UUID.
	parts := strings.Split(objectKey, "/")
	if len(parts) >= 3 {
		return fmt.Sprintf("%s/%s/%s/", parts[0], parts[1], parts[2])
	}
	return objectKey
}
