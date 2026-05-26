// Package worker implements background goroutines for EphemeralShare's cleanup pipeline.
// It handles three responsibilities:
//  1. Destroy queue polling — dequeues and executes destruction jobs from destroy_queue ZSET.
//  2. Orphan scanning — finds and removes S3 objects with no corresponding token.
//  3. Periodic ZSET stale entry cleanup — prevents unbounded ZSET growth.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"ephemeral-share/backend/internal/audit"
	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/models"
	"ephemeral-share/backend/internal/rediskeys"
	"ephemeral-share/backend/internal/storage"
	"ephemeral-share/backend/internal/store"
)

const (
	// orphanScanInterval is how often the orphan scanner runs.
	orphanScanInterval = 15 * time.Minute

	// zsetCleanInterval is how often the ZSET stale entry cleaner runs.
	zsetCleanInterval = 1 * time.Hour

	// cleanupLockTTL is the TTL for the distributed cleanup lock.
	cleanupLockTTL = 60 * time.Second

	// destroyBaseDelaySeconds is the base delay (in seconds) for exponential backoff.
	destroyBaseDelaySeconds = 30

	// destroyedKeyTTL is the TTL for the destroyed:{hash} sentinel key.
	destroyedKeyTTL = 86400 * time.Second

	// maxGracePeriod is the maximum time a CONSUMING token is allowed before
	// the orphan scanner treats it as stale and deletes the S3 object.
	maxGracePeriod = 5 * time.Minute
)

// Worker runs the background cleanup goroutines for EphemeralShare.
type Worker struct {
	cfg   *config.Config
	redis *store.RedisClient
	s3    *storage.S3Client
	audit *audit.Logger
}

// NewWorker creates a new Worker with the given dependencies.
func NewWorker(
	cfg *config.Config,
	redis *store.RedisClient,
	s3 *storage.S3Client,
	auditLogger *audit.Logger,
) *Worker {
	return &Worker{
		cfg:   cfg,
		redis: redis,
		s3:    s3,
		audit: auditLogger,
	}
}

// Start launches all background goroutines. It returns immediately; the
// goroutines run until ctx is cancelled.
func (w *Worker) Start(ctx context.Context) {
	go w.runDestroyQueuePoller(ctx)
	go w.runOrphanScanner(ctx)
	go w.runZSETCleaner(ctx)
}

// Stop is a no-op placeholder — callers should cancel the context passed to
// Start to signal shutdown. Kept for API symmetry.
func (w *Worker) Stop() {}

// ---------------------------------------------------------------------------
// 1. Destroy queue poller
// ---------------------------------------------------------------------------

// runDestroyQueuePoller polls the destroy_queue ZSET every
// cfg.DestroyQueuePollIntervalSeconds seconds and executes due destruction jobs.
func (w *Worker) runDestroyQueuePoller(ctx context.Context) {
	interval := time.Duration(w.cfg.DestroyQueuePollIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.processDestroyQueue(ctx)
		}
	}
}

// processDestroyQueue fetches all due jobs from destroy_queue and executes them.
func (w *Worker) processDestroyQueue(ctx context.Context) {
	redisNow, err := w.redis.GetRedisServerTime(ctx)
	if err != nil {
		// Log and continue — next tick will retry.
		w.audit.Emit(ctx, audit.EventDestroyJobFailed, false,
			audit.WithDetails(map[string]interface{}{
				"error": "failed to get redis server time: " + err.Error(),
			}),
		)
		return
	}

	// ZRANGEBYSCORE destroy_queue 0 {redis_now}
	members, err := w.redis.ZRangeByScore(ctx, rediskeys.KeyDestroyQueue, 0, float64(redisNow))
	if err != nil {
		w.audit.Emit(ctx, audit.EventDestroyJobFailed, false,
			audit.WithDetails(map[string]interface{}{
				"error": "failed to range destroy_queue: " + err.Error(),
			}),
		)
		return
	}

	for _, member := range members {
		// Check for context cancellation between jobs.
		select {
		case <-ctx.Done():
			return
		default:
		}

		w.executeDestroyJob(ctx, member, redisNow)
	}
}

// executeDestroyJob parses a single destroy_queue member and runs the
// destruction pipeline, handling retries and DLQ promotion on failure.
func (w *Worker) executeDestroyJob(ctx context.Context, member string, redisNow int64) {
	var job models.DestroyJob
	if err := json.Unmarshal([]byte(member), &job); err != nil {
		// Malformed member — remove it to avoid infinite loop.
		_ = w.redis.ZRem(ctx, rediskeys.KeyDestroyQueue, member)
		w.audit.Emit(ctx, audit.EventDestroyJobFailed, false,
			audit.WithDetails(map[string]interface{}{
				"error":  "failed to parse destroy job JSON: " + err.Error(),
				"member": member,
			}),
		)
		return
	}

	// --- Execute destruction pipeline ---

	// Step 1: Delete S3 object (404 treated as success by DeleteObject).
	s3Err := w.s3.DeleteObject(ctx, job.ObjectKey)

	if s3Err != nil {
		// S3 delete failed — apply retry / DLQ logic.
		w.handleDestroyJobFailure(ctx, member, job, redisNow, s3Err)
		return
	}

	// Step 2: DEL token:{hash}
	_ = w.redis.Del(ctx, rediskeys.Token(job.TokenHash))

	// Step 3: DEL lock:{hash}
	_ = w.redis.Del(ctx, rediskeys.Lock(job.TokenHash))

	// Step 4: SETEX destroyed:{hash} 86400
	_ = w.redis.Set(ctx, rediskeys.Destroyed(job.TokenHash), "1", destroyedKeyTTL)

	// Step 5: ZREM from destroy_queue after successful pipeline.
	_ = w.redis.ZRem(ctx, rediskeys.KeyDestroyQueue, member)

	// Step 6: Emit file_destroyed audit event.
	w.audit.Emit(ctx, audit.EventFileDestroyed, true,
		audit.WithObjectKey(job.ObjectKey),
		audit.WithTokenHash(job.TokenHash),
		audit.WithDetails(map[string]interface{}{
			"job_id":  job.JobID,
			"attempt": job.Attempt,
		}),
	)
}

// handleDestroyJobFailure handles an S3 delete failure by either re-queuing
// with exponential backoff or promoting to the DLQ.
func (w *Worker) handleDestroyJobFailure(
	ctx context.Context,
	originalMember string,
	job models.DestroyJob,
	redisNow int64,
	s3Err error,
) {
	job.Attempt++

	if job.Attempt >= w.cfg.MaxDestroyRetries {
		// Max retries exceeded — move to DLQ.
		_ = w.redis.ZAddWithScore(ctx, rediskeys.KeyDestroyDLQ, float64(redisNow), originalMember)
		_ = w.redis.ZRem(ctx, rediskeys.KeyDestroyQueue, originalMember)

		w.audit.Emit(ctx, audit.EventDestroyJobDLQ, false,
			audit.WithObjectKey(job.ObjectKey),
			audit.WithTokenHash(job.TokenHash),
			audit.WithDetails(map[string]interface{}{
				"job_id":  job.JobID,
				"attempt": job.Attempt,
				"error":   s3Err.Error(),
				"level":   "CRITICAL",
			}),
		)
		return
	}

	// Compute exponential backoff score: redis_now + base_delay * 2^attempt
	backoffSeconds := int64(destroyBaseDelaySeconds) * int64(math.Pow(2, float64(job.Attempt)))
	backoffScore := float64(redisNow + backoffSeconds)

	// Re-marshal job with incremented attempt.
	newMemberBytes, err := json.Marshal(job)
	if err != nil {
		// Fallback: keep original member in queue to avoid losing the job.
		w.audit.Emit(ctx, audit.EventDestroyJobFailed, false,
			audit.WithObjectKey(job.ObjectKey),
			audit.WithTokenHash(job.TokenHash),
			audit.WithDetails(map[string]interface{}{
				"job_id": job.JobID,
				"error":  "failed to re-marshal job: " + err.Error(),
			}),
		)
		return
	}
	newMember := string(newMemberBytes)

	// Remove old entry and add new one with backoff score.
	_ = w.redis.ZRem(ctx, rediskeys.KeyDestroyQueue, originalMember)
	_ = w.redis.ZAddWithScore(ctx, rediskeys.KeyDestroyQueue, backoffScore, newMember)

	w.audit.Emit(ctx, audit.EventDestroyJobFailed, false,
		audit.WithObjectKey(job.ObjectKey),
		audit.WithTokenHash(job.TokenHash),
		audit.WithDetails(map[string]interface{}{
			"job_id":          job.JobID,
			"attempt":         job.Attempt,
			"error":           s3Err.Error(),
			"next_retry_at":   redisNow + backoffSeconds,
			"backoff_seconds": backoffSeconds,
		}),
	)
}

// ---------------------------------------------------------------------------
// 2. Orphan scanner
// ---------------------------------------------------------------------------

// runOrphanScanner runs the orphan scan cycle every 15 minutes.
// It acquires a distributed lock before each cycle to prevent duplicate work
// when multiple instances are running.
func (w *Worker) runOrphanScanner(ctx context.Context) {
	ticker := time.NewTicker(orphanScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOrphanScanCycle(ctx)
		}
	}
}

// runOrphanScanCycle acquires the distributed cleanup lock and runs one full
// orphan scan cycle. If the lock cannot be acquired, the cycle is skipped.
func (w *Worker) runOrphanScanCycle(ctx context.Context) {
	hostname, _ := os.Hostname()
	pid := strconv.Itoa(os.Getpid())
	lockValue := hostname + ":" + pid

	acquired, err := w.redis.SetNX(ctx, rediskeys.KeyCleanupLock, lockValue, cleanupLockTTL)
	if err != nil || !acquired {
		// Another instance holds the lock — skip this cycle.
		return
	}
	defer func() {
		_ = w.redis.Del(ctx, rediskeys.KeyCleanupLock)
	}()

	now := time.Now().Unix()

	// --- Process cleanup_by_expiry ---
	w.processCleanupByExpiry(ctx, now)

	// --- Process uploads_pending ---
	w.processExpiredUploads(ctx, rediskeys.KeyUploadsPending, now)

	// --- Process uploads_unconfirmed ---
	w.processExpiredUploads(ctx, rediskeys.KeyUploadsUnconfirmed, now)
}

// processCleanupByExpiry handles expired entries in the cleanup_by_expiry ZSET.
// For each expired object_key it checks whether any token still references it
// and decides whether to delete the S3 object.
func (w *Worker) processCleanupByExpiry(ctx context.Context, now int64) {
	objectKeys, err := w.redis.ZRangeByScore(ctx, rediskeys.KeyCleanupByExpiry, 0, float64(now))
	if err != nil {
		return
	}

	for _, objectKey := range objectKeys {
		select {
		case <-ctx.Done():
			return
		default:
		}

		w.processExpiredObjectKey(ctx, objectKey, now)

		// ZREM after processing regardless of outcome.
		_ = w.redis.ZRem(ctx, rediskeys.KeyCleanupByExpiry, objectKey)
	}
}

// processExpiredObjectKey checks whether an object_key is still referenced by
// a live token and deletes the S3 object if it is an orphan or stale.
func (w *Worker) processExpiredObjectKey(ctx context.Context, objectKey string, now int64) {
	// Scan token:* keys to find if any token references this object_key.
	tokenKeys, err := w.redis.ScanKeys(ctx, rediskeys.KeyPrefixToken+"*")
	if err != nil {
		return
	}

	for _, tokenKey := range tokenKeys {
		val, err := w.redis.Get(ctx, tokenKey)
		if err != nil || val == "" {
			continue
		}

		var meta models.FileMetadata
		if err := json.Unmarshal([]byte(val), &meta); err != nil {
			continue
		}

		if meta.ObjectKey != objectKey {
			continue
		}

		// Found a token referencing this object_key.
		switch meta.Status {
		case models.FileStatusConsuming:
			// If within MAX_GRACE_PERIOD, skip deletion.
			if meta.DestructionScheduledAt != nil {
				elapsed := time.Duration(now-meta.DestructionScheduledAt.Unix()) * time.Second
				if elapsed < maxGracePeriod {
					return // still within grace period
				}
			}
			// Stale CONSUMING — fall through to delete.

		case models.FileStatusActive:
			// Active token that has passed its expiry — delete.
			if meta.ExpiresAt.Unix() > now {
				return // not yet expired
			}
			// Fall through to delete.

		default:
			// DESTROYED, PENDING_UPLOAD, etc. — fall through to delete.
		}

		// Delete the S3 object.
		if err := w.s3.DeleteObject(ctx, objectKey); err == nil {
			w.audit.Emit(ctx, audit.EventOrphanCleaned, true,
				audit.WithObjectKey(objectKey),
				audit.WithDetails(map[string]interface{}{
					"reason": fmt.Sprintf("stale token status: %s", meta.Status),
				}),
			)
		}
		return
	}

	// No token found referencing this object_key — it is an orphan.
	if err := w.s3.DeleteObject(ctx, objectKey); err == nil {
		w.audit.Emit(ctx, audit.EventOrphanCleaned, true,
			audit.WithObjectKey(objectKey),
			audit.WithDetails(map[string]interface{}{
				"reason": "no token found (orphan)",
			}),
		)
	}
}

// processExpiredUploads handles expired entries in uploads_pending or
// uploads_unconfirmed ZSETs. For each expired upload_id it retrieves the
// upload session, deletes the S3 object, and removes the upload key.
func (w *Worker) processExpiredUploads(ctx context.Context, zsetKey string, now int64) {
	uploadIDs, err := w.redis.ZRangeByScore(ctx, zsetKey, 0, float64(now))
	if err != nil {
		return
	}

	for _, uploadID := range uploadIDs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		uploadKey := rediskeys.Upload(uploadID)
		val, err := w.redis.Get(ctx, uploadKey)
		if err != nil || val == "" {
			// Key already gone — just remove from ZSET.
			_ = w.redis.ZRem(ctx, zsetKey, uploadID)
			continue
		}

		var session models.UploadSession
		if err := json.Unmarshal([]byte(val), &session); err != nil {
			_ = w.redis.ZRem(ctx, zsetKey, uploadID)
			continue
		}

		// Delete the S3 object if an object key is present.
		if session.ObjectKey != "" {
			_ = w.s3.DeleteObject(ctx, session.ObjectKey)
		}

		// Remove the upload key and ZSET entry.
		_ = w.redis.Del(ctx, uploadKey)
		_ = w.redis.ZRem(ctx, zsetKey, uploadID)
	}
}

// ---------------------------------------------------------------------------
// 3. Periodic ZSET stale entry cleanup
// ---------------------------------------------------------------------------

// runZSETCleaner calls CleanStaleZSETEntries every hour to prevent unbounded
// ZSET growth across all secondary indexes.
func (w *Worker) runZSETCleaner(ctx context.Context) {
	ticker := time.NewTicker(zsetCleanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.redis.CleanStaleZSETEntries(ctx)
		}
	}
}
