package store

import (
	"context"
	"fmt"
	"time"

	"ephemeral-share/backend/internal/rediskeys"
)

// CleanStaleZSETEntries removes stale entries from all ZSET secondary indexes
// using ZREMRANGEBYSCORE. This method is intended to be called hourly by the
// cleanup worker (Task 10) to prevent unbounded ZSET growth.
//
// Stale thresholds (entries with score older than):
//   - destroy_queue:      now − 86400  (24 hours)
//   - destroy_dlq:        now − 604800 (7 days)
//   - uploads_pending:    now − 3600   (1 hour)
//   - uploads_unconfirmed: now − 3600  (1 hour)
//   - cleanup_by_expiry:  now − 86400  (24 hours)
func (r *RedisClient) CleanStaleZSETEntries(ctx context.Context) error {
	now := time.Now().Unix()

	type cleanupTarget struct {
		key       string
		maxAge    int64 // seconds
		threshold int64 // score cutoff = now - maxAge
	}

	targets := []cleanupTarget{
		{
			key:       rediskeys.KeyDestroyQueue,
			maxAge:    86400,
			threshold: now - 86400,
		},
		{
			key:       rediskeys.KeyDestroyDLQ,
			maxAge:    604800,
			threshold: now - 604800,
		},
		{
			key:       rediskeys.KeyUploadsPending,
			maxAge:    3600,
			threshold: now - 3600,
		},
		{
			key:       rediskeys.KeyUploadsUnconfirmed,
			maxAge:    3600,
			threshold: now - 3600,
		},
		{
			key:       rediskeys.KeyCleanupByExpiry,
			maxAge:    86400,
			threshold: now - 86400,
		},
	}

	var firstErr error
	for _, t := range targets {
		// ZREMRANGEBYSCORE key -inf (threshold-1)
		// Remove all entries with score strictly less than threshold.
		removed, err := r.client.ZRemRangeByScore(
			ctx,
			t.key,
			"-inf",
			fmt.Sprintf("%d", t.threshold),
		).Result()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("redis: ZREMRANGEBYSCORE %s failed: %w", t.key, err)
			}
			continue
		}
		_ = removed // caller may log this if desired
	}

	return firstErr
}
