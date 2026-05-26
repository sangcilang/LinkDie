// Package store provides the Redis data layer for EphemeralShare.
// It wraps go-redis/v9 with application-specific methods for token management,
// ZSET secondary indexes, and TTL enforcement.
package store

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/models"
	"ephemeral-share/backend/internal/rediskeys"
)

// ErrAlreadyConsuming is returned by CASTokenConsume when the token is already
// in CONSUMING or DESTROYED state.
var ErrAlreadyConsuming = errors.New("token already consuming or destroyed")

// luaCASTokenConsume is the atomic Lua script that transitions a token from
// ACTIVE → CONSUMING, setting destruction_scheduled_at and destroy_job_id atomically.
//
// KEYS[1] = "token:{hash}"
// ARGV[1] = current Unix timestamp as string (destruction_scheduled_at)
// ARGV[2] = UUID v4 string (destroy_job_id)
//
// Returns:
//   - nil          → token not found
//   - "ALREADY_CONSUMING" → token is CONSUMING or DESTROYED
//   - JSON string  → updated metadata (after ACTIVE → CONSUMING transition)
var luaCASTokenConsume = redis.NewScript(`
local meta_str = redis.call('GET', KEYS[1])
if not meta_str then return nil end
local meta = cjson.decode(meta_str)
if meta.status == 'CONSUMING' or meta.status == 'DESTROYED' then
  return 'ALREADY_CONSUMING'
end
meta.status = 'CONSUMING'
meta.destruction_scheduled_at = tonumber(ARGV[1])
meta.destroy_job_id = ARGV[2]
local updated = cjson.encode(meta)
redis.call('SET', KEYS[1], updated)
return updated
`)

// RedisClient wraps a go-redis client with application-specific methods.
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis client using the provided configuration.
// Connection pooling is handled by go-redis defaults (10 connections per CPU).
func NewRedisClient(cfg *config.Config) (*RedisClient, error) {
	opts := &redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	}

	if cfg.RedisTLSEnabled {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := redis.NewClient(opts)

	// Verify connectivity at startup.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis: failed to connect to %s: %w", cfg.RedisAddr, err)
	}

	return &RedisClient{client: client}, nil
}

// Close closes the underlying Redis connection pool.
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// HealthCheck pings Redis and returns an error if the server is unreachable.
func (r *RedisClient) HealthCheck(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// GetRedisServerTime returns the current Unix timestamp in seconds from the
// Redis server using the TIME command. This avoids NTP clock skew between
// application instances when computing grace period scores for destroy_queue.
func (r *RedisClient) GetRedisServerTime(ctx context.Context) (int64, error) {
	t, err := r.client.Time(ctx).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: TIME command failed: %w", err)
	}
	return t.Unix(), nil
}

// ---------------------------------------------------------------------------
// Token state machine
// ---------------------------------------------------------------------------

// casTokenResult is an intermediate struct used to unmarshal the JSON returned
// by the Lua CAS script. The Lua script stores destruction_scheduled_at as a
// Unix timestamp integer, which differs from the time.Time JSON format used by
// models.FileMetadata. We unmarshal into this struct first, then convert.
type casTokenResult struct {
	ObjectKey              string     `json:"object_key"`
	OriginalFilename       string     `json:"original_filename"`
	ContentType            string     `json:"content_type"`
	SizeBytes              int64      `json:"size_bytes"`
	UploadedAt             time.Time  `json:"uploaded_at"`
	ExpiresAt              time.Time  `json:"expires_at"`
	MaxDownloads           int        `json:"max_downloads"`
	DownloadCount          int        `json:"download_count"`
	ChecksumSHA256         string     `json:"checksum_sha256"`
	AdminNote              string     `json:"admin_note,omitempty"`
	Status                 string     `json:"status"`
	// destruction_scheduled_at is stored as a Unix timestamp integer by the Lua script.
	DestructionScheduledAt *int64     `json:"destruction_scheduled_at,omitempty"`
	DestroyJobID           string     `json:"destroy_job_id,omitempty"`
}

// CASTokenConsume atomically transitions a token from ACTIVE → CONSUMING using
// the Lua CAS script. It sets destruction_scheduled_at to now and destroy_job_id
// to the provided UUID v4 jobID.
//
// Returns:
//   - metadata, false, nil  → transition succeeded; metadata contains updated fields
//   - nil, true, nil        → token is already CONSUMING or DESTROYED
//   - nil, false, err       → token not found or Redis error
func (r *RedisClient) CASTokenConsume(
	ctx context.Context,
	tokenHash string,
	now int64,
	jobID string,
) (metadata *models.FileMetadata, alreadyConsuming bool, err error) {
	key := rediskeys.Token(tokenHash)

	result, err := luaCASTokenConsume.Run(
		ctx,
		r.client,
		[]string{key},
		fmt.Sprintf("%d", now),
		jobID,
	).Result()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Token not found.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("redis: CAS token consume script failed: %w", err)
	}

	str, ok := result.(string)
	if !ok {
		// Nil result from Lua means token not found.
		return nil, false, nil
	}

	if str == "ALREADY_CONSUMING" {
		return nil, true, nil
	}

	// The Lua script stores destruction_scheduled_at as a Unix timestamp integer.
	// Unmarshal via the intermediate struct, then convert to models.FileMetadata.
	var raw casTokenResult
	if err := json.Unmarshal([]byte(str), &raw); err != nil {
		return nil, false, fmt.Errorf("redis: failed to unmarshal token metadata: %w", err)
	}

	meta := &models.FileMetadata{
		ObjectKey:        raw.ObjectKey,
		OriginalFilename: raw.OriginalFilename,
		ContentType:      raw.ContentType,
		SizeBytes:        raw.SizeBytes,
		UploadedAt:       raw.UploadedAt,
		ExpiresAt:        raw.ExpiresAt,
		MaxDownloads:     raw.MaxDownloads,
		DownloadCount:    raw.DownloadCount,
		ChecksumSHA256:   raw.ChecksumSHA256,
		AdminNote:        raw.AdminNote,
		Status:           models.FileStatus(raw.Status),
		DestroyJobID:     raw.DestroyJobID,
	}

	if raw.DestructionScheduledAt != nil {
		t := time.Unix(*raw.DestructionScheduledAt, 0).UTC()
		meta.DestructionScheduledAt = &t
	}

	return meta, false, nil
}

// ---------------------------------------------------------------------------
// ZSET secondary index helpers
// ---------------------------------------------------------------------------

// ZAddWithScore adds a member with the given score to a sorted set.
func (r *RedisClient) ZAddWithScore(ctx context.Context, key string, score float64, member string) error {
	return r.client.ZAdd(ctx, key, redis.Z{
		Score:  score,
		Member: member,
	}).Err()
}

// ZRangeByScore returns all members in a sorted set with scores between min and max (inclusive).
func (r *RedisClient) ZRangeByScore(ctx context.Context, key string, min, max float64) ([]string, error) {
	return r.client.ZRangeByScore(ctx, key, &redis.ZRangeBy{
		Min: fmt.Sprintf("%g", min),
		Max: fmt.Sprintf("%g", max),
	}).Result()
}

// ZRangeByScoreWithScores returns all members and their scores in a sorted set
// with scores between min and max (inclusive).
func (r *RedisClient) ZRangeByScoreWithScores(ctx context.Context, key string, min, max float64) ([]redis.Z, error) {
	return r.client.ZRangeByScoreWithScores(ctx, key, &redis.ZRangeBy{
		Min: fmt.Sprintf("%g", min),
		Max: fmt.Sprintf("%g", max),
	}).Result()
}

// ZRem removes one or more members from a sorted set.
func (r *RedisClient) ZRem(ctx context.Context, key string, members ...string) error {
	ifaces := make([]interface{}, len(members))
	for i, m := range members {
		ifaces[i] = m
	}
	return r.client.ZRem(ctx, key, ifaces...).Err()
}

// ZCard returns the number of members in a sorted set.
func (r *RedisClient) ZCard(ctx context.Context, key string) (int64, error) {
	return r.client.ZCard(ctx, key).Result()
}

// ---------------------------------------------------------------------------
// Explicit TTL enforcement helpers
// ---------------------------------------------------------------------------

// IncrEnumCounter increments the token enumeration counter for an IP and sets
// the TTL to 3600 seconds (1 hour) on each increment.
// Returns the new counter value.
func (r *RedisClient) IncrEnumCounter(ctx context.Context, ip string) (int64, error) {
	key := rediskeys.Enum(ip)
	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 3600*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis: failed to increment enum counter for %s: %w", ip, err)
	}
	return incrCmd.Val(), nil
}

// IncrFailedCounter increments the failed login counter for an IP and sets
// the TTL to 600 seconds (10 minutes) on each increment.
// Returns the new counter value.
func (r *RedisClient) IncrFailedCounter(ctx context.Context, ip string) (int64, error) {
	key := rediskeys.Failed(ip)
	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 600*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis: failed to increment failed counter for %s: %w", ip, err)
	}
	return incrCmd.Val(), nil
}

// IncrQuotaUploads increments the daily upload count quota for the given date
// (format: YYYY-MM-DD) and sets EXPIREAT to midnight of that date.
// Returns the new counter value.
func (r *RedisClient) IncrQuotaUploads(ctx context.Context, date string) (int64, error) {
	key := rediskeys.QuotaUploads(date)
	midnight := nextMidnight(date)
	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.ExpireAt(ctx, key, midnight)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis: failed to increment quota uploads for %s: %w", date, err)
	}
	return incrCmd.Val(), nil
}

// IncrByQuotaBytes increments the daily bytes quota for the given date
// (format: YYYY-MM-DD) by delta and sets EXPIREAT to midnight of that date.
// Returns the new counter value.
func (r *RedisClient) IncrByQuotaBytes(ctx context.Context, date string, delta int64) (int64, error) {
	key := rediskeys.QuotaBytes(date)
	midnight := nextMidnight(date)
	pipe := r.client.Pipeline()
	incrCmd := pipe.IncrBy(ctx, key, delta)
	pipe.ExpireAt(ctx, key, midnight)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis: failed to increment quota bytes for %s: %w", date, err)
	}
	return incrCmd.Val(), nil
}

// nextMidnight returns the time.Time for midnight (00:00:00 UTC) of the day
// following the given date string (format: YYYY-MM-DD).
func nextMidnight(date string) time.Time {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		// Fallback: midnight tomorrow UTC.
		now := time.Now().UTC()
		return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	}
	return time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
}

// ---------------------------------------------------------------------------
// Generic key helpers (used by other services)
// ---------------------------------------------------------------------------

// Get retrieves the string value for a key. Returns ("", nil) if not found.
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return val, err
}

// Set sets a key to a string value with an optional TTL (0 = no expiry).
func (r *RedisClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

// SetNX sets a key only if it does not already exist. Returns true if set.
func (r *RedisClient) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, ttl).Result()
}

// Del deletes one or more keys.
func (r *RedisClient) Del(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// Incr increments a key by 1 and returns the new value.
func (r *RedisClient) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// Expire sets the TTL on a key.
func (r *RedisClient) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return r.client.Expire(ctx, key, ttl).Err()
}

// SAdd adds members to a set.
func (r *RedisClient) SAdd(ctx context.Context, key string, members ...string) error {
	ifaces := make([]interface{}, len(members))
	for i, m := range members {
		ifaces[i] = m
	}
	return r.client.SAdd(ctx, key, ifaces...).Err()
}

// SRem removes members from a set.
func (r *RedisClient) SRem(ctx context.Context, key string, members ...string) error {
	ifaces := make([]interface{}, len(members))
	for i, m := range members {
		ifaces[i] = m
	}
	return r.client.SRem(ctx, key, ifaces...).Err()
}

// ScanKeys returns all Redis keys matching the given pattern using SCAN cursor iteration.
// This is acceptable for MVP admin token listing (low cardinality expected).
func (r *RedisClient) ScanKeys(ctx context.Context, pattern string) ([]string, error) {
	var keys []string
	var cursor uint64

	for {
		var batch []string
		var err error
		batch, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("redis: SCAN failed for pattern %q: %w", pattern, err)
		}
		keys = append(keys, batch...)
		if cursor == 0 {
			break
		}
	}

	return keys, nil
}
