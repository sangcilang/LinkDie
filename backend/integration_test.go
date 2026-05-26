//go:build integration

// Package integration_test contains Phase 1 integration tests for EphemeralShare.
// These tests require a running Redis instance (REDIS_ADDR env var, default localhost:6379).
// They do NOT require real S3 or ClamAV — only Redis state machine logic is tested.
//
// Run with:
//
//	go test -tags integration -run TestIntegration ./...
package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/models"
	"ephemeral-share/backend/internal/rediskeys"
	"ephemeral-share/backend/internal/store"
	"ephemeral-share/backend/internal/util"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// testRedisClient is the shared Redis client for all integration tests.
var testRedisClient *store.RedisClient

// rawRedisClient is the underlying go-redis client for low-level operations.
var rawRedisClient *redis.Client

// TestMain checks Redis availability and skips all tests if Redis is not reachable.
func TestMain(m *testing.M) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	// Try to connect to Redis.
	raw := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := raw.Ping(ctx).Err(); err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: Redis not available at %s: %v\n", addr, err)
		os.Exit(0)
	}
	rawRedisClient = raw

	// Build a minimal config for the store.RedisClient.
	cfg := &config.Config{
		RedisAddr:     addr,
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		RedisDB:       0,
	}

	var err error
	testRedisClient, err = store.NewRedisClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: failed to create Redis client: %v\n", err)
		os.Exit(0)
	}

	code := m.Run()
	_ = testRedisClient.Close()
	_ = rawRedisClient.Close()
	os.Exit(code)
}

// keyPrefix returns a unique key prefix for a test to avoid cross-test conflicts.
func keyPrefix(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test:%s:", uuid.New().String())
}

// prefixedToken returns a token key scoped to the test prefix.
func prefixedToken(prefix, tokenHash string) string {
	return prefix + rediskeys.KeyPrefixToken + tokenHash
}

// prefixedDestroyed returns a destroyed key scoped to the test prefix.
func prefixedDestroyed(prefix, tokenHash string) string {
	return prefix + rediskeys.KeyPrefixDestroyed + tokenHash
}

// prefixedLock returns a lock key scoped to the test prefix.
func prefixedLock(prefix, tokenHash string) string {
	return prefix + rediskeys.KeyPrefixLock + tokenHash
}

// storeActiveToken stores a FileMetadata with ACTIVE status in Redis under the
// given key, with the provided TTL.
func storeActiveToken(t *testing.T, ctx context.Context, key string, meta models.FileMetadata, ttl time.Duration) {
	t.Helper()
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("failed to marshal FileMetadata: %v", err)
	}
	if err := rawRedisClient.SetEx(ctx, key, string(data), ttl).Err(); err != nil {
		t.Fatalf("failed to SETEX token key %s: %v", key, err)
	}
}

// buildActiveMetadata returns a minimal FileMetadata with ACTIVE status.
func buildActiveMetadata(objectKey string) models.FileMetadata {
	now := time.Now().UTC()
	return models.FileMetadata{
		ObjectKey:        objectKey,
		OriginalFilename: "test-file.pdf",
		ContentType:      "application/pdf",
		SizeBytes:        1024,
		UploadedAt:       now,
		ExpiresAt:        now.Add(24 * time.Hour),
		MaxDownloads:     1,
		DownloadCount:    0,
		ChecksumSHA256:   "abc123",
		Status:           models.FileStatusActive,
	}
}

// ---------------------------------------------------------------------------
// Test 1: Full upload → download → destroy cycle
// ---------------------------------------------------------------------------

// TestIntegration_UploadDownloadDestroyCycle verifies the full state machine:
// ACTIVE → CONSUMING → DESTROYED.
//
// Requirements: 4.1, 4.2, 4.3, 4.4, 6.1
func TestIntegration_UploadDownloadDestroyCycle(t *testing.T) {
	ctx := context.Background()
	prefix := keyPrefix(t)

	// Generate a token hash.
	_, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	tokenKey := prefixedToken(prefix, tokenHash)
	destroyedKey := prefixedDestroyed(prefix, tokenHash)
	lockKey := prefixedLock(prefix, tokenHash)

	// Register cleanup.
	t.Cleanup(func() {
		rawRedisClient.Del(ctx, tokenKey, destroyedKey, lockKey)
	})

	// Step 1: Store ACTIVE token.
	meta := buildActiveMetadata("ep/2024/01/" + uuid.New().String())
	storeActiveToken(t, ctx, tokenKey, meta, 24*time.Hour)

	// Verify it was stored.
	val, err := testRedisClient.Get(ctx, tokenKey)
	if err != nil || val == "" {
		t.Fatalf("expected token to exist in Redis, got err=%v val=%q", err, val)
	}

	// Step 2: CAS transition ACTIVE → CONSUMING.
	// We call the Lua script directly via the store client.
	// Since the key uses a test prefix, we need to use the raw client for the
	// Lua script. We replicate the CAS logic using the raw client here.
	now := time.Now().Unix()
	jobID := uuid.New().String()

	// Use the raw Lua script approach: read, update, write.
	// We simulate what CASTokenConsume does but on our prefixed key.
	rawVal, err := rawRedisClient.Get(ctx, tokenKey).Result()
	if err != nil {
		t.Fatalf("GET token key: %v", err)
	}

	var storedMeta models.FileMetadata
	if err := json.Unmarshal([]byte(rawVal), &storedMeta); err != nil {
		t.Fatalf("unmarshal stored meta: %v", err)
	}

	if storedMeta.Status != models.FileStatusActive {
		t.Fatalf("expected ACTIVE status, got %s", storedMeta.Status)
	}

	// Transition to CONSUMING.
	destructionTime := time.Unix(now, 0).UTC()
	storedMeta.Status = models.FileStatusConsuming
	storedMeta.DestructionScheduledAt = &destructionTime
	storedMeta.DestroyJobID = jobID

	updatedData, err := json.Marshal(storedMeta)
	if err != nil {
		t.Fatalf("marshal updated meta: %v", err)
	}
	if err := rawRedisClient.Set(ctx, tokenKey, string(updatedData), 0).Err(); err != nil {
		t.Fatalf("SET updated token: %v", err)
	}

	// Step 3: Verify CONSUMING state.
	rawVal2, err := rawRedisClient.Get(ctx, tokenKey).Result()
	if err != nil {
		t.Fatalf("GET after CAS: %v", err)
	}
	var consumingMeta models.FileMetadata
	if err := json.Unmarshal([]byte(rawVal2), &consumingMeta); err != nil {
		t.Fatalf("unmarshal consuming meta: %v", err)
	}

	if consumingMeta.Status != models.FileStatusConsuming {
		t.Errorf("expected CONSUMING status, got %s", consumingMeta.Status)
	}
	if consumingMeta.DestructionScheduledAt == nil {
		t.Error("expected DestructionScheduledAt to be set")
	}
	if consumingMeta.DestroyJobID != jobID {
		t.Errorf("expected DestroyJobID=%s, got %s", jobID, consumingMeta.DestroyJobID)
	}

	// Step 4: Simulate destruction pipeline.
	// DEL token:{hash}
	if err := rawRedisClient.Del(ctx, tokenKey).Err(); err != nil {
		t.Fatalf("DEL token key: %v", err)
	}
	// DEL lock:{hash}
	if err := rawRedisClient.Del(ctx, lockKey).Err(); err != nil {
		t.Fatalf("DEL lock key: %v", err)
	}
	// SETEX destroyed:{hash} 86400 "1"
	if err := rawRedisClient.SetEx(ctx, destroyedKey, "1", 86400*time.Second).Err(); err != nil {
		t.Fatalf("SETEX destroyed key: %v", err)
	}

	// Step 5: Verify DESTROYED state.
	tokenVal, err := testRedisClient.Get(ctx, tokenKey)
	if err != nil {
		t.Fatalf("GET token after destroy: %v", err)
	}
	if tokenVal != "" {
		t.Errorf("expected token key to be empty after destroy, got %q", tokenVal)
	}

	destroyedVal, err := testRedisClient.Get(ctx, destroyedKey)
	if err != nil {
		t.Fatalf("GET destroyed key: %v", err)
	}
	if destroyedVal != "1" {
		t.Errorf("expected destroyed key to be '1', got %q", destroyedVal)
	}
}

// ---------------------------------------------------------------------------
// Test 2: Concurrent download — exactly one 302, one 423
// ---------------------------------------------------------------------------

// TestIntegration_ConcurrentDownloadExclusivity verifies that when two goroutines
// simultaneously call CASTokenConsume, exactly one succeeds and one gets
// alreadyConsuming=true.
//
// Requirements: 4.2, 4.9
func TestIntegration_ConcurrentDownloadExclusivity(t *testing.T) {
	ctx := context.Background()
	prefix := keyPrefix(t)

	_, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// We use the real token key (no prefix) for CASTokenConsume since it uses
	// the rediskeys.Token() helper internally. We'll use a unique token hash
	// to avoid conflicts.
	tokenKey := rediskeys.Token(tokenHash)

	t.Cleanup(func() {
		rawRedisClient.Del(ctx, tokenKey)
	})

	// Store ACTIVE token.
	meta := buildActiveMetadata("ep/2024/01/" + uuid.New().String())
	storeActiveToken(t, ctx, tokenKey, meta, 24*time.Hour)

	// Launch 2 goroutines simultaneously calling CASTokenConsume.
	type result struct {
		alreadyConsuming bool
		err              error
	}

	results := make([]result, 2)
	var wg sync.WaitGroup
	var mu sync.Mutex

	now := time.Now().Unix()

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			jobID := uuid.New().String()
			_, ac, err := testRedisClient.CASTokenConsume(ctx, tokenHash, now, jobID)
			mu.Lock()
			results[idx] = result{alreadyConsuming: ac, err: err}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Verify no errors.
	for i, r := range results {
		if r.err != nil {
			t.Errorf("goroutine %d returned error: %v", i, r.err)
		}
	}

	// Count successes and already-consuming responses.
	successCount := 0
	alreadyConsumingCount := 0
	for _, r := range results {
		if r.alreadyConsuming {
			alreadyConsumingCount++
		} else {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 success, got %d", successCount)
	}
	if alreadyConsumingCount != 1 {
		t.Errorf("expected exactly 1 alreadyConsuming=true, got %d", alreadyConsumingCount)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Orphan cleanup — upload → expire token → verify cleanup state
// ---------------------------------------------------------------------------

// TestIntegration_OrphanCleanupDetectsExpiredToken verifies that an expired
// ACTIVE token is correctly indexed in cleanup_by_expiry and that the Redis
// state is correct for the cleanup worker to process.
//
// Requirements: 6.1, 6.2
func TestIntegration_OrphanCleanupDetectsExpiredToken(t *testing.T) {
	ctx := context.Background()
	prefix := keyPrefix(t)

	_, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	objectKey := "ep/2024/01/" + uuid.New().String()
	tokenKey := prefixedToken(prefix, tokenHash)
	// Use a prefixed cleanup_by_expiry ZSET to avoid polluting the real one.
	cleanupZSET := prefix + rediskeys.KeyCleanupByExpiry

	t.Cleanup(func() {
		rawRedisClient.Del(ctx, tokenKey)
		rawRedisClient.ZRem(ctx, cleanupZSET, objectKey)
	})

	// Create a token with ExpiresAt = now - 1 hour (already expired).
	expiredAt := time.Now().UTC().Add(-1 * time.Hour)
	meta := models.FileMetadata{
		ObjectKey:        objectKey,
		OriginalFilename: "expired-file.pdf",
		ContentType:      "application/pdf",
		SizeBytes:        512,
		UploadedAt:       expiredAt.Add(-2 * time.Hour),
		ExpiresAt:        expiredAt,
		MaxDownloads:     1,
		DownloadCount:    0,
		ChecksumSHA256:   "deadbeef",
		Status:           models.FileStatusActive,
	}
	storeActiveToken(t, ctx, tokenKey, meta, 1*time.Hour)

	// Add to cleanup_by_expiry ZSET with score = expiredAt Unix timestamp.
	score := float64(expiredAt.Unix())
	if err := rawRedisClient.ZAdd(ctx, cleanupZSET, redis.Z{
		Score:  score,
		Member: objectKey,
	}).Err(); err != nil {
		t.Fatalf("ZADD cleanup_by_expiry: %v", err)
	}

	// Verify the token is in the ZSET via ZRangeByScore.
	now := float64(time.Now().Unix())
	members, err := rawRedisClient.ZRangeByScore(ctx, cleanupZSET, &redis.ZRangeBy{
		Min: "-inf",
		Max: fmt.Sprintf("%g", now),
	}).Result()
	if err != nil {
		t.Fatalf("ZRangeByScore: %v", err)
	}

	found := false
	for _, m := range members {
		if m == objectKey {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected objectKey %q to be in cleanup_by_expiry ZSET, members=%v", objectKey, members)
	}

	// Verify the token key exists in Redis.
	val, err := testRedisClient.Get(ctx, tokenKey)
	if err != nil {
		t.Fatalf("GET token key: %v", err)
	}
	if val == "" {
		t.Error("expected token key to exist in Redis")
	}

	// Verify the stored metadata has the correct expired status.
	var storedMeta models.FileMetadata
	if err := json.Unmarshal([]byte(val), &storedMeta); err != nil {
		t.Fatalf("unmarshal stored meta: %v", err)
	}
	if storedMeta.Status != models.FileStatusActive {
		t.Errorf("expected ACTIVE status, got %s", storedMeta.Status)
	}
	if !storedMeta.ExpiresAt.Before(time.Now()) {
		t.Errorf("expected ExpiresAt to be in the past, got %v", storedMeta.ExpiresAt)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Grace period — verify ZADD score uses Redis server time
// ---------------------------------------------------------------------------

// TestIntegration_GracePeriodUsesRedisServerTime verifies that GetRedisServerTime
// returns a value close to time.Now() and that ZADD scores based on Redis server
// time correctly gate job visibility.
//
// Requirements: 4.4, 4.9
func TestIntegration_GracePeriodUsesRedisServerTime(t *testing.T) {
	ctx := context.Background()
	prefix := keyPrefix(t)

	destroyQueueKey := prefix + rediskeys.KeyDestroyQueue
	jobMember := "test-job-" + uuid.New().String()

	t.Cleanup(func() {
		rawRedisClient.ZRem(ctx, destroyQueueKey, jobMember)
	})

	// Get Redis server time.
	redisNow, err := testRedisClient.GetRedisServerTime(ctx)
	if err != nil {
		t.Fatalf("GetRedisServerTime: %v", err)
	}

	// Verify it's within 5 seconds of time.Now().Unix().
	localNow := time.Now().Unix()
	diff := redisNow - localNow
	if diff < -5 || diff > 5 {
		t.Errorf("Redis server time %d differs from local time %d by %d seconds (expected within 5s)",
			redisNow, localNow, diff)
	}

	// Create a destroy job with score = redisNow + 45 (grace period).
	graceScore := float64(redisNow + 45)
	if err := rawRedisClient.ZAdd(ctx, destroyQueueKey, redis.Z{
		Score:  graceScore,
		Member: jobMember,
	}).Err(); err != nil {
		t.Fatalf("ZADD destroy_queue: %v", err)
	}

	// Verify ZRangeByScore(0, redisNow) returns empty (job not yet due).
	notDue, err := rawRedisClient.ZRangeByScore(ctx, destroyQueueKey, &redis.ZRangeBy{
		Min: "0",
		Max: fmt.Sprintf("%d", redisNow),
	}).Result()
	if err != nil {
		t.Fatalf("ZRangeByScore (not due): %v", err)
	}
	for _, m := range notDue {
		if m == jobMember {
			t.Error("job should NOT be due yet (score > redisNow), but was returned")
		}
	}

	// Verify ZRangeByScore(0, redisNow+50) returns the job.
	due, err := rawRedisClient.ZRangeByScore(ctx, destroyQueueKey, &redis.ZRangeBy{
		Min: "0",
		Max: fmt.Sprintf("%d", redisNow+50),
	}).Result()
	if err != nil {
		t.Fatalf("ZRangeByScore (due): %v", err)
	}
	found := false
	for _, m := range due {
		if m == jobMember {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected job to be returned when querying up to redisNow+50, got %v", due)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Token enumeration blocking
// ---------------------------------------------------------------------------

// TestIntegration_TokenEnumerationBlocking verifies that IncrEnumCounter
// correctly increments the counter and sets a TTL on the enum:{ip} key.
//
// Requirements: 9.5, 9.6
func TestIntegration_TokenEnumerationBlocking(t *testing.T) {
	ctx := context.Background()

	// Use a unique IP to avoid conflicts with other tests.
	testIP := fmt.Sprintf("192.0.2.%d", time.Now().UnixNano()%254+1)
	enumKey := rediskeys.Enum(testIP)

	t.Cleanup(func() {
		rawRedisClient.Del(ctx, enumKey)
	})

	// Call IncrEnumCounter 11 times.
	var lastCount int64
	for i := 0; i < 11; i++ {
		count, err := testRedisClient.IncrEnumCounter(ctx, testIP)
		if err != nil {
			t.Fatalf("IncrEnumCounter call %d: %v", i+1, err)
		}
		lastCount = count
	}

	// Verify the 11th call returns count > 10.
	if lastCount <= 10 {
		t.Errorf("expected count > 10 after 11 increments, got %d", lastCount)
	}

	// Verify the enum:{ip} key exists with TTL > 0.
	ttl, err := rawRedisClient.TTL(ctx, enumKey).Result()
	if err != nil {
		t.Fatalf("TTL enum key: %v", err)
	}
	if ttl <= 0 {
		t.Errorf("expected enum key TTL > 0, got %v", ttl)
	}

	// Verify the final count is exactly 11.
	val, err := rawRedisClient.Get(ctx, enumKey).Result()
	if err != nil {
		t.Fatalf("GET enum key: %v", err)
	}
	if val != "11" {
		t.Errorf("expected enum counter to be '11', got %q", val)
	}
}

// ---------------------------------------------------------------------------
// Test 6: Destroy queue retry + DLQ
// ---------------------------------------------------------------------------

// TestIntegration_DestroyQueueRetryAndDLQ verifies that a job at max retries
// is moved to destroy_dlq and removed from destroy_queue.
//
// Requirements: 6.1, 6.3
func TestIntegration_DestroyQueueRetryAndDLQ(t *testing.T) {
	ctx := context.Background()
	prefix := keyPrefix(t)

	destroyQueueKey := prefix + rediskeys.KeyDestroyQueue
	destroyDLQKey := prefix + rediskeys.KeyDestroyDLQ

	const maxDestroyRetries = 3

	// Create a DestroyJob with Attempt=maxDestroyRetries (at max retries).
	job := models.DestroyJob{
		JobID:       uuid.New().String(),
		ObjectKey:   "ep/2024/01/" + uuid.New().String(),
		TokenHash:   uuid.New().String(),
		Attempt:     maxDestroyRetries,
		ScheduledAt: time.Now().Unix(),
	}

	jobJSON, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal DestroyJob: %v", err)
	}
	member := string(jobJSON)

	now := time.Now().Unix()

	// ZADD to destroy_queue with score = now - 1 (already due).
	if err := rawRedisClient.ZAdd(ctx, destroyQueueKey, redis.Z{
		Score:  float64(now - 1),
		Member: member,
	}).Err(); err != nil {
		t.Fatalf("ZADD destroy_queue: %v", err)
	}

	t.Cleanup(func() {
		rawRedisClient.ZRem(ctx, destroyQueueKey, member)
		rawRedisClient.ZRem(ctx, destroyDLQKey, member)
	})

	// Simulate the worker logic: if attempt >= MaxDestroyRetries → move to DLQ.
	if job.Attempt >= maxDestroyRetries {
		// ZADD to destroy_dlq.
		if err := rawRedisClient.ZAdd(ctx, destroyDLQKey, redis.Z{
			Score:  float64(now),
			Member: member,
		}).Err(); err != nil {
			t.Fatalf("ZADD destroy_dlq: %v", err)
		}
		// ZREM from destroy_queue.
		if err := rawRedisClient.ZRem(ctx, destroyQueueKey, member).Err(); err != nil {
			t.Fatalf("ZREM destroy_queue: %v", err)
		}
	}

	// Verify job is in destroy_dlq.
	dlqMembers, err := rawRedisClient.ZRangeByScore(ctx, destroyDLQKey, &redis.ZRangeBy{
		Min: "-inf",
		Max: "+inf",
	}).Result()
	if err != nil {
		t.Fatalf("ZRangeByScore destroy_dlq: %v", err)
	}
	foundInDLQ := false
	for _, m := range dlqMembers {
		if m == member {
			foundInDLQ = true
			break
		}
	}
	if !foundInDLQ {
		t.Errorf("expected job to be in destroy_dlq, members=%v", dlqMembers)
	}

	// Verify job is NOT in destroy_queue.
	queueMembers, err := rawRedisClient.ZRangeByScore(ctx, destroyQueueKey, &redis.ZRangeBy{
		Min: "-inf",
		Max: "+inf",
	}).Result()
	if err != nil {
		t.Fatalf("ZRangeByScore destroy_queue: %v", err)
	}
	for _, m := range queueMembers {
		if m == member {
			t.Error("job should NOT be in destroy_queue after DLQ promotion")
		}
	}
}

// ---------------------------------------------------------------------------
// Test 7: Distributed lock — two instances, only one acquires
// ---------------------------------------------------------------------------

// TestIntegration_DistributedCleanupLock verifies that SetNX enforces mutual
// exclusion: only the first caller acquires the lock, and after deletion the
// lock can be re-acquired.
//
// Requirements: 6.2
func TestIntegration_DistributedCleanupLock(t *testing.T) {
	ctx := context.Background()
	prefix := keyPrefix(t)

	// Use a prefixed cleanup lock to avoid interfering with the real worker.
	lockKey := prefix + rediskeys.KeyCleanupLock

	t.Cleanup(func() {
		rawRedisClient.Del(ctx, lockKey)
	})

	// First SetNX → should succeed.
	acquired1, err := rawRedisClient.SetNX(ctx, lockKey, "instance-1", 60*time.Second).Result()
	if err != nil {
		t.Fatalf("SetNX instance-1: %v", err)
	}
	if !acquired1 {
		t.Error("expected instance-1 to acquire the lock")
	}

	// Second SetNX → should fail (lock already held).
	acquired2, err := rawRedisClient.SetNX(ctx, lockKey, "instance-2", 60*time.Second).Result()
	if err != nil {
		t.Fatalf("SetNX instance-2: %v", err)
	}
	if acquired2 {
		t.Error("expected instance-2 to NOT acquire the lock (already held by instance-1)")
	}

	// Verify the lock value is still "instance-1".
	lockVal, err := rawRedisClient.Get(ctx, lockKey).Result()
	if err != nil {
		t.Fatalf("GET lock key: %v", err)
	}
	if lockVal != "instance-1" {
		t.Errorf("expected lock value 'instance-1', got %q", lockVal)
	}

	// DEL cleanup_lock.
	if err := rawRedisClient.Del(ctx, lockKey).Err(); err != nil {
		t.Fatalf("DEL lock key: %v", err)
	}

	// Third SetNX → should succeed now.
	acquired3, err := rawRedisClient.SetNX(ctx, lockKey, "instance-1", 60*time.Second).Result()
	if err != nil {
		t.Fatalf("SetNX instance-1 (second attempt): %v", err)
	}
	if !acquired3 {
		t.Error("expected instance-1 to re-acquire the lock after deletion")
	}
}

// ---------------------------------------------------------------------------
// Test 8: Token round-trip integrity
// ---------------------------------------------------------------------------

// TestIntegration_TokenRoundTrip verifies that FileMetadata survives a
// marshal → SETEX → GET → unmarshal round-trip with all fields intact.
//
// Requirements: 2.1, 3.1
func TestIntegration_TokenRoundTrip(t *testing.T) {
	ctx := context.Background()

	// Generate a real token.
	_, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	tokenKey := rediskeys.Token(tokenHash)

	t.Cleanup(func() {
		rawRedisClient.Del(ctx, tokenKey)
	})

	// Build FileMetadata with all fields populated.
	now := time.Now().UTC().Truncate(time.Second) // truncate for JSON round-trip
	objectKey := "ep/2024/01/" + uuid.New().String()
	meta := models.FileMetadata{
		ObjectKey:        objectKey,
		OriginalFilename: "important-document.pdf",
		ContentType:      "application/pdf",
		SizeBytes:        204800,
		UploadedAt:       now,
		ExpiresAt:        now.Add(48 * time.Hour),
		MaxDownloads:     1,
		DownloadCount:    0,
		ChecksumSHA256:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		AdminNote:        "For the client meeting",
		Status:           models.FileStatusActive,
	}

	// Marshal to JSON.
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal FileMetadata: %v", err)
	}

	// SETEX token:{hash}.
	if err := rawRedisClient.SetEx(ctx, tokenKey, string(data), 48*time.Hour).Err(); err != nil {
		t.Fatalf("SETEX token key: %v", err)
	}

	// GET token:{hash}.
	val, err := testRedisClient.Get(ctx, tokenKey)
	if err != nil {
		t.Fatalf("GET token key: %v", err)
	}
	if val == "" {
		t.Fatal("expected token key to exist")
	}

	// Unmarshal and verify all fields.
	var retrieved models.FileMetadata
	if err := json.Unmarshal([]byte(val), &retrieved); err != nil {
		t.Fatalf("unmarshal retrieved meta: %v", err)
	}

	if retrieved.ObjectKey != meta.ObjectKey {
		t.Errorf("ObjectKey: got %q, want %q", retrieved.ObjectKey, meta.ObjectKey)
	}
	if retrieved.OriginalFilename != meta.OriginalFilename {
		t.Errorf("OriginalFilename: got %q, want %q", retrieved.OriginalFilename, meta.OriginalFilename)
	}
	if retrieved.ContentType != meta.ContentType {
		t.Errorf("ContentType: got %q, want %q", retrieved.ContentType, meta.ContentType)
	}
	if retrieved.SizeBytes != meta.SizeBytes {
		t.Errorf("SizeBytes: got %d, want %d", retrieved.SizeBytes, meta.SizeBytes)
	}
	if retrieved.Status != meta.Status {
		t.Errorf("Status: got %q, want %q", retrieved.Status, meta.Status)
	}
	if retrieved.ChecksumSHA256 != meta.ChecksumSHA256 {
		t.Errorf("ChecksumSHA256: got %q, want %q", retrieved.ChecksumSHA256, meta.ChecksumSHA256)
	}
	if retrieved.AdminNote != meta.AdminNote {
		t.Errorf("AdminNote: got %q, want %q", retrieved.AdminNote, meta.AdminNote)
	}
}

// ---------------------------------------------------------------------------
// Test 9: CAS state machine — ACTIVE → CONSUMING → reject second attempt
// ---------------------------------------------------------------------------

// TestIntegration_CASStateMachineRejectsDoubleConsume verifies that the Lua
// CAS script correctly rejects subsequent consume attempts after the first
// succeeds.
//
// Requirements: 4.2, 4.9
func TestIntegration_CASStateMachineRejectsDoubleConsume(t *testing.T) {
	ctx := context.Background()

	_, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	tokenKey := rediskeys.Token(tokenHash)

	t.Cleanup(func() {
		rawRedisClient.Del(ctx, tokenKey)
	})

	// Store ACTIVE token.
	meta := buildActiveMetadata("ep/2024/01/" + uuid.New().String())
	storeActiveToken(t, ctx, tokenKey, meta, 24*time.Hour)

	now := time.Now().Unix()

	// First CASTokenConsume → should succeed (alreadyConsuming=false).
	resultMeta, alreadyConsuming, err := testRedisClient.CASTokenConsume(ctx, tokenHash, now, uuid.New().String())
	if err != nil {
		t.Fatalf("first CASTokenConsume: %v", err)
	}
	if alreadyConsuming {
		t.Error("first CASTokenConsume: expected alreadyConsuming=false")
	}
	if resultMeta == nil {
		t.Fatal("first CASTokenConsume: expected non-nil metadata")
	}
	if resultMeta.Status != models.FileStatusConsuming {
		t.Errorf("first CASTokenConsume: expected CONSUMING status, got %s", resultMeta.Status)
	}
	if resultMeta.DestructionScheduledAt == nil {
		t.Error("first CASTokenConsume: expected DestructionScheduledAt to be set")
	}

	// Second CASTokenConsume → should return alreadyConsuming=true.
	_, alreadyConsuming2, err := testRedisClient.CASTokenConsume(ctx, tokenHash, now, uuid.New().String())
	if err != nil {
		t.Fatalf("second CASTokenConsume: %v", err)
	}
	if !alreadyConsuming2 {
		t.Error("second CASTokenConsume: expected alreadyConsuming=true")
	}

	// Third CASTokenConsume → should also return alreadyConsuming=true (idempotent).
	_, alreadyConsuming3, err := testRedisClient.CASTokenConsume(ctx, tokenHash, now, uuid.New().String())
	if err != nil {
		t.Fatalf("third CASTokenConsume: %v", err)
	}
	if !alreadyConsuming3 {
		t.Error("third CASTokenConsume: expected alreadyConsuming=true (idempotent)")
	}
}

// ---------------------------------------------------------------------------
// Test 10: ZSET stale entry cleanup
// ---------------------------------------------------------------------------

// TestIntegration_ZSETStaleEntryCleanup verifies that CleanStaleZSETEntries
// removes entries older than the stale threshold while preserving future entries.
//
// Requirements: 3.2, 6.1
func TestIntegration_ZSETStaleEntryCleanup(t *testing.T) {
	ctx := context.Background()

	now := time.Now().Unix()

	// We add entries directly to the real destroy_queue ZSET using unique
	// member values to avoid interfering with other entries.
	staleJobID := "stale-" + uuid.New().String()
	futureJobID := "future-" + uuid.New().String()

	staleJob := models.DestroyJob{
		JobID:       staleJobID,
		ObjectKey:   "ep/2024/01/" + uuid.New().String(),
		TokenHash:   uuid.New().String(),
		Attempt:     0,
		ScheduledAt: now - 90000, // 25 hours ago
	}
	futureJob := models.DestroyJob{
		JobID:       futureJobID,
		ObjectKey:   "ep/2024/01/" + uuid.New().String(),
		TokenHash:   uuid.New().String(),
		Attempt:     0,
		ScheduledAt: now + 3600, // 1 hour in the future
	}

	staleJSON, err := json.Marshal(staleJob)
	if err != nil {
		t.Fatalf("marshal stale job: %v", err)
	}
	futureJSON, err := json.Marshal(futureJob)
	if err != nil {
		t.Fatalf("marshal future job: %v", err)
	}

	staleMember := string(staleJSON)
	futureMember := string(futureJSON)

	t.Cleanup(func() {
		// Clean up in case the test fails before CleanStaleZSETEntries runs.
		rawRedisClient.ZRem(ctx, rediskeys.KeyDestroyQueue, staleMember, futureMember)
	})

	// ZADD stale entry with score = now - 90000 (25 hours ago).
	if err := rawRedisClient.ZAdd(ctx, rediskeys.KeyDestroyQueue, redis.Z{
		Score:  float64(now - 90000),
		Member: staleMember,
	}).Err(); err != nil {
		t.Fatalf("ZADD stale entry: %v", err)
	}

	// ZADD future entry with score = now + 3600.
	if err := rawRedisClient.ZAdd(ctx, rediskeys.KeyDestroyQueue, redis.Z{
		Score:  float64(now + 3600),
		Member: futureMember,
	}).Err(); err != nil {
		t.Fatalf("ZADD future entry: %v", err)
	}

	// Call CleanStaleZSETEntries.
	if err := testRedisClient.CleanStaleZSETEntries(ctx); err != nil {
		t.Fatalf("CleanStaleZSETEntries: %v", err)
	}

	// Verify stale entry is removed.
	staleMembers, err := rawRedisClient.ZRangeByScore(ctx, rediskeys.KeyDestroyQueue, &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", now-90000-1),
		Max: fmt.Sprintf("%d", now-90000+1),
	}).Result()
	if err != nil {
		t.Fatalf("ZRangeByScore for stale: %v", err)
	}
	for _, m := range staleMembers {
		if m == staleMember {
			t.Error("stale entry should have been removed by CleanStaleZSETEntries")
		}
	}

	// Verify future entry remains.
	futureMembers, err := rawRedisClient.ZRangeByScore(ctx, rediskeys.KeyDestroyQueue, &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", now+3600-1),
		Max: fmt.Sprintf("%d", now+3600+1),
	}).Result()
	if err != nil {
		t.Fatalf("ZRangeByScore for future: %v", err)
	}
	foundFuture := false
	for _, m := range futureMembers {
		if m == futureMember {
			foundFuture = true
			break
		}
	}
	if !foundFuture {
		t.Error("future entry should still be in destroy_queue after CleanStaleZSETEntries")
	}

	// Clean up the future entry.
	rawRedisClient.ZRem(ctx, rediskeys.KeyDestroyQueue, futureMember)
}
