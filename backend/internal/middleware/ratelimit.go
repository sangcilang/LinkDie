package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"ephemeral-share/backend/internal/audit"
	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/rediskeys"
	"ephemeral-share/backend/internal/store"
)

// RateLimit returns a Fiber middleware that enforces a fixed-window rate limit
// using Redis INCR + EXPIRE.
//
// Parameters:
//   - zone:          logical name for this rate limit zone (e.g. "download", "api")
//   - maxRequests:   maximum number of requests allowed per window
//   - windowSeconds: length of the rate limit window in seconds
//   - redis:         Redis client used to store counters
//
// Redis key format: rl:{zone}:{ip}
//
// When the limit is exceeded the middleware returns HTTP 429 with headers:
//   - Retry-After: {windowSeconds}
//   - X-RateLimit-Limit: {maxRequests}
//   - X-RateLimit-Remaining: 0
//   - X-RateLimit-Reset: {unix_timestamp_when_window_resets}
func RateLimit(zone string, maxRequests int, windowSeconds int, redis *store.RedisClient) fiber.Handler {
	ttl := time.Duration(windowSeconds) * time.Second

	return func(c *fiber.Ctx) error {
		ctx := context.Background()
		ip := c.IP()
		key := rediskeys.RateLimit(zone, ip)

		// Increment the counter.
		count, err := redis.Incr(ctx, key)
		if err != nil {
			// On Redis error, fail open (allow the request) to avoid blocking
			// legitimate traffic due to a Redis outage.
			return c.Next()
		}

		// On the first increment, set the TTL for the window.
		if count == 1 {
			if expErr := redis.Expire(ctx, key, ttl); expErr != nil {
				// Non-fatal: the key will eventually be cleaned up by Redis memory
				// pressure or a future request that succeeds in setting the TTL.
				_ = expErr
			}
		}

		if count > int64(maxRequests) {
			resetAt := time.Now().Add(ttl).Unix()
			c.Set("Retry-After", fmt.Sprintf("%d", windowSeconds))
			c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", maxRequests))
			c.Set("X-RateLimit-Remaining", "0")
			c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt))
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "RATE_LIMIT_EXCEEDED",
			})
		}

		remaining := int64(maxRequests) - count
		if remaining < 0 {
			remaining = 0
		}
		resetAt := time.Now().Add(ttl).Unix()
		c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", maxRequests))
		c.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt))

		return c.Next()
	}
}

// TokenEnumerationDetection returns a Fiber middleware that tracks requests to
// /d/* endpoints and blocks IPs that make too many requests with invalid tokens.
//
// Algorithm:
//  1. Check if enum:{ip} == "BLOCKED" → return 429 immediately.
//  2. Increment enum:{ip} counter (INCR + EXPIRE 60s).
//  3. If count > 10 → set enum:{ip} = "BLOCKED" with EXPIRE 3600 + return 429.
//  4. Emit suspicious_activity audit event when blocking.
//
// This middleware should be applied to /d/* routes.
func TokenEnumerationDetection(redis *store.RedisClient, auditLogger *audit.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Only apply to /d/* paths.
		if !strings.HasPrefix(c.Path(), "/d/") {
			return c.Next()
		}

		ctx := context.Background()
		ip := c.IP()
		key := rediskeys.Enum(ip)

		// Check if already blocked.
		val, err := redis.Get(ctx, key)
		if err == nil && val == "BLOCKED" {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "TOKEN_ENUMERATION_DETECTED",
			})
		}

		// Increment the counter with a 60-second window.
		count, err := redis.IncrEnumCounter(ctx, ip)
		if err != nil {
			// Fail open on Redis error.
			return c.Next()
		}

		if count > 10 {
			// Block the IP for 1 hour.
			_ = redis.Set(ctx, key, "BLOCKED", 3600*time.Second)

			// Emit suspicious_activity audit event.
			if auditLogger != nil {
				auditLogger.Emit(ctx, audit.EventSuspiciousActivity, false,
					audit.WithRecipientIP(ip),
					audit.WithDetails(map[string]interface{}{
						"reason":    "token_enumeration_detected",
						"ip":        ip,
						"count":     count,
						"action":    "blocked_1h",
					}),
				)
			}

			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "TOKEN_ENUMERATION_DETECTED",
			})
		}

		return c.Next()
	}
}

// GlobalBackpressure returns a Fiber middleware that rejects upload requests
// when the system is overloaded (too many pending uploads).
//
// It checks ZCARD uploads_pending >= cfg.MaxTotalPendingUploads and returns
// HTTP 429 SYSTEM_OVERLOADED if the threshold is reached.
//
// Only applies to the /api/admin/request-upload path prefix.
func GlobalBackpressure(cfg *config.Config, redis *store.RedisClient) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Only apply to upload request endpoints.
		if !strings.HasPrefix(c.Path(), "/api/admin/request-upload") {
			return c.Next()
		}

		ctx := context.Background()

		count, err := redis.ZCard(ctx, rediskeys.KeyUploadsPending)
		if err != nil {
			// Fail open on Redis error.
			return c.Next()
		}

		if count >= int64(cfg.MaxTotalPendingUploads) {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "SYSTEM_OVERLOADED",
			})
		}

		return c.Next()
	}
}
