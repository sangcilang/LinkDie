// Package rediskeys defines all Redis key prefixes and constants used by EphemeralShare.
// All keys with a colon suffix are prefixes — append the specific identifier to form the full key.
// All keys without a colon suffix are standalone keys (no suffix needed).
package rediskeys

import "fmt"

// Key prefixes — append identifier to form full key.
const (
	// KeyPrefixToken is the prefix for file token metadata.
	// Full key: token:{token_hash}
	// Value: JSON-encoded FileMetadata
	// TTL: configured per upload (1h–168h)
	KeyPrefixToken = "token:"

	// KeyPrefixLock is the prefix for distributed download locks.
	// Full key: lock:{token_hash}
	// Value: request identifier
	// TTL: 30 seconds (SET NX EX 30)
	KeyPrefixLock = "lock:"

	// KeyPrefixDestroyed is the prefix for the destroyed token list.
	// Full key: destroyed:{token_hash}
	// Value: "1"
	// TTL: 86400 seconds (24 hours) — prevents replay attacks
	KeyPrefixDestroyed = "destroyed:"

	// KeyPrefixRateLimit is the prefix for rate limiting counters.
	// Full key: rl:{zone}:{ip}
	// Value: request count
	// TTL: zone-specific window
	KeyPrefixRateLimit = "rl:"

	// KeyPrefixFailed is the prefix for failed login attempt counters.
	// Full key: failed:{ip}
	// Value: failure count
	// TTL: 600 seconds (10 minutes)
	KeyPrefixFailed = "failed:"

	// KeyPrefixCleanup is the prefix for cleanup date bucket sets.
	// Full key: cleanup:{YYYY-MM-DD}
	// Value: SADD set of object_keys uploaded on that date
	// TTL: max_ttl + 1 day (managed by cleanup worker)
	KeyPrefixCleanup = "cleanup:"

	// KeyPrefixSession is the prefix for admin session data.
	// Full key: session:{session_id}
	// Value: JSON-encoded session metadata
	// TTL: refresh token TTL (8 hours)
	KeyPrefixSession = "session:"

	// KeyPrefixEnum is the prefix for token enumeration detection counters.
	// Full key: enum:{ip}
	// Value: invalid token request count
	// TTL: 3600 seconds (1 hour) — set on block
	KeyPrefixEnum = "enum:"

	// KeyPrefixHoneypot is the prefix for honeypot token metadata.
	// Full key: honeypot:{token_hash}
	// Value: JSON-encoded fake FileMetadata
	// TTL: random 1–48 hours
	KeyPrefixHoneypot = "honeypot:"

	// KeyPrefixUpload is the prefix for upload session state.
	// Full key: upload:{upload_id}
	// Value: JSON-encoded UploadSession
	// TTL: 1800 seconds (30 minutes)
	KeyPrefixUpload = "upload:"

	// KeyPrefixQuotaUploads is the prefix for daily upload count quota.
	// Full key: quota:uploads:{YYYY-MM-DD}
	// Value: integer count
	// TTL: EXPIREAT midnight of the date
	KeyPrefixQuotaUploads = "quota:uploads:"

	// KeyPrefixQuotaBytes is the prefix for daily upload bytes quota.
	// Full key: quota:bytes:{YYYY-MM-DD}
	// Value: integer byte count
	// TTL: EXPIREAT midnight of the date
	KeyPrefixQuotaBytes = "quota:bytes:"

	// KeyPrefixRefresh is the prefix for refresh token JTI tracking.
	// Full key: refresh:{jti}
	// Value: session_id
	// TTL: 28800 seconds (8 hours)
	KeyPrefixRefresh = "refresh:"
)

// Standalone keys — used as-is without appending an identifier.
const (
	// KeyDestroyQueue is the ZSET of pending destruction jobs.
	// Score: Unix timestamp when the job should be executed.
	// Member: JSON-encoded DestroyJob
	KeyDestroyQueue = "destroy_queue"

	// KeyUploadsPending is the ZSET of pending upload sessions.
	// Score: Unix timestamp when the session expires.
	// Member: upload_id
	KeyUploadsPending = "uploads_pending"

	// KeyUploadsUnconfirmed is the ZSET of unconfirmed upload sessions.
	// Score: Unix timestamp when the session expires.
	// Member: upload_id
	KeyUploadsUnconfirmed = "uploads_unconfirmed"

	// KeyCleanupByExpiry is the ZSET of tokens indexed by expiry time.
	// Score: Unix timestamp when the token expires.
	// Member: object_key
	KeyCleanupByExpiry = "cleanup_by_expiry"

	// KeyDestroyDLQ is the ZSET dead-letter queue for failed destruction jobs.
	// Score: Unix timestamp when the job was moved to DLQ.
	// Member: JSON-encoded DestroyJob
	KeyDestroyDLQ = "destroy_dlq"

	// KeyCleanupLock is the distributed lock for the orphan scan worker.
	// Value: {hostname}:{pid}
	// TTL: 60 seconds (SET NX EX 60)
	KeyCleanupLock = "cleanup_lock"
)

// KeyDestroyJobID is the field name within FileMetadata for the destruction job UUID.
// Used when checking if a destruction job has already been scheduled.
const KeyDestroyJobID = "destroy_job_id"

// --- Helper functions to build full Redis keys ---

// Token returns the full Redis key for a file token.
func Token(tokenHash string) string {
	return KeyPrefixToken + tokenHash
}

// Lock returns the full Redis key for a download lock.
func Lock(tokenHash string) string {
	return KeyPrefixLock + tokenHash
}

// Destroyed returns the full Redis key for a destroyed token entry.
func Destroyed(tokenHash string) string {
	return KeyPrefixDestroyed + tokenHash
}

// RateLimit returns the full Redis key for a rate limit counter.
func RateLimit(zone, ip string) string {
	return fmt.Sprintf("%s%s:%s", KeyPrefixRateLimit, zone, ip)
}

// Failed returns the full Redis key for a failed login counter.
func Failed(ip string) string {
	return KeyPrefixFailed + ip
}

// Cleanup returns the full Redis key for a cleanup date bucket.
func Cleanup(dateBucket string) string {
	return KeyPrefixCleanup + dateBucket
}

// Session returns the full Redis key for an admin session.
func Session(sessionID string) string {
	return KeyPrefixSession + sessionID
}

// Enum returns the full Redis key for a token enumeration counter.
func Enum(ip string) string {
	return KeyPrefixEnum + ip
}

// Honeypot returns the full Redis key for a honeypot token.
func Honeypot(tokenHash string) string {
	return KeyPrefixHoneypot + tokenHash
}

// Upload returns the full Redis key for an upload session.
func Upload(uploadID string) string {
	return KeyPrefixUpload + uploadID
}

// QuotaUploads returns the full Redis key for the daily upload count quota.
func QuotaUploads(date string) string {
	return KeyPrefixQuotaUploads + date
}

// QuotaBytes returns the full Redis key for the daily upload bytes quota.
func QuotaBytes(date string) string {
	return KeyPrefixQuotaBytes + date
}

// Refresh returns the full Redis key for a refresh token JTI.
func Refresh(jti string) string {
	return KeyPrefixRefresh + jti
}
