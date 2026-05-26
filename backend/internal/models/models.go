package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// FileStatus represents the lifecycle state of a file token.
type FileStatus string

const (
	FileStatusPendingUpload      FileStatus = "PENDING_UPLOAD"
	FileStatusUploadedUnconfirmed FileStatus = "UPLOADED_UNCONFIRMED"
	FileStatusActive             FileStatus = "ACTIVE"
	FileStatusConsuming          FileStatus = "CONSUMING"
	FileStatusDestroyed          FileStatus = "DESTROYED"
)

// FileMetadata holds all metadata associated with an uploaded file token.
// It is stored in Redis under the key token:{Token_Hash}.
type FileMetadata struct {
	// ObjectKey is the S3/R2 object key in format ep/{YYYY}/{MM}/{uuid-v4}.
	ObjectKey string `json:"object_key"`

	// OriginalFilename is the sanitized original filename provided by the admin.
	OriginalFilename string `json:"original_filename"`

	// ContentType is the MIME type detected from the first 512 bytes of file content.
	ContentType string `json:"content_type"`

	// SizeBytes is the file size in bytes.
	SizeBytes int64 `json:"size_bytes"`

	// UploadedAt is the timestamp when the upload was confirmed.
	UploadedAt time.Time `json:"uploaded_at"`

	// ExpiresAt is the timestamp when the token expires.
	ExpiresAt time.Time `json:"expires_at"`

	// MaxDownloads is the maximum number of allowed downloads (default 1).
	MaxDownloads int `json:"max_downloads"`

	// DownloadCount is the number of times the file has been downloaded.
	DownloadCount int `json:"download_count"`

	// ChecksumSHA256 is the SHA-256 checksum of the file content (hex-encoded).
	ChecksumSHA256 string `json:"checksum_sha256"`

	// AdminNote is an optional note from the admin (not shown to recipient).
	AdminNote string `json:"admin_note,omitempty"`

	// Status is the current lifecycle state of the file.
	Status FileStatus `json:"status"`

	// DestructionScheduledAt is the timestamp when destruction was scheduled.
	// Set atomically by the Lua CAS script when transitioning ACTIVE → CONSUMING.
	DestructionScheduledAt *time.Time `json:"destruction_scheduled_at,omitempty"`

	// DestroyJobID is the UUID v4 of the destruction job.
	// Set atomically by the Lua CAS script when transitioning ACTIVE → CONSUMING.
	DestroyJobID string `json:"destroy_job_id,omitempty"`
}

// AuditEvent represents a structured audit log entry emitted to stdout as JSON.
type AuditEvent struct {
	// Ts is the ISO 8601 timestamp of the event.
	Ts time.Time `json:"ts"`

	// Event is the event type constant (e.g., "upload_initiated").
	Event string `json:"event"`

	// ObjectKey is the S3/R2 object key (not the original filename).
	ObjectKey string `json:"object_key,omitempty"`

	// TokenHash is the SHA-256 hash of the token (not the raw token).
	TokenHash string `json:"token_hash,omitempty"`

	// Success indicates whether the operation succeeded.
	Success bool `json:"success"`

	// AdminIP is the IP address of the admin (for admin events).
	AdminIP string `json:"admin_ip,omitempty"`

	// RecipientIP is the IP address of the recipient (for download events).
	RecipientIP string `json:"recipient_ip,omitempty"`

	// Details contains additional event-specific information.
	// MUST NOT contain file content, raw tokens, or passwords.
	Details map[string]interface{} `json:"details,omitempty"`
}

// AdminClaims extends jwt.RegisteredClaims with EphemeralShare-specific fields.
type AdminClaims struct {
	jwt.RegisteredClaims

	// Role is the admin role (always "admin" for now).
	Role string `json:"role"`

	// SessionID is a unique identifier for the admin session.
	// Used for refresh token rotation and session revocation.
	SessionID string `json:"session_id"`

	// GeoRegion is the country code at login time (e.g., "VN", "US").
	// Used for geo anomaly detection.
	GeoRegion string `json:"geo_region,omitempty"`

	// DeviceFingerprint is a hash of User-Agent + Accept-Language.
	// Used for device change detection (logged, not hard-rejected).
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
}

// DestroyJob represents a destruction job stored in the destroy_queue ZSET.
type DestroyJob struct {
	// JobID is the UUID v4 identifier for this destruction job.
	JobID string `json:"job_id"`

	// ObjectKey is the S3/R2 object key to delete.
	ObjectKey string `json:"object_key"`

	// TokenHash is the SHA-256 hash of the token to revoke.
	TokenHash string `json:"token_hash"`

	// Attempt is the number of destruction attempts made (0-indexed).
	Attempt int `json:"attempt"`

	// ScheduledAt is the Unix timestamp when the job was first scheduled.
	ScheduledAt int64 `json:"scheduled_at"`
}

// HealthResponse is the JSON response body for GET /health.
type HealthResponse struct {
	// Status is "ok" when all dependencies are healthy, "degraded" otherwise.
	Status string `json:"status"`

	// Redis is "ok" or "unavailable".
	Redis string `json:"redis"`

	// Storage is "ok" or "unavailable".
	Storage string `json:"storage"`

	// Version is the application version string.
	Version string `json:"version"`
}

// UploadSession holds the state of an in-progress upload.
// Stored in Redis under upload:{upload_id}.
type UploadSession struct {
	// UploadID is the unique identifier for this upload session.
	UploadID string `json:"upload_id"`

	// ObjectKey is the S3/R2 object key for this upload.
	ObjectKey string `json:"object_key"`

	// Status is the current state of the upload session.
	Status FileStatus `json:"status"`

	// Filename is the sanitized original filename.
	Filename string `json:"filename"`

	// ContentType is the declared MIME type.
	ContentType string `json:"content_type"`

	// SizeBytes is the declared file size.
	SizeBytes int64 `json:"size_bytes"`

	// TTLHours is the configured TTL for the token.
	TTLHours int `json:"ttl_hours"`

	// AdminNote is an optional note from the admin.
	AdminNote string `json:"admin_note,omitempty"`

	// CreatedAt is when the upload session was created.
	CreatedAt time.Time `json:"created_at"`
}
