package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Server
	Port            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	BodyLimitMB     int
	AppVersion      string

	// Redis
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisTLSEnabled bool

	// S3 / R2
	S3Endpoint        string
	S3Region          string
	S3Bucket          string
	S3AccessKeyID     string
	S3SecretAccessKey string

	// Auth
	AdminPasswordHash    string // bcrypt hash
	JWTSecret            string
	TOTPSecret           string // empty = TOTP disabled
	AdminAllowedIPs      []string
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration

	// Upload
	MaxFileSizeBytes          int64
	DefaultTTLHours           int
	MaxTTLHours               int
	MinTTLHours               int
	MaxPendingUploadsPerAdmin int
	MaxTotalPendingUploads    int
	MaxDailyUploads           int   // 0 = unlimited
	MaxDailyBytes             int64 // 0 = unlimited
	AllowedMIMETypes          []string

	// Public
	PublicBaseURL string

	// Download
	PresignedURLTTLSeconds  int
	DestructionGraceSeconds int

	// Cleanup Worker
	DestroyQueuePollIntervalSeconds int
	MaxDestroyRetries               int

	// ClamAV
	ClamAVAddress          string
	ClamAVScanTimeoutSeconds int

	// Security
	MinimalDisclosureMode bool
	LogMinimizationMode   bool
	DownloadMode          string // "redirect" or "stream"

	// Encryption (Phase 2)
	EncryptionEnabled bool
	MasterEncryptionKey string

	// Honeypot (Phase 2)
	HoneypotBaseIntervalSeconds int
	HoneypotJitterSeconds       int
	HoneypotMinCount            int
	HoneypotMaxCount            int

	// Metrics
	MetricsAllowedCIDRs []string
}

// Load reads configuration from environment variables and returns a Config.
// Required variables that are missing will cause an error.
func Load() (*Config, error) {
	cfg := &Config{}

	// Server
	cfg.Port = getEnvOrDefault("PORT", "8080")
	cfg.ReadTimeout = getDurationOrDefault("READ_TIMEOUT_SECONDS", 30) * time.Second
	cfg.WriteTimeout = getDurationOrDefault("WRITE_TIMEOUT_SECONDS", 60) * time.Second
	cfg.BodyLimitMB = getIntOrDefault("BODY_LIMIT_MB", 500)
	cfg.AppVersion = getEnvOrDefault("APP_VERSION", "dev")

	// Redis
	cfg.RedisAddr = getEnvOrDefault("REDIS_ADDR", "localhost:6379")
	cfg.RedisPassword = os.Getenv("REDIS_PASSWORD")
	cfg.RedisDB = getIntOrDefault("REDIS_DB", 0)
	cfg.RedisTLSEnabled = getBoolOrDefault("REDIS_TLS_ENABLED", false)

	// S3 / R2
	cfg.S3Endpoint = getEnvOrDefault("S3_ENDPOINT", "")
	cfg.S3Region = getEnvOrDefault("S3_REGION", "auto")
	cfg.S3Bucket = getEnvOrDefault("S3_BUCKET", "")
	cfg.S3AccessKeyID = os.Getenv("S3_ACCESS_KEY_ID")
	cfg.S3SecretAccessKey = os.Getenv("S3_SECRET_ACCESS_KEY")

	// Auth
	cfg.AdminPasswordHash = os.Getenv("ADMIN_PASSWORD_HASH")
	if cfg.AdminPasswordHash == "" {
		return nil, fmt.Errorf("ADMIN_PASSWORD_HASH is required")
	}
	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	cfg.TOTPSecret = os.Getenv("TOTP_SECRET")
	cfg.AdminAllowedIPs = splitCSV(os.Getenv("ADMIN_ALLOWED_IPS"))
	cfg.AccessTokenTTL = getDurationOrDefault("ACCESS_TOKEN_TTL_SECONDS", 900) * time.Second
	cfg.RefreshTokenTTL = getDurationOrDefault("REFRESH_TOKEN_TTL_SECONDS", 28800) * time.Second

	// Upload
	cfg.MaxFileSizeBytes = int64(getIntOrDefault("MAX_FILE_SIZE_MB", 500)) * 1024 * 1024
	cfg.DefaultTTLHours = getIntOrDefault("DEFAULT_TTL_HOURS", 24)
	cfg.MaxTTLHours = getIntOrDefault("MAX_TTL_HOURS", 168)
	cfg.MinTTLHours = getIntOrDefault("MIN_TTL_HOURS", 1)
	cfg.MaxPendingUploadsPerAdmin = getIntOrDefault("MAX_PENDING_UPLOADS_PER_ADMIN", 10)
	cfg.MaxTotalPendingUploads = getIntOrDefault("MAX_TOTAL_PENDING_UPLOADS", 50)
	cfg.MaxDailyUploads = getIntOrDefault("MAX_DAILY_UPLOADS", 0)
	cfg.MaxDailyBytes = int64(getIntOrDefault("MAX_DAILY_BYTES_MB", 0)) * 1024 * 1024
	cfg.AllowedMIMETypes = splitCSV(getEnvOrDefault("ALLOWED_MIME_TYPES",
		"application/pdf,application/zip,application/x-zip-compressed,"+
			"application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,"+
			"application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,"+
			"application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation,"+
			"image/jpeg,image/png,image/gif,image/webp,image/svg+xml,"+
			"text/plain,text/csv,"+
			"video/mp4,video/webm,"+
			"audio/mpeg,audio/ogg,audio/wav"))

	// Download
	cfg.PresignedURLTTLSeconds = getIntOrDefault("PRESIGNED_URL_TTL_SECONDS", 30)
	if cfg.PresignedURLTTLSeconds > 60 {
		cfg.PresignedURLTTLSeconds = 60
	}
	cfg.DestructionGraceSeconds = getIntOrDefault("DESTRUCTION_GRACE_SECONDS", 15)

	// Cleanup Worker
	cfg.DestroyQueuePollIntervalSeconds = getIntOrDefault("DESTROY_QUEUE_POLL_INTERVAL_SECONDS", 5)
	cfg.MaxDestroyRetries = getIntOrDefault("MAX_DESTROY_RETRIES", 3)

	// ClamAV
	cfg.ClamAVAddress = getEnvOrDefault("CLAMAV_ADDRESS", "clamav:3310")
	cfg.ClamAVScanTimeoutSeconds = getIntOrDefault("CLAMAV_SCAN_TIMEOUT_SECONDS", 60)

	// Security
	cfg.MinimalDisclosureMode = getBoolOrDefault("MINIMAL_DISCLOSURE_MODE", false)
	cfg.LogMinimizationMode = getBoolOrDefault("LOG_MINIMIZATION_MODE", false)
	cfg.DownloadMode = getEnvOrDefault("DOWNLOAD_MODE", "redirect")

	// Public
	cfg.PublicBaseURL = getEnvOrDefault("PUBLIC_BASE_URL", "http://localhost:3000")

	// Encryption (Phase 2)
	cfg.EncryptionEnabled = getBoolOrDefault("ENCRYPTION_ENABLED", false)
	cfg.MasterEncryptionKey = os.Getenv("MASTER_ENCRYPTION_KEY")

	// Honeypot (Phase 2)
	cfg.HoneypotBaseIntervalSeconds = getIntOrDefault("HONEYPOT_BASE_INTERVAL_SECONDS", 300)
	cfg.HoneypotJitterSeconds = getIntOrDefault("HONEYPOT_JITTER_SECONDS", 120)
	cfg.HoneypotMinCount = getIntOrDefault("HONEYPOT_MIN_COUNT", 5)
	cfg.HoneypotMaxCount = getIntOrDefault("HONEYPOT_MAX_COUNT", 20)

	// Metrics
	cfg.MetricsAllowedCIDRs = splitCSV(getEnvOrDefault("METRICS_ALLOWED_CIDRS", "10.0.0.0/8,172.16.0.0/12"))

	return cfg, nil
}

// getEnvOrDefault returns the value of the environment variable or the default.
func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// getIntOrDefault parses an integer environment variable or returns the default.
func getIntOrDefault(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}

// getDurationOrDefault parses an integer environment variable as seconds duration.
func getDurationOrDefault(key string, defaultSeconds int) time.Duration {
	return time.Duration(getIntOrDefault(key, defaultSeconds))
}

// getBoolOrDefault parses a boolean environment variable or returns the default.
func getBoolOrDefault(key string, defaultVal bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return defaultVal
}

// splitCSV splits a comma-separated string into a trimmed slice, ignoring empty entries.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
