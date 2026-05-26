package audit

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"ephemeral-share/backend/internal/models"
)

// Event type constants for all audit log events.
const (
	EventUploadInitiated            = "upload_initiated"
	EventUploadConfirmed            = "upload_confirmed"
	EventDownloadAccessed           = "download_accessed"
	EventFileDestroyed              = "file_destroyed"
	EventOrphanCleaned              = "orphan_cleaned"
	EventAdminLoginSuccess          = "admin_login_success"
	EventAdminLoginFailure          = "admin_login_failure"
	EventSuspiciousActivity         = "suspicious_activity"
	EventHoneypotHit                = "honeypot_hit"
	EventRefreshTokenReplayDetected = "refresh_token_replay_detected"
	EventMalwareDetected            = "malware_detected"
	EventDestroyJobFailed           = "destroy_job_failed"
	EventDestroyJobDLQ              = "destroy_job_dlq"
)

// sensitiveKeys are Details map keys whose values must be redacted.
var sensitiveKeys = map[string]struct{}{
	"password":  {},
	"token":     {},
	"secret":    {},
	"key":       {},
	"raw_token": {},
	"content":   {},
}

// EventOption is a functional option for configuring an AuditEvent.
type EventOption func(*models.AuditEvent)

// WithObjectKey sets the ObjectKey field on the event.
func WithObjectKey(key string) EventOption {
	return func(e *models.AuditEvent) {
		e.ObjectKey = key
	}
}

// WithTokenHash sets the TokenHash field on the event.
func WithTokenHash(hash string) EventOption {
	return func(e *models.AuditEvent) {
		e.TokenHash = hash
	}
}

// WithAdminIP sets the AdminIP field on the event.
func WithAdminIP(ip string) EventOption {
	return func(e *models.AuditEvent) {
		e.AdminIP = ip
	}
}

// WithRecipientIP sets the RecipientIP field on the event.
func WithRecipientIP(ip string) EventOption {
	return func(e *models.AuditEvent) {
		e.RecipientIP = ip
	}
}

// WithDetails sets the Details map on the event.
func WithDetails(details map[string]interface{}) EventOption {
	return func(e *models.AuditEvent) {
		e.Details = details
	}
}

// Logger writes structured JSON audit events to stdout.
type Logger struct {
	enc *json.Encoder
	log *log.Logger
}

// NewLogger creates a new Logger that writes JSON audit events to os.Stdout.
func NewLogger() *Logger {
	return &Logger{
		enc: json.NewEncoder(os.Stdout),
		log: log.New(os.Stdout, "", 0),
	}
}

// Log marshals the given AuditEvent to JSON and writes it to stdout.
// Sensitive data is sanitized before writing.
func (l *Logger) Log(_ context.Context, event *models.AuditEvent) {
	l.sanitizeEvent(event)
	if err := l.enc.Encode(event); err != nil {
		l.log.Printf("audit: failed to encode event %q: %v", event.Event, err)
	}
}

// Emit is a convenience method that constructs an AuditEvent from the given
// parameters and functional options, then logs it.
func (l *Logger) Emit(ctx context.Context, eventType string, success bool, opts ...EventOption) {
	event := &models.AuditEvent{
		Ts:      time.Now().UTC(),
		Event:   eventType,
		Success: success,
	}
	for _, opt := range opts {
		opt(event)
	}
	l.Log(ctx, event)
}

// sanitizeEvent ensures no sensitive data appears in the event before logging.
// It redacts TokenHash values that look like raw tokens (< 32 chars) and
// removes sensitive keys from the Details map.
func (l *Logger) sanitizeEvent(e *models.AuditEvent) {
	// A proper SHA-256 hex hash is 64 characters. If the value is shorter
	// than 32 characters it is likely a raw token rather than a hash.
	if e.TokenHash != "" && len(e.TokenHash) < 32 {
		e.TokenHash = "[REDACTED]"
	}

	if e.Details != nil {
		for k := range e.Details {
			if _, sensitive := sensitiveKeys[strings.ToLower(k)]; sensitive {
				e.Details[k] = "[REDACTED]"
			}
		}
	}
}
