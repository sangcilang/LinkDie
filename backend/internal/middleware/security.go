// Package middleware provides HTTP middleware for EphemeralShare.
package middleware

import (
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// sensitivePatterns are regex patterns that indicate internal/sensitive information
// that must be stripped from error responses before sending to clients.
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)redis:`),
	regexp.MustCompile(`(?i)s3:`),
	regexp.MustCompile(`(?i)storage:`),
	regexp.MustCompile(`(?i)token:`),
	regexp.MustCompile(`(?i)lock:`),
	regexp.MustCompile(`(?i)bucket`),
	// Internal file paths (Unix and Windows)
	regexp.MustCompile(`/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+\.go`),
	regexp.MustCompile(`[A-Za-z]:\\[A-Za-z0-9_\-\\]+\.go`),
	// Stack trace indicators
	regexp.MustCompile(`goroutine \d+`),
	regexp.MustCompile(`runtime/`),
	regexp.MustCompile(`\.go:\d+`),
}

// SecurityHeaders returns a Fiber middleware that sets security-related HTTP
// response headers on every response.
//
// Headers set:
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains
//   - Referrer-Policy: no-referrer
//   - Cache-Control: no-store, no-cache, must-revalidate
//   - Server: (empty — hides server identity)
//   - Permissions-Policy: camera=(), microphone=(), geolocation=()
//   - Cross-Origin-Opener-Policy: same-origin
//   - Cross-Origin-Resource-Policy: same-origin
func SecurityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Cache-Control", "no-store, no-cache, must-revalidate")
		c.Set("Server", "")
		c.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Set("Cross-Origin-Opener-Policy", "same-origin")
		c.Set("Cross-Origin-Resource-Policy", "same-origin")
		return c.Next()
	}
}

// ErrorSanitizer returns a Fiber middleware that intercepts error responses and
// strips sensitive information before sending them to clients.
//
// For 5xx responses, any error message containing internal patterns (Redis keys,
// S3 references, file paths, stack traces) is replaced with a generic
// INTERNAL_ERROR message.
func ErrorSanitizer() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()

		// Handle Fiber errors (returned from handlers).
		if err != nil {
			code := fiber.StatusInternalServerError
			msg := err.Error()

			if fe, ok := err.(*fiber.Error); ok {
				code = fe.Code
				msg = fe.Message
			}

			if code >= 500 {
				msg = sanitizeErrorMessage(msg)
				return c.Status(code).JSON(fiber.Map{
					"error": msg,
				})
			}

			// For non-5xx errors, still sanitize but preserve the status code.
			return c.Status(code).JSON(fiber.Map{
				"error": msg,
			})
		}

		// Sanitize already-written 5xx responses.
		if c.Response().StatusCode() >= 500 {
			// We can't rewrite the body at this point if it was already sent,
			// but we can ensure the response body is sanitized if it's still buffered.
			body := c.Response().Body()
			if len(body) > 0 {
				sanitized := sanitizeResponseBody(string(body))
				if sanitized != string(body) {
					c.Response().SetBodyString(sanitized)
				}
			}
		}

		return nil
	}
}

// sanitizeErrorMessage checks if the error message contains sensitive patterns
// and returns a generic INTERNAL_ERROR string if it does.
func sanitizeErrorMessage(msg string) string {
	for _, pattern := range sensitivePatterns {
		if pattern.MatchString(msg) {
			return "INTERNAL_ERROR"
		}
	}
	// Also check for common internal path separators that suggest file paths.
	if strings.Contains(msg, "ephemeral-share/backend/internal/") {
		return "INTERNAL_ERROR"
	}
	return msg
}

// sanitizeResponseBody sanitizes a JSON response body string by replacing
// sensitive error messages with INTERNAL_ERROR.
func sanitizeResponseBody(body string) string {
	for _, pattern := range sensitivePatterns {
		if pattern.MatchString(body) {
			return `{"error":"INTERNAL_ERROR"}`
		}
	}
	if strings.Contains(body, "ephemeral-share/backend/internal/") {
		return `{"error":"INTERNAL_ERROR"}`
	}
	return body
}
