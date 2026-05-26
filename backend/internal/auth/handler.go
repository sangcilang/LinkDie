// Package auth implements HTTP handlers and middleware for admin authentication.
// It covers login (bcrypt + optional TOTP), JWT issuance, refresh token rotation
// with replay detection, logout, and brute-force lockout.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"ephemeral-share/backend/internal/audit"
	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/models"
	"ephemeral-share/backend/internal/rediskeys"
	"ephemeral-share/backend/internal/store"
)

const (
	refreshCookieName = "refresh_token"
	maxFailedAttempts = 5
	failedLockoutTTL  = 600 * time.Second // 10 minutes
	artificialDelay   = 500 * time.Millisecond
)

// Handler holds dependencies for auth HTTP handlers.
type Handler struct {
	cfg   *config.Config
	redis *store.RedisClient
	audit *audit.Logger
}

// NewHandler creates a new auth Handler.
func NewHandler(cfg *config.Config, redis *store.RedisClient, auditLogger *audit.Logger) *Handler {
	return &Handler{
		cfg:   cfg,
		redis: redis,
		audit: auditLogger,
	}
}

// loginRequest is the JSON body for POST /api/admin/login.
type loginRequest struct {
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// loginResponse is the JSON response for a successful login.
type loginResponse struct {
	AccessToken string `json:"access_token"`
	SessionID   string `json:"session_id"`
	ExpiresIn   int    `json:"expires_in"`
}

// Login handles POST /api/admin/login.
//
// Flow:
//  1. Check brute-force lockout (failed:{ip} >= 5 → 429)
//  2. Verify bcrypt password
//  3. If TOTP enabled, verify TOTP code
//  4. On success: issue access JWT + refresh token cookie
func (h *Handler) Login(c *fiber.Ctx) error {
	ip := c.IP()
	ctx := context.Background()

	// 1. Brute-force lockout check.
	failedKey := rediskeys.Failed(ip)
	failedStr, err := h.redis.Get(ctx, failedKey)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}
	if failedStr != "" {
		count, _ := strconv.ParseInt(failedStr, 10, 64)
		if count >= maxFailedAttempts {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "LOCKED_OUT",
			})
		}
	}

	// 2. Parse request body.
	var req loginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "INVALID_REQUEST",
		})
	}

	// 3. Verify bcrypt password.
	if err := bcrypt.CompareHashAndPassword(
		[]byte(h.cfg.AdminPasswordHash),
		[]byte(req.Password),
	); err != nil {
		return h.handleLoginFailure(c, ctx, ip, "password_mismatch")
	}

	// 4. TOTP check (if enabled).
	if h.cfg.TOTPSecret != "" {
		if req.TOTPCode == "" {
			// Password correct but TOTP not provided — tell client TOTP is required.
			// We do NOT increment the failure counter here because the password was valid.
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "TOTP_REQUIRED",
			})
		}
		valid := totp.Validate(req.TOTPCode, h.cfg.TOTPSecret)
		if !valid {
			return h.handleLoginFailure(c, ctx, ip, "totp_invalid")
		}
	}

	// 5. Success — clear failure counter.
	if err := h.redis.Del(ctx, failedKey); err != nil {
		// Non-fatal: log but continue.
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithAdminIP(ip),
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to clear failed counter",
				"error":  err.Error(),
			}),
		)
	}

	// 6. Build session.
	sessionID := uuid.New().String()
	geoRegion := geoRegionFromRequest(c)
	deviceFP := deviceFingerprint(c)

	// 7. Issue access JWT.
	accessToken, jti, err := h.issueAccessJWT(sessionID, geoRegion, deviceFP)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "TOKEN_GENERATION_FAILED")
	}

	// 8. Issue refresh token and store in Redis.
	refreshToken, err := h.issueRefreshToken(ctx, jti, sessionID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "TOKEN_GENERATION_FAILED")
	}

	// 9. Store session metadata in Redis (for geo anomaly detection).
	sessionKey := rediskeys.Session(sessionID)
	sessionData := fmt.Sprintf(`{"geo_region":%q,"device_fingerprint":%q}`, geoRegion, deviceFP)
	if err := h.redis.Set(ctx, sessionKey, sessionData, h.cfg.RefreshTokenTTL); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "SESSION_STORE_FAILED")
	}

	// 10. Set HttpOnly Secure SameSite=Strict refresh token cookie.
	setRefreshCookie(c, refreshToken, int(h.cfg.RefreshTokenTTL.Seconds()))

	// 11. Emit audit event.
	h.audit.Emit(ctx, audit.EventAdminLoginSuccess, true,
		audit.WithAdminIP(ip),
		audit.WithDetails(map[string]interface{}{
			"session_id": sessionID,
			"geo_region": geoRegion,
		}),
	)

	return c.Status(fiber.StatusOK).JSON(loginResponse{
		AccessToken: accessToken,
		SessionID:   sessionID,
		ExpiresIn:   900,
	})
}

// handleLoginFailure increments the failure counter, adds an artificial delay,
// emits an audit event, and returns 401 INVALID_CREDENTIALS.
func (h *Handler) handleLoginFailure(c *fiber.Ctx, ctx context.Context, ip, reason string) error {
	if _, err := h.redis.IncrFailedCounter(ctx, ip); err != nil {
		// Non-fatal.
		h.audit.Emit(ctx, audit.EventSuspiciousActivity, false,
			audit.WithAdminIP(ip),
			audit.WithDetails(map[string]interface{}{
				"reason": "failed to increment failed counter",
				"error":  err.Error(),
			}),
		)
	}

	h.audit.Emit(ctx, audit.EventAdminLoginFailure, false,
		audit.WithAdminIP(ip),
		audit.WithDetails(map[string]interface{}{
			"reason": reason,
		}),
	)

	// Artificial delay to slow brute-force.
	time.Sleep(artificialDelay)

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "INVALID_CREDENTIALS",
	})
}

// Refresh handles POST /api/admin/refresh.
//
// Flow:
//  1. CSRF Origin check
//  2. Read refresh token from cookie
//  3. Validate JTI in Redis (replay detection)
//  4. Rotate: DEL old JTI, issue new access JWT + new refresh token
func (h *Handler) Refresh(c *fiber.Ctx) error {
	ctx := context.Background()

	// 1. CSRF check.
	if err := h.checkCSRF(c); err != nil {
		return err
	}

	// 2. Read refresh token from cookie.
	refreshToken := c.Cookies(refreshCookieName)
	if refreshToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "REFRESH_TOKEN_INVALID",
		})
	}

	// 3. Parse the refresh token to extract JTI.
	jti, _, err := parseRefreshToken(refreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "REFRESH_TOKEN_INVALID",
		})
	}

	refreshKey := rediskeys.Refresh(jti)

	// 4. Validate JTI exists in Redis.
	storedSessionID, err := h.redis.Get(ctx, refreshKey)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	if storedSessionID == "" {
		// JTI not found — possible replay attack.
		// We need the session_id to revoke the chain. Extract it from the token format.
		// Since we can't get it from Redis (key is gone), we parse it from the cookie.
		// The session_id is not embedded in the cookie — we can only log the JTI.
		ip := c.IP()
		h.audit.Emit(ctx, audit.EventRefreshTokenReplayDetected, false,
			audit.WithAdminIP(ip),
			audit.WithDetails(map[string]interface{}{
				"jti":      jti,
				"severity": "CRITICAL",
			}),
		)

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "REFRESH_TOKEN_INVALID",
		})
	}

	// Use the session_id from Redis (authoritative).
	sessionID := storedSessionID

	// 5. Rotate: DEL old JTI.
	if err := h.redis.Del(ctx, refreshKey); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "INTERNAL_ERROR")
	}

	// 6. Retrieve session metadata for geo/device info.
	sessionKey := rediskeys.Session(sessionID)
	sessionData, err := h.redis.Get(ctx, sessionKey)
	if err != nil || sessionData == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "REFRESH_TOKEN_INVALID",
		})
	}

	geoRegion, deviceFP := parseSessionData(sessionData)

	// 7. Issue new access JWT + new refresh token.
	newAccessToken, newJTI, err := h.issueAccessJWT(sessionID, geoRegion, deviceFP)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "TOKEN_GENERATION_FAILED")
	}

	newRefreshToken, err := h.issueRefreshToken(ctx, newJTI, sessionID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "TOKEN_GENERATION_FAILED")
	}

	// 8. Set new refresh token cookie.
	setRefreshCookie(c, newRefreshToken, int(h.cfg.RefreshTokenTTL.Seconds()))

	return c.Status(fiber.StatusOK).JSON(loginResponse{
		AccessToken: newAccessToken,
		SessionID:   sessionID,
		ExpiresIn:   900,
	})
}

// Logout handles POST /api/admin/logout.
//
// Flow:
//  1. CSRF check
//  2. Read refresh token from cookie
//  3. DEL refresh:{jti} and session:{session_id}
//  4. Clear cookie
func (h *Handler) Logout(c *fiber.Ctx) error {
	ctx := context.Background()

	// 1. CSRF check.
	if err := h.checkCSRF(c); err != nil {
		return err
	}

	// 2. Read refresh token from cookie.
	refreshToken := c.Cookies(refreshCookieName)
	if refreshToken != "" {
		jti, _, err := parseRefreshToken(refreshToken)
		if err == nil {
			// 3. Look up session_id from Redis, then DEL both keys.
			refreshKey := rediskeys.Refresh(jti)
			sessionID, _ := h.redis.Get(ctx, refreshKey)
			if sessionID != "" {
				sessionKey := rediskeys.Session(sessionID)
				_ = h.redis.Del(ctx, refreshKey, sessionKey)
			} else {
				_ = h.redis.Del(ctx, refreshKey)
			}
		}
	}

	// 4. Clear cookie.
	clearRefreshCookie(c)

	return c.SendStatus(fiber.StatusOK)
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

// issueAccessJWT creates a signed AdminClaims JWT.
// Returns the signed token string and the JTI (used as the refresh token identifier).
func (h *Handler) issueAccessJWT(sessionID, geoRegion, deviceFP string) (tokenStr, jti string, err error) {
	jti = uuid.New().String()
	now := time.Now().UTC()
	exp := now.Add(h.cfg.AccessTokenTTL)

	claims := models.AdminClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Role:              "admin",
		SessionID:         sessionID,
		GeoRegion:         geoRegion,
		DeviceFingerprint: deviceFP,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err = token.SignedString([]byte(h.cfg.JWTSecret))
	return tokenStr, jti, err
}

// issueRefreshToken generates a 32-byte cryptographically random refresh token,
// stores refresh:{jti} = session_id in Redis with RefreshTokenTTL, and returns
// the encoded token string (format: "{jti}:{hex_random}").
func (h *Handler) issueRefreshToken(ctx context.Context, jti, sessionID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: failed to generate refresh token: %w", err)
	}

	refreshKey := rediskeys.Refresh(jti)
	if err := h.redis.Set(ctx, refreshKey, sessionID, h.cfg.RefreshTokenTTL); err != nil {
		return "", fmt.Errorf("auth: failed to store refresh token: %w", err)
	}

	// Encode as "jti:hex_random" so we can extract JTI from the cookie later.
	return jti + ":" + hex.EncodeToString(raw), nil
}

// ---------------------------------------------------------------------------
// CSRF helpers
// ---------------------------------------------------------------------------

// checkCSRF verifies the Origin header matches the expected host.
// Returns a 403 fiber error if the check fails.
func (h *Handler) checkCSRF(c *fiber.Ctx) error {
	origin := c.Get("Origin")
	if origin == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "CSRF_DETECTED",
		})
	}

	// Build expected origin from the request host.
	// Accept both http and https schemes to handle reverse-proxy scenarios.
	host := c.Hostname()
	if origin != "https://"+host && origin != "http://"+host {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "CSRF_DETECTED",
		})
	}

	return nil
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

func setRefreshCookie(c *fiber.Ctx, token string, maxAgeSecs int) {
	c.Cookie(&fiber.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
		MaxAge:   maxAgeSecs,
		Path:     "/api/admin",
	})
}

func clearRefreshCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
		MaxAge:   0,
		Path:     "/api/admin",
	})
}

// ---------------------------------------------------------------------------
// Geo / device fingerprint helpers
// ---------------------------------------------------------------------------

// geoRegionFromRequest extracts the country code from the CF-IPCountry header
// (set by Cloudflare) or returns "unknown".
func geoRegionFromRequest(c *fiber.Ctx) string {
	if region := c.Get("CF-IPCountry"); region != "" {
		return region
	}
	return "unknown"
}

// deviceFingerprint computes SHA-256(User-Agent + Accept-Language) and returns
// the full hex-encoded hash as a compact fingerprint.
func deviceFingerprint(c *fiber.Ctx) string {
	ua := c.Get("User-Agent")
	al := c.Get("Accept-Language")
	h := sha256.Sum256([]byte(ua + al))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// Refresh token parsing
// ---------------------------------------------------------------------------

// parseRefreshToken splits a refresh token string of the form "jti:hex_random"
// and returns the JTI. The second return value is always empty — the authoritative
// session_id is stored in Redis under refresh:{jti}.
func parseRefreshToken(token string) (jti, sessionID string, err error) {
	// Format: "{uuid_jti}:{hex_random_32bytes}"
	// UUID v4 is 36 chars, colon separator, then 64 hex chars.
	if len(token) < 38 {
		return "", "", fmt.Errorf("auth: refresh token too short")
	}
	// The UUID separator is at position 36.
	sep := 36
	if token[sep] != ':' {
		return "", "", fmt.Errorf("auth: refresh token malformed")
	}
	jti = token[:sep]
	return jti, "", nil
}

// ---------------------------------------------------------------------------
// Session data parsing
// ---------------------------------------------------------------------------

// parseSessionData extracts geo_region and device_fingerprint from the minimal
// JSON stored in Redis under session:{session_id}.
// Format: {"geo_region":"XX","device_fingerprint":"..."}
func parseSessionData(data string) (geoRegion, deviceFP string) {
	geoRegion = extractJSONStringField(data, "geo_region")
	deviceFP = extractJSONStringField(data, "device_fingerprint")
	if geoRegion == "" {
		geoRegion = "unknown"
	}
	return geoRegion, deviceFP
}

// extractJSONStringField extracts a string value from a simple flat JSON object
// for the given key. Returns "" if not found.
func extractJSONStringField(jsonStr, key string) string {
	needle := `"` + key + `":"`
	idx := indexOfStr(jsonStr, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := indexOfStr(jsonStr[start:], `"`)
	if end < 0 {
		return ""
	}
	return jsonStr[start : start+end]
}

// indexOfStr returns the index of substr in s, or -1 if not found.
func indexOfStr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
