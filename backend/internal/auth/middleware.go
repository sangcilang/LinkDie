package auth

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"ephemeral-share/backend/internal/audit"
	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/models"
	"ephemeral-share/backend/internal/rediskeys"
	"ephemeral-share/backend/internal/store"
)

// contextKeyAdminClaims is the Fiber locals key for storing AdminClaims.
const contextKeyAdminClaims = "admin_claims"

// RequireAdmin is a Fiber middleware that validates the Bearer JWT in the
// Authorization header and enforces session validity + geo anomaly detection.
//
// On success, the parsed *models.AdminClaims are stored in c.Locals("admin_claims").
func RequireAdmin(cfg *config.Config, redis *store.RedisClient, auditLogger *audit.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := context.Background()

		// 1. Extract Bearer token.
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "UNAUTHORIZED",
			})
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		// 2. Parse and validate JWT.
		claims := &models.AdminClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(fiber.StatusUnauthorized, "INVALID_TOKEN_ALGORITHM")
			}
			return []byte(cfg.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "UNAUTHORIZED",
			})
		}

		// 3. Validate role.
		if claims.Role != "admin" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "UNAUTHORIZED",
			})
		}

		// 4. Check session exists in Redis.
		sessionKey := rediskeys.Session(claims.SessionID)
		sessionData, err := redis.Get(ctx, sessionKey)
		if err != nil || sessionData == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "UNAUTHORIZED",
			})
		}

		// 5. Geo anomaly detection.
		storedGeoRegion, currentDeviceFP := parseSessionData(sessionData)
		if storedGeoRegion != "" && claims.GeoRegion != "" && storedGeoRegion != claims.GeoRegion {
			ip := c.IP()
			auditLogger.Emit(ctx, audit.EventSuspiciousActivity, false,
				audit.WithAdminIP(ip),
				audit.WithDetails(map[string]interface{}{
					"reason":           "geo_anomaly",
					"session_id":       claims.SessionID,
					"token_geo_region": claims.GeoRegion,
					"stored_geo_region": storedGeoRegion,
				}),
			)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "GEO_ANOMALY",
			})
		}

		// 6. Device fingerprint change detection (log only, don't reject).
		currentFP := deviceFingerprint(c)
		_ = currentDeviceFP // stored fingerprint from session data
		if claims.DeviceFingerprint != "" && currentFP != claims.DeviceFingerprint {
			ip := c.IP()
			auditLogger.Emit(ctx, audit.EventSuspiciousActivity, false,
				audit.WithAdminIP(ip),
				audit.WithDetails(map[string]interface{}{
					"reason":     "device_fingerprint_change",
					"session_id": claims.SessionID,
				}),
			)
			// Do NOT reject — log only.
		}

		// 7. Store claims in context for downstream handlers.
		c.Locals(contextKeyAdminClaims, claims)

		return c.Next()
	}
}

// GetAdminClaims retrieves the AdminClaims stored by RequireAdmin middleware.
// Returns nil if not present.
func GetAdminClaims(c *fiber.Ctx) *models.AdminClaims {
	claims, _ := c.Locals(contextKeyAdminClaims).(*models.AdminClaims)
	return claims
}

// IPWhitelist is a Fiber middleware that rejects requests from IPs not in the
// configured whitelist. If cfg.AdminAllowedIPs is empty, all IPs are allowed.
func IPWhitelist(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if len(cfg.AdminAllowedIPs) == 0 {
			return c.Next()
		}

		clientIP := c.IP()
		for _, allowed := range cfg.AdminAllowedIPs {
			if clientIP == allowed {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "IP_NOT_ALLOWED",
		})
	}
}
