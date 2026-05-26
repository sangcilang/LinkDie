// Package health implements the GET /health endpoint for EphemeralShare.
// It checks Redis and S3 connectivity and returns a HealthResponse JSON body.
// No authentication or rate limiting is applied to this endpoint.
package health

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"

	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/models"
	"ephemeral-share/backend/internal/storage"
	"ephemeral-share/backend/internal/store"
)

// Handler holds dependencies for the health check HTTP handler.
type Handler struct {
	cfg   *config.Config
	redis *store.RedisClient
	s3    *storage.S3Client
}

// NewHandler creates a new health Handler.
func NewHandler(cfg *config.Config, redis *store.RedisClient, s3 *storage.S3Client) *Handler {
	return &Handler{
		cfg:   cfg,
		redis: redis,
		s3:    s3,
	}
}

// HealthCheck handles GET /health.
//
// It pings Redis and S3 concurrently and returns:
//   - 200 {"status":"ok","redis":"ok","storage":"ok","version":"..."} when both healthy
//   - 503 {"status":"degraded",...} when one or both dependencies are unavailable
func (h *Handler) HealthCheck(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping Redis and S3 concurrently.
	type result struct {
		err error
	}

	redisCh := make(chan result, 1)
	s3Ch := make(chan result, 1)

	go func() {
		redisCh <- result{err: h.redis.HealthCheck(ctx)}
	}()

	go func() {
		s3Ch <- result{err: h.s3.HealthCheck(ctx)}
	}()

	redisResult := <-redisCh
	s3Result := <-s3Ch

	redisStatus := "ok"
	if redisResult.err != nil {
		redisStatus = "unavailable"
	}

	storageStatus := "ok"
	if s3Result.err != nil {
		storageStatus = "unavailable"
	}

	overallStatus := "ok"
	httpStatus := fiber.StatusOK
	if redisResult.err != nil || s3Result.err != nil {
		overallStatus = "degraded"
		httpStatus = fiber.StatusServiceUnavailable
	}

	resp := models.HealthResponse{
		Status:  overallStatus,
		Redis:   redisStatus,
		Storage: storageStatus,
		Version: h.cfg.AppVersion,
	}

	return c.Status(httpStatus).JSON(resp)
}
