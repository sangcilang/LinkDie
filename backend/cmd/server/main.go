package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"

	"ephemeral-share/backend/internal/audit"
	"ephemeral-share/backend/internal/auth"
	"ephemeral-share/backend/internal/config"
	"ephemeral-share/backend/internal/download"
	"ephemeral-share/backend/internal/health"
	"ephemeral-share/backend/internal/metrics"
	"ephemeral-share/backend/internal/middleware"
	"ephemeral-share/backend/internal/storage"
	"ephemeral-share/backend/internal/store"
	"ephemeral-share/backend/internal/upload"
	"ephemeral-share/backend/internal/worker"
)

func main() {
	// ---------------------------------------------------------------------------
	// 1. Load configuration
	// ---------------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// ---------------------------------------------------------------------------
	// 2. Register Prometheus metrics
	// ---------------------------------------------------------------------------
	if err := metrics.Register(); err != nil {
		log.Fatalf("failed to register metrics: %v", err)
	}

	// ---------------------------------------------------------------------------
	// 3. Create Redis client
	// ---------------------------------------------------------------------------
	redisClient, err := store.NewRedisClient(cfg)
	if err != nil {
		log.Fatalf("failed to create Redis client: %v", err)
	}

	// ---------------------------------------------------------------------------
	// 4. Create S3 client
	// ---------------------------------------------------------------------------
	s3Client, err := storage.NewS3Client(cfg)
	if err != nil {
		log.Fatalf("failed to create S3 client: %v", err)
	}

	// ---------------------------------------------------------------------------
	// 5. Create audit logger
	// ---------------------------------------------------------------------------
	auditLogger := audit.NewLogger()

	// ---------------------------------------------------------------------------
	// 6. Create handlers
	// ---------------------------------------------------------------------------
	authHandler := auth.NewHandler(cfg, redisClient, auditLogger)
	uploadHandler := upload.NewHandler(cfg, redisClient, s3Client, auditLogger)
	downloadHandler := download.NewHandler(cfg, redisClient, s3Client, auditLogger)
	healthHandler := health.NewHandler(cfg, redisClient, s3Client)

	// ---------------------------------------------------------------------------
	// 7. Create and start cleanup worker
	// ---------------------------------------------------------------------------
	cleanupWorker := worker.NewWorker(cfg, redisClient, s3Client, auditLogger)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	cleanupWorker.Start(workerCtx)

	// ---------------------------------------------------------------------------
	// 8. Configure Fiber app with hardened settings
	// ---------------------------------------------------------------------------
	app := fiber.New(fiber.Config{
		BodyLimit:             cfg.BodyLimitMB * 1024 * 1024,
		ReadTimeout:           cfg.ReadTimeout,
		WriteTimeout:          cfg.WriteTimeout,
		DisableStartupMessage: true,
		StrictRouting:         true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": "INTERNAL_ERROR"})
		},
	})

	// ---------------------------------------------------------------------------
	// 9. Register global middleware
	// ---------------------------------------------------------------------------
	app.Use(middleware.SecurityHeaders())
	app.Use(middleware.ErrorSanitizer())

	// ---------------------------------------------------------------------------
	// 10. Register route groups
	// ---------------------------------------------------------------------------

	// /d/* — download page + enumeration detection + rate limit
	d := app.Group("/d")
	d.Use(middleware.TokenEnumerationDetection(redisClient, auditLogger))
	d.Use(middleware.RateLimit("download", 5, 60, redisClient))
	d.Get("/:token", downloadHandler.GetTokenMetadata)

	// /api/download/* — consume token
	apiDownload := app.Group("/api/download")
	apiDownload.Use(middleware.RateLimit("api", 30, 60, redisClient))
	apiDownload.Post("/:token", downloadHandler.ConsumeToken)

	// /api/admin/* — IP whitelist + rate limit
	admin := app.Group("/api/admin")
	admin.Use(auth.IPWhitelist(cfg))
	admin.Use(middleware.RateLimit("api", 30, 60, redisClient))
	admin.Post("/login", authHandler.Login)
	admin.Post("/refresh", authHandler.Refresh)
	admin.Post("/logout", authHandler.Logout)

	// Protected admin routes — require JWT
	adminProtected := admin.Group("/", auth.RequireAdmin(cfg, redisClient, auditLogger))
	adminProtected.Use(middleware.GlobalBackpressure(cfg, redisClient))

	// /request-upload gets its own tighter rate limit
	adminProtected.Post("/request-upload",
		middleware.RateLimit("request_upload", 5, 60, redisClient),
		uploadHandler.RequestUpload,
	)
	adminProtected.Post("/confirm-upload", uploadHandler.ConfirmUpload)
	adminProtected.Get("/tokens", uploadHandler.ListTokens)
	adminProtected.Delete("/tokens/:token_hash", uploadHandler.RevokeToken)

	// ---------------------------------------------------------------------------
	// 11. System routes
	// ---------------------------------------------------------------------------
	app.Get("/health", healthHandler.HealthCheck)
	app.Get("/metrics", metrics.MetricsHandler(cfg))
	app.Get("/expired", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "This link has expired or has already been used.",
		})
	})

	// ---------------------------------------------------------------------------
	// 12. Start server + graceful shutdown
	// ---------------------------------------------------------------------------
	go func() {
		if err := app.Listen(":" + cfg.Port); err != nil {
			log.Printf("server error: %v", err)
		}
	}()

	log.Printf("EphemeralShare %s listening on :%s", cfg.AppVersion, cfg.Port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Println("shutting down...")
	workerCancel()
	if err := app.ShutdownWithTimeout(30 * time.Second); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	redisClient.Close()
}
