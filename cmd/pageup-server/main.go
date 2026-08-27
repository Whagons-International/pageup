package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	pageupserver "github.com/desarso/pageup/internal/server"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	maxPageBytes := int64(5 << 20)
	if value := os.Getenv("PAGEUP_MAX_PAGE_BYTES"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed <= 0 {
			logger.Error("invalid PAGEUP_MAX_PAGE_BYTES", "value", value)
			os.Exit(1)
		}
		maxPageBytes = parsed
	}
	service, err := pageupserver.New(pageupserver.Config{
		DataDir:       envOr("PAGEUP_DATA_DIR", "/data"),
		PublicURL:     os.Getenv("PAGEUP_PUBLIC_URL"),
		DownloadsDir:  envOr("PAGEUP_DOWNLOADS_DIR", "/app/downloads"),
		BootstrapKeys: os.Getenv("PAGEUP_BOOTSTRAP_KEYS"),
		MaxPageBytes:  maxPageBytes,
		Version:       version,
		Logger:        logger,
		Authorizer: pageupserver.NewWhagonsDeveloperAuthorizer(
			envOr("PAGEUP_WHAGONS_AUTH_URL", "https://gonvex.whagons.com/api/internal/pageup/authorize"),
			envOr("PAGEUP_WHAGONS_PROJECT_ID", "whagons-5"),
		),
		S3: pageupserver.S3Config{
			Endpoint:        os.Getenv("PAGEUP_S3_ENDPOINT"),
			Region:          envOr("PAGEUP_S3_REGION", "us-east-1"),
			Bucket:          os.Getenv("PAGEUP_S3_BUCKET"),
			AccessKeyID:     os.Getenv("PAGEUP_S3_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("PAGEUP_S3_SECRET_ACCESS_KEY"),
			Prefix:          os.Getenv("PAGEUP_S3_PREFIX"),
		},
	})
	if err != nil {
		logger.Error("initialize server", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              envOr("PAGEUP_LISTEN_ADDR", ":8080"),
		Handler:           service.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("graceful shutdown", "error", err)
		}
	}()

	logger.Info("pageup listening", "address", server.Addr, "version", version)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
