// Command hydra-oidc is an Ory Hydra login app that bridges Hydra's
// login/consent/logout flow to an upstream OIDC provider (it acts as a Relying
// Party to a third-party IdP). It is stateless: no server-side session is kept;
// cross-redirect state travels in encrypted cookies (optionally Redis for the
// upstream id_token used at logout).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"

	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/config"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/flowstate"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/httpx"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/hydra"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/metrics"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/obs"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/upstream"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// .env is best-effort for local dev; real env vars always win.
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	reporter, flush, err := obs.Init(cfg.SentryDSN, cfg.SentryEnvironment, cfg.Version)
	if err != nil {
		return fmt.Errorf("init sentry: %w", err)
	}
	defer flush()

	ctx := context.Background()

	upstreamClient, err := upstream.New(ctx, cfg, cfg.BaseURL+httpx.CallbackPath)
	if err != nil {
		return fmt.Errorf("init upstream oidc: %w", err)
	}

	var store flowstate.Store
	if cfg.RedisDSN != "" {
		store, err = flowstate.NewRedisStore(cfg.RedisDSN, cfg.RedisPrefix)
		if err != nil {
			return fmt.Errorf("init redis: %w", err)
		}
		logger.Info("upstream id_token persisted in redis", "ttl", cfg.RedisTTL)
	} else {
		logger.Info("upstream id_token persisted in encrypted cookie (stateless)")
	}
	flow := flowstate.New(cfg.AppSecret, cfg.CookiePath, cfg.HTTPS(), store, cfg.RedisTTL)

	srvHandler := httpx.New(httpx.Deps{
		Config:   cfg,
		Hydra:    hydra.New(cfg.HydraAdminBaseURL, cfg.HydraAPIPathPrefix, 10*time.Second),
		Upstream: upstreamClient,
		Flow:     flow,
		Reporter: reporter,
		Metrics:  metrics.New(prometheus.NewRegistry()),
		Logger:   logger,
	}).Routes()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srvHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-stop:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "err", err)
	}
	logger.Info("stopped")
	return nil
}
