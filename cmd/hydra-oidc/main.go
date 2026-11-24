// Command hydra-oidc is an Ory Hydra login app that bridges Hydra's
// login/consent/logout flow to an upstream OIDC provider (it acts as a Relying
// Party to a third-party IdP). It is stateless: no server-side session is kept;
// cross-redirect state travels in encrypted cookies, the upstream id_token used
// at logout included.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/Cadoles/hydra-oidc-go/internal/config"
	"github.com/Cadoles/hydra-oidc-go/internal/flowstate"
	"github.com/Cadoles/hydra-oidc-go/internal/httpx"
	"github.com/Cadoles/hydra-oidc-go/internal/hydra"
	"github.com/Cadoles/hydra-oidc-go/internal/metrics"
	"github.com/Cadoles/hydra-oidc-go/internal/obs"
	"github.com/Cadoles/hydra-oidc-go/internal/upstream"
)

// version is the release, set at build time (-ldflags -X main.version=…).
var version = "dev"

func main() {
	// "healthcheck" probes the server of this configuration: the image has no
	// shell nor curl for its HEALTHCHECK.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		// The configured logger may not exist yet.
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).Error("fatal", "err", err)
		os.Exit(1)
	}
}

// healthcheck asks /health of the server listening on LISTEN_ADDR.
func healthcheck() error {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: status %d", resp.StatusCode)
	}
	return nil
}

func run() error {
	// .env is best-effort for local dev; real env vars always win.
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.Version == "" {
		cfg.Version = version
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	slog.SetDefault(logger)
	logger.Info("starting", "version", cfg.Version, "log_level", cfg.SlogLevel().String(),
		"callback_path", cfg.CallbackPath, "logout_callback_path", cfg.LogoutCallbackPath,
		"session_ttl", cfg.SessionTTL.String())

	reporter, flush, err := obs.Init(cfg.SentryDSN, cfg.SentryEnvironment, cfg.Version)
	if err != nil {
		return fmt.Errorf("init sentry: %w", err)
	}
	defer flush()

	ctx := context.Background()

	upstreamClient, err := upstream.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("init upstream oidc: %w", err)
	}

	flow := flowstate.New(cfg.AppSecret, cfg.CookiePath, cfg.HTTPS(), cfg.SessionTTL)

	srvHandler := httpx.New(httpx.Deps{
		Config:   cfg,
		Hydra:    hydra.New(cfg.HydraAdminBaseURL, cfg.HydraAPIPathPrefix, 10*time.Second, logger),
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
