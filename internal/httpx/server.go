// Package httpx is the HTTP layer: the chi router and the stateless OIDC-bridge
// handlers (login → upstream → callback → consent → logout). No server-side
// session is used; cross-redirect state travels in encrypted cookies (see
// package flowstate).
package httpx

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/RudyMCh/hydra-oidc-go/internal/config"
	"github.com/RudyMCh/hydra-oidc-go/internal/flowstate"
	"github.com/RudyMCh/hydra-oidc-go/internal/hydra"
	"github.com/RudyMCh/hydra-oidc-go/internal/metrics"
	"github.com/RudyMCh/hydra-oidc-go/internal/obs"
	"github.com/RudyMCh/hydra-oidc-go/internal/upstream"
)

// Route paths. The returns from the provider are served at CALLBACK_PATH and
// LOGOUT_CALLBACK_PATH, which (prefixed with BASE_URL) are also the upstream
// redirect_uri and post_logout_redirect_uri.
const (
	LoginPath   = "/login"
	ConsentPath = "/consent"
	LogoutPath  = "/logout"
)

// Deps are the collaborators a Server needs.
type Deps struct {
	Config   *config.Config
	Hydra    hydra.Client
	Upstream *upstream.Client
	Flow     *flowstate.Manager
	Metrics  *metrics.Metrics
	Reporter obs.Reporter
	Logger   *slog.Logger
}

// Server holds the HTTP handlers and their dependencies.
type Server struct {
	Deps
}

// New builds a Server.
func New(d Deps) *Server {
	if d.Reporter == nil {
		d.Reporter = obs.Noop{}
	}
	if d.Metrics == nil {
		d.Metrics = metrics.New(prometheus.NewRegistry())
	}
	return &Server{Deps: d}
}

// Routes returns the configured router.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(s.Metrics.Middleware)

	r.Get("/health", s.health)
	r.Handle("/metrics", s.Metrics.Handler())
	r.Get(LoginPath, s.login)
	r.Get(s.Config.CallbackPath, s.callback)
	r.Get(ConsentPath, s.consent)
	r.Get(LogoutPath, s.logout)
	r.Get(s.Config.LogoutCallbackPath, s.logoutCallback)
	return r
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("healthy"))
}

// fail logs the underlying error and writes a plain status to the client.
func (s *Server) fail(w http.ResponseWriter, status int, msg string, err error) {
	if err != nil {
		s.Logger.Error(msg, "err", err, "status", status)
		if status >= 500 {
			s.Reporter.Capture(err)
		}
	}
	http.Error(w, msg, status)
}
