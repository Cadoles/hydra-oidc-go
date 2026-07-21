// Package metrics exposes Prometheus instrumentation: HTTP request counts and
// latencies, and login outcomes. All metrics live on an injected registry so
// tests get an isolated one.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Login outcome label values.
const (
	LoginSuccess      = "success"
	LoginInvalid      = "invalid_credentials"
	LoginTechnical    = "technical_error"
	LoginAltchaFailed = "altcha_failed"
	LoginRateLimited  = "rate_limited"
)

// Metrics holds the registered collectors.
type Metrics struct {
	reg          prometheus.Registerer
	gatherer     prometheus.Gatherer
	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	logins       *prometheus.CounterVec
}

// New registers the collectors on reg. Pass a fresh prometheus.NewRegistry()
// (which is both Registerer and Gatherer) in production and in tests.
func New(reg *prometheus.Registry) *Metrics {
	m := &Metrics{
		reg:      reg,
		gatherer: reg,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by method, route and status.",
		}, []string{"method", "route", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency by method and route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		logins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Login attempts by outcome.",
		}, []string{"result"}),
	}
	reg.MustRegister(m.httpRequests, m.httpDuration, m.logins)
	return m
}

// Handler serves the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
}

// Middleware records request count and latency, labeled by the matched chi
// route pattern (available after the request is served).
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unknown"
		}
		m.httpRequests.WithLabelValues(r.Method, route, strconv.Itoa(ww.Status())).Inc()
		m.httpDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

// LoginOutcome counts a login attempt result (use the Login* constants).
func (m *Metrics) LoginOutcome(result string) {
	m.logins.WithLabelValues(result).Inc()
}
