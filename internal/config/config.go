// Package config loads and validates application configuration from the
// environment. Validation happens once at boot so misconfiguration fails fast
// instead of per-request.
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the fully-resolved application configuration.
type Config struct {
	// HTTP server
	ListenAddr string `env:"LISTEN_ADDR" envDefault:":8080"`
	BaseURL    string `env:"BASE_URL,required"`
	// CookiePath scopes the flow cookies (set to the external sub-path, e.g.
	// /auth/oidc, when served behind a prefix).
	CookiePath string `env:"COOKIE_PATH" envDefault:"/"`
	// CallbackPath and LogoutCallbackPath are where the app serves the return
	// from the provider's login and logout. The provider is sent BASE_URL
	// followed by the path, and refuses a URL it was not declared: these let
	// the app take over the URLs already declared for another one.
	CallbackPath       string `env:"CALLBACK_PATH" envDefault:"/callback"`
	LogoutCallbackPath string `env:"LOGOUT_CALLBACK_PATH" envDefault:"/logout/callback"`

	// Logging. LOG_LEVEL sets the slog level: debug, info, warn, error.
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`

	// Ory Hydra admin API. HydraAPIPathPrefix replaces the SDK's "/admin" path
	// segment: keep "/admin" for a real Hydra v2 admin API, or set it to ""
	// when pointing at the Cadoles hydra-dispatcher (v1-style /oauth2 paths).
	// Resolved in Load via os.LookupEnv because caarlos0/env discards empty
	// values (an explicit HYDRA_API_PATH_PREFIX="" must win over the default).
	HydraAdminBaseURL  string `env:"HYDRA_ADMIN_BASE_URL,required"`
	HydraAPIPathPrefix string `env:"-"`

	// Upstream OIDC provider (the IdP this app bridges to).
	OIDCIssuer            string `env:"OIDC_ISSUER"` // optional: enables discovery
	OIDCAuthorizeEndpoint string `env:"OIDC_AUTHORIZE_ENDPOINT"`
	OIDCTokenEndpoint     string `env:"OIDC_TOKEN_ENDPOINT"`
	OIDCUserinfoEndpoint  string `env:"OIDC_USERINFO_ENDPOINT"`
	OIDCJWKSEndpoint      string `env:"OIDC_JWKS_ENDPOINT"`
	// OIDCLogoutEndpoint is the upstream RP-initiated logout endpoint. It may be
	// a plain URL or a printf template containing a single %s for the query
	// string (the original PHP app used the "...logout?%s" template form).
	OIDCLogoutEndpoint string `env:"OIDC_LOGOUT_ENDPOINT"`
	ClientID           string `env:"CLIENT_ID,required"`
	ClientSecret       string `env:"CLIENT_SECRET,required"`
	// Scopes requested upstream. OIDC_SCOPE is space-separated (e.g.
	// "openid identite_pivot email"), matching the original app.
	Scopes []string `env:"-"`
	// Extra authorize-request params to add (PARAMS_TO_INSERT, JSON object, e.g.
	// {"acr_values":"eidas1"}) or strip (PARAMS_TO_DELETE, JSON array).
	ParamsToInsert map[string]string `env:"-"`
	ParamsToDelete []string          `env:"-"`

	// Security knobs (strict by default; relax per-provider for quirky IdPs).
	PKCEEnabled        bool     `env:"OIDC_PKCE_ENABLED" envDefault:"true"`
	VerifySignature    bool     `env:"OIDC_VERIFY_SIGNATURE" envDefault:"true"`
	IDTokenSigningAlgs []string `env:"OIDC_ID_TOKEN_SIGNING_ALGS" envSeparator:","`
	SkipUserinfo       bool     `env:"OIDC_SKIP_USERINFO" envDefault:"false"`

	// Consent & claims. FilterClaimsByScope gates id_token claims by granted
	// scope; default false to match the original pass-through behavior.
	ConsentAutoAccept   bool              `env:"CONSENT_AUTO_ACCEPT" envDefault:"true"`
	ConsentRememberFor  int64             `env:"CONSENT_REMEMBER_FOR" envDefault:"0"`
	FilterClaimsByScope bool              `env:"FILTER_CLAIMS_BY_SCOPE" envDefault:"false"`
	ClaimScopes         map[string]string `env:"-"`
	AuthAMR             []string          `env:"-"`
	AuthACR             string            `env:"AUTH_ACR"`

	// RedirectOnErrorURL is where an error is shown, with ?status_code and
	// ?message; empty, the app answers a plain status.
	RedirectOnErrorURL string `env:"REDIRECT_ON_ERROR_URL"`
	// UpstreamLogoutOnError ends the provider's session before the error is
	// shown, when a login fails after the provider answered: the next attempt
	// then asks the provider for the identity again, instead of failing the
	// same way with the same one.
	UpstreamLogoutOnError bool `env:"UPSTREAM_LOGOUT_ON_ERROR" envDefault:"false"`

	// Optional Redis — used ONLY to hold the upstream id_token between login and
	// a (possibly much later) logout, keyed by an opaque session id. When unset,
	// the id_token rides in an encrypted cookie instead (fully stateless).
	RedisDSN    string        `env:"REDIS_DSN"`
	RedisPrefix string        `env:"HYDRA_OIDC_REDIS_PREFIX"`
	RedisTTL    time.Duration `env:"-"`

	// Cookies are signed AND encrypted with keys derived from this secret.
	AppSecret string `env:"APP_SECRET,required"`

	// Optional Sentry error reporting.
	SentryDSN         string `env:"SENTRY_DSN"`
	SentryEnvironment string `env:"SENTRY_ENVIRONMENT"`

	Version string `env:"VERSION"`
}

// Load reads and validates configuration from the environment.
func Load() (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, fmt.Errorf("parse environment: %w", err)
	}

	// Resolve manually so an explicit empty value (dispatcher mode) is honored;
	// caarlos0/env would otherwise treat "" as unset and apply the default.
	cfg.HydraAPIPathPrefix = "/admin"
	if v, ok := os.LookupEnv("HYDRA_API_PATH_PREFIX"); ok {
		cfg.HydraAPIPathPrefix = v
	}

	// OIDC_SCOPE is space-separated; default to just "openid".
	cfg.Scopes = []string{"openid"}
	if v, ok := os.LookupEnv("OIDC_SCOPE"); ok {
		if fields := strings.Fields(v); len(fields) > 0 {
			cfg.Scopes = fields
		}
	}

	// AUTH_AMR is comma-separated; default ["oidc"]. "" means advertise none.
	cfg.AuthAMR = []string{"oidc"}
	if v, ok := os.LookupEnv("AUTH_AMR"); ok {
		if v == "" {
			cfg.AuthAMR = nil
		} else {
			cfg.AuthAMR = splitComma(v)
		}
	}

	// PARAMS_TO_INSERT (JSON object) / PARAMS_TO_DELETE (JSON array).
	if v, ok := os.LookupEnv("PARAMS_TO_INSERT"); ok && strings.TrimSpace(v) != "" {
		if err := json.Unmarshal([]byte(v), &cfg.ParamsToInsert); err != nil {
			return nil, fmt.Errorf("parse PARAMS_TO_INSERT: %w", err)
		}
	}
	if v, ok := os.LookupEnv("PARAMS_TO_DELETE"); ok && strings.TrimSpace(v) != "" {
		if err := json.Unmarshal([]byte(v), &cfg.ParamsToDelete); err != nil {
			return nil, fmt.Errorf("parse PARAMS_TO_DELETE: %w", err)
		}
	}

	// CLAIM_SCOPES: "claim:scope,claim:scope". Default maps email→email; every
	// other claim defaults to the profile scope at filter time.
	cfg.ClaimScopes = map[string]string{"email": "email"}
	if v, ok := os.LookupEnv("CLAIM_SCOPES"); ok {
		cfg.ClaimScopes = parseClaimScopes(v)
	}

	// HYDRA_OIDC_REDIS_TTL is in seconds (default 3600), matching the original.
	cfg.RedisTTL = time.Hour
	if v, ok := os.LookupEnv("HYDRA_OIDC_REDIS_TTL"); ok && strings.TrimSpace(v) != "" {
		secs, err := time.ParseDuration(v + "s")
		if err != nil {
			return nil, fmt.Errorf("parse HYDRA_OIDC_REDIS_TTL (seconds): %w", err)
		}
		cfg.RedisTTL = secs
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks invariants that would otherwise blow up at request time.
func (c *Config) Validate() error {
	// Either discovery (issuer) or the explicit authorize+token endpoints.
	if c.OIDCIssuer == "" && (c.OIDCAuthorizeEndpoint == "" || c.OIDCTokenEndpoint == "") {
		return fmt.Errorf("set OIDC_ISSUER (discovery) or both OIDC_AUTHORIZE_ENDPOINT and OIDC_TOKEN_ENDPOINT")
	}
	// JWKS is needed to verify id_token signatures unless discovery provides it
	// or verification is explicitly disabled.
	if c.VerifySignature && c.OIDCIssuer == "" && c.OIDCJWKSEndpoint == "" {
		return fmt.Errorf("OIDC_VERIFY_SIGNATURE is on but no OIDC_ISSUER (discovery) or OIDC_JWKS_ENDPOINT is set")
	}
	// The lifetime of the upstream session is the age past which its cookie is
	// refused: zero would turn that check off, and keep the cookie for ever.
	if c.RedisTTL < time.Second {
		return fmt.Errorf("HYDRA_OIDC_REDIS_TTL must be at least one second")
	}
	if _, ok := parseSlogLevel(c.LogLevel); !ok {
		return fmt.Errorf("LOG_LEVEL %q is invalid (allowed: debug, info, warn, error)", c.LogLevel)
	}
	for name, p := range map[string]string{"CALLBACK_PATH": c.CallbackPath, "LOGOUT_CALLBACK_PATH": c.LogoutCallbackPath} {
		if err := validRoute(p); err != nil {
			return fmt.Errorf("%s %q: %w", name, p, err)
		}
	}
	if c.CallbackPath == c.LogoutCallbackPath {
		return fmt.Errorf("CALLBACK_PATH and LOGOUT_CALLBACK_PATH must differ")
	}
	if len(c.AppSecret) < 16 {
		return fmt.Errorf("APP_SECRET must be at least 16 bytes")
	}
	return nil
}

// reservedRoutes are the paths the app serves itself.
var reservedRoutes = []string{"/login", "/consent", "/logout", "/health", "/metrics"}

// validRoute checks a configurable path: absolute, literal (the router would
// read braces and stars as patterns), and not one of the app's own.
func validRoute(p string) error {
	if !strings.HasPrefix(p, "/") || p == "/" {
		return fmt.Errorf("must be a path starting with / and not / alone")
	}
	if strings.ContainsAny(p, "{}*?# \t") {
		return fmt.Errorf("must be a literal path, without query, fragment, space nor pattern")
	}
	for _, r := range reservedRoutes {
		if p == r {
			return fmt.Errorf("is a path of the app")
		}
	}
	return nil
}

// SlogLevel returns the level LOG_LEVEL names; Validate has refused an
// unknown one.
func (c *Config) SlogLevel() slog.Level {
	lvl, _ := parseSlogLevel(c.LogLevel)
	return lvl
}

// parseSlogLevel maps a name to an slog.Level; empty is info, the default.
func parseSlogLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, true
	case "debug":
		return slog.LevelDebug, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// HTTPS reports whether the public BaseURL is https (used to mark cookies Secure).
func (c *Config) HTTPS() bool {
	return strings.HasPrefix(c.BaseURL, "https://")
}

func parseClaimScopes(s string) map[string]string {
	out := make(map[string]string)
	for _, pair := range splitComma(s) {
		k, v, found := strings.Cut(strings.TrimSpace(pair), ":")
		if !found {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
