// Package config loads and validates application configuration from the
// environment. Validation happens once at boot so misconfiguration fails fast
// instead of per-request.
package config

import (
	"encoding/json"
	"fmt"
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

	// Ory Hydra admin API. HydraAPIPathPrefix replaces the SDK's "/admin" path
	// segment: keep "/admin" for a real Hydra v2 admin API, or set it to ""
	// when pointing at the Cadoles hydra-dispatcher (v1-style /oauth2 paths).
	// Resolved in Load via os.LookupEnv because caarlos0/env discards empty
	// values (an explicit HYDRA_API_PATH_PREFIX="" must win over the default).
	HydraAdminBaseURL  string `env:"HYDRA_ADMIN_BASE_URL,required"`
	HydraAPIPathPrefix string `env:"-"`

	// Upstream OIDC provider (the IdP this app bridges to).
	OIDCIssuer            string `env:"OIDC_ISSUER"` // optional: enables discovery
	OIDCAuthorizeEndpoint string `env:"OIC_AUTHORIZE_ENDPOINT"`
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

	// Redirects
	PostLogoutRedirectURL string `env:"POST_LOGOUT_REDIRECT_URL"`
	RedirectOnErrorURL    string `env:"REDIRECT_ON_ERROR_URL"`

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

	TrustedProxies []string `env:"TRUSTED_PROXIES" envSeparator:","`
	Version        string   `env:"VERSION"`
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
		return fmt.Errorf("set OIDC_ISSUER (discovery) or both OIC_AUTHORIZE_ENDPOINT and OIDC_TOKEN_ENDPOINT")
	}
	// JWKS is needed to verify id_token signatures unless discovery provides it
	// or verification is explicitly disabled.
	if c.VerifySignature && c.OIDCIssuer == "" && c.OIDCJWKSEndpoint == "" {
		return fmt.Errorf("OIDC_VERIFY_SIGNATURE is on but no OIDC_ISSUER (discovery) or OIDC_JWKS_ENDPOINT is set")
	}
	if len(c.AppSecret) < 16 {
		return fmt.Errorf("APP_SECRET must be at least 16 bytes")
	}
	return nil
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
