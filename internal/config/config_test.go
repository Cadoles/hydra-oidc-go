package config

import (
	"log/slog"
	"testing"
)

func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BASE_URL", "https://oidc.example.test")
	t.Setenv("APP_SECRET", "test-secret-test-secret")
	t.Setenv("HYDRA_ADMIN_BASE_URL", "http://hydra:4445")
	t.Setenv("CLIENT_ID", "client")
	t.Setenv("CLIENT_SECRET", "secret")
}

func TestLoadExplicitEndpoints(t *testing.T) {
	baseEnv(t)
	t.Setenv("OIDC_AUTHORIZE_ENDPOINT", "https://idp/authorize")
	t.Setenv("OIDC_TOKEN_ENDPOINT", "https://idp/token")
	t.Setenv("OIDC_JWKS_ENDPOINT", "https://idp/jwks")
	t.Setenv("OIDC_SCOPE", "openid identite_pivot email")
	t.Setenv("PARAMS_TO_INSERT", `{"acr_values":"eidas1"}`)
	t.Setenv("HYDRA_API_PATH_PREFIX", "") // dispatcher mode: empty must win

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HydraAPIPathPrefix != "" {
		t.Errorf("HYDRA_API_PATH_PREFIX empty should win, got %q", cfg.HydraAPIPathPrefix)
	}
	if len(cfg.Scopes) != 3 || cfg.Scopes[1] != "identite_pivot" {
		t.Errorf("scopes parse (space-separated) failed: %#v", cfg.Scopes)
	}
	if cfg.ParamsToInsert["acr_values"] != "eidas1" {
		t.Errorf("PARAMS_TO_INSERT parse failed: %#v", cfg.ParamsToInsert)
	}
	if !cfg.HTTPS() {
		t.Errorf("HTTPS() should be true for https BaseURL")
	}
	if len(cfg.AuthAMR) != 1 || cfg.AuthAMR[0] != "oidc" {
		t.Errorf("AUTH_AMR default should be [oidc], got %#v", cfg.AuthAMR)
	}
}

func TestLoadScopesDefault(t *testing.T) {
	baseEnv(t)
	t.Setenv("OIDC_ISSUER", "") // use explicit, but provide them
	t.Setenv("OIDC_AUTHORIZE_ENDPOINT", "https://idp/authorize")
	t.Setenv("OIDC_TOKEN_ENDPOINT", "https://idp/token")
	t.Setenv("OIDC_JWKS_ENDPOINT", "https://idp/jwks")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "openid" {
		t.Errorf("default scope should be [openid], got %#v", cfg.Scopes)
	}
}

func TestValidateRequiresIssuerOrEndpoints(t *testing.T) {
	baseEnv(t)
	// Neither issuer nor explicit endpoints → invalid.
	if _, err := Load(); err == nil {
		t.Fatalf("expected error when neither OIDC_ISSUER nor endpoints are set")
	}
}

func TestValidateRequiresJWKSWhenVerifying(t *testing.T) {
	baseEnv(t)
	t.Setenv("OIDC_AUTHORIZE_ENDPOINT", "https://idp/authorize")
	t.Setenv("OIDC_TOKEN_ENDPOINT", "https://idp/token")
	// VerifySignature defaults true, no issuer, no JWKS → invalid.
	if _, err := Load(); err == nil {
		t.Fatalf("expected error: verifying signatures needs issuer or JWKS endpoint")
	}
	// Disabling verification removes the requirement.
	t.Setenv("OIDC_VERIFY_SIGNATURE", "false")
	if _, err := Load(); err != nil {
		t.Fatalf("with verification off it should load: %v", err)
	}
}

// The lifetime of the upstream session must be positive: zero would turn the
// age check of its cookie off.
func TestValidateSessionLifetime(t *testing.T) {
	for value, ok := range map[string]bool{"7200": true, "1": true, "0": false, "-5": false, "abc": false} {
		t.Run(value, func(t *testing.T) {
			baseEnv(t)
			t.Setenv("OIDC_ISSUER", "https://idp")
			t.Setenv("HYDRA_OIDC_REDIS_TTL", value)
			cfg, err := Load()
			if (err == nil) != ok {
				t.Fatalf("Load: err = %v, want accepted: %v", err, ok)
			}
			if ok && cfg.RedisTTL.Seconds() < 1 {
				t.Errorf("RedisTTL = %v", cfg.RedisTTL)
			}
		})
	}
}

func TestLoadOptions(t *testing.T) {
	baseEnv(t)
	t.Setenv("OIDC_ISSUER", "https://idp")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CallbackPath != "/callback" || cfg.LogoutCallbackPath != "/logout/callback" || cfg.UpstreamLogoutOnError || cfg.SlogLevel() != slog.LevelInfo {
		t.Errorf("defaults: %q %q %v %v", cfg.CallbackPath, cfg.LogoutCallbackPath, cfg.UpstreamLogoutOnError, cfg.SlogLevel())
	}

	t.Setenv("CALLBACK_PATH", "/connect/oidc/check")
	t.Setenv("LOGOUT_CALLBACK_PATH", "/logout-done")
	t.Setenv("UPSTREAM_LOGOUT_ON_ERROR", "true")
	t.Setenv("LOG_LEVEL", "Debug")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CallbackPath != "/connect/oidc/check" || cfg.LogoutCallbackPath != "/logout-done" || !cfg.UpstreamLogoutOnError || cfg.SlogLevel() != slog.LevelDebug {
		t.Errorf("set: %q %q %v %v", cfg.CallbackPath, cfg.LogoutCallbackPath, cfg.UpstreamLogoutOnError, cfg.SlogLevel())
	}
}

func TestValidateOptions(t *testing.T) {
	for name, env := range map[string][2]string{
		"relative callback":      {"CALLBACK_PATH", "callback"},
		"root":                   {"CALLBACK_PATH", "/"},
		"a pattern":              {"CALLBACK_PATH", "/cb/{id}"},
		"a wildcard":             {"LOGOUT_CALLBACK_PATH", "/cb/*"},
		"a query":                {"CALLBACK_PATH", "/cb?x=1"},
		"a path of the app":      {"CALLBACK_PATH", "/login"},
		"the logout of the app":  {"LOGOUT_CALLBACK_PATH", "/logout"},
		"both returns the same":  {"LOGOUT_CALLBACK_PATH", "/callback"},
		"an unknown log level":   {"LOG_LEVEL", "verbose"},
		"the former name, alone": {"OIC_AUTHORIZE_ENDPOINT", "https://idp/authorize"},
	} {
		t.Run(name, func(t *testing.T) {
			baseEnv(t)
			if env[0] != "OIC_AUTHORIZE_ENDPOINT" {
				t.Setenv("OIDC_ISSUER", "https://idp")
			} else {
				t.Setenv("OIDC_TOKEN_ENDPOINT", "https://idp/token")
				t.Setenv("OIDC_JWKS_ENDPOINT", "https://idp/jwks")
			}
			t.Setenv(env[0], env[1])
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%q: expected an error", env[0], env[1])
			}
		})
	}
}
