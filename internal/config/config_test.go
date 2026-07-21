package config

import "testing"

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
	t.Setenv("OIC_AUTHORIZE_ENDPOINT", "https://idp/authorize")
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
	t.Setenv("OIC_AUTHORIZE_ENDPOINT", "https://idp/authorize")
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
	t.Setenv("OIC_AUTHORIZE_ENDPOINT", "https://idp/authorize")
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
