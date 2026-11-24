package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/RudyMCh/hydra-oidc-go/internal/config"
	"github.com/RudyMCh/hydra-oidc-go/internal/oidctest"
)

// testClient builds a client on explicit endpoints (no discovery), signatures
// verified.
func testClient(t *testing.T, idp *oidctest.Provider, mutate func(*config.Config)) *Client {
	t.Helper()
	cfg := &config.Config{
		ClientID:              oidctest.ClientID,
		ClientSecret:          "secret",
		BaseURL:               "https://app.test",
		OIDCAuthorizeEndpoint: idp.URL + "/authorize",
		OIDCTokenEndpoint:     idp.URL + "/token",
		OIDCJWKSEndpoint:      idp.URL + "/jwks",
		OIDCUserinfoEndpoint:  idp.URL + "/userinfo",
		Scopes:                []string{"openid", "email"},
		PKCEEnabled:           true,
		VerifySignature:       true,
	}
	if mutate != nil {
		mutate(cfg)
	}
	c, err := New(context.Background(), cfg, "https://app.test/callback")
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return c
}

func idClaims(mutate func(map[string]any)) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"iss": "https://idp.test", "aud": oidctest.ClientID, "sub": "user-123",
		"nonce": "nonce-ok", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"email": "u@example.test", "given_name": "Ada",
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

func withIDToken(raw string) *oauth2.Token {
	return (&oauth2.Token{AccessToken: "at"}).WithExtra(map[string]any{"id_token": raw})
}

func TestAuthCodeURL(t *testing.T) {
	idp := oidctest.New(t)
	c := testClient(t, idp, func(cfg *config.Config) {
		cfg.ParamsToInsert = map[string]string{"acr_values": "eidas1"}
	})
	raw := c.AuthCodeURL("state-1", "nonce-1", "verifier-1234567890")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	checks := map[string]string{
		"client_id":             oidctest.ClientID,
		"state":                 "state-1",
		"nonce":                 "nonce-1",
		"redirect_uri":          "https://app.test/callback",
		"code_challenge_method": "S256",
		"acr_values":            "eidas1",
		"response_type":         "code",
	}
	for k, want := range checks {
		if q.Get(k) != want {
			t.Errorf("authorize param %q = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("code_challenge") == "" {
		t.Errorf("expected a PKCE code_challenge")
	}
	if q.Get("scope") == "" {
		t.Errorf("expected scope param")
	}
}

func TestVerifyIDToken(t *testing.T) {
	idp := oidctest.New(t)
	c := testClient(t, idp, nil)
	tokenStr := idp.Sign(t, "RS256", idClaims(nil))
	tok := withIDToken(tokenStr)

	raw, sub, claims, err := c.VerifyIDToken(context.Background(), tok, "nonce-ok")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if raw != tokenStr {
		t.Errorf("raw id_token not returned verbatim")
	}
	if sub != "user-123" {
		t.Errorf("subject = %q, want user-123", sub)
	}
	if claims["email"] != "u@example.test" {
		t.Errorf("claims missing email: %#v", claims)
	}

	// Wrong nonce must fail.
	if _, _, _, err := c.VerifyIDToken(context.Background(), tok, "nonce-WRONG"); err == nil {
		t.Errorf("expected nonce mismatch error")
	}
}

func TestVerifyIDTokenRejects(t *testing.T) {
	idp := oidctest.New(t)
	cases := []struct {
		name  string
		algs  []string
		token func() string
	}{
		{"another audience", nil, func() string {
			return idp.Sign(t, "RS256", idClaims(func(c map[string]any) { c["aud"] = "someone-else" }))
		}},
		{"expired", nil, func() string {
			return idp.Sign(t, "RS256", idClaims(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }))
		}},
		{"a key the provider does not publish", nil, func() string {
			return idp.SignForeign(t, idClaims(nil))
		}},
		// Without discovery nor OIDC_ID_TOKEN_SIGNING_ALGS, RS256 only.
		{"ES256 not allowed", nil, func() string {
			return idp.Sign(t, "ES256", idClaims(nil))
		}},
		{"RS256 when ES256 alone is allowed", []string{"ES256"}, func() string {
			return idp.Sign(t, "RS256", idClaims(nil))
		}},
		{"no id_token", nil, func() string { return "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, idp, func(cfg *config.Config) { cfg.IDTokenSigningAlgs = tc.algs })
			if _, _, _, err := c.VerifyIDToken(context.Background(), withIDToken(tc.token()), "nonce-ok"); err == nil {
				t.Errorf("expected the id_token to be refused")
			}
		})
	}
}

func TestVerifyIDTokenES256(t *testing.T) {
	idp := oidctest.New(t)
	c := testClient(t, idp, func(cfg *config.Config) { cfg.IDTokenSigningAlgs = []string{"ES256"} })
	_, sub, _, err := c.VerifyIDToken(context.Background(), withIDToken(idp.Sign(t, "ES256", idClaims(nil))), "nonce-ok")
	if err != nil || sub != "user-123" {
		t.Fatalf("VerifyIDToken: sub=%q err=%v", sub, err)
	}
}

// With discovery the issuer is checked, and the algorithms are the provider's.
func TestVerifyIDTokenDiscovery(t *testing.T) {
	idp := oidctest.New(t)
	c := testClient(t, idp, func(cfg *config.Config) {
		cfg.OIDCIssuer = idp.URL
		cfg.OIDCAuthorizeEndpoint, cfg.OIDCTokenEndpoint, cfg.OIDCJWKSEndpoint, cfg.OIDCUserinfoEndpoint = "", "", "", ""
	})
	good := idp.Sign(t, "ES256", idClaims(func(c map[string]any) { c["iss"] = idp.URL }))
	if _, _, _, err := c.VerifyIDToken(context.Background(), withIDToken(good), "nonce-ok"); err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	other := idp.Sign(t, "ES256", idClaims(nil)) // iss https://idp.test
	if _, _, _, err := c.VerifyIDToken(context.Background(), withIDToken(other), "nonce-ok"); err == nil {
		t.Errorf("expected another issuer to be refused")
	}
	if !c.UserInfoEnabled() {
		t.Errorf("the userinfo endpoint of the discovery document should be used")
	}
}

func TestUserInfo(t *testing.T) {
	idp := oidctest.New(t)
	ctx := context.Background()
	tok := &oauth2.Token{AccessToken: "at"}
	claims := map[string]any{"sub": "user-123", "email": "ui@x.test"}

	cases := []struct {
		name     string
		verify   bool
		answer   http.HandlerFunc
		wantErr  bool
		invalid  bool // ErrUserInfoInvalid
		wantMail string
	}{
		{name: "json", verify: true, answer: oidctest.JSONUserInfo(claims), wantMail: "ui@x.test"},
		{name: "jwt RS256", verify: true, answer: oidctest.JWTUserInfo(idp.Sign(t, "RS256", claims)), wantMail: "ui@x.test"},
		{name: "jwt ES256", verify: true, answer: oidctest.JWTUserInfo(idp.Sign(t, "ES256", claims)), wantMail: "ui@x.test"},
		{name: "jwt of another key", verify: true, answer: oidctest.JWTUserInfo(idp.SignForeign(t, claims)), wantErr: true, invalid: true},
		{name: "jwt of another key, verification off", verify: false, answer: oidctest.JWTUserInfo(idp.SignForeign(t, claims)), wantMail: "ui@x.test"},
		{name: "json, another sub", verify: true, answer: oidctest.JSONUserInfo(map[string]any{"sub": "someone-else", "email": "e@x.test"}), wantErr: true, invalid: true},
		{name: "jwt, another sub", verify: true, answer: oidctest.JWTUserInfo(idp.Sign(t, "RS256", map[string]any{"sub": "someone-else"})), wantErr: true, invalid: true},
		{name: "another sub, verification off", verify: false, answer: oidctest.JSONUserInfo(map[string]any{"sub": "someone-else"}), wantErr: true, invalid: true},
		{name: "no sub", verify: true, answer: oidctest.JSONUserInfo(map[string]any{"email": "e@x.test"}), wantErr: true, invalid: true},
		{name: "status 500", verify: true, answer: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, wantErr: true},
		{name: "neither JSON nor JWT", verify: true, answer: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("oops")) }, wantErr: true, invalid: true},
		{name: "neither JSON nor JWT, verification off", verify: false, answer: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("oops")) }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp.Set(func(p *oidctest.Provider) { p.UserInfo = tc.answer })
			c := testClient(t, idp, func(cfg *config.Config) { cfg.VerifySignature = tc.verify })
			got, err := c.UserInfo(ctx, tok, "user-123")
			if (err != nil) != tc.wantErr {
				t.Fatalf("UserInfo: err = %v, want an error: %v", err, tc.wantErr)
			}
			if errors.Is(err, ErrUserInfoInvalid) != tc.invalid {
				t.Errorf("err = %v, want ErrUserInfoInvalid: %v", err, tc.invalid)
			}
			if tc.wantErr {
				if got != nil {
					t.Errorf("no claims expected with an error, got %#v", got)
				}
				return
			}
			if got["email"] != tc.wantMail {
				t.Errorf("claims = %#v", got)
			}
		})
	}
}

func TestUserInfoDisabled(t *testing.T) {
	idp := oidctest.New(t)
	for name, mutate := range map[string]func(*config.Config){
		"skipped":     func(cfg *config.Config) { cfg.SkipUserinfo = true },
		"no endpoint": func(cfg *config.Config) { cfg.OIDCUserinfoEndpoint = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := testClient(t, idp, mutate)
			got, err := c.UserInfo(context.Background(), &oauth2.Token{AccessToken: "at"}, "user-123")
			if got != nil || err != nil {
				t.Errorf("UserInfo = %#v, %v; want nil, nil", got, err)
			}
			if idp.Hit("/userinfo") != 0 {
				t.Errorf("the userinfo endpoint must not be called")
			}
		})
	}
}

func TestLogoutURL(t *testing.T) {
	idp := oidctest.New(t)

	tmpl := testClient(t, idp, func(cfg *config.Config) {
		cfg.OIDCLogoutEndpoint = "https://idp.test/logout?%s"
	})
	got := tmpl.LogoutURL("ID_TOKEN", "st", "https://app.test/logout/callback")
	u, _ := url.Parse(got)
	if u.Query().Get("id_token_hint") != "ID_TOKEN" || u.Query().Get("state") != "st" {
		t.Errorf("templated logout URL wrong: %s", got)
	}

	plain := testClient(t, idp, func(cfg *config.Config) {
		cfg.OIDCLogoutEndpoint = "https://idp.test/logout"
	})
	got = plain.LogoutURL("ID", "", "https://app.test/cb")
	u, _ = url.Parse(got)
	if u.Query().Get("id_token_hint") != "ID" {
		t.Errorf("plain logout URL wrong: %s", got)
	}

	none := testClient(t, idp, nil)
	if none.CanLogout() || none.LogoutURL("x", "y", "z") != "" {
		t.Errorf("no logout endpoint should yield empty URL and CanLogout()=false")
	}
}
