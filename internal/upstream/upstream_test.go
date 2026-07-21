package upstream

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/config"
)

// --- a tiny RS256 IdP for tests (JWKS + signer), no external JWT lib ---

type testIDP struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (idp *testIDP) sign(claims map[string]any) string {
	header := b64([]byte(`{"alg":"RS256","typ":"JWT","kid":"test"}`))
	payloadJSON, _ := json.Marshal(claims)
	signingInput := header + "." + b64(payloadJSON)
	h := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, h[:])
	return signingInput + "." + b64(sig)
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	idp := &testIDP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := map[string]any{
			"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()),
			"e": b64(big.NewInt(int64(key.E)).Bytes()),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func testClient(t *testing.T, idp *testIDP, mutate func(*config.Config)) *Client {
	t.Helper()
	cfg := &config.Config{
		ClientID:              "client-x",
		ClientSecret:          "secret",
		BaseURL:               "https://app.test",
		OIDCAuthorizeEndpoint: idp.server.URL + "/authorize",
		OIDCTokenEndpoint:     idp.server.URL + "/token",
		OIDCJWKSEndpoint:      idp.server.URL + "/jwks",
		OIDCUserinfoEndpoint:  idp.server.URL + "/userinfo",
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

func TestAuthCodeURL(t *testing.T) {
	idp := newTestIDP(t)
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
		"client_id":             "client-x",
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
	idp := newTestIDP(t)
	c := testClient(t, idp, nil)
	now := time.Now()
	tokenStr := idp.sign(map[string]any{
		"iss": "https://idp.test", "aud": "client-x", "sub": "user-123",
		"nonce": "nonce-ok", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"email": "u@example.test", "given_name": "Ada",
	})
	tok := (&oauth2.Token{AccessToken: "at"}).WithExtra(map[string]any{"id_token": tokenStr})

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

func TestVerifyIDTokenRejectsBadAudience(t *testing.T) {
	idp := newTestIDP(t)
	c := testClient(t, idp, nil)
	now := time.Now()
	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idp.sign(map[string]any{
		"iss": "https://idp.test", "aud": "someone-else", "sub": "u",
		"nonce": "n", "exp": now.Add(time.Hour).Unix(),
	})})
	if _, _, _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Errorf("expected audience mismatch to fail verification")
	}
}

func TestUserInfoJSONAndJWT(t *testing.T) {
	idp := newTestIDP(t)

	t.Run("json", func(t *testing.T) {
		c := testClient(t, idp, func(cfg *config.Config) {
			cfg.OIDCUserinfoEndpoint = jsonUserinfoServer(t, `{"sub":"u","email":"j@x.test"}`)
		})
		got, err := c.UserInfo(context.Background(), &oauth2.Token{AccessToken: "at"})
		if err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if got["email"] != "j@x.test" {
			t.Errorf("json userinfo: %#v", got)
		}
	})

	t.Run("jwt", func(t *testing.T) {
		jwt := idp.sign(map[string]any{"sub": "u", "email": "jwt@x.test"})
		c := testClient(t, idp, func(cfg *config.Config) {
			cfg.OIDCUserinfoEndpoint = jwtUserinfoServer(t, jwt)
		})
		got, err := c.UserInfo(context.Background(), &oauth2.Token{AccessToken: "at"})
		if err != nil {
			t.Fatalf("UserInfo (jwt): %v", err)
		}
		if got["email"] != "jwt@x.test" {
			t.Errorf("jwt userinfo decode: %#v", got)
		}
	})
}

func TestLogoutURL(t *testing.T) {
	idp := newTestIDP(t)

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

func TestDecodeJWTPayload(t *testing.T) {
	payload := b64([]byte(`{"sub":"abc","email":"e@x"}`))
	got, err := decodeJWTPayload("header." + payload + ".sig")
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}
	if got["sub"] != "abc" {
		t.Errorf("decoded payload: %#v", got)
	}
	if _, err := decodeJWTPayload("not-a-jwt"); err == nil {
		t.Errorf("expected error for non-JWT")
	}
}

func jsonUserinfoServer(t *testing.T, body string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func jwtUserinfoServer(t *testing.T, jwt string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(jwt))
	}))
	t.Cleanup(s.Close)
	return s.URL
}
