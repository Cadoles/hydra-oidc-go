package httpx

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/config"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/flowstate"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/hydra"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/upstream"
)

// --- fake Hydra ---

type fakeHydra struct {
	loginReq       *hydra.LoginRequest
	consentReq     *hydra.ConsentRequest
	acceptLogin    hydra.LoginAccept
	acceptConsent  hydra.ConsentAccept
	logoutAccepted string
}

func (f *fakeHydra) GetLoginRequest(context.Context, string) (*hydra.LoginRequest, error) {
	return f.loginReq, nil
}
func (f *fakeHydra) AcceptLogin(_ context.Context, _ string, a hydra.LoginAccept) (string, error) {
	f.acceptLogin = a
	return "https://hydra/after-login", nil
}
func (f *fakeHydra) GetConsentRequest(context.Context, string) (*hydra.ConsentRequest, error) {
	return f.consentReq, nil
}
func (f *fakeHydra) AcceptConsent(_ context.Context, _ string, a hydra.ConsentAccept) (string, error) {
	f.acceptConsent = a
	return "https://hydra/after-consent", nil
}
func (f *fakeHydra) RejectConsent(context.Context, string, string, string) (string, error) {
	return "https://hydra/rejected", nil
}
func (f *fakeHydra) GetLogoutRequest(_ context.Context, c string) (string, error) { return c, nil }
func (f *fakeHydra) AcceptLogout(_ context.Context, c string) (string, error) {
	f.logoutAccepted = c
	return "https://hydra/after-logout", nil
}

func newServer(t *testing.T, fh *fakeHydra, mutate func(*config.Config)) (*Server, *flowstate.Manager) {
	t.Helper()
	cfg := &config.Config{
		BaseURL:               "https://app.test",
		AppSecret:             "test-secret-test-secret",
		CookiePath:            "/",
		ClientID:              "client-x",
		ClientSecret:          "secret",
		OIDCAuthorizeEndpoint: "https://idp.test/authorize",
		OIDCTokenEndpoint:     "https://idp.test/token",
		OIDCJWKSEndpoint:      "https://idp.test/jwks",
		Scopes:                []string{"openid", "email"},
		PKCEEnabled:           true,
		ConsentAutoAccept:     true,
		AuthAMR:               []string{"oidc"},
	}
	if mutate != nil {
		mutate(cfg)
	}
	up, err := upstream.New(context.Background(), cfg, cfg.BaseURL+CallbackPath)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	flow := flowstate.New(cfg.AppSecret, cfg.CookiePath, cfg.HTTPS(), nil, time.Hour)
	s := New(Deps{
		Config:   cfg,
		Hydra:    fh,
		Upstream: up,
		Flow:     flow,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return s, flow
}

func cookies(rec *httptest.ResponseRecorder, req *http.Request) {
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
}

func TestLoginRedirectsToUpstream(t *testing.T) {
	fh := &fakeHydra{loginReq: &hydra.LoginRequest{Challenge: "c1"}}
	s, _ := newServer(t, fh, nil)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?login_challenge=c1", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.test/authorize") {
		t.Errorf("should redirect to upstream authorize, got %q", loc)
	}
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "oidc_flow" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an oidc_flow cookie to be set")
	}
}

func TestLoginSkipAcceptsDirectly(t *testing.T) {
	fh := &fakeHydra{loginReq: &hydra.LoginRequest{Challenge: "c1", Skip: true, Subject: "sub-1"}}
	s, _ := newServer(t, fh, nil)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?login_challenge=c1", nil))

	if fh.acceptLogin.Subject != "sub-1" {
		t.Errorf("skip should accept with subject sub-1, got %q", fh.acceptLogin.Subject)
	}
	if rec.Header().Get("Location") != "https://hydra/after-login" {
		t.Errorf("redirect = %q", rec.Header().Get("Location"))
	}
}

func TestLoginMissingChallenge(t *testing.T) {
	s, _ := newServer(t, &fakeHydra{}, nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestConsentAutoAccept(t *testing.T) {
	fh := &fakeHydra{consentReq: &hydra.ConsentRequest{
		Challenge:      "c1",
		RequestedScope: []string{"openid", "email"},
		Context:        map[string]any{"email": "a@b.test", "given_name": "Ada"},
	}}
	s, _ := newServer(t, fh, nil)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=c1", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	idToken, ok := fh.acceptConsent.IDToken.(map[string]any)
	if !ok || idToken["email"] != "a@b.test" {
		t.Errorf("consent should pass through claims as id_token: %#v", fh.acceptConsent.IDToken)
	}
	if len(fh.acceptConsent.GrantScope) != 2 {
		t.Errorf("grant scope should mirror requested: %#v", fh.acceptConsent.GrantScope)
	}
}

func TestConsentScopeFiltering(t *testing.T) {
	fh := &fakeHydra{consentReq: &hydra.ConsentRequest{
		Challenge:      "c1",
		RequestedScope: []string{"openid", "email"}, // no "profile"
		Context:        map[string]any{"email": "a@b.test", "given_name": "Ada"},
	}}
	s, _ := newServer(t, fh, func(cfg *config.Config) {
		cfg.FilterClaimsByScope = true
		cfg.ClaimScopes = map[string]string{"email": "email"} // given_name → profile (not granted)
	})

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=c1", nil))

	idToken, _ := fh.acceptConsent.IDToken.(map[string]any)
	if _, ok := idToken["email"]; !ok {
		t.Errorf("email should survive scope filter")
	}
	if _, ok := idToken["given_name"]; ok {
		t.Errorf("given_name should be filtered out (profile scope not granted)")
	}
}

func TestLogoutDirectWhenNoSession(t *testing.T) {
	fh := &fakeHydra{}
	s, _ := newServer(t, fh, nil)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=l1", nil))

	if fh.logoutAccepted != "l1" {
		t.Errorf("logout should be accepted directly, got %q", fh.logoutAccepted)
	}
	if rec.Header().Get("Location") != "https://hydra/after-logout" {
		t.Errorf("redirect = %q", rec.Header().Get("Location"))
	}
}

func TestLogoutRedirectsToUpstreamWhenSessionPresent(t *testing.T) {
	fh := &fakeHydra{}
	s, flow := newServer(t, fh, func(cfg *config.Config) {
		cfg.OIDCLogoutEndpoint = "https://idp.test/logout?%s"
	})

	// Seed an upstream id_token session cookie.
	seed := httptest.NewRecorder()
	if err := flow.SetSession(context.Background(), seed, "UPSTREAM_ID_TOKEN"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=l1", nil)
	cookies(seed, req)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.test/logout?") || !strings.Contains(loc, "id_token_hint=UPSTREAM_ID_TOKEN") {
		t.Errorf("should redirect to upstream logout with id_token_hint, got %q", loc)
	}
	if fh.logoutAccepted != "" {
		t.Errorf("hydra logout must NOT be accepted yet (waits for upstream callback)")
	}
}
