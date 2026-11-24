package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RudyMCh/hydra-oidc-go/internal/config"
	"github.com/RudyMCh/hydra-oidc-go/internal/hydra"
	"github.com/RudyMCh/hydra-oidc-go/internal/oidctest"
)

const (
	backToClient = "https://client.test/cb?error=request_expired"
	errorPage    = "https://portal.test/erreur"
)

// goneTo is what the admin API answers for a challenge already used: 410 and
// the way back to the client. gone is a challenge it does not know.
var (
	goneTo = &hydra.ChallengeGoneError{Op: "op", Status: http.StatusGone, RedirectTo: backToClient}
	gone   = &hydra.ChallengeGoneError{Op: "op", Status: http.StatusNotFound}
)

// journey is a login started at /login against the fake provider: the server,
// the cookies the browser holds and the state sent to the provider.
type journey struct {
	t       *testing.T
	s       *Server
	fh      *fakeHydra
	idp     *oidctest.Provider
	cookies []*http.Cookie
	state   string
	nonce   string
}

// startLogin runs GET /login and keeps what the browser would: the cookies and
// the authorization request. The provider's endpoints are explicit and its
// signatures verified, as in production; mutate changes the configuration.
func startLogin(t *testing.T, mutate func(cfg *config.Config, idp *oidctest.Provider)) *journey {
	t.Helper()
	idp := oidctest.New(t)
	fh := &fakeHydra{loginReq: &hydra.LoginRequest{Challenge: "login-1"}, errs: map[string]error{}}
	s, _ := newServer(t, fh, func(cfg *config.Config) {
		cfg.ClientID = oidctest.ClientID
		cfg.OIDCAuthorizeEndpoint = idp.URL + "/authorize"
		cfg.OIDCTokenEndpoint = idp.URL + "/token"
		cfg.OIDCJWKSEndpoint = idp.URL + "/jwks"
		cfg.OIDCUserinfoEndpoint = idp.URL + "/userinfo"
		cfg.VerifySignature = true
		if mutate != nil {
			mutate(cfg, idp)
		}
	})
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?login_challenge=login-1", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status %d", rec.Code)
	}
	authorize, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	j := &journey{
		t: t, s: s, fh: fh, idp: idp,
		cookies: rec.Result().Cookies(),
		state:   authorize.Query().Get("state"),
		nonce:   authorize.Query().Get("nonce"),
	}
	if j.state == "" || j.nonce == "" {
		t.Fatalf("login: no state or nonce in %s", authorize)
	}
	return j
}

// idToken returns the claims of a valid id_token for this journey.
func (j *journey) idToken(mutate func(map[string]any)) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"iss": j.idp.URL, "aud": oidctest.ClientID, "sub": "user-123",
		"nonce": j.nonce, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"acr": "eidas1", "email": "id@example.test", "given_name": "Ada",
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

// provider sets what the provider answers: an RS256 id_token of the claims,
// and a JSON userinfo for the same sub.
func (j *journey) provider(idToken, userinfo map[string]any) {
	raw := j.idp.Sign(j.t, "RS256", idToken)
	j.idp.Set(func(p *oidctest.Provider) {
		p.IDToken = raw
		p.UserInfo = oidctest.JSONUserInfo(userinfo)
	})
}

// get plays a request with the browser's cookies, and keeps those it sets.
func (j *journey) get(target string) *httptest.ResponseRecorder {
	j.t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range j.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	j.s.Routes().ServeHTTP(rec, req)
	// As a browser: a cookie set again replaces the one of the same name, and
	// a cleared one is dropped.
	for _, c := range rec.Result().Cookies() {
		j.cookies = slices.DeleteFunc(j.cookies, func(old *http.Cookie) bool { return old.Name == c.Name })
		if c.MaxAge >= 0 {
			j.cookies = append(j.cookies, c)
		}
	}
	return rec
}

// callback is the provider's return, with the state it was sent.
func (j *journey) callback() *httptest.ResponseRecorder {
	j.t.Helper()
	return j.get("/callback?code=good-code&state=" + url.QueryEscape(j.state))
}

func setCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func userinfoOf(sub string) map[string]any {
	return map[string]any{"sub": sub, "email": "ui@example.test", "family_name": "Lovelace", "iss": "https://ui.test", "aud": "x"}
}

func TestCallbackAcceptsLogin(t *testing.T) {
	j := startLogin(t, nil)
	j.provider(j.idToken(nil), userinfoOf("user-123"))

	rec := j.callback()

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://hydra/after-login" {
		t.Fatalf("callback: %d %q, body %q", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if len(j.fh.loginAccepted) != 1 || j.fh.loginAccepted[0] != "login-1" {
		t.Fatalf("accepted challenges = %v", j.fh.loginAccepted)
	}
	got := j.fh.acceptLogin
	if got.Subject != "user-123" || got.ACR != "eidas1" || len(got.AMR) != 1 || got.AMR[0] != "oidc" {
		t.Errorf("accept = %+v", got)
	}
	claims, _ := got.Context.(map[string]any)
	// The userinfo wins over the id_token, and the claims of protocol of both
	// are left out.
	want := map[string]any{"email": "ui@example.test", "given_name": "Ada", "family_name": "Lovelace"}
	if len(claims) != len(want) {
		t.Errorf("claims = %#v, want %#v", claims, want)
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, claims[k], v)
		}
	}
	form := j.idp.Form()
	if form.Get("code") != "good-code" || form.Get("code_verifier") == "" || form.Get("redirect_uri") != "https://app.test/callback" {
		t.Errorf("token request = %v", form)
	}
	if c := setCookie(rec, "oidc_session"); c == nil || c.MaxAge != 3600 || !c.HttpOnly || !c.Secure {
		t.Errorf("session cookie = %+v", c)
	}
}

// A provider that signs in ES256 and sends its userinfo as a signed JWT.
func TestCallbackES256AndJWTUserinfo(t *testing.T) {
	j := startLogin(t, func(cfg *config.Config, _ *oidctest.Provider) {
		cfg.IDTokenSigningAlgs = []string{"ES256"}
	})
	raw := j.idp.Sign(t, "ES256", j.idToken(nil))
	userinfo := j.idp.Sign(t, "ES256", userinfoOf("user-123"))
	j.idp.Set(func(p *oidctest.Provider) {
		p.IDToken = raw
		p.UserInfo = oidctest.JWTUserInfo(userinfo)
	})

	rec := j.callback()

	if rec.Code != http.StatusSeeOther || len(j.fh.loginAccepted) != 1 {
		t.Fatalf("callback: %d, accepted %v, body %q", rec.Code, j.fh.loginAccepted, rec.Body)
	}
	if claims, _ := j.fh.acceptLogin.Context.(map[string]any); claims["family_name"] != "Lovelace" {
		t.Errorf("claims = %#v", claims)
	}
}

func TestCallbackWithoutUserinfo(t *testing.T) {
	j := startLogin(t, func(cfg *config.Config, _ *oidctest.Provider) { cfg.SkipUserinfo = true })
	j.provider(j.idToken(nil), nil)

	rec := j.callback()

	if rec.Code != http.StatusSeeOther || len(j.fh.loginAccepted) != 1 {
		t.Fatalf("callback: %d, accepted %v", rec.Code, j.fh.loginAccepted)
	}
	if claims, _ := j.fh.acceptLogin.Context.(map[string]any); claims["email"] != "id@example.test" {
		t.Errorf("claims = %#v", claims)
	}
	if j.idp.Hit("/userinfo") != 0 {
		t.Errorf("the userinfo endpoint must not be called")
	}
}

// Whatever fails, the login is not accepted and no session is kept.
func TestCallbackRefuses(t *testing.T) {
	cases := []struct {
		name string
		// prepare sets the provider's answers and returns the callback URL.
		prepare func(j *journey) string
		status  int
	}{
		{"another state", func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("user-123"))
			return "/callback?code=good-code&state=forged"
		}, http.StatusForbidden},
		{"no state", func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("user-123"))
			return "/callback?code=good-code"
		}, http.StatusForbidden},
		{"no code", func(j *journey) string {
			return "/callback?state=" + url.QueryEscape(j.state)
		}, http.StatusBadRequest},
		{"the provider's error", func(j *journey) string {
			return "/callback?error=access_denied&state=" + url.QueryEscape(j.state)
		}, http.StatusForbidden},
		{"no flow cookie", func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("user-123"))
			j.cookies = nil
			return "/callback?code=good-code&state=" + url.QueryEscape(j.state)
		}, http.StatusBadRequest},
		{"the code refused", func(j *journey) string {
			j.idp.Set(func(p *oidctest.Provider) { p.TokenStatus = http.StatusBadRequest })
			return ""
		}, http.StatusBadGateway},
		{"another nonce", func(j *journey) string {
			j.provider(j.idToken(func(c map[string]any) { c["nonce"] = "replayed" }), userinfoOf("user-123"))
			return ""
		}, http.StatusForbidden},
		{"another audience", func(j *journey) string {
			j.provider(j.idToken(func(c map[string]any) { c["aud"] = "someone-else" }), userinfoOf("user-123"))
			return ""
		}, http.StatusForbidden},
		{"an expired id_token", func(j *journey) string {
			j.provider(j.idToken(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), userinfoOf("user-123"))
			return ""
		}, http.StatusForbidden},
		{"an id_token of another key", func(j *journey) string {
			raw := j.idp.SignForeign(j.t, j.idToken(nil))
			j.idp.Set(func(p *oidctest.Provider) {
				p.IDToken = raw
				p.UserInfo = oidctest.JSONUserInfo(userinfoOf("user-123"))
			})
			return ""
		}, http.StatusForbidden},
		{"an ES256 id_token, RS256 alone allowed", func(j *journey) string {
			raw := j.idp.Sign(j.t, "ES256", j.idToken(nil))
			j.idp.Set(func(p *oidctest.Provider) {
				p.IDToken = raw
				p.UserInfo = oidctest.JSONUserInfo(userinfoOf("user-123"))
			})
			return ""
		}, http.StatusForbidden},
		{"the userinfo fails", func(j *journey) string {
			j.provider(j.idToken(nil), nil)
			j.idp.Set(func(p *oidctest.Provider) {
				p.UserInfo = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }
			})
			return ""
		}, http.StatusBadGateway},
		{"the userinfo of another sub", func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("someone-else"))
			return ""
		}, http.StatusForbidden},
		{"a userinfo JWT of another key", func(j *journey) string {
			j.provider(j.idToken(nil), nil)
			forged := j.idp.SignForeign(j.t, userinfoOf("user-123"))
			j.idp.Set(func(p *oidctest.Provider) { p.UserInfo = oidctest.JWTUserInfo(forged) })
			return ""
		}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := startLogin(t, nil)
			target := tc.prepare(j)
			if target == "" {
				target = "/callback?code=good-code&state=" + url.QueryEscape(j.state)
			}

			rec := j.get(target)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.status, rec.Body)
			}
			if len(j.fh.loginAccepted) != 0 {
				t.Errorf("the login must not be accepted: %v", j.fh.loginAccepted)
			}
			if c := setCookie(rec, "oidc_session"); c != nil {
				t.Errorf("no session must be kept: %+v", c)
			}
		})
	}
}

// With REDIRECT_ON_ERROR_URL a failure goes to that page, with its status.
func TestCallbackErrorPage(t *testing.T) {
	j := startLogin(t, func(cfg *config.Config, _ *oidctest.Provider) { cfg.RedirectOnErrorURL = errorPage })
	j.provider(j.idToken(nil), userinfoOf("someone-else"))

	rec := j.callback()

	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc.String(), errorPage+"?") || loc.Query().Get("status_code") != "403" {
		t.Errorf("callback: %d %q", rec.Code, loc)
	}
	if len(j.fh.loginAccepted) != 0 {
		t.Errorf("the login must not be accepted")
	}
}

// The browser's back button returns to the provider, which sends a new code
// with the same state, perhaps for another account. Nothing is exchanged nor
// accepted again, the session stays the first one's, and the read of the used
// challenge says where the flow went.
func TestCallbackReplayed(t *testing.T) {
	j := startLogin(t, func(cfg *config.Config, _ *oidctest.Provider) { cfg.RedirectOnErrorURL = errorPage })
	j.provider(j.idToken(nil), userinfoOf("user-123"))
	if rec := j.callback(); rec.Header().Get("Location") != "https://hydra/after-login" {
		t.Fatalf("first callback: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	tokens := j.idp.Hit("/token")

	// The provider now answers for someone else.
	j.provider(j.idToken(func(c map[string]any) { c["sub"] = "bob" }), userinfoOf("bob"))
	j.fh.errs["get login"] = goneTo
	rec := j.callback()

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != backToClient {
		t.Errorf("replayed callback: %d %q, want the redirect_to of the 410", rec.Code, rec.Header().Get("Location"))
	}
	if j.idp.Hit("/token") != tokens {
		t.Errorf("the replayed callback must not exchange the code")
	}
	if len(j.fh.loginAccepted) != 1 || j.fh.acceptLogin.Subject != "user-123" {
		t.Errorf("accepted = %v, subject %q: nothing more must be accepted", j.fh.loginAccepted, j.fh.acceptLogin.Subject)
	}
	if c := setCookie(rec, "oidc_session"); c != nil {
		t.Errorf("the session must stay the first one's")
	}

	// The challenge unknown, or still open: an error, never a second login.
	for name, err := range map[string]error{"unknown": gone, "still open": nil} {
		j.fh.errs["get login"] = err
		rec := j.callback()
		if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, errorPage+"?") || len(j.fh.loginAccepted) != 1 {
			t.Errorf("%s: %d %q, accepted %v", name, rec.Code, loc, j.fh.loginAccepted)
		}
	}
}

// Hydra refuses the accept (it answers 409 to an accept replayed): no session
// of the provider is kept for a login that did not go through.
func TestCallbackAcceptRefusedKeepsNoSession(t *testing.T) {
	j := startLogin(t, nil)
	j.provider(j.idToken(nil), userinfoOf("user-123"))
	j.fh.errs["accept login"] = errors.New("409 conflict")

	rec := j.callback()

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if c := setCookie(rec, "oidc_session"); c != nil {
		t.Errorf("no session must be kept: %+v", c)
	}
	// The flow is not marked done: the user may come back with a new code.
	if c := setCookie(rec, "oidc_flow"); c != nil {
		t.Errorf("the flow cookie must be left as it is: %+v", c)
	}
}

// A challenge already used or expired: the redirect_to of the 410 is followed
// at each call of the admin API; without one, an error, as for an admin API
// that fails.
func TestGoneChallenge(t *testing.T) {
	calls := []struct {
		op   string
		play func(t *testing.T, fh *fakeHydra, mutate func(*config.Config)) *httptest.ResponseRecorder
	}{
		{"get login", func(t *testing.T, fh *fakeHydra, mutate func(*config.Config)) *httptest.ResponseRecorder {
			return play(t, fh, mutate, "/login?login_challenge=c1")
		}},
		{"accept login", func(t *testing.T, fh *fakeHydra, mutate func(*config.Config)) *httptest.ResponseRecorder {
			fh.loginReq = &hydra.LoginRequest{Challenge: "c1", Skip: true, Subject: "user-123"}
			return play(t, fh, mutate, "/login?login_challenge=c1")
		}},
		{"get consent", func(t *testing.T, fh *fakeHydra, mutate func(*config.Config)) *httptest.ResponseRecorder {
			return play(t, fh, mutate, "/consent?consent_challenge=c1")
		}},
		{"accept consent", func(t *testing.T, fh *fakeHydra, mutate func(*config.Config)) *httptest.ResponseRecorder {
			fh.consentReq = &hydra.ConsentRequest{Challenge: "c1"}
			return play(t, fh, mutate, "/consent?consent_challenge=c1")
		}},
		{"accept logout", func(t *testing.T, fh *fakeHydra, mutate func(*config.Config)) *httptest.ResponseRecorder {
			return play(t, fh, mutate, "/logout?logout_challenge=c1")
		}},
	}
	answers := []struct {
		name     string
		err      error
		location string // "" = the error page
		status   string
	}{
		{"410 with redirect_to", goneTo, backToClient, ""},
		{"unknown challenge", gone, "", "410"},
		{"admin API down", errors.New("boom"), "", "502"},
	}
	for _, c := range calls {
		for _, a := range answers {
			t.Run(c.op+"/"+a.name, func(t *testing.T) {
				fh := &fakeHydra{loginReq: &hydra.LoginRequest{Challenge: "c1"}, errs: map[string]error{c.op: a.err}}

				rec := c.play(t, fh, func(cfg *config.Config) { cfg.RedirectOnErrorURL = errorPage })

				if rec.Code != http.StatusSeeOther {
					t.Fatalf("status = %d, want 303", rec.Code)
				}
				loc := rec.Header().Get("Location")
				if a.location != "" {
					if loc != a.location {
						t.Errorf("Location = %q, want %q", loc, a.location)
					}
					return
				}
				u, _ := url.Parse(loc)
				if !strings.HasPrefix(loc, errorPage+"?") || u.Query().Get("status_code") != a.status {
					t.Errorf("Location = %q, want the error page with status %s", loc, a.status)
				}
			})
		}
	}
}

func play(t *testing.T, fh *fakeHydra, mutate func(*config.Config), target string) *httptest.ResponseRecorder {
	t.Helper()
	s, _ := newServer(t, fh, mutate)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// --- the return from the provider's logout ---

// startLogout runs GET /logout with a session, and returns the server, the
// browser's cookies and the state sent to the provider.
func startLogout(t *testing.T, fh *fakeHydra) (*Server, []*http.Cookie, string) {
	t.Helper()
	s, flow := newServer(t, fh, func(cfg *config.Config) {
		cfg.OIDCLogoutEndpoint = "https://idp.test/logout?%s"
	})
	seed := httptest.NewRecorder()
	if err := flow.SetSession(context.Background(), seed, "UPSTREAM_ID_TOKEN"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=logout-1", nil)
	cookies(seed, req)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	end, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || end.Query().Get("state") == "" {
		t.Fatalf("logout: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := end.Query().Get("post_logout_redirect_uri"); got != "https://app.test/logout/callback" {
		t.Fatalf("post_logout_redirect_uri = %q", got)
	}
	return s, append(seed.Result().Cookies(), rec.Result().Cookies()...), end.Query().Get("state")
}

func logoutCallback(s *Server, cookies []*http.Cookie, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/logout/callback"+query, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

func TestLogoutCallbackAcceptsLogout(t *testing.T) {
	fh := &fakeHydra{}
	s, cookies, state := startLogout(t, fh)

	rec := logoutCallback(s, cookies, "?state="+url.QueryEscape(state))

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://hydra/after-logout" {
		t.Fatalf("logout callback: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if fh.logoutAccepted != "logout-1" {
		t.Errorf("accepted logout = %q", fh.logoutAccepted)
	}
	for _, name := range []string{"oidc_session", "oidc_logout"} {
		if c := setCookie(rec, name); c == nil || c.MaxAge >= 0 {
			t.Errorf("%s must be cleared: %+v", name, c)
		}
	}
}

// The state returned must be the one sent: the logout is not accepted, and the
// session is kept, otherwise.
func TestLogoutCallbackRefuses(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		cookies bool
		status  int
	}{
		{"another state", "?state=forged", true, http.StatusForbidden},
		{"no state", "", true, http.StatusForbidden},
		{"no cookie", "?state=anything", false, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fh := &fakeHydra{}
			s, cookies, _ := startLogout(t, fh)
			if !tc.cookies {
				cookies = nil
			}

			rec := logoutCallback(s, cookies, tc.query)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			if fh.logoutAccepted != "" {
				t.Errorf("the logout must not be accepted")
			}
			if c := setCookie(rec, "oidc_session"); c != nil {
				t.Errorf("the session must be kept: %+v", c)
			}
		})
	}
}

// A logout challenge already used: the redirect_to of the 410 is followed.
func TestLogoutCallbackGoneChallenge(t *testing.T) {
	fh := &fakeHydra{errs: map[string]error{"accept logout": goneTo}}
	s, cookies, state := startLogout(t, fh)

	rec := logoutCallback(s, cookies, "?state="+url.QueryEscape(state))

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != backToClient {
		t.Errorf("logout callback: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSameToken(t *testing.T) {
	for _, tc := range []struct {
		got, want string
		same      bool
	}{
		{"abc", "abc", true},
		{"abd", "abc", false},
		{"", "abc", false},
		{"", "", false}, // a cookie without a value matches nothing
	} {
		if sameToken(tc.got, tc.want) != tc.same {
			t.Errorf("sameToken(%q, %q) = %v", tc.got, tc.want, !tc.same)
		}
	}
}

// CALLBACK_PATH and LOGOUT_CALLBACK_PATH: the app serves them, sends them to
// the provider, and no longer serves the defaults.
func TestConfiguredReturnPaths(t *testing.T) {
	paths := func(cfg *config.Config, _ *oidctest.Provider) {
		cfg.CallbackPath = "/connect/oidc/check"
		cfg.LogoutCallbackPath = "/logout-done"
		cfg.OIDCLogoutEndpoint = "https://idp.test/logout?%s"
	}
	j := startLogin(t, paths)
	j.provider(j.idToken(nil), userinfoOf("user-123"))

	if rec := j.get("/callback?code=good-code&state=" + url.QueryEscape(j.state)); rec.Code != http.StatusNotFound {
		t.Errorf("the default callback must not be served: %d", rec.Code)
	}
	rec := j.get("/connect/oidc/check?code=good-code&state=" + url.QueryEscape(j.state))
	if rec.Code != http.StatusSeeOther || len(j.fh.loginAccepted) != 1 {
		t.Fatalf("callback: %d, accepted %v, body %q", rec.Code, j.fh.loginAccepted, rec.Body)
	}
	if got := j.idp.Form().Get("redirect_uri"); got != "https://app.test/connect/oidc/check" {
		t.Errorf("redirect_uri = %q", got)
	}

	rec = j.get("/logout?logout_challenge=logout-1")
	end, _ := url.Parse(rec.Header().Get("Location"))
	if got := end.Query().Get("post_logout_redirect_uri"); got != "https://app.test/logout-done" {
		t.Fatalf("post_logout_redirect_uri = %q (%d %q)", got, rec.Code, end)
	}
	if rec := j.get("/logout/callback?state=" + url.QueryEscape(end.Query().Get("state"))); rec.Code != http.StatusNotFound {
		t.Errorf("the default logout callback must not be served: %d", rec.Code)
	}
	rec = j.get("/logout-done?state=" + url.QueryEscape(end.Query().Get("state")))
	if rec.Code != http.StatusSeeOther || j.fh.logoutAccepted != "logout-1" {
		t.Errorf("logout callback: %d, accepted %q", rec.Code, j.fh.logoutAccepted)
	}
}

// UPSTREAM_LOGOUT_ON_ERROR: a login that fails after the provider answered
// first ends the provider's session, then shows the error.
func TestUpstreamLogoutOnError(t *testing.T) {
	on := func(cfg *config.Config, _ *oidctest.Provider) {
		cfg.UpstreamLogoutOnError = true
		cfg.OIDCLogoutEndpoint = "https://idp.test/logout?%s"
		cfg.RedirectOnErrorURL = errorPage
	}
	cases := []struct {
		name    string
		prepare func(j *journey)
		status  string
		hint    bool // the id_token is the one of the token response
	}{
		{"the userinfo of another sub", func(j *journey) {
			j.provider(j.idToken(nil), userinfoOf("someone-else"))
		}, "403", true},
		{"the userinfo fails", func(j *journey) {
			j.provider(j.idToken(nil), nil)
			j.idp.Set(func(p *oidctest.Provider) {
				p.UserInfo = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }
			})
		}, "502", true},
		{"another nonce", func(j *journey) {
			j.provider(j.idToken(func(c map[string]any) { c["nonce"] = "replayed" }), userinfoOf("user-123"))
		}, "403", true},
		{"hydra refuses the accept", func(j *journey) {
			j.provider(j.idToken(nil), userinfoOf("user-123"))
			j.fh.errs["accept login"] = errors.New("boom")
		}, "502", true},
		{"the challenge unknown to hydra", func(j *journey) {
			j.provider(j.idToken(nil), userinfoOf("user-123"))
			j.fh.errs["accept login"] = gone
		}, "410", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := startLogin(t, on)
			tc.prepare(j)

			rec := j.callback()

			end, _ := url.Parse(rec.Header().Get("Location"))
			if rec.Code != http.StatusSeeOther || !strings.HasPrefix(end.String(), "https://idp.test/logout?") {
				t.Fatalf("callback: %d %q, want the provider's logout", rec.Code, end)
			}
			q := end.Query()
			if q.Get("id_token_hint") == "" || q.Get("state") == "" || q.Get("post_logout_redirect_uri") != "https://app.test/logout/callback" {
				t.Errorf("logout request = %v", q)
			}
			if len(j.fh.loginAccepted) != 0 {
				t.Errorf("the login must not be accepted")
			}

			// Another state: no error page of ours, and nothing accepted.
			if rec := j.get("/logout/callback?state=forged"); !strings.Contains(rec.Header().Get("Location"), "status_code=403") {
				t.Errorf("forged return: %d %q", rec.Code, rec.Header().Get("Location"))
			}
			rec = j.get("/logout/callback?state=" + url.QueryEscape(q.Get("state")))
			page, _ := url.Parse(rec.Header().Get("Location"))
			if !strings.HasPrefix(page.String(), errorPage+"?") || page.Query().Get("status_code") != tc.status {
				t.Errorf("return: %d %q, want the error page with status %s", rec.Code, page, tc.status)
			}
			if j.fh.logoutAccepted != "" {
				t.Errorf("no logout of hydra is to accept: %q", j.fh.logoutAccepted)
			}
			if c := setCookie(rec, "oidc_logout"); c == nil || c.MaxAge >= 0 {
				t.Errorf("oidc_logout must be cleared: %+v", c)
			}
		})
	}
}

// The option off, without a provider logout, before the provider answered, or
// for a flow that already went on: the error at once, no logout.
func TestUpstreamLogoutOnErrorNotUsed(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(cfg *config.Config)
		prepare func(j *journey) string
		want    string // prefix of the Location
	}{
		{"the option off", func(cfg *config.Config) { cfg.UpstreamLogoutOnError = false }, func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("someone-else"))
			return ""
		}, errorPage},
		{"no logout endpoint", func(cfg *config.Config) { cfg.OIDCLogoutEndpoint = "" }, func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("someone-else"))
			return ""
		}, errorPage},
		{"the code refused", nil, func(j *journey) string {
			j.idp.Set(func(p *oidctest.Provider) { p.TokenStatus = http.StatusBadRequest })
			return ""
		}, errorPage},
		{"another state", nil, func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("user-123"))
			return "/callback?code=good-code&state=forged"
		}, errorPage},
		{"the flow already went on", nil, func(j *journey) string {
			j.provider(j.idToken(nil), userinfoOf("user-123"))
			j.fh.errs["accept login"] = goneTo
			return ""
		}, backToClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := startLogin(t, func(cfg *config.Config, _ *oidctest.Provider) {
				cfg.UpstreamLogoutOnError = true
				cfg.OIDCLogoutEndpoint = "https://idp.test/logout?%s"
				cfg.RedirectOnErrorURL = errorPage
				if tc.mutate != nil {
					tc.mutate(cfg)
				}
			})
			target := tc.prepare(j)
			if target == "" {
				target = "/callback?code=good-code&state=" + url.QueryEscape(j.state)
			}

			rec := j.get(target)

			if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, tc.want) {
				t.Errorf("Location = %q, want %q", loc, tc.want)
			}
		})
	}
}

// An id_token too large for the session cookie: the user is signed in all the
// same, and the logout will go without the provider.
func TestCallbackIDTokenTooLargeForTheCookie(t *testing.T) {
	j := startLogin(t, nil)
	j.provider(j.idToken(func(c map[string]any) { c["groups"] = strings.Repeat("g", 4000) }), userinfoOf("user-123"))

	rec := j.callback()

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://hydra/after-login" || len(j.fh.loginAccepted) != 1 {
		t.Fatalf("callback: %d %q, accepted %v", rec.Code, rec.Header().Get("Location"), j.fh.loginAccepted)
	}
	if c := setCookie(rec, "oidc_session"); c != nil {
		t.Errorf("no session cookie expected: %d bytes", len(c.Value))
	}
}

// The logout that follows a failed login returns to LOGOUT_CALLBACK_PATH too.
func TestUpstreamLogoutOnErrorConfiguredPath(t *testing.T) {
	j := startLogin(t, func(cfg *config.Config, _ *oidctest.Provider) {
		cfg.UpstreamLogoutOnError = true
		cfg.OIDCLogoutEndpoint = "https://idp.test/logout?%s"
		cfg.LogoutCallbackPath = "/logout-done"
	})
	j.provider(j.idToken(nil), userinfoOf("someone-else"))

	rec := j.callback()

	end, _ := url.Parse(rec.Header().Get("Location"))
	if got := end.Query().Get("post_logout_redirect_uri"); got != "https://app.test/logout-done" {
		t.Fatalf("post_logout_redirect_uri = %q", got)
	}
	// Without REDIRECT_ON_ERROR_URL, the error is a plain status.
	if rec := j.get("/logout-done?state=" + url.QueryEscape(end.Query().Get("state"))); rec.Code != http.StatusForbidden {
		t.Errorf("return: %d, want 403", rec.Code)
	}
}
