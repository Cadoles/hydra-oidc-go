package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/config"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/hydra"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/oidctest"
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
	j.cookies = append(j.cookies, rec.Result().Cookies()...)
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

// FranceConnect's shape: ES256, the userinfo a signed JWT.
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
// with the same state: the accept of a challenge already used answers where
// the flow went, and the user follows.
func TestCallbackReplayed(t *testing.T) {
	j := startLogin(t, func(cfg *config.Config, _ *oidctest.Provider) { cfg.RedirectOnErrorURL = errorPage })
	j.provider(j.idToken(nil), userinfoOf("user-123"))
	if rec := j.callback(); rec.Header().Get("Location") != "https://hydra/after-login" {
		t.Fatalf("first callback: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	j.fh.errs["accept login"] = goneTo
	rec := j.callback()

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != backToClient {
		t.Errorf("replayed callback: %d %q, want the redirect_to of the 410", rec.Code, rec.Header().Get("Location"))
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
