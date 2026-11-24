package httpx

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/oauth2"

	"github.com/RudyMCh/hydra-oidc-go/internal/flowstate"
	"github.com/RudyMCh/hydra-oidc-go/internal/hydra"
	"github.com/RudyMCh/hydra-oidc-go/internal/metrics"
	"github.com/RudyMCh/hydra-oidc-go/internal/oidc"
	"github.com/RudyMCh/hydra-oidc-go/internal/upstream"
)

// protocolClaims are OIDC/JWT envelope claims that must NOT be copied from the
// upstream token into the id_token we hand Hydra. Identity claims pass through.
var protocolClaims = map[string]struct{}{
	"iss": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"nonce": {}, "at_hash": {}, "c_hash": {}, "s_hash": {}, "azp": {},
	"sid": {}, "auth_time": {}, "sub": {}, "amr": {}, "acr": {},
}

// login handles GET /login: it starts a fresh upstream authorization (or
// accepts immediately when Hydra says the login can be skipped).
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		s.fail(w, http.StatusBadRequest, "missing login_challenge", nil)
		return
	}

	lr, err := s.Hydra.GetLoginRequest(r.Context(), challenge)
	if err != nil {
		s.hydraFailed(w, r, "could not fetch login request", err)
		return
	}
	s.Logger.Debug("login request", "challenge", challenge, "skip", lr.Skip)

	// Hydra can skip when it already has an authenticated session for the
	// subject. We have no fresh claims here; accept with the subject only.
	if lr.Skip {
		redirect, err := s.Hydra.AcceptLogin(r.Context(), challenge, hydra.LoginAccept{
			Subject: lr.Subject,
			AMR:     s.Config.AuthAMR,
			ACR:     s.Config.AuthACR,
		})
		if err != nil {
			s.hydraFailed(w, r, "could not accept (skip) login", err)
			return
		}
		s.Logger.Info("login accepted, skipped by hydra", "challenge", challenge, "subject", lr.Subject)
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}

	state := flowstate.RandString(24)
	nonce := flowstate.RandString(24)
	verifier := ""
	if s.Upstream.PKCEEnabled() {
		verifier = oauth2.GenerateVerifier()
	}
	if err := s.Flow.SetFlow(w, flowstate.FlowState{
		State:          state,
		Nonce:          nonce,
		Verifier:       verifier,
		LoginChallenge: challenge,
	}); err != nil {
		s.errorRedirect(w, r, http.StatusInternalServerError, "could not set flow state", err)
		return
	}

	s.Logger.Debug("redirecting to the provider", "challenge", challenge)
	http.Redirect(w, r, s.Upstream.AuthCodeURL(state, nonce, verifier), http.StatusSeeOther)
}

// callback handles GET CALLBACK_PATH: the upstream redirect_uri. It validates the
// round-trip, exchanges the code, verifies the id_token, gathers claims, and
// accepts the Hydra login.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.errorRedirect(w, r, http.StatusForbidden, "upstream error: "+e+" "+q.Get("error_description"), nil)
		return
	}

	fs, err := s.Flow.ReadFlow(r)
	if err != nil {
		s.errorRedirect(w, r, http.StatusBadRequest, "missing or invalid flow state", err)
		return
	}
	if !sameToken(q.Get("state"), fs.State) {
		s.errorRedirect(w, r, http.StatusForbidden, "state mismatch", nil)
		return
	}
	if fs.Done {
		s.callbackReplayed(w, r, fs)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.errorRedirect(w, r, http.StatusBadRequest, "missing authorization code", nil)
		return
	}

	tok, err := s.Upstream.Exchange(r.Context(), code, fs.Verifier)
	if err != nil {
		s.Metrics.LoginOutcome(metrics.LoginTechnical)
		s.errorRedirect(w, r, http.StatusBadGateway, "code exchange failed", err)
		return
	}
	// From here the provider has signed the user in: a failure may end its
	// session before the error is shown (UPSTREAM_LOGOUT_ON_ERROR). The
	// id_token goes back to the provider as a hint, verified or not.
	hint := upstream.RawIDToken(tok)

	rawIDToken, subject, idClaims, err := s.Upstream.VerifyIDToken(r.Context(), tok, fs.Nonce)
	if err != nil {
		s.Metrics.LoginOutcome(metrics.LoginInvalid)
		s.failAfterProvider(w, r, hint, http.StatusForbidden, "id_token verification failed", err)
		return
	}
	s.Logger.Debug("id_token verified", "challenge", fs.LoginChallenge, "subject", subject)

	// Carry the upstream acr through if the provider sent one (used as the Hydra
	// acr unless an explicit AUTH_ACR is configured).
	acr := s.Config.AuthACR
	if acr == "" {
		if v, ok := idClaims["acr"].(string); ok {
			acr = v
		}
	}

	claims := map[string]any{}
	for k, v := range idClaims {
		claims[k] = v
	}
	// Augment with userinfo (overrides id_token claims of the same name). When
	// the provider is asked for it, a login without it is refused: its claims
	// would be missing, or someone else's.
	ui, err := s.Upstream.UserInfo(r.Context(), tok, subject)
	if errors.Is(err, upstream.ErrUserInfoInvalid) {
		s.Metrics.LoginOutcome(metrics.LoginInvalid)
		s.failAfterProvider(w, r, hint, http.StatusForbidden, "userinfo verification failed", err)
		return
	}
	if err != nil {
		s.Metrics.LoginOutcome(metrics.LoginTechnical)
		s.failAfterProvider(w, r, hint, http.StatusBadGateway, "userinfo fetch failed", err)
		return
	}
	for k, v := range ui {
		claims[k] = v
	}
	sanitizeClaims(claims)

	redirect, err := s.Hydra.AcceptLogin(r.Context(), fs.LoginChallenge, hydra.LoginAccept{
		Subject: subject,
		Context: claims,
		AMR:     s.Config.AuthAMR,
		ACR:     acr,
	})
	if to := hydra.RedirectTo(err); to != "" {
		// The flow already went on (back button, double click): the user
		// follows it, signed in at the provider as before.
		s.Logger.Info("challenge no longer valid, following redirect_to", "op", "accept login")
		http.Redirect(w, r, to, http.StatusSeeOther)
		return
	}
	if err != nil {
		s.Metrics.LoginOutcome(metrics.LoginTechnical)
		status, msg := http.StatusBadGateway, "could not accept login"
		if errors.Is(err, hydra.ErrChallengeNotFound) {
			status, msg = http.StatusGone, "challenge expired or unknown"
		}
		s.failAfterProvider(w, r, hint, status, msg, err)
		return
	}

	// Persist the upstream id_token for RP-initiated logout (id_token_hint),
	// once Hydra has the login: a session is kept for an accepted login only.
	if err := s.Flow.SetSession(r.Context(), w, rawIDToken); err != nil {
		// The user is signed in; only the logout will not reach the provider.
		s.Logger.Error("could not persist the upstream session: the logout will not go through the provider", "err", err)
		s.Reporter.Capture(err)
	}
	// The flow is over: its cookie becomes a mark, without nonce nor PKCE
	// verifier, so that a callback replayed with the same state (the back
	// button returns to the provider, which answers again) is recognised
	// and exchanges nothing (callbackReplayed).
	if err := s.Flow.SetFlow(w, flowstate.FlowState{State: fs.State, LoginChallenge: fs.LoginChallenge, Done: true}); err != nil {
		s.Logger.Warn("could not mark the flow as done", "err", err)
		s.Flow.ClearFlow(w)
	}
	s.Metrics.LoginOutcome(metrics.LoginSuccess)
	s.Logger.Info("login accepted", "challenge", fs.LoginChallenge, "subject", subject)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// callbackReplayed answers a callback that returns with the state of a login
// already accepted: the back button, or a callback forged from the
// authorization URL. Nothing is exchanged nor accepted, whoever signed in at
// the provider this time: the read of the used challenge says where the flow
// went (410 and redirect_to, from Hydra as from the dispatcher), and the user
// follows it.
func (s *Server) callbackReplayed(w http.ResponseWriter, r *http.Request, fs *flowstate.FlowState) {
	if _, err := s.Hydra.GetLoginRequest(r.Context(), fs.LoginChallenge); err != nil {
		s.hydraFailed(w, r, "callback replayed", err)
		return
	}
	// The challenge is still open, though this browser was accepted on it.
	s.errorRedirect(w, r, http.StatusBadRequest, "login already completed", nil)
}

// failAfterProvider answers a login that fails once the provider has signed
// the user in. With UPSTREAM_LOGOUT_ON_ERROR, and a provider logout to go to,
// the browser first ends the provider's session: the error is shown at the
// return (logoutCallback), and the next attempt asks for the identity again.
// Otherwise the error is shown at once.
func (s *Server) failAfterProvider(w http.ResponseWriter, r *http.Request, idTokenHint string, status int, msg string, err error) {
	if !s.Config.UpstreamLogoutOnError || idTokenHint == "" || !s.Upstream.CanLogout() {
		s.errorRedirect(w, r, status, msg, err)
		return
	}
	s.logError(status, msg, err)
	state := flowstate.RandString(24)
	if err := s.Flow.SetLogout(w, flowstate.LogoutState{State: state, ErrorStatus: status, ErrorMessage: msg}); err != nil {
		s.Logger.Error("could not set logout state", "err", err)
		s.sendError(w, r, status, msg)
		return
	}
	s.Logger.Info("ending the provider's session before the error")
	http.Redirect(w, r, s.Upstream.LogoutURL(idTokenHint, state, s.Config.BaseURL+s.Config.LogoutCallbackPath), http.StatusSeeOther)
}

// consent handles GET /consent: auto-accepts (the bridge has no consent UI),
// emitting the upstream claims as id_token claims (optionally scope-filtered).
func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		s.fail(w, http.StatusBadRequest, "missing consent_challenge", nil)
		return
	}

	cr, err := s.Hydra.GetConsentRequest(r.Context(), challenge)
	if err != nil {
		s.hydraFailed(w, r, "could not fetch consent request", err)
		return
	}

	if !cr.Skip && !s.Config.ConsentAutoAccept {
		// Headless bridge: no interactive consent page.
		s.fail(w, http.StatusNotImplemented, "interactive consent is not supported; set CONSENT_AUTO_ACCEPT=true", nil)
		return
	}

	claims := oidc.CoerceClaims(cr.Context)
	idToken := claims
	if s.Config.FilterClaimsByScope {
		idToken = oidc.FilterClaims(claims, cr.RequestedScope, s.Config.ClaimScopes)
	}

	s.Logger.Debug("consent request", "challenge", challenge, "skip", cr.Skip, "scopes", cr.RequestedScope)
	redirect, err := s.Hydra.AcceptConsent(r.Context(), challenge, hydra.ConsentAccept{
		GrantScope:    cr.RequestedScope,
		GrantAudience: cr.RequestedAccessTokenAudience,
		IDToken:       idToken,
		Remember:      true,
		RememberFor:   s.Config.ConsentRememberFor,
	})
	if err != nil {
		s.hydraFailed(w, r, "could not accept consent", err)
		return
	}
	s.Logger.Info("consent accepted", "challenge", challenge, "subject", cr.Subject)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// logout handles GET /logout: RP-initiated logout at the upstream IdP when we
// hold its id_token, otherwise it accepts the Hydra logout directly.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("logout_challenge")
	if challenge == "" {
		s.fail(w, http.StatusBadRequest, "missing logout_challenge", nil)
		return
	}

	idToken, _ := s.Flow.ReadSession(r.Context(), r) // best-effort
	if idToken != "" && s.Upstream.CanLogout() {
		state := flowstate.RandString(24)
		if err := s.Flow.SetLogout(w, flowstate.LogoutState{LogoutChallenge: challenge, State: state}); err != nil {
			s.errorRedirect(w, r, http.StatusInternalServerError, "could not set logout state", err)
			return
		}
		postLogout := s.Config.BaseURL + s.Config.LogoutCallbackPath
		s.Logger.Debug("logout through the provider", "challenge", challenge)
		http.Redirect(w, r, s.Upstream.LogoutURL(idToken, state, postLogout), http.StatusSeeOther)
		return
	}

	// No upstream logout: accept the Hydra logout directly.
	redirect, err := s.Hydra.AcceptLogout(r.Context(), challenge)
	if err != nil {
		s.hydraFailed(w, r, "could not accept logout", err)
		return
	}
	s.Flow.ClearSession(r.Context(), w, r)
	s.Logger.Info("logout accepted, without the provider", "challenge", challenge)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// logoutCallback handles GET LOGOUT_CALLBACK_PATH: the upstream post-logout
// redirect. It accepts the Hydra logout and clears all cookies. The state the
// provider returns must be the one sent to it: otherwise another site could
// end a logout the user left open at the provider.
func (s *Server) logoutCallback(w http.ResponseWriter, r *http.Request) {
	ls, err := s.Flow.ReadLogout(r)
	if err != nil {
		s.errorRedirect(w, r, http.StatusBadRequest, "missing or invalid logout state", err)
		return
	}
	if !sameToken(r.URL.Query().Get("state"), ls.State) {
		s.errorRedirect(w, r, http.StatusForbidden, "logout state mismatch", nil)
		return
	}
	if ls.LogoutChallenge == "" {
		// The logout that follows a failed login (failAfterProvider): the
		// provider's session is ended, the error is shown. Already logged.
		s.Flow.ClearLogout(w)
		s.Flow.ClearSession(r.Context(), w, r)
		s.sendError(w, r, ls.ErrorStatus, ls.ErrorMessage)
		return
	}
	redirect, err := s.Hydra.AcceptLogout(r.Context(), ls.LogoutChallenge)
	if err != nil {
		s.hydraFailed(w, r, "could not accept logout", err)
		return
	}
	s.Flow.ClearLogout(w)
	s.Flow.ClearSession(r.Context(), w, r)
	s.Logger.Info("logout accepted", "challenge", ls.LogoutChallenge)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// hydraFailed answers a failed call to the admin API. A challenge already used
// or expired (410) comes with the way back to the client that started the
// flow, followed like a normal answer: the user pressed back, or clicked
// twice. Without it the challenge is unknown; anything else is a gateway
// error.
func (s *Server) hydraFailed(w http.ResponseWriter, r *http.Request, msg string, err error) {
	if !errors.Is(err, hydra.ErrChallengeNotFound) {
		s.errorRedirect(w, r, http.StatusBadGateway, msg, err)
		return
	}
	// Never a fixed URL: only Hydra's redirect_to knows which client the
	// user came from.
	if to := hydra.RedirectTo(err); to != "" {
		s.Logger.Info("challenge no longer valid, following redirect_to", "op", msg)
		http.Redirect(w, r, to, http.StatusSeeOther)
		return
	}
	s.Logger.Info("challenge no longer valid", "op", msg, "err", err)
	s.errorRedirect(w, r, http.StatusGone, "challenge expired or unknown", nil)
}

// sameToken compares a random value returned by the browser with the one kept
// in the cookie, in constant time; an empty value never matches.
func sameToken(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// errorRedirect logs/reports and either redirects to REDIRECT_ON_ERROR_URL or
// returns a plain status (when no error URL is configured).
func (s *Server) errorRedirect(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	s.logError(status, msg, err)
	s.sendError(w, r, status, msg)
}

func (s *Server) logError(status int, msg string, err error) {
	if err == nil {
		s.Logger.Warn(msg, "status", status)
		return
	}
	s.Logger.Error(msg, "err", err, "status", status)
	if status >= 500 {
		s.Reporter.Capture(err)
	}
}

func (s *Server) sendError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if status < 400 || status > 599 {
		status = http.StatusInternalServerError
	}
	u, perr := url.Parse(s.Config.RedirectOnErrorURL)
	if s.Config.RedirectOnErrorURL == "" || perr != nil {
		http.Error(w, msg, status)
		return
	}
	q := u.Query()
	q.Set("status_code", strconv.Itoa(status))
	q.Set("message", msg)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func sanitizeClaims(claims map[string]any) {
	for k := range claims {
		if _, drop := protocolClaims[k]; drop {
			delete(claims, k)
		}
	}
}
