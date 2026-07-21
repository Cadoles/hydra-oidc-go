package httpx

import (
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/oauth2"

	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/flowstate"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/hydra"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/metrics"
	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/oidc"
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
		s.errorRedirect(w, r, http.StatusBadGateway, "could not fetch login request", err)
		return
	}

	// Hydra can skip when it already has an authenticated session for the
	// subject. We have no fresh claims here; accept with the subject only.
	if lr.Skip {
		redirect, err := s.Hydra.AcceptLogin(r.Context(), challenge, hydra.LoginAccept{
			Subject: lr.Subject,
			AMR:     s.Config.AuthAMR,
			ACR:     s.Config.AuthACR,
		})
		if err != nil {
			s.errorRedirect(w, r, http.StatusBadGateway, "could not accept (skip) login", err)
			return
		}
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

	http.Redirect(w, r, s.Upstream.AuthCodeURL(state, nonce, verifier), http.StatusSeeOther)
}

// callback handles GET /callback: the upstream redirect_uri. It validates the
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
	if q.Get("state") != fs.State {
		s.errorRedirect(w, r, http.StatusForbidden, "state mismatch", nil)
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

	rawIDToken, subject, idClaims, err := s.Upstream.VerifyIDToken(r.Context(), tok, fs.Nonce)
	if err != nil {
		s.Metrics.LoginOutcome(metrics.LoginInvalid)
		s.errorRedirect(w, r, http.StatusForbidden, "id_token verification failed", err)
		return
	}

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
	// Augment with userinfo (overrides id_token claims of the same name).
	if ui, err := s.Upstream.UserInfo(r.Context(), tok); err != nil {
		s.Logger.Warn("userinfo fetch failed; continuing with id_token claims only", "err", err)
	} else {
		for k, v := range ui {
			claims[k] = v
		}
	}
	sanitizeClaims(claims)

	// Persist the upstream id_token for RP-initiated logout (id_token_hint).
	if err := s.Flow.SetSession(r.Context(), w, rawIDToken); err != nil {
		s.errorRedirect(w, r, http.StatusInternalServerError, "could not persist session", err)
		return
	}

	redirect, err := s.Hydra.AcceptLogin(r.Context(), fs.LoginChallenge, hydra.LoginAccept{
		Subject: subject,
		Context: claims,
		AMR:     s.Config.AuthAMR,
		ACR:     acr,
	})
	if err != nil {
		s.errorRedirect(w, r, http.StatusBadGateway, "could not accept login", err)
		return
	}
	s.Flow.ClearFlow(w)
	s.Metrics.LoginOutcome(metrics.LoginSuccess)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
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
		s.errorRedirect(w, r, http.StatusBadGateway, "could not fetch consent request", err)
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

	redirect, err := s.Hydra.AcceptConsent(r.Context(), challenge, hydra.ConsentAccept{
		GrantScope:    cr.RequestedScope,
		GrantAudience: cr.RequestedAccessTokenAudience,
		IDToken:       idToken,
		Remember:      true,
		RememberFor:   s.Config.ConsentRememberFor,
	})
	if err != nil {
		s.errorRedirect(w, r, http.StatusBadGateway, "could not accept consent", err)
		return
	}
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
		postLogout := s.Config.BaseURL + LogoutCallbackPath
		http.Redirect(w, r, s.Upstream.LogoutURL(idToken, state, postLogout), http.StatusSeeOther)
		return
	}

	// No upstream logout: accept the Hydra logout directly.
	redirect, err := s.Hydra.AcceptLogout(r.Context(), challenge)
	if err != nil {
		s.errorRedirect(w, r, http.StatusBadGateway, "could not accept logout", err)
		return
	}
	s.Flow.ClearSession(r.Context(), w, r)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// logoutCallback handles GET /logout/callback: the upstream post-logout
// redirect. It accepts the Hydra logout and clears all cookies.
func (s *Server) logoutCallback(w http.ResponseWriter, r *http.Request) {
	ls, err := s.Flow.ReadLogout(r)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "missing or invalid logout state", err)
		return
	}
	redirect, err := s.Hydra.AcceptLogout(r.Context(), ls.LogoutChallenge)
	if err != nil {
		s.errorRedirect(w, r, http.StatusBadGateway, "could not accept logout", err)
		return
	}
	s.Flow.ClearLogout(w)
	s.Flow.ClearSession(r.Context(), w, r)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// errorRedirect logs/reports and either redirects to REDIRECT_ON_ERROR_URL or
// returns a plain status (when no error URL is configured).
func (s *Server) errorRedirect(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	if err != nil {
		s.Logger.Error(msg, "err", err, "status", status)
		if status >= 500 {
			s.Reporter.Capture(err)
		}
	} else {
		s.Logger.Warn(msg, "status", status)
	}
	if s.Config.RedirectOnErrorURL == "" {
		http.Error(w, msg, status)
		return
	}
	u, perr := url.Parse(s.Config.RedirectOnErrorURL)
	if perr != nil {
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
