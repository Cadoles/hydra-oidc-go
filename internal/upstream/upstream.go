// Package upstream is the OIDC Relying Party client for the IdP this app
// bridges to. It wraps coreos/go-oidc (discovery, JWKS, id_token verification)
// and golang.org/x/oauth2 (authorize URL, code exchange, PKCE), and adds the
// quirks the original PHP app relied on: configurable signature verification,
// JWT-encoded userinfo, extra authorize params, and a templated logout URL.
package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"forge.cadoles.com/vcarroy/hydra-oidc-go/internal/config"
)

// Client talks to the upstream OIDC provider.
type Client struct {
	oauth          *oauth2.Config
	verifier       *oidc.IDTokenVerifier
	userinfoURL    string
	logoutEndpoint string
	pkce           bool
	skipUserinfo   bool
	extraParams    map[string]string
	deleteParams   []string
	httpClient     *http.Client
}

// New builds the client. redirectURL must be the app's externally-reachable
// callback URL (BASE_URL + the callback route). It performs discovery when
// OIDC_ISSUER is set, otherwise it uses the explicit endpoints.
func New(ctx context.Context, cfg *config.Config, redirectURL string) (*Client, error) {
	httpClient := &http.Client{Timeout: 15 * time.Second}
	ctx = oidc.ClientContext(ctx, httpClient)

	var provider *oidc.Provider
	var err error
	if cfg.OIDCIssuer != "" {
		// Discovery fetches the issuer's well-known document at boot; tolerate an
		// upstream that is still starting up (common in compose/k8s) by retrying.
		provider, err = newProviderWithRetry(ctx, cfg.OIDCIssuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery (%s): %w", cfg.OIDCIssuer, err)
		}
	} else {
		issuer := cfg.OIDCIssuer
		if issuer == "" {
			issuer = cfg.BaseURL // synthetic; iss check is skipped below
		}
		provider = (&oidc.ProviderConfig{
			IssuerURL:   issuer,
			AuthURL:     cfg.OIDCAuthorizeEndpoint,
			TokenURL:    cfg.OIDCTokenEndpoint,
			UserInfoURL: cfg.OIDCUserinfoEndpoint,
			JWKSURL:     cfg.OIDCJWKSEndpoint,
			Algorithms:  cfg.IDTokenSigningAlgs,
		}).NewProvider(ctx)
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       cfg.Scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:                   cfg.ClientID,
		SupportedSigningAlgs:       cfg.IDTokenSigningAlgs,
		SkipIssuerCheck:            cfg.OIDCIssuer == "",
		InsecureSkipSignatureCheck: !cfg.VerifySignature,
	})

	// Resolve the userinfo endpoint: explicit config, else discovery metadata.
	userinfoURL := cfg.OIDCUserinfoEndpoint
	if userinfoURL == "" {
		var meta struct {
			UserInfoURL string `json:"userinfo_endpoint"`
		}
		_ = provider.Claims(&meta)
		userinfoURL = meta.UserInfoURL
	}

	return &Client{
		oauth:          oauthCfg,
		verifier:       verifier,
		userinfoURL:    userinfoURL,
		logoutEndpoint: cfg.OIDCLogoutEndpoint,
		pkce:           cfg.PKCEEnabled,
		skipUserinfo:   cfg.SkipUserinfo,
		extraParams:    cfg.ParamsToInsert,
		deleteParams:   cfg.ParamsToDelete,
		httpClient:     httpClient,
	}, nil
}

// PKCEEnabled reports whether PKCE is on (callers gate verifier generation).
func (c *Client) PKCEEnabled() bool { return c.pkce }

// AuthCodeURL builds the upstream authorization URL. pkceVerifier may be empty
// when PKCE is disabled.
func (c *Client) AuthCodeURL(state, nonce, pkceVerifier string) string {
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce)}
	if c.pkce && pkceVerifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(pkceVerifier))
	}
	for k, v := range c.extraParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	u := c.oauth.AuthCodeURL(state, opts...)
	// PARAMS_TO_DELETE: strip params some IdPs reject (rare in Go; we control
	// the set, but honor it for parity with the original app).
	if len(c.deleteParams) > 0 {
		u = stripQueryParams(u, c.deleteParams)
	}
	return u
}

// Exchange swaps the authorization code for tokens (with the PKCE verifier when
// enabled).
func (c *Client) Exchange(ctx context.Context, code, pkceVerifier string) (*oauth2.Token, error) {
	ctx = oidc.ClientContext(ctx, c.httpClient)
	var opts []oauth2.AuthCodeOption
	if c.pkce && pkceVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(pkceVerifier))
	}
	return c.oauth.Exchange(ctx, code, opts...)
}

// VerifyIDToken extracts and verifies the id_token from the token response. It
// checks signature (unless disabled), audience, expiry, and the nonce. It
// returns the raw id_token (for use as id_token_hint at logout), the verified
// subject, and the full claim set.
func (c *Client) VerifyIDToken(ctx context.Context, tok *oauth2.Token, expectedNonce string) (rawIDToken, subject string, claims map[string]any, err error) {
	ctx = oidc.ClientContext(ctx, c.httpClient)
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", "", nil, fmt.Errorf("no id_token in token response")
	}
	idt, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return "", "", nil, fmt.Errorf("verify id_token: %w", err)
	}
	if idt.Nonce != expectedNonce {
		return "", "", nil, fmt.Errorf("id_token nonce mismatch")
	}
	claims = map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return "", "", nil, fmt.Errorf("decode id_token claims: %w", err)
	}
	return raw, idt.Subject, claims, nil
}

// UserInfo fetches the userinfo endpoint and returns its claims. It tolerates a
// JWT-encoded response (some IdPs, e.g. FranceConnect, return the userinfo as a
// signed JWT rather than JSON) by decoding the JWT payload. Returns nil when
// userinfo is disabled or no endpoint is known.
func (c *Client) UserInfo(ctx context.Context, tok *oauth2.Token) (map[string]any, error) {
	if c.skipUserinfo || c.userinfoURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	tok.SetAuthHeader(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo: unexpected status %d", resp.StatusCode)
	}

	claims := map[string]any{}
	if err := json.Unmarshal(body, &claims); err == nil {
		return claims, nil
	}
	// Not JSON — assume a JWT and decode its payload (no signature check; this
	// matches the original app, which trusted the TLS channel for userinfo).
	decoded, derr := decodeJWTPayload(string(body))
	if derr != nil {
		return nil, fmt.Errorf("userinfo not JSON and not a decodable JWT: %w", derr)
	}
	return decoded, nil
}

// LogoutURL builds the upstream RP-initiated logout URL. OIDC_LOGOUT_ENDPOINT
// may be a plain URL or a printf template with a single %s for the query string.
func (c *Client) LogoutURL(idTokenHint, state, postLogoutRedirectURI string) string {
	if c.logoutEndpoint == "" {
		return ""
	}
	q := url.Values{}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if state != "" {
		q.Set("state", state)
	}
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	encoded := q.Encode()
	if strings.Contains(c.logoutEndpoint, "%s") {
		return fmt.Sprintf(c.logoutEndpoint, encoded)
	}
	sep := "?"
	if strings.Contains(c.logoutEndpoint, "?") {
		sep = "&"
	}
	return c.logoutEndpoint + sep + encoded
}

// CanLogout reports whether an upstream logout endpoint is configured.
func (c *Client) CanLogout() bool { return c.logoutEndpoint != "" }

// newProviderWithRetry runs OIDC discovery, retrying for up to ~30s so the app
// survives an upstream IdP that is still booting (compose/k8s ordering).
func newProviderWithRetry(ctx context.Context, issuer string) (*oidc.Provider, error) {
	const attempts = 30
	var err error
	for i := 0; i < attempts; i++ {
		var p *oidc.Provider
		if p, err = oidc.NewProvider(ctx, issuer); err == nil {
			return p, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, err
}

func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func stripQueryParams(rawURL string, drop []string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	for _, d := range drop {
		q.Del(d)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
