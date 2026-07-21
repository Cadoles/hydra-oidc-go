// Package hydra wraps the official Ory Hydra admin SDK behind a small,
// domain-shaped interface so handlers don't depend on the generated client and
// can be tested with a fake.
package hydra

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
)

// LoginRequest is the subset of Hydra's login request the app cares about.
type LoginRequest struct {
	Challenge string
	Skip      bool
	Subject   string
	UiLocales []string
	LoginHint string // OIDC login_hint, used to prefill the username field
}

// ConsentRequest is the subset of Hydra's consent request the app cares about.
// Context carries whatever was stashed at login accept (the user attributes).
type ConsentRequest struct {
	Challenge                    string
	ClientName                   string
	Subject                      string
	Skip                         bool
	RequestedScope               []string
	RequestedAccessTokenAudience []string
	Context                      interface{}
}

// LoginAccept is the data sent when accepting a login request.
type LoginAccept struct {
	Subject     string
	Context     interface{} // round-trips to the consent request (user attributes)
	Remember    bool
	RememberFor int64
	AMR         []string // authentication methods references, e.g. ["pwd"]
	ACR         string   // authentication context class reference
}

// ConsentAccept is the data sent when accepting a consent request.
type ConsentAccept struct {
	GrantScope    []string
	GrantAudience []string
	IDToken       interface{} // session.id_token claims
	Remember      bool
	RememberFor   int64
}

// Client is the behavior the app needs from Hydra's admin API.
type Client interface {
	GetLoginRequest(ctx context.Context, challenge string) (*LoginRequest, error)
	AcceptLogin(ctx context.Context, challenge string, accept LoginAccept) (redirectTo string, err error)
	GetConsentRequest(ctx context.Context, challenge string) (*ConsentRequest, error)
	AcceptConsent(ctx context.Context, challenge string, accept ConsentAccept) (redirectTo string, err error)
	RejectConsent(ctx context.Context, challenge, errID, errDesc string) (redirectTo string, err error)
	GetLogoutRequest(ctx context.Context, challenge string) (resolvedChallenge string, err error)
	AcceptLogout(ctx context.Context, challenge string) (redirectTo string, err error)
}

// SDKClient is the production Client backed by the Ory SDK.
type SDKClient struct {
	api ory.OAuth2API
}

// New builds an SDKClient targeting the given admin base URL with a request
// timeout. apiPathPrefix replaces the SDK's hard-coded "/admin" path segment:
// pass "/admin" for a real Ory Hydra v2 admin API, or "" for the Cadoles
// hydra-dispatcher (which serves the v1-style "/oauth2/auth/requests/..." paths).
func New(adminBaseURL, apiPathPrefix string, timeout time.Duration) *SDKClient {
	cfg := ory.NewConfiguration()
	cfg.Servers = ory.ServerConfigurations{{URL: adminBaseURL}}
	cfg.HTTPClient = &http.Client{
		Timeout:   timeout,
		Transport: &adminPathRewriter{prefix: apiPathPrefix, base: http.DefaultTransport},
	}
	return &SDKClient{api: ory.NewAPIClient(cfg).OAuth2API}
}

// adminPathRewriter rewrites the leading "/admin" segment that the Ory SDK
// prepends, so the same client works against both Hydra v2 (/admin/...) and the
// dispatcher (/...).
type adminPathRewriter struct {
	prefix string
	base   http.RoundTripper
}

func (t *adminPathRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.prefix != "/admin" && strings.HasPrefix(req.URL.Path, "/admin/") {
		clone := req.Clone(req.Context())
		clone.URL.Path = t.prefix + strings.TrimPrefix(req.URL.Path, "/admin")
		req = clone
	}
	return t.base.RoundTrip(req)
}

func (c *SDKClient) GetLoginRequest(ctx context.Context, challenge string) (*LoginRequest, error) {
	req, resp, err := c.api.GetOAuth2LoginRequest(ctx).LoginChallenge(challenge).Execute()
	if err := apiErr("get login request", resp, err); err != nil {
		return nil, err
	}
	out := &LoginRequest{
		Challenge: req.GetChallenge(),
		Skip:      req.GetSkip(),
		Subject:   req.GetSubject(),
	}
	if oidc, ok := req.GetOidcContextOk(); ok && oidc != nil {
		out.UiLocales = oidc.GetUiLocales()
		out.LoginHint = oidc.GetLoginHint()
	}
	return out, nil
}

func (c *SDKClient) AcceptLogin(ctx context.Context, challenge string, accept LoginAccept) (string, error) {
	body := ory.NewAcceptOAuth2LoginRequest(accept.Subject)
	body.SetRemember(accept.Remember)
	if accept.RememberFor > 0 {
		body.SetRememberFor(accept.RememberFor)
	}
	if accept.Context != nil {
		body.SetContext(accept.Context)
	}
	if len(accept.AMR) > 0 {
		body.SetAmr(accept.AMR)
	}
	if accept.ACR != "" {
		body.SetAcr(accept.ACR)
	}
	redirect, resp, err := c.api.AcceptOAuth2LoginRequest(ctx).
		LoginChallenge(challenge).
		AcceptOAuth2LoginRequest(*body).
		Execute()
	if err := apiErr("accept login request", resp, err); err != nil {
		return "", err
	}
	return redirect.GetRedirectTo(), nil
}

func (c *SDKClient) GetConsentRequest(ctx context.Context, challenge string) (*ConsentRequest, error) {
	req, resp, err := c.api.GetOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).Execute()
	if err := apiErr("get consent request", resp, err); err != nil {
		return nil, err
	}
	out := &ConsentRequest{
		Challenge:                    req.GetChallenge(),
		Subject:                      req.GetSubject(),
		Skip:                         req.GetSkip(),
		RequestedScope:               req.GetRequestedScope(),
		RequestedAccessTokenAudience: req.GetRequestedAccessTokenAudience(),
		Context:                      req.GetContext(),
	}
	if client, ok := req.GetClientOk(); ok && client != nil {
		out.ClientName = client.GetClientName()
		if out.ClientName == "" {
			out.ClientName = client.GetClientId()
		}
	}
	return out, nil
}

func (c *SDKClient) AcceptConsent(ctx context.Context, challenge string, accept ConsentAccept) (string, error) {
	body := ory.NewAcceptOAuth2ConsentRequest()
	body.SetGrantScope(accept.GrantScope)
	if len(accept.GrantAudience) > 0 {
		body.SetGrantAccessTokenAudience(accept.GrantAudience)
	}
	body.SetSession(ory.AcceptOAuth2ConsentRequestSession{IdToken: accept.IDToken})
	body.SetRemember(accept.Remember)
	if accept.RememberFor > 0 {
		body.SetRememberFor(accept.RememberFor)
	}
	redirect, resp, err := c.api.AcceptOAuth2ConsentRequest(ctx).
		ConsentChallenge(challenge).
		AcceptOAuth2ConsentRequest(*body).
		Execute()
	if err := apiErr("accept consent request", resp, err); err != nil {
		return "", err
	}
	return redirect.GetRedirectTo(), nil
}

func (c *SDKClient) RejectConsent(ctx context.Context, challenge, errID, errDesc string) (string, error) {
	body := ory.RejectOAuth2Request{}
	body.SetError(errID)
	body.SetErrorDescription(errDesc)
	redirect, resp, err := c.api.RejectOAuth2ConsentRequest(ctx).
		ConsentChallenge(challenge).
		RejectOAuth2Request(body).
		Execute()
	if err := apiErr("reject consent request", resp, err); err != nil {
		return "", err
	}
	return redirect.GetRedirectTo(), nil
}

func (c *SDKClient) GetLogoutRequest(ctx context.Context, challenge string) (string, error) {
	req, resp, err := c.api.GetOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
	if err := apiErr("get logout request", resp, err); err != nil {
		return "", err
	}
	return req.GetChallenge(), nil
}

func (c *SDKClient) AcceptLogout(ctx context.Context, challenge string) (string, error) {
	redirect, resp, err := c.api.AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
	if err := apiErr("accept logout request", resp, err); err != nil {
		return "", err
	}
	return redirect.GetRedirectTo(), nil
}

// apiErr normalizes SDK errors and non-2xx responses into one error value.
func apiErr(op string, resp *http.Response, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if resp != nil && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("%s: unexpected status %d", op, resp.StatusCode)
	}
	return nil
}

var _ Client = (*SDKClient)(nil)
