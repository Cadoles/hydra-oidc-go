// Package oidctest is a fake OIDC provider for the tests: discovery, JWKS,
// token and userinfo endpoints over httptest, with an RS256 and an ES256 key.
// A test sets what the token and userinfo endpoints answer.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// ClientID is the client the provider issues tokens for.
const ClientID = "client-x"

// Provider is the fake provider. Its answers are read at each request: Set
// changes them.
type Provider struct {
	URL string

	mu sync.Mutex
	// IDToken is what the token endpoint answers; TokenStatus, when not 0,
	// makes it fail with that status instead.
	IDToken     string
	TokenStatus int
	// UserInfo answers the userinfo endpoint; nil answers 404.
	UserInfo http.HandlerFunc
	// TokenForm is the form of the last token request, and Hits counts the
	// requests by path.
	TokenForm url.Values
	Hits      map[string]int

	keys map[jose.SignatureAlgorithm]any
}

// New starts a provider, stopped at the end of the test.
func New(t *testing.T) *Provider {
	t.Helper()
	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	p := &Provider{
		Hits: map[string]int{},
		keys: map[jose.SignatureAlgorithm]any{jose.RS256: rs, jose.ES256: ec},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                p.URL,
			"authorization_endpoint":                p.URL + "/authorize",
			"token_endpoint":                        p.URL + "/token",
			"userinfo_endpoint":                     p.URL + "/userinfo",
			"jwks_uri":                              p.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &rs.PublicKey, KeyID: "rs", Algorithm: "RS256", Use: "sig"},
			{Key: &ec.PublicKey, KeyID: "ec", Algorithm: "ES256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.TokenForm = r.PostForm
		status, idToken := p.TokenStatus, p.IDToken
		p.mu.Unlock()
		if status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idToken})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		h := p.UserInfo
		p.mu.Unlock()
		if h == nil || r.Header.Get("Authorization") != "Bearer at" {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.Hits[r.URL.Path]++
		p.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	p.URL = srv.URL
	return p
}

// Set changes the answers of the provider.
func (p *Provider) Set(change func(p *Provider)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(p)
}

// Hit returns how many requests reached path.
func (p *Provider) Hit(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Hits[path]
}

// Form returns the form of the last token request.
func (p *Provider) Form() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.TokenForm
}

// Sign returns claims as a JWT signed by the provider's key for alg, "RS256"
// or "ES256".
func (p *Provider) Sign(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	a := jose.SignatureAlgorithm(alg)
	kid := map[jose.SignatureAlgorithm]string{jose.RS256: "rs", jose.ES256: "ec"}[a]
	return sign(t, a, p.keys[a], kid, claims)
}

// SignForeign returns claims as an RS256 JWT signed by a key the provider does
// not publish, under the key id of its own.
func (p *Provider) SignForeign(t *testing.T, claims map[string]any) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return sign(t, jose.RS256, key, "rs", claims)
}

// JSONUserInfo answers the userinfo endpoint with claims as JSON.
func JSONUserInfo(claims map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, claims) }
}

// JWTUserInfo answers the userinfo endpoint with a JWT.
func JWTUserInfo(jwt string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(jwt))
	}
}

func sign(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
