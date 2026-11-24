// Package flowstate carries the state needed across the OIDC bridge's browser
// redirects WITHOUT a server-side session, mirroring hydra-sql-go's stateless
// design. Short-lived flow/logout state rides in encrypted, signed cookies. The
// upstream id_token (needed as id_token_hint at a possibly-much-later logout)
// rides in an encrypted cookie too, unless a Redis Store is configured — then
// the cookie holds only an opaque session id and the token lives in Redis.
package flowstate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

// Cookie names.
const (
	flowCookie    = "oidc_flow"
	sessionCookie = "oidc_session"
	logoutCookie  = "oidc_logout"
)

// FlowState is stashed at /login and read back at the callback. Once the
// login is accepted it is replaced by its mark, Done, with the state and the
// challenge alone: a callback that comes back with that state is a replay.
type FlowState struct {
	State          string
	Nonce          string
	Verifier       string // PKCE code_verifier ("" when PKCE disabled)
	LoginChallenge string
	Done           bool
}

// LogoutState is stashed before the provider's logout and read back at the
// logout callback. A logout Hydra asked for carries its LogoutChallenge; one
// that follows a failed login (UPSTREAM_LOGOUT_ON_ERROR) carries the error to
// show once the provider's session is ended, and no challenge.
type LogoutState struct {
	LogoutChallenge string
	State           string
	ErrorStatus     int
	ErrorMessage    string
}

// Store is the optional backend for the upstream id_token (Redis in prod).
type Store interface {
	Put(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, key string) error
}

// flowTTL is how long the login and logout round-trips to the provider may
// take.
const flowTTL = 10 * time.Minute

// Manager builds and reads the flow cookies.
type Manager struct {
	// codecs holds one codec per cookie: securecookie refuses a value older
	// than the MaxAge of its codec, and each cookie has its own lifetime.
	codecs     map[string]*securecookie.SecureCookie
	ttls       map[string]time.Duration
	secure     bool
	cookiePath string
	store      Store
}

// New derives hash+block keys from appSecret (so cookies are signed AND
// encrypted) and configures the manager. store may be nil (cookie-only).
// sessionTTL is the lifetime of the upstream session: its cookie, and its
// entry in the store.
func New(appSecret, cookiePath string, secure bool, store Store, sessionTTL time.Duration) *Manager {
	return newManager(appSecret, cookiePath, secure, store, map[string]time.Duration{
		flowCookie:    flowTTL,
		logoutCookie:  flowTTL,
		sessionCookie: sessionTTL,
	})
}

func newManager(appSecret, cookiePath string, secure bool, store Store, ttls map[string]time.Duration) *Manager {
	hashKey := sha256.Sum256([]byte("hydra-oidc-go/hash:" + appSecret))
	blockKey := sha256.Sum256([]byte("hydra-oidc-go/block:" + appSecret)) // 32 bytes → AES-256
	codecs := make(map[string]*securecookie.SecureCookie, len(ttls))
	for name, ttl := range ttls {
		codecs[name] = securecookie.New(hashKey[:], blockKey[:]).MaxAge(int(ttl.Seconds()))
	}
	if cookiePath == "" {
		cookiePath = "/"
	}
	return &Manager{
		codecs:     codecs,
		ttls:       ttls,
		secure:     secure,
		cookiePath: cookiePath,
		store:      store,
	}
}

// --- flow state (login → callback) ---

func (m *Manager) SetFlow(w http.ResponseWriter, fs FlowState) error {
	return m.set(w, flowCookie, fs)
}

func (m *Manager) ReadFlow(r *http.Request) (*FlowState, error) {
	var fs FlowState
	if err := m.read(r, flowCookie, &fs); err != nil {
		return nil, err
	}
	return &fs, nil
}

func (m *Manager) ClearFlow(w http.ResponseWriter) { m.clear(w, flowCookie) }

// --- logout state (logout → logout callback) ---

func (m *Manager) SetLogout(w http.ResponseWriter, ls LogoutState) error {
	return m.set(w, logoutCookie, ls)
}

func (m *Manager) ReadLogout(r *http.Request) (*LogoutState, error) {
	var ls LogoutState
	if err := m.read(r, logoutCookie, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

func (m *Manager) ClearLogout(w http.ResponseWriter) { m.clear(w, logoutCookie) }

// --- upstream session (callback → logout), carries the id_token ---

// SetSession persists the upstream id_token. With a Store it writes the token
// to Redis under a random id and puts only that id in the cookie; otherwise the
// (encrypted) token rides in the cookie directly.
func (m *Manager) SetSession(ctx context.Context, w http.ResponseWriter, idToken string) error {
	value := idToken
	if m.store != nil {
		sid := RandString(24)
		if err := m.store.Put(ctx, sid, idToken, m.ttls[sessionCookie]); err != nil {
			return err
		}
		value = sid
	}
	return m.set(w, sessionCookie, value)
}

// ReadSession returns the upstream id_token, or "" when absent.
func (m *Manager) ReadSession(ctx context.Context, r *http.Request) (string, error) {
	var value string
	if err := m.read(r, sessionCookie, &value); err != nil {
		return "", err
	}
	if m.store == nil {
		return value, nil
	}
	return m.store.Get(ctx, value)
}

// ClearSession removes the cookie and any Redis entry.
func (m *Manager) ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if m.store != nil {
		var sid string
		if err := m.read(r, sessionCookie, &sid); err == nil && sid != "" {
			_ = m.store.Del(ctx, sid)
		}
	}
	m.clear(w, sessionCookie)
}

// --- helpers ---

func (m *Manager) set(w http.ResponseWriter, name string, value any) error {
	enc, err := m.codecs[name].Encode(name, value)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    enc,
		Path:     m.cookiePath,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttls[name].Seconds()),
	})
	return nil
}

func (m *Manager) read(r *http.Request, name string, dst any) error {
	c, err := r.Cookie(name)
	if err != nil {
		return err
	}
	return m.codecs[name].Decode(name, c.Value, dst)
}

func (m *Manager) clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     m.cookiePath,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// RandString returns n bytes of crypto-random data, base64url-encoded (no pad).
func RandString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; if it does, a panic is the safe choice
		// for a security-sensitive value rather than returning something weak.
		panic("flowstate: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
