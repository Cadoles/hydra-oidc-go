// Package flowstate carries the state needed across the OIDC bridge's browser
// redirects WITHOUT a server-side session, mirroring hydra-sql-go's stateless
// design. Short-lived flow/logout state rides in encrypted, signed cookies. The
// upstream id_token (needed as id_token_hint at a possibly-much-later logout)
// rides in an encrypted cookie too.
package flowstate

import (
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
}

// New derives hash+block keys from appSecret (so cookies are signed AND
// encrypted) and configures the manager. sessionTTL is the lifetime of the
// upstream session, the cookie that holds the provider's id_token.
func New(appSecret, cookiePath string, secure bool, sessionTTL time.Duration) *Manager {
	return newManager(appSecret, cookiePath, secure, map[string]time.Duration{
		flowCookie:    flowTTL,
		logoutCookie:  flowTTL,
		sessionCookie: sessionTTL,
	})
}

func newManager(appSecret, cookiePath string, secure bool, ttls map[string]time.Duration) *Manager {
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

// SetSession keeps the upstream id_token, encrypted, in the session cookie. It
// fails for a token too large for a cookie.
func (m *Manager) SetSession(w http.ResponseWriter, idToken string) error {
	return m.set(w, sessionCookie, idToken)
}

// ReadSession returns the upstream id_token, or an error when the cookie is
// absent, older than its lifetime or not ours.
func (m *Manager) ReadSession(r *http.Request) (string, error) {
	var idToken string
	if err := m.read(r, sessionCookie, &idToken); err != nil {
		return "", err
	}
	return idToken, nil
}

// ClearSession removes the session cookie.
func (m *Manager) ClearSession(w http.ResponseWriter) { m.clear(w, sessionCookie) }

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
