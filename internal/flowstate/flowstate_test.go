package flowstate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const secret = "test-secret-test-secret-test"

// replay copies cookies written to a recorder onto a fresh request.
func replay(rec *httptest.ResponseRecorder) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func TestFlowRoundTrip(t *testing.T) {
	m := New(secret, "/auth/oidc", true, nil, time.Hour)
	rec := httptest.NewRecorder()
	want := FlowState{State: "st", Nonce: "no", Verifier: "ve", LoginChallenge: "ch"}
	if err := m.SetFlow(rec, want); err != nil {
		t.Fatalf("SetFlow: %v", err)
	}
	got, err := m.ReadFlow(replay(rec))
	if err != nil {
		t.Fatalf("ReadFlow: %v", err)
	}
	if *got != want {
		t.Errorf("round-trip mismatch: %#v != %#v", *got, want)
	}
}

func TestLogoutRoundTrip(t *testing.T) {
	m := New(secret, "/", false, nil, time.Hour)
	rec := httptest.NewRecorder()
	if err := m.SetLogout(rec, LogoutState{LogoutChallenge: "lc", State: "s"}); err != nil {
		t.Fatalf("SetLogout: %v", err)
	}
	got, err := m.ReadLogout(replay(rec))
	if err != nil {
		t.Fatalf("ReadLogout: %v", err)
	}
	if got.LogoutChallenge != "lc" || got.State != "s" {
		t.Errorf("logout round-trip mismatch: %#v", got)
	}
}

func TestSessionCookieOnly(t *testing.T) {
	m := New(secret, "/", false, nil, time.Hour)
	rec := httptest.NewRecorder()
	if err := m.SetSession(context.Background(), rec, "the.id.token"); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	got, err := m.ReadSession(context.Background(), replay(rec))
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	if got != "the.id.token" {
		t.Errorf("session cookie round-trip: got %q", got)
	}
}

// memStore is an in-memory Store for testing the Redis-backed path.
type memStore struct {
	m   map[string]string
	ttl time.Duration // of the last Put
}

func (s *memStore) Put(_ context.Context, k, v string, ttl time.Duration) error {
	s.m[k] = v
	s.ttl = ttl
	return nil
}
func (s *memStore) Get(_ context.Context, k string) (string, error) { return s.m[k], nil }
func (s *memStore) Del(_ context.Context, k string) error           { delete(s.m, k); return nil }

func TestSessionWithStore(t *testing.T) {
	store := &memStore{m: map[string]string{}}
	m := New(secret, "/", false, store, 2*time.Hour)
	rec := httptest.NewRecorder()
	if err := m.SetSession(context.Background(), rec, "BIG.JWT.TOKEN"); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	// The entry lasts as long as the cookie that names it.
	if store.ttl != 2*time.Hour {
		t.Errorf("ttl of the entry = %v, want 2h", store.ttl)
	}
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].MaxAge != 7200 {
		t.Errorf("session cookie = %+v", c)
	}
	// The cookie must hold an opaque id, not the token itself.
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value == "BIG.JWT.TOKEN" {
			t.Fatalf("token must not be stored directly in the cookie when a Store is set")
		}
	}
	if len(store.m) != 1 {
		t.Fatalf("expected one entry in the store, got %d", len(store.m))
	}
	got, err := m.ReadSession(context.Background(), replay(rec))
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	if got != "BIG.JWT.TOKEN" {
		t.Errorf("store-backed session round-trip: got %q", got)
	}
}

func TestReadFlowMissing(t *testing.T) {
	m := New(secret, "/", false, nil, time.Hour)
	if _, err := m.ReadFlow(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Errorf("expected error reading a missing flow cookie")
	}
}

// Each cookie has its own lifetime: the upstream session outlives the flow
// cookies, and a flow cookie past its lifetime is refused whatever the
// browser sends.
func TestCookieLifetimes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("the session outlives the flow", func(t *testing.T) {
		t.Parallel()
		m := newManager(secret, "/", false, nil, map[string]time.Duration{
			flowCookie: time.Second, logoutCookie: time.Second, sessionCookie: time.Hour,
		})
		rec := httptest.NewRecorder()
		if err := m.SetFlow(rec, FlowState{State: "st"}); err != nil {
			t.Fatalf("SetFlow: %v", err)
		}
		if err := m.SetLogout(rec, LogoutState{State: "st"}); err != nil {
			t.Fatalf("SetLogout: %v", err)
		}
		if err := m.SetSession(ctx, rec, "the.id.token"); err != nil {
			t.Fatalf("SetSession: %v", err)
		}
		time.Sleep(2100 * time.Millisecond)
		req := replay(rec)
		if _, err := m.ReadFlow(req); err == nil {
			t.Errorf("a flow cookie past its lifetime must be refused")
		}
		if _, err := m.ReadLogout(req); err == nil {
			t.Errorf("a logout cookie past its lifetime must be refused")
		}
		if got, err := m.ReadSession(ctx, req); err != nil || got != "the.id.token" {
			t.Errorf("the session must still be readable: %q, %v", got, err)
		}
	})

	t.Run("the session ends at its own lifetime", func(t *testing.T) {
		t.Parallel()
		m := newManager(secret, "/", false, nil, map[string]time.Duration{
			flowCookie: time.Hour, logoutCookie: time.Hour, sessionCookie: time.Second,
		})
		rec := httptest.NewRecorder()
		if err := m.SetSession(ctx, rec, "the.id.token"); err != nil {
			t.Fatalf("SetSession: %v", err)
		}
		time.Sleep(2100 * time.Millisecond)
		if got, err := m.ReadSession(ctx, replay(rec)); err == nil {
			t.Errorf("a session cookie past its lifetime must be refused, got %q", got)
		}
	})
}

// The lifetimes New sets: the browser is told the same as the codec enforces.
func TestNewLifetimes(t *testing.T) {
	m := New(secret, "/", false, nil, 2*time.Hour)
	rec := httptest.NewRecorder()
	_ = m.SetFlow(rec, FlowState{})
	_ = m.SetLogout(rec, LogoutState{})
	_ = m.SetSession(context.Background(), rec, "tok")
	want := map[string]int{flowCookie: 600, logoutCookie: 600, sessionCookie: 7200}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge != want[c.Name] {
			t.Errorf("%s: MaxAge = %d, want %d", c.Name, c.MaxAge, want[c.Name])
		}
		delete(want, c.Name)
	}
	if len(want) != 0 {
		t.Errorf("cookies not set: %v", want)
	}
}
