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
type memStore struct{ m map[string]string }

func (s *memStore) Put(_ context.Context, k, v string, _ time.Duration) error {
	s.m[k] = v
	return nil
}
func (s *memStore) Get(_ context.Context, k string) (string, error) { return s.m[k], nil }
func (s *memStore) Del(_ context.Context, k string) error           { delete(s.m, k); return nil }

func TestSessionWithStore(t *testing.T) {
	store := &memStore{m: map[string]string{}}
	m := New(secret, "/", false, store, time.Hour)
	rec := httptest.NewRecorder()
	if err := m.SetSession(context.Background(), rec, "BIG.JWT.TOKEN"); err != nil {
		t.Fatalf("SetSession: %v", err)
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
