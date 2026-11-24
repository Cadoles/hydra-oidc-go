package flowstate

import (
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
	m := New(secret, "/auth/oidc", true, time.Hour)
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
	m := New(secret, "/", false, time.Hour)
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
	m := New(secret, "/", false, time.Hour)
	rec := httptest.NewRecorder()
	if err := m.SetSession(rec, "the.id.token"); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	got, err := m.ReadSession(replay(rec))
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	if got != "the.id.token" {
		t.Errorf("session cookie round-trip: got %q", got)
	}
}

func TestReadFlowMissing(t *testing.T) {
	m := New(secret, "/", false, time.Hour)
	if _, err := m.ReadFlow(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Errorf("expected error reading a missing flow cookie")
	}
}

// Each cookie has its own lifetime: the upstream session outlives the flow
// cookies, and a flow cookie past its lifetime is refused whatever the
// browser sends.
func TestCookieLifetimes(t *testing.T) {
	t.Parallel()

	t.Run("the session outlives the flow", func(t *testing.T) {
		t.Parallel()
		m := newManager(secret, "/", false, map[string]time.Duration{
			flowCookie: time.Second, logoutCookie: time.Second, sessionCookie: time.Hour,
		})
		rec := httptest.NewRecorder()
		if err := m.SetFlow(rec, FlowState{State: "st"}); err != nil {
			t.Fatalf("SetFlow: %v", err)
		}
		if err := m.SetLogout(rec, LogoutState{State: "st"}); err != nil {
			t.Fatalf("SetLogout: %v", err)
		}
		if err := m.SetSession(rec, "the.id.token"); err != nil {
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
		if got, err := m.ReadSession(req); err != nil || got != "the.id.token" {
			t.Errorf("the session must still be readable: %q, %v", got, err)
		}
	})

	t.Run("the session ends at its own lifetime", func(t *testing.T) {
		t.Parallel()
		m := newManager(secret, "/", false, map[string]time.Duration{
			flowCookie: time.Hour, logoutCookie: time.Hour, sessionCookie: time.Second,
		})
		rec := httptest.NewRecorder()
		if err := m.SetSession(rec, "the.id.token"); err != nil {
			t.Fatalf("SetSession: %v", err)
		}
		time.Sleep(2100 * time.Millisecond)
		if got, err := m.ReadSession(replay(rec)); err == nil {
			t.Errorf("a session cookie past its lifetime must be refused, got %q", got)
		}
	})
}

// The lifetimes New sets: the browser is told the same as the codec enforces.
func TestNewLifetimes(t *testing.T) {
	m := New(secret, "/", false, 2*time.Hour)
	rec := httptest.NewRecorder()
	_ = m.SetFlow(rec, FlowState{})
	_ = m.SetLogout(rec, LogoutState{})
	_ = m.SetSession(rec, "tok")
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
