package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestClient points an SDKClient at a stub admin API. It forces a JSON
// content type on every response so the SDK decoder accepts the body.
func newTestClient(t *testing.T, h http.HandlerFunc) *SDKClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "/admin", 5*time.Second, nil)
}

func TestAPIErrClassification(t *testing.T) {
	boom := errors.New("dial tcp: connection refused")

	cases := []struct {
		name   string
		status int // 0 = no response at all
		err    error
		want   error // nil = no error expected
	}{
		{"unknown challenge", http.StatusNotFound, errors.New("404"), ErrChallengeNotFound},
		{"challenge gone", http.StatusGone, errors.New("410"), ErrChallengeNotFound},
		{"hydra broken", http.StatusInternalServerError, errors.New("500"), ErrUnavailable},
		{"hydra down", http.StatusServiceUnavailable, nil, ErrUnavailable},
		{"no response at all", 0, boom, ErrUnavailable},
		{"success", http.StatusOK, nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			if tc.status != 0 {
				resp = &http.Response{StatusCode: tc.status}
			}
			got := apiErr("op", resp, tc.err)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("apiErr = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("apiErr = %v, want errors.Is(..., %v)", got, tc.want)
			}
		})
	}
}

// A 4xx that is not 404/410 must not pass as success.
func TestAPIErrOtherClientErrorIsUnclassified(t *testing.T) {
	got := apiErr("op", &http.Response{StatusCode: http.StatusConflict}, nil)
	if got == nil {
		t.Fatal("apiErr = nil, want an error for 409")
	}
	if errors.Is(got, ErrChallengeNotFound) || errors.Is(got, ErrUnavailable) {
		t.Fatalf("apiErr = %v, want neither sentinel", got)
	}
}

// A 410 carries the way back to the client that started the flow, on a read as
// on an accept; a 404 does not.
func TestGoneChallengeKeepsRedirectTo(t *testing.T) {
	const back = "https://partner.example/cb?error=login_required"
	calls := map[string]func(*SDKClient) error{
		"get login": func(c *SDKClient) error {
			_, err := c.GetLoginRequest(context.Background(), "c")
			return err
		},
		"accept login": func(c *SDKClient) error {
			_, err := c.AcceptLogin(context.Background(), "c", LoginAccept{Subject: "s"})
			return err
		},
		"get consent": func(c *SDKClient) error {
			_, err := c.GetConsentRequest(context.Background(), "c")
			return err
		},
		"accept consent": func(c *SDKClient) error {
			_, err := c.AcceptConsent(context.Background(), "c", ConsentAccept{})
			return err
		},
		"accept logout": func(c *SDKClient) error {
			_, err := c.AcceptLogout(context.Background(), "c")
			return err
		},
	}
	answers := []struct {
		name   string
		status int
		body   map[string]any
		want   string
	}{
		{"gone with redirect", http.StatusGone, map[string]any{"redirect_to": back}, back},
		{"not found", http.StatusNotFound, map[string]any{"error": "Not Found", "status_code": 404}, ""},
	}
	for name, call := range calls {
		for _, a := range answers {
			t.Run(name+"/"+a.name, func(t *testing.T) {
				c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(a.status)
					_ = json.NewEncoder(w).Encode(a.body)
				})
				err := call(c)
				if !errors.Is(err, ErrChallengeNotFound) {
					t.Fatalf("err = %v, want ErrChallengeNotFound", err)
				}
				if got := RedirectTo(err); got != a.want {
					t.Errorf("RedirectTo = %q, want %q", got, a.want)
				}
			})
		}
	}
}

func TestRedirectToOfOtherErrors(t *testing.T) {
	if got := RedirectTo(errors.New("boom")); got != "" {
		t.Errorf("RedirectTo = %q, want empty", got)
	}
	if got := RedirectTo(nil); got != "" {
		t.Errorf("RedirectTo(nil) = %q, want empty", got)
	}
}
