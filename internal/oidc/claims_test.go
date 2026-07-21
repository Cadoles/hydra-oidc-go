package oidc

import "testing"

func TestFilterClaims(t *testing.T) {
	claims := map[string]any{
		"email":      "a@b.c",
		"given_name": "Ada",
		"verified":   true,
	}
	scopes := map[string]string{"email": "email"} // given_name/verified default to "profile"

	got := FilterClaims(claims, []string{"openid", "email"}, scopes)
	if _, ok := got["email"]; !ok {
		t.Errorf("email should be granted by the email scope")
	}
	if _, ok := got["given_name"]; ok {
		t.Errorf("given_name should NOT be granted without the profile scope")
	}

	got = FilterClaims(claims, []string{"openid", "profile", "email"}, scopes)
	if len(got) != 3 {
		t.Errorf("with profile+email all claims granted, got %d: %#v", len(got), got)
	}

	if FilterClaims(claims, []string{"openid"}, scopes) != nil {
		t.Errorf("openid alone should grant no claims (nil)")
	}
}

func TestCoerceClaims(t *testing.T) {
	in := map[string]any{"sub": "x", "n": float64(1)}
	if got := CoerceClaims(in); got["sub"] != "x" || got["n"].(float64) != 1 {
		t.Errorf("CoerceClaims passthrough failed: %#v", got)
	}
	if CoerceClaims("not-a-map") != nil {
		t.Errorf("non-object context should coerce to nil")
	}
}
