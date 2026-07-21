// Package oidc holds helpers shared by the consent flow — chiefly mapping the
// upstream claims to id_token claims, optionally gated by the granted scopes.
//
// Unlike the SQL login app (whose attributes are always strings), an upstream
// OIDC provider returns arbitrary JSON claims, so claims are carried as
// map[string]any throughout.
package oidc

// defaultScope is used for any claim without an explicit CLAIM_SCOPES entry.
const defaultScope = "profile"

// FilterClaims returns the subset of claims whose mapped scope is among the
// granted scopes. A claim with no entry in claimScopes is treated as belonging
// to the "profile" scope. The special "openid" scope grants no claims on its
// own. The result is nil when nothing qualifies (so the id_token carries only
// the subject).
func FilterClaims(claims map[string]any, grantedScopes []string, claimScopes map[string]string) map[string]any {
	granted := make(map[string]struct{}, len(grantedScopes))
	for _, s := range grantedScopes {
		granted[s] = struct{}{}
	}

	var out map[string]any
	for claim, val := range claims {
		scope := claimScopes[claim]
		if scope == "" {
			scope = defaultScope
		}
		if _, ok := granted[scope]; ok {
			if out == nil {
				out = make(map[string]any)
			}
			out[claim] = val
		}
	}
	return out
}

// CoerceClaims converts Hydra's context (which decodes from JSON as
// map[string]any) back to a claims map. Returns nil when the context is not a
// JSON object.
func CoerceClaims(ctx any) map[string]any {
	if m, ok := ctx.(map[string]any); ok {
		return m
	}
	return nil
}
