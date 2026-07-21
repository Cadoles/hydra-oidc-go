# hydra-oidc-go

A stateless [Ory Hydra](https://www.ory.sh/hydra/) login app, written in Go, that **bridges Hydra's
login/consent/logout flow to an upstream OIDC provider** (it acts as an OIDC Relying Party to a
third-party IdP such as FranceConnect). It is the OIDC-bridge sibling of `hydra-sql-go` (which
authenticates against a SQL database).

## Flow

1. Hydra redirects the browser to `GET /login?login_challenge=…`.
2. The app generates `state`, `nonce` and a PKCE verifier, stashes them in an encrypted cookie, and
   redirects the browser to the upstream provider's authorization endpoint.
3. The provider redirects back to `GET /callback`. The app validates `state`, exchanges the code
   (with PKCE), verifies the `id_token` (signature via JWKS, audience, expiry, nonce), optionally
   fetches userinfo (JSON or JWT), and **accepts the Hydra login** with `subject = upstream sub` and
   the upstream claims carried in Hydra's `context`.
4. `GET /consent` **auto-accepts** (the bridge has no consent UI), emitting the upstream claims as
   `id_token` claims (optionally scope-filtered).
5. `GET /logout?logout_challenge=…` performs RP-initiated logout at the upstream provider (using the
   stored upstream `id_token` as `id_token_hint`), then `GET /logout/callback` accepts the Hydra
   logout.

## Stateless design

No server-side session. Cross-redirect state travels in **encrypted, signed cookies**
(`gorilla/securecookie`, keys derived from `APP_SECRET`):

- `oidc_flow` — `state`, `nonce`, PKCE verifier, login challenge (login → callback, ~10 min).
- `oidc_session` — the upstream `id_token`, needed as `id_token_hint` at logout. Held in the cookie
  by default; when `REDIS_DSN` is set it is stored in Redis under an opaque id and the cookie holds
  only that id.
- `oidc_logout` — logout challenge + state (logout → logout callback, ~10 min).

## Differences vs the original PHP app

- Built on `coreos/go-oidc` + `golang.org/x/oauth2` (discovery, JWKS, verification, PKCE).
- **id_token signatures are verified** (the PHP app only checked the nonce) and **PKCE is used** —
  both default-on and each disableable per-provider (`OIDC_VERIFY_SIGNATURE`, `OIDC_PKCE_ENABLED`).
- Stateless cookies instead of a Redis session (Redis is optional, only for the logout id_token).
- The JWT-encoded userinfo quirk (FranceConnect) is preserved.

## Configuration (environment variables)

| Variable | Default | Notes |
| --- | --- | --- |
| `HYDRA_ADMIN_BASE_URL` | (required) | Hydra admin API, or the hydra-dispatcher URL |
| `HYDRA_API_PATH_PREFIX` | `/admin` | Set `""` when pointing at the hydra-dispatcher (v1 paths) |
| `BASE_URL` | (required) | Public base URL; `redirect_uri` is `BASE_URL` + `/callback` |
| `APP_SECRET` | (required) | ≥16 bytes; cookie signing + encryption keys are derived from it |
| `COOKIE_PATH` | `/` | Scope cookies to the external sub-path (e.g. `/auth/oidc`) |
| `OIDC_ISSUER` | empty | If set, endpoints are auto-discovered (`.well-known`) |
| `OIC_AUTHORIZE_ENDPOINT` | | Explicit authorize endpoint (when no issuer) |
| `OIDC_TOKEN_ENDPOINT` | | Explicit token endpoint (when no issuer) |
| `OIDC_USERINFO_ENDPOINT` | | Explicit userinfo endpoint |
| `OIDC_JWKS_ENDPOINT` | | Explicit JWKS endpoint (needed to verify signatures without an issuer) |
| `OIDC_LOGOUT_ENDPOINT` | | Upstream RP-logout URL; plain or a `…?%s` printf template |
| `CLIENT_ID` / `CLIENT_SECRET` | (required) | RP credentials at the upstream provider |
| `OIDC_SCOPE` | `openid` | Space-separated, e.g. `openid identite_pivot email` |
| `PARAMS_TO_INSERT` | | JSON object of extra authorize params, e.g. `{"acr_values":"eidas1"}` |
| `PARAMS_TO_DELETE` | | JSON array of authorize params to strip |
| `OIDC_PKCE_ENABLED` | `true` | Disable for providers that reject PKCE |
| `OIDC_VERIFY_SIGNATURE` | `true` | Disable only for non-compliant providers |
| `OIDC_ID_TOKEN_SIGNING_ALGS` | | Comma-separated allow-list (e.g. `RS256,ES256`) |
| `OIDC_SKIP_USERINFO` | `false` | Skip the userinfo call (claims from the id_token only) |
| `CONSENT_AUTO_ACCEPT` | `true` | The bridge has no consent UI; keep this on |
| `FILTER_CLAIMS_BY_SCOPE` | `false` | Gate id_token claims by granted scope (off = pass-through) |
| `CLAIM_SCOPES` | `email:email` | `claim:scope,…`; other claims default to the `profile` scope |
| `AUTH_AMR` | `oidc` | Comma-separated AMR advertised to Hydra (`""` = none) |
| `AUTH_ACR` | | Overrides the upstream `acr` passed to Hydra |
| `POST_LOGOUT_REDIRECT_URL` | | Passed through to the upstream logout |
| `REDIRECT_ON_ERROR_URL` | | On error, redirect here with `?status_code&message`; else a plain status |
| `REDIS_DSN` | empty | Optional; stores the upstream id_token for logout (else cookie) |
| `HYDRA_OIDC_REDIS_PREFIX` | | Redis key prefix |
| `HYDRA_OIDC_REDIS_TTL` | `3600` | Upstream-session TTL, in seconds |
| `TRUSTED_PROXIES` | | CIDRs/IPs trusted for `X-Forwarded-For` |
| `SENTRY_DSN` / `SENTRY_ENVIRONMENT` | | Optional error reporting |
| `LISTEN_ADDR` | `:8080` | |

## Build & run

```bash
go build ./... && go vet ./... && go test ./...
docker build -t hydra-oidc-go .
```
