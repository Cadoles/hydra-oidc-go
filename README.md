# hydra-oidc-go

A stateless [Ory Hydra](https://www.ory.sh/hydra/) login app, written in Go, that **bridges Hydra's
login/consent/logout flow to an upstream OIDC provider** (it acts as an OIDC Relying Party to a
third-party IdP). It is the OIDC-bridge sibling of `hydra-sql-go` (which authenticates against a
SQL database), and like it knows nothing of the deployment it runs in: everything that depends on
it is an environment variable with a neutral default.

## Flow

1. Hydra redirects the browser to `GET /login?login_challenge=…`.
2. The app generates `state`, `nonce` and a PKCE verifier, stashes them in an encrypted cookie, and
   redirects the browser to the upstream provider's authorization endpoint.
3. The provider redirects back to `GET /callback` (`CALLBACK_PATH`). The app validates `state`, exchanges the code
   (with PKCE), verifies the `id_token` (signature via JWKS, audience, expiry, nonce), fetches
   userinfo (JSON or JWT) unless `OIDC_SKIP_USERINFO` is set or no userinfo endpoint is known, and **accepts the Hydra login** with
   `subject = upstream sub` and the upstream claims carried in Hydra's `context`. The userinfo
   `sub` must be the `id_token`'s, and a userinfo sent as a JWT is verified with the provider's
   keys (unless `OIDC_VERIFY_SIGNATURE` is off). A userinfo that fails, or does not pass these
   checks, fails the login.
4. `GET /consent` **auto-accepts** (the bridge has no consent UI), emitting the upstream claims as
   `id_token` claims (optionally scope-filtered).
5. `GET /logout?logout_challenge=…` performs RP-initiated logout at the upstream provider (using the
   stored upstream `id_token` as `id_token_hint`), then `GET /logout/callback`
   (`LOGOUT_CALLBACK_PATH`) accepts the Hydra
   logout, once the `state` the provider returns is the one it was sent.

A challenge already used or expired (the browser's back button, a double click) is answered by
Hydra, or the dispatcher, with a 410 and a `redirect_to` when it is read: the app follows it, as
it follows the answer of an accept. An accept replayed is another matter (Hydra answers 409, an
error), so the app never replays one: a callback that returns with the `state` of a login already
accepted exchanges nothing and accepts nothing, whoever signed in at the provider this time; it
reads the challenge and follows where the flow went.

### Errors

An error is shown at `REDIRECT_ON_ERROR_URL`, with `?status_code` and `?message`, or as a plain
status when that URL is not set. With `UPSTREAM_LOGOUT_ON_ERROR`, a login that fails once the
provider has answered (an `id_token` or a userinfo that does not pass, Hydra refusing the accept)
first sends the browser to the provider's logout, then shows the error at the return: the next
attempt asks the provider for the identity again, instead of failing the same way with the same
one. It needs `OIDC_LOGOUT_ENDPOINT`.

## Stateless design

No server-side session. Cross-redirect state travels in **encrypted, signed cookies**
(`gorilla/securecookie`, keys derived from `APP_SECRET`):

- `oidc_flow` — `state`, `nonce`, PKCE verifier, login challenge (login → callback, 10 min). Once
  the login is accepted it is replaced by a mark, the `state` and the challenge alone, which
  recognises a replayed callback until it expires.
- `oidc_session` — the upstream `id_token`, needed as `id_token_hint` at logout. Held in the cookie
  by default; when `REDIS_DSN` is set it is stored in Redis under an opaque id and the cookie holds
  only that id. It lasts `HYDRA_OIDC_REDIS_TTL` in both cases: after it, a logout no longer goes
  through the provider. An `id_token` too large for a cookie (about 2 kB) is not kept: the user
  is signed in, and the logout goes without the provider; a log line says so.
- `oidc_logout` — logout challenge + state (logout → logout callback, 10 min); for
  `UPSTREAM_LOGOUT_ON_ERROR`, the error to show at the return.

Each cookie is refused once older than its own lifetime, whatever the browser sends.

## Differences vs the original PHP app

- Built on `coreos/go-oidc` + `golang.org/x/oauth2` (discovery, JWKS, verification, PKCE).
- **id_token signatures are verified** (the PHP app only checked the nonce) and **PKCE is used** —
  both default-on and each disableable per-provider (`OIDC_VERIFY_SIGNATURE`, `OIDC_PKCE_ENABLED`).
- Stateless cookies instead of a Redis session (Redis is optional, only for the logout id_token).
- A userinfo sent as a JWT is supported, its signature verified.
- The provider's tokens are no longer put in Hydra's `session.access_token`.
- The returns from the provider are served at `/callback` and `/logout/callback` by default
  (`/connect/oidc/check` and `/logout-hydra` in the PHP app): set `CALLBACK_PATH` and
  `LOGOUT_CALLBACK_PATH` to keep URLs already declared at a provider.
- `OIC_AUTHORIZE_ENDPOINT` is `OIDC_AUTHORIZE_ENDPOINT`; `POST_LOGOUT_REDIRECT_URL` and
  `TRUSTED_PROXIES`, which did nothing, are gone; the health probe is `/health`.

## Configuration (environment variables)

| Variable | Default | Notes |
| --- | --- | --- |
| `HYDRA_ADMIN_BASE_URL` | (required) | Hydra admin API, or the hydra-dispatcher URL |
| `HYDRA_API_PATH_PREFIX` | `/admin` | Set `""` when pointing at the hydra-dispatcher (v1 paths) |
| `BASE_URL` | (required) | Public base URL; `redirect_uri` is `BASE_URL` + `CALLBACK_PATH` |
| `CALLBACK_PATH` | `/callback` | Where the app serves the return from the provider's login; declared at the provider as `BASE_URL` + this path |
| `LOGOUT_CALLBACK_PATH` | `/logout/callback` | The same for the provider's logout (`post_logout_redirect_uri`) |
| `APP_SECRET` | (required) | ≥16 bytes; cookie signing + encryption keys are derived from it |
| `COOKIE_PATH` | `/` | Scope cookies to the external sub-path (e.g. `/auth/oidc`) |
| `OIDC_ISSUER` | empty | If set, endpoints are auto-discovered (`.well-known`) |
| `OIDC_AUTHORIZE_ENDPOINT` | | Explicit authorize endpoint (when no issuer) |
| `OIDC_TOKEN_ENDPOINT` | | Explicit token endpoint (when no issuer) |
| `OIDC_USERINFO_ENDPOINT` | | Explicit userinfo endpoint |
| `OIDC_JWKS_ENDPOINT` | | Explicit JWKS endpoint (needed to verify signatures without an issuer) |
| `OIDC_LOGOUT_ENDPOINT` | | Upstream RP-logout URL; plain or a `…?%s` printf template |
| `CLIENT_ID` / `CLIENT_SECRET` | (required) | RP credentials at the upstream provider |
| `OIDC_SCOPE` | `openid` | Space-separated, e.g. `openid profile email` |
| `PARAMS_TO_INSERT` | | JSON object of extra authorize params, e.g. `{"acr_values":"eidas1"}` |
| `PARAMS_TO_DELETE` | | JSON array of authorize params to strip |
| `OIDC_PKCE_ENABLED` | `true` | Disable for providers that reject PKCE |
| `OIDC_VERIFY_SIGNATURE` | `true` | Signature of the id_token, and of a userinfo sent as a JWT. Disable only for non-compliant providers |
| `OIDC_ID_TOKEN_SIGNING_ALGS` | | Comma-separated allow-list (e.g. `RS256,ES256`) |
| `OIDC_SKIP_USERINFO` | `false` | Skip the userinfo call (claims from the id_token only) |
| `CONSENT_AUTO_ACCEPT` | `true` | The bridge has no consent UI; keep this on |
| `CONSENT_REMEMBER_FOR` | `0` | Seconds Hydra remembers the consent; `0` = until the session ends |
| `FILTER_CLAIMS_BY_SCOPE` | `false` | Gate id_token claims by granted scope (off = pass-through) |
| `CLAIM_SCOPES` | `email:email` | `claim:scope,…`; other claims default to the `profile` scope |
| `AUTH_AMR` | `oidc` | Comma-separated AMR advertised to Hydra (`""` = none) |
| `AUTH_ACR` | | Overrides the upstream `acr` passed to Hydra |
| `REDIRECT_ON_ERROR_URL` | | On error, redirect here with `?status_code&message`; else a plain status |
| `UPSTREAM_LOGOUT_ON_ERROR` | `false` | End the provider's session before the error, when a login fails after the provider answered |
| `REDIS_DSN` | empty | Optional; stores the upstream id_token for logout (else cookie) |
| `HYDRA_OIDC_REDIS_PREFIX` | | Redis key prefix |
| `HYDRA_OIDC_REDIS_TTL` | `3600` | Upstream-session TTL, in seconds: the cookie's, and the Redis entry's |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`; JSON lines on stdout |
| `SENTRY_DSN` / `SENTRY_ENVIRONMENT` | | Optional error reporting |
| `LISTEN_ADDR` | `:8080` | |

`GET /health` answers 200 for the probes, `GET /metrics` the Prometheus metrics: keep the latter
off the public route.

## Build & run

```bash
go build ./... && go vet ./... && go test -race ./...
go tool staticcheck ./... && go tool govulncheck ./...
docker build -t hydra-oidc-go .
```

The image is distroless: a static binary, no shell, running as `nonroot`. Its `HEALTHCHECK` is
the binary itself (`/hydra-oidc healthcheck`, which asks `/health` on `LISTEN_ADDR`).

## Releases

A tag `v*` pushed to GitHub runs `.github/workflows/release.yaml`: the image is built and pushed
by its digest, its CycloneDX SBOM attested, both signed with the key pair of the project
(`cosign.pub`, at the root of the repository), and the version tags are set only once the
signature verifies.

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
