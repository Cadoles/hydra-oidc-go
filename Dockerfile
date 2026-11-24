# --- build stage ---
# Images pinned by digest, bumped by Renovate. This one sets GOTOOLCHAIN=local:
# keep its Go version that of the toolchain directive of go.mod.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
# Cache mounts: the build fetches only the modules it compiles, not the tools
# of go.mod, and keeps them across go.mod changes.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/hydra-oidc ./cmd/hydra-oidc

# --- runtime stage ---
# No shell, no package manager, the CA certificates the calls to the provider
# need. The app is headless (no templates nor assets): it only redirects. The
# binary probes itself for HEALTHCHECK, on LISTEN_ADDR.
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/hydra-oidc /hydra-oidc
ENV LISTEN_ADDR=:8080
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s CMD ["/hydra-oidc", "healthcheck"]
ENTRYPOINT ["/hydra-oidc"]
