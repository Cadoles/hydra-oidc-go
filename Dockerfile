# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hydra-oidc ./cmd/hydra-oidc

# --- runtime stage ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
WORKDIR /app

COPY --from=build /out/hydra-oidc /app/hydra-oidc

# This app is headless (no templates/assets): the bridge only redirects.
ENV LISTEN_ADDR=:8080

EXPOSE 8080
USER app
ENTRYPOINT ["/app/hydra-oidc"]
