module github.com/Cadoles/hydra-oidc-go

go 1.26.4

toolchain go1.27.4

require (
	github.com/caarlos0/env/v11 v11.4.1
	github.com/coreos/go-oidc/v3 v3.19.0
	github.com/getsentry/sentry-go v0.47.0
	github.com/go-chi/chi/v5 v5.4.0
	github.com/go-jose/go-jose/v4 v4.1.6
	github.com/gorilla/securecookie v1.1.2
	github.com/joho/godotenv v1.5.1
	github.com/ory/hydra-client-go/v26 v26.2.0
	github.com/prometheus/client_golang v1.23.2
	golang.org/x/oauth2 v0.36.0
)

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/telemetry v0.0.0-20261116191925-e77a43154acb // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
	golang.org/x/vuln v1.10.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	honnef.co/go/tools v0.8.2 // indirect
)

tool (
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)
