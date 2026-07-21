// Package obs provides optional error reporting (Sentry). When no DSN is
// configured it degrades to a no-op so the rest of the app stays unaware.
package obs

import (
	"time"

	"github.com/getsentry/sentry-go"
)

// Reporter captures errors to an external service.
type Reporter interface {
	Capture(err error)
}

// Noop discards everything.
type Noop struct{}

func (Noop) Capture(error) {}

type sentryReporter struct{}

func (sentryReporter) Capture(err error) {
	if err != nil {
		sentry.CaptureException(err)
	}
}

// Init returns a Reporter and a flush function. With an empty DSN it returns a
// no-op reporter. The flush function should be deferred in main.
func Init(dsn, environment, release string) (Reporter, func(), error) {
	if dsn == "" {
		return Noop{}, func() {}, nil
	}
	if err := sentry.Init(sentry.ClientOptions{
		Dsn:         dsn,
		Environment: environment,
		Release:     release,
	}); err != nil {
		return Noop{}, func() {}, err
	}
	flush := func() { sentry.Flush(2 * time.Second) }
	return sentryReporter{}, flush, nil
}
