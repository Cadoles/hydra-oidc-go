package httpx

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type ctxKey int

const (
	clientIPKey ctxKey = iota
	basePathKey
)

// parseTrustedProxies turns CIDR or bare-IP strings into networks. Bare IPs
// become /32 (or /128) networks. Invalid entries are skipped.
func parseTrustedProxies(entries []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

func isTrusted(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// realIP resolves the client IP and stores it in the request context. It honors
// X-Forwarded-For ONLY when the direct peer is a configured trusted proxy,
// walking the header right-to-left and returning the first non-trusted address.
// Without trusted proxies configured, the direct peer address is always used —
// XFF is never trusted (it is client-controlled and spoofable).
func (s *Server) realIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), clientIPKey, resolveClientIP(r, s.trustedProxies))
		// X-Forwarded-Prefix only affects the (sanitized, same-origin) path of
		// emitted URLs, and the proxy sets it authoritatively. It is NOT gated on
		// a trusted peer — that gating broke sub-path serving whenever the proxy's
		// pod CIDR didn't match TRUSTED_PROXIES. The sanitizer is the safeguard.
		if bp := sanitizeBasePath(r.Header.Get("X-Forwarded-Prefix")); bp != "" {
			ctx = context.WithValue(ctx, basePathKey, bp)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sanitizeBasePath validates a forwarded path prefix: it must be a single
// absolute path segment chain ("/auth/sql"), not protocol-relative ("//evil"),
// and contain only safe path characters. The trailing slash is trimmed. Returns
// "" when invalid so callers fall back to no prefix.
func sanitizeBasePath(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") {
		return ""
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == '_' || r == '.' || r == '~':
		default:
			return ""
		}
	}
	return strings.TrimRight(p, "/")
}

// BasePath returns the request's external path prefix (from a sanitized
// X-Forwarded-Prefix), or "" when serving at the root.
func BasePath(r *http.Request) string {
	if bp, ok := r.Context().Value(basePathKey).(string); ok {
		return bp
	}
	return ""
}

func resolveClientIP(r *http.Request, trusted []*net.IPNet) string {
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}
	peer := net.ParseIP(peerHost)

	// Only consult XFF if the immediate peer is a trusted proxy.
	if len(trusted) == 0 || peer == nil || !isTrusted(peer, trusted) {
		return peerHost
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peerHost
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		if !isTrusted(ip, trusted) {
			return candidate // first non-proxy address from the right
		}
	}
	// Every hop was trusted; use the left-most forwarded address.
	return strings.TrimSpace(parts[0])
}

// ClientIP returns the resolved client IP for the request, or the raw
// RemoteAddr host if the middleware did not run.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
