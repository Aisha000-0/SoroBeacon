package api

import (
	"net/http"

	"github.com/sorotrail/sorobeacon/internal/auth"
)

// AuthMiddleware requires a credential on every /api/v1 route once a token
// is configured through API_TOKEN. Two credentials are accepted:
//
//   - Authorization: Bearer <token> — scripts, CI and other services.
//   - the dashboard's session cookie — a browser that signed in at /login.
//     The dashboard is same-origin with the API and links straight to
//     endpoints like /api/v1/alerts.csv, and a plain link cannot attach a
//     header, so the cookie has to count here too. It is HttpOnly and
//     SameSite=Lax, so a cross-site page can neither read it nor get a
//     forged POST to carry it.
//
// With no token configured the middleware steps aside completely: an
// unauthenticated deployment behaves exactly as it did before this existed
// (the process logs one startup warning instead).
//
// Probes (/health, /livez, /readyz) stay exempt so an authenticated
// deployment cannot fail its own health checks, and so the docker-compose
// healthcheck keeps working with no token in its environment. This is the
// same exemption the rate limiter uses (isProbePath); the cost is that the
// readiness detail — dependency names and error strings — is readable
// without a token. Do not expose these paths to the public internet.
func AuthMiddleware(a *auth.Authenticator) func(http.Handler) http.Handler {
	if !a.Enabled() {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isProbePath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if !a.Authenticated(r) {
				// One message for a missing header, a malformed one and a
				// wrong token: the response must not tell a caller which of
				// those it got. The presented credential is never echoed.
				w.Header().Set("WWW-Authenticate", `Bearer realm="sorobeacon"`)
				writeErr(w, r, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
