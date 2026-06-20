package auth

import "context"

// Claims holds the identity attributes a verifier established for a request,
// exposed to the step pipeline as $.auth.
type Claims map[string]interface{}

// Credentials holds the credentials parsed from an incoming request's
// Authorization header for a given security scheme.
type Credentials struct {
	// Scheme is the HTTP auth scheme the credentials were parsed from,
	// either "basic" or "bearer".
	Scheme string
	// Username and Password are populated for basic auth.
	Username string
	Password string
	// Token is populated for bearer auth.
	Token string
	// Scopes are the scopes required by the matched security requirement.
	Scopes []string
	// DiscoveryURL is the OpenID Connect discovery URL declared on the
	// security scheme (openIdConnectUrl), populated for openIdConnect schemes.
	DiscoveryURL string
}

// Verifier validates parsed credentials for a security scheme. On success it
// returns the Claims it established (may be nil) and a nil error; on failure it
// returns a non-nil error describing why authentication failed.
type Verifier func(ctx context.Context, creds Credentials) (Claims, error)
