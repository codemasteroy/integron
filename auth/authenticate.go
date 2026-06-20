package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
)

// Authenticate is an openapi3filter.AuthenticationFunc that handles HTTP basic
// and bearer security schemes. It parses the credentials from the request and
// delegates verification to the Verifier registered for the scheme name.
func Authenticate(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	scheme := input.SecurityScheme
	if scheme == nil {
		return input.NewError(fmt.Errorf("missing security scheme"))
	}

	r := input.RequestValidationInput.Request

	var creds Credentials
	var err error
	switch {
	case strings.EqualFold(scheme.Type, "http"):
		switch strings.ToLower(scheme.Scheme) {
		case "basic":
			creds, err = parseBasic(r)
		case "bearer":
			creds, err = parseBearer(r)
		default:
			return input.NewError(fmt.Errorf("unsupported http auth scheme %q", scheme.Scheme))
		}
	case strings.EqualFold(scheme.Type, "openIdConnect"):
		creds, err = parseBearer(r)
		creds.DiscoveryURL = scheme.OpenIdConnectUrl
	default:
		return input.NewError(fmt.Errorf("unsupported security scheme type %q", scheme.Type))
	}
	if err != nil {
		return input.NewError(err)
	}
	creds.Scopes = input.Scopes

	verifier, err := GetVerifier(input.SecuritySchemeName)
	if err != nil {
		return input.NewError(err)
	}
	claims, err := verifier(ctx, creds)
	if err != nil {
		return input.NewError(err)
	}
	if claims != nil {
		claimsSinkFrom(ctx).set(claims)
	}
	return nil
}

func parseBasic(r *http.Request) (Credentials, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return Credentials{}, fmt.Errorf("missing or invalid basic authorization header")
	}
	return Credentials{Scheme: "basic", Username: username, Password: password}, nil
}

func parseBearer(r *http.Request) (Credentials, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return Credentials{}, fmt.Errorf("missing authorization header")
	}
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return Credentials{}, fmt.Errorf("invalid bearer authorization header")
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return Credentials{}, fmt.Errorf("empty bearer token")
	}
	return Credentials{Scheme: "bearer", Token: token}, nil
}
