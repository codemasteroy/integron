package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
)

// StaticBasicVerifier returns a Verifier that accepts a single username and
// password pair, compared in constant time. It fails closed when the security
// requirement demands scopes, which a static credential cannot satisfy.
func StaticBasicVerifier(username, password string) Verifier {
	return func(_ context.Context, creds Credentials) (Claims, error) {
		if len(creds.Scopes) > 0 {
			return nil, fmt.Errorf("static basic auth cannot satisfy required scopes")
		}
		userOK := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(creds.Password), []byte(password)) == 1
		if !userOK || !passOK {
			return nil, fmt.Errorf("invalid username or password")
		}
		return Claims{"sub": username}, nil
	}
}

// StaticBearerVerifier returns a Verifier that accepts a single bearer token,
// compared in constant time. It fails closed when the security requirement
// demands scopes, which a static token cannot satisfy.
func StaticBearerVerifier(token string) Verifier {
	return func(_ context.Context, creds Credentials) (Claims, error) {
		if len(creds.Scopes) > 0 {
			return nil, fmt.Errorf("static bearer auth cannot satisfy required scopes")
		}
		if subtle.ConstantTimeCompare([]byte(creds.Token), []byte(token)) != 1 {
			return nil, fmt.Errorf("invalid bearer token")
		}
		return nil, nil
	}
}
