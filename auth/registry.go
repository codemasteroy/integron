package auth

import "fmt"

var verifierRegistry = make(map[string]Verifier)

// RegisterVerifier registers a Verifier for a security scheme name as declared
// in the OpenAPI spec's components.securitySchemes.
func RegisterVerifier(schemeName string, verifier Verifier) {
	verifierRegistry[schemeName] = verifier
}

// GetVerifier retrieves the Verifier registered for a security scheme name.
func GetVerifier(schemeName string) (Verifier, error) {
	verifier, exists := verifierRegistry[schemeName]
	if !exists {
		return nil, fmt.Errorf("no verifier registered for security scheme %q", schemeName)
	}
	return verifier, nil
}
