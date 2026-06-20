package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
)

const EXPECTED_ERROR_GOT_NIL = "Expected error, got nil"
const EXPECTED_NIL_GOT = "Expected nil, got %v"

func authInput(scheme *openapi3.SecurityScheme, name string, r *http.Request) *openapi3filter.AuthenticationInput {
	return &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: r},
		SecuritySchemeName:     name,
		SecurityScheme:         scheme,
	}
}

func basicScheme() *openapi3.SecurityScheme {
	return &openapi3.SecurityScheme{Type: "http", Scheme: "basic"}
}

func bearerScheme() *openapi3.SecurityScheme {
	return &openapi3.SecurityScheme{Type: "http", Scheme: "bearer"}
}

func TestAuthenticateBasicValid(t *testing.T) {
	RegisterVerifier("basicAuth", StaticBasicVerifier("alice", "secret"))

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.SetBasicAuth("alice", "secret")

	if err := Authenticate(context.Background(), authInput(basicScheme(), "basicAuth", r)); err != nil {
		t.Errorf(EXPECTED_NIL_GOT, err)
	}
}

func TestAuthenticateBasicWrongPassword(t *testing.T) {
	RegisterVerifier("basicAuth", StaticBasicVerifier("alice", "secret"))

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.SetBasicAuth("alice", "wrong")

	if err := Authenticate(context.Background(), authInput(basicScheme(), "basicAuth", r)); err == nil {
		t.Error(EXPECTED_ERROR_GOT_NIL)
	}
}

func TestAuthenticateBasicMissingHeader(t *testing.T) {
	RegisterVerifier("basicAuth", StaticBasicVerifier("alice", "secret"))

	r, _ := http.NewRequest("GET", "http://example.com", nil)

	if err := Authenticate(context.Background(), authInput(basicScheme(), "basicAuth", r)); err == nil {
		t.Error(EXPECTED_ERROR_GOT_NIL)
	}
}

func TestAuthenticateBearerValid(t *testing.T) {
	RegisterVerifier("bearerAuth", StaticBearerVerifier("t0ken"))

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer t0ken")

	if err := Authenticate(context.Background(), authInput(bearerScheme(), "bearerAuth", r)); err != nil {
		t.Errorf(EXPECTED_NIL_GOT, err)
	}
}

func TestAuthenticateBearerWrongToken(t *testing.T) {
	RegisterVerifier("bearerAuth", StaticBearerVerifier("t0ken"))

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer nope")

	if err := Authenticate(context.Background(), authInput(bearerScheme(), "bearerAuth", r)); err == nil {
		t.Error(EXPECTED_ERROR_GOT_NIL)
	}
}

func TestAuthenticateBearerCaseInsensitivePrefix(t *testing.T) {
	RegisterVerifier("bearerAuth", StaticBearerVerifier("t0ken"))

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Set("Authorization", "bearer t0ken")

	if err := Authenticate(context.Background(), authInput(bearerScheme(), "bearerAuth", r)); err != nil {
		t.Errorf(EXPECTED_NIL_GOT, err)
	}
}

func TestAuthenticateUnregisteredScheme(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Set("Authorization", "Bearer t0ken")

	if err := Authenticate(context.Background(), authInput(bearerScheme(), "unknownScheme", r)); err == nil {
		t.Error(EXPECTED_ERROR_GOT_NIL)
	}
}

func TestAuthenticateUnsupportedSchemeType(t *testing.T) {
	scheme := &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-API-Key"}
	r, _ := http.NewRequest("GET", "http://example.com", nil)

	if err := Authenticate(context.Background(), authInput(scheme, "apiKeyAuth", r)); err == nil {
		t.Error(EXPECTED_ERROR_GOT_NIL)
	}
}

func TestParseBasicMalformed(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	// Not base64 / missing colon separator.
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("nocolon")))

	_, _, ok := r.BasicAuth()
	if ok {
		t.Error("Expected BasicAuth parse to fail for credentials without a colon")
	}
}
