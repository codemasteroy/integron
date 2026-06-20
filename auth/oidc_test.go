package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const testKeyID = "test-key"

// mockOIDC is an httptest-backed OIDC provider that serves a discovery document
// and a JWKS built from an in-memory RSA key, and can mint signed JWTs.
type mockOIDC struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	issuer string
}

func newMockOIDC(t *testing.T) *mockOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	m := &mockOIDC{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                m.issuer,
			"jwks_uri":                              m.issuer + "/jwks",
			"authorization_endpoint":                m.issuer + "/auth",
			"token_endpoint":                        m.issuer + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     testKeyID,
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockOIDC) discoveryURL() string { return m.issuer + wellKnownSuffix }

// sign mints a JWT signed with the mock provider's key (kid = testKeyID unless
// signWith overrides the signing key for negative tests).
func (m *mockOIDC) sign(t *testing.T, claims map[string]interface{}, signWith *rsa.PrivateKey) string {
	t.Helper()
	if signWith == nil {
		signWith = m.key
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: signWith, KeyID: testKeyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return token
}

func (m *mockOIDC) baseClaims(aud string) map[string]interface{} {
	return map[string]interface{}{
		"iss": m.issuer,
		"sub": "user-123",
		"aud": aud,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func TestOIDCVerifierValid(t *testing.T) {
	m := newMockOIDC(t)
	verifier := OIDCVerifier(OIDCConfig{Audience: "my-api"})
	token := m.sign(t, m.baseClaims("my-api"), nil)

	claims, err := verifier(context.Background(), Credentials{Token: token, DiscoveryURL: m.discoveryURL()})
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Errorf("expected sub user-123, got %v", claims["sub"])
	}
}

func TestOIDCVerifierIssuerFromConfig(t *testing.T) {
	m := newMockOIDC(t)
	verifier := OIDCVerifier(OIDCConfig{Issuer: m.issuer}) // no audience -> skip aud check
	token := m.sign(t, m.baseClaims("anything"), nil)

	if _, err := verifier(context.Background(), Credentials{Token: token}); err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
}

func TestOIDCVerifierExpired(t *testing.T) {
	m := newMockOIDC(t)
	verifier := OIDCVerifier(OIDCConfig{Issuer: m.issuer})
	claims := m.baseClaims("x")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := m.sign(t, claims, nil)

	if _, err := verifier(context.Background(), Credentials{Token: token}); err == nil {
		t.Error("expected expired token to fail, got nil")
	}
}

func TestOIDCVerifierWrongAudience(t *testing.T) {
	m := newMockOIDC(t)
	verifier := OIDCVerifier(OIDCConfig{Issuer: m.issuer, Audience: "my-api"})
	token := m.sign(t, m.baseClaims("other-api"), nil)

	if _, err := verifier(context.Background(), Credentials{Token: token}); err == nil {
		t.Error("expected wrong audience to fail, got nil")
	}
}

func TestOIDCVerifierWrongIssuer(t *testing.T) {
	m := newMockOIDC(t)
	verifier := OIDCVerifier(OIDCConfig{Issuer: m.issuer})
	claims := m.baseClaims("x")
	claims["iss"] = "https://evil.example.com"
	token := m.sign(t, claims, nil)

	if _, err := verifier(context.Background(), Credentials{Token: token}); err == nil {
		t.Error("expected wrong issuer to fail, got nil")
	}
}

func TestOIDCVerifierBadSignature(t *testing.T) {
	m := newMockOIDC(t)
	verifier := OIDCVerifier(OIDCConfig{Issuer: m.issuer})
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := m.sign(t, m.baseClaims("x"), otherKey)

	if _, err := verifier(context.Background(), Credentials{Token: token}); err == nil {
		t.Error("expected bad signature to fail, got nil")
	}
}

func TestOIDCVerifierScopeEnforcement(t *testing.T) {
	m := newMockOIDC(t)
	verifier := OIDCVerifier(OIDCConfig{Issuer: m.issuer})

	claims := m.baseClaims("x")
	claims["scope"] = "read write"
	token := m.sign(t, claims, nil)

	// Required scope present.
	got, err := verifier(context.Background(), Credentials{Token: token, Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("expected scope satisfied, got %v", err)
	}
	if _, ok := got["scopes"]; !ok {
		t.Error("expected normalized scopes exposed in claims")
	}

	// Required scope missing.
	if _, err := verifier(context.Background(), Credentials{Token: token, Scopes: []string{"admin"}}); err == nil {
		t.Error("expected missing scope to fail, got nil")
	}
}

func TestOIDCVerifierMissingToken(t *testing.T) {
	verifier := OIDCVerifier(OIDCConfig{Issuer: "https://issuer.example.com"})
	if _, err := verifier(context.Background(), Credentials{}); err == nil {
		t.Error("expected missing token to fail, got nil")
	}
}

func TestOIDCVerifierNoIssuer(t *testing.T) {
	verifier := OIDCVerifier(OIDCConfig{})
	if _, err := verifier(context.Background(), Credentials{Token: "x.y.z"}); err == nil {
		t.Error("expected missing issuer to fail, got nil")
	}
}
