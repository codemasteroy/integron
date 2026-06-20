package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

const wellKnownSuffix = "/.well-known/openid-configuration"

// OIDCConfig configures an OIDC verifier. Both fields are optional.
type OIDCConfig struct {
	// Issuer is the OIDC issuer URL. When empty, the issuer is derived from the
	// security scheme's openIdConnectUrl (DiscoveryURL on the credentials).
	Issuer string
	// Audience is the expected token audience (aud). When empty, the audience
	// check is skipped (signature, exp and iss are still verified).
	Audience string
}

// OIDCVerifier returns a Verifier that validates JWT bearer tokens against an
// OIDC provider discovered via its .well-known/openid-configuration document.
// Providers are discovered lazily on first use and cached per issuer, so server
// startup does not depend on the identity provider being reachable.
func OIDCVerifier(cfg OIDCConfig) Verifier {
	cache := &providerCache{providers: make(map[string]*oidc.Provider)}

	return func(ctx context.Context, creds Credentials) (Claims, error) {
		if creds.Token == "" {
			return nil, fmt.Errorf("missing bearer token")
		}

		issuer := cfg.Issuer
		if issuer == "" {
			issuer = issuerFromDiscoveryURL(creds.DiscoveryURL)
		}
		if issuer == "" {
			return nil, fmt.Errorf("no OIDC issuer configured and none derivable from the security scheme")
		}

		provider, err := cache.get(ctx, issuer)
		if err != nil {
			return nil, fmt.Errorf("OIDC discovery failed for %q: %w", issuer, err)
		}

		verifierCfg := &oidc.Config{ClientID: cfg.Audience}
		if cfg.Audience == "" {
			verifierCfg.SkipClientIDCheck = true
		}

		idToken, err := provider.Verifier(verifierCfg).Verify(ctx, creds.Token)
		if err != nil {
			return nil, fmt.Errorf("token verification failed: %w", err)
		}

		var claims Claims
		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse token claims: %w", err)
		}

		granted := GrantedScopes(claims)
		if err := RequireScopes(creds.Scopes, granted); err != nil {
			return nil, err
		}
		// Expose the normalized granted scopes to the step pipeline.
		if len(granted) > 0 {
			claims["scopes"] = granted
		}

		return claims, nil
	}
}

func issuerFromDiscoveryURL(url string) string {
	return strings.TrimSuffix(strings.TrimSpace(url), wellKnownSuffix)
}

// providerCache lazily creates and caches an *oidc.Provider per issuer.
type providerCache struct {
	mu        sync.Mutex
	providers map[string]*oidc.Provider
}

func (c *providerCache) get(ctx context.Context, issuer string) (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if provider, ok := c.providers[issuer]; ok {
		return provider, nil
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	c.providers[issuer] = provider
	return provider, nil
}
