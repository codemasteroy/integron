package auth

import (
	"fmt"
	"strings"
)

// GrantedScopes extracts the scopes granted by a token from its claims,
// normalizing the shapes commonly used by identity providers:
//   - "scope":  space-delimited string (OAuth2 standard)
//   - "scp":    space-delimited string, or an array of strings (e.g. Azure AD)
//   - "scopes": an array of strings (fallback)
func GrantedScopes(claims Claims) []string {
	if claims == nil {
		return nil
	}
	var granted []string
	for _, key := range []string{"scope", "scp", "scopes"} {
		granted = append(granted, scopeValues(claims[key])...)
	}
	return granted
}

func scopeValues(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return strings.Fields(v)
	case []string:
		var out []string
		for _, s := range v {
			out = append(out, strings.Fields(s)...)
		}
		return out
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, strings.Fields(s)...)
			}
		}
		return out
	default:
		return nil
	}
}

// RequireScopes returns an error naming the missing scope(s) unless every
// required scope is present in granted. An empty required set always passes.
func RequireScopes(required, granted []string) error {
	if len(required) == 0 {
		return nil
	}
	have := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		have[s] = struct{}{}
	}
	var missing []string
	for _, s := range required {
		if _, ok := have[s]; !ok {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required scope(s): %s", strings.Join(missing, ", "))
	}
	return nil
}
