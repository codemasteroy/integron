package auth

import (
	"reflect"
	"sort"
	"testing"
)

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestGrantedScopes(t *testing.T) {
	cases := []struct {
		name   string
		claims Claims
		want   []string
	}{
		{"scope space-delimited string", Claims{"scope": "read write"}, []string{"read", "write"}},
		{"scp string", Claims{"scp": "read write"}, []string{"read", "write"}},
		{"scp array", Claims{"scp": []interface{}{"read", "write"}}, []string{"read", "write"}},
		{"scopes array", Claims{"scopes": []interface{}{"read", "write"}}, []string{"read", "write"}},
		{"nil claims", nil, nil},
		{"no scope claims", Claims{"sub": "x"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GrantedScopes(c.claims)
			if len(c.want) == 0 && len(got) == 0 {
				return
			}
			if !reflect.DeepEqual(sorted(got), sorted(c.want)) {
				t.Errorf("GrantedScopes = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRequireScopes(t *testing.T) {
	if err := RequireScopes(nil, nil); err != nil {
		t.Errorf("empty required should pass, got %v", err)
	}
	if err := RequireScopes([]string{"read"}, []string{"read", "write"}); err != nil {
		t.Errorf("subset present should pass, got %v", err)
	}
	if err := RequireScopes([]string{"read", "admin"}, []string{"read", "write"}); err == nil {
		t.Error("missing scope should fail, got nil")
	}
}
