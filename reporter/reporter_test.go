package reporter

import "testing"

func TestAffectedDirective(t *testing.T) {

	tests := []struct {
		name string
		cspr ContentSecurityPolicyReport
		want string
	}{
		{"empty", ContentSecurityPolicyReport{ViolatedDirective: ""}, unknownDirective},
		{"invalid", ContentSecurityPolicyReport{ViolatedDirective: "my-directive"}, unknownDirective},
		{"valid", ContentSecurityPolicyReport{ViolatedDirective: "script-src"}, "script-src"},
		{"extended", ContentSecurityPolicyReport{ViolatedDirective: "script-src http something something"}, "script-src"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AffectedDirective(tt.cspr); got != tt.want {
				t.Errorf("AffectedDirective() = %v, want %v", got, tt.want)
			}
		})
	}
}
