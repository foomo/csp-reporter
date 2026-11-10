package reporter

import "testing"

func TestAffectedDirective(t *testing.T) {

	tests := []struct {
		name       string
		cspr       ContentSecurityPolicyReport
		want       string
		wantSource string
	}{
		{"empty", ContentSecurityPolicyReport{ViolatedDirective: ""}, unknownDirective, sourceMissing},
		{"invalid", ContentSecurityPolicyReport{ViolatedDirective: "my-directive"}, unknownDirective, sourceUnrecognised},
		{"valid", ContentSecurityPolicyReport{ViolatedDirective: "script-src"}, "script-src", sourceViolatedDirective},
		{"extended", ContentSecurityPolicyReport{ViolatedDirective: "script-src http something something"}, "script-src", sourceViolatedDirective},
		{"effective only", ContentSecurityPolicyReport{EffectiveDirective: "img-src"}, "img-src", sourceEffectiveDirective},
		{
			"effective preferred over a fallback",
			ContentSecurityPolicyReport{ViolatedDirective: "default-src 'self'", EffectiveDirective: "img-src"},
			"img-src", sourceEffectiveDirective,
		},
		{
			"unknown effective falls back to violated",
			ContentSecurityPolicyReport{ViolatedDirective: "script-src 'self'", EffectiveDirective: "trusted-types"},
			"script-src", sourceViolatedDirective,
		},
		{
			"neither known",
			ContentSecurityPolicyReport{ViolatedDirective: "require-trusted-types-for", EffectiveDirective: "trusted-types"},
			unknownDirective, sourceUnrecognised,
		},
		{"effective unknown, violated empty", ContentSecurityPolicyReport{EffectiveDirective: "my-directive"}, unknownDirective, sourceUnrecognised},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AffectedDirective(tt.cspr); got != tt.want {
				t.Errorf("AffectedDirective() = %v, want %v", got, tt.want)
			}
			if _, source := directiveWithSource(tt.cspr); source != tt.wantSource {
				t.Errorf("directive source = %v, want %v", source, tt.wantSource)
			}
		})
	}
}
