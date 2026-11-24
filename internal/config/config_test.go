package config

import (
	"strings"
	"testing"
	"time"
)

func baseYAML() string {
	return `
organisation:
  name: Example Corp
  domains: [example.com]
safety:
  max_global_rps: 3
  max_per_host_rps: 0.2
`
}

func TestParseMinimal(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Organisation.Name != "Example Corp" {
		t.Errorf("name = %q", cfg.Organisation.Name)
	}
	if !cfg.Scope().InDomain("a.b.example.com") {
		t.Error("subdomain should be in scope")
	}
	if cfg.Scope().InDomain("evil-example.com") {
		t.Error("suffix lookalike must not be in scope")
	}
	if !cfg.Scope().InDomain("example.com") {
		t.Error("apex should be in scope")
	}
}

func TestRejectsUnsafeRates(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "global above ceiling",
			yaml: strings.Replace(baseYAML(), "max_global_rps: 3", "max_global_rps: 500", 1),
			want: "hard ceiling",
		},
		{
			name: "per host above 1",
			yaml: strings.Replace(baseYAML(), "max_per_host_rps: 0.2", "max_per_host_rps: 5", 1),
			want: "exceeds 1 request/second/host",
		},
		{
			name: "zero global",
			yaml: strings.Replace(baseYAML(), "max_global_rps: 3", "max_global_rps: -1", 1),
			want: "max_global_rps must be > 0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestRejectsUnsafePaths(t *testing.T) {
	for _, p := range []string{"/delete-user", "/admin?action=drop", "http://elsewhere/", "/shutdown"} {
		y := strings.Replace(baseYAML(), "safety:", "probes:\n  http_paths: [\""+p+"\"]\nsafety:", 1)
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("path %q should have been rejected", p)
		}
	}
}

func TestScanWindow(t *testing.T) {
	y := strings.Replace(baseYAML(), "safety:", `safety:
  scan_window: "01:00-05:00"
  timezone: UTC`, 1)
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cases := []struct {
		when time.Time
		want bool
	}{
		{time.Date(2026, 1, 1, 0, 59, 0, 0, time.UTC), false},
		{time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 1, 1, 4, 59, 0, 0, time.UTC), true},
		{time.Date(2026, 1, 1, 5, 0, 0, 0, time.UTC), false},
		{time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		if got := cfg.InWindow(c.when); got != c.want {
			t.Errorf("InWindow(%s) = %v, want %v", c.when.Format("15:04"), got, c.want)
		}
	}
	// NextWindowStart from noon should be 01:00 the following day.
	next := cfg.NextWindowStart(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	want := time.Date(2026, 1, 2, 1, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("NextWindowStart = %s, want %s", next, want)
	}
}

func TestWindowCrossingMidnight(t *testing.T) {
	y := strings.Replace(baseYAML(), "safety:", `safety:
  scan_window: "23:00-02:00"
  timezone: UTC`, 1)
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, c := range []struct {
		h    int
		want bool
	}{{22, false}, {23, true}, {0, true}, {1, true}, {2, false}, {12, false}} {
		got := cfg.InWindow(time.Date(2026, 1, 1, c.h, 30, 0, 0, time.UTC))
		if got != c.want {
			t.Errorf("hour %d: got %v want %v", c.h, got, c.want)
		}
	}
}

func TestScopeExclusions(t *testing.T) {
	y := baseYAML() + `
  exclude_hosts: ["*.internal.example.com", "payments.example.com"]
  exclude_ips: ["10.0.0.0/8"]
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sc := cfg.Scope()
	for _, h := range []string{"a.internal.example.com", "payments.example.com", "x.y.internal.example.com"} {
		if !sc.ExcludedHost(h) {
			t.Errorf("%s should be excluded", h)
		}
	}
	for _, h := range []string{"www.example.com", "internal.example.com.evil.com"} {
		if sc.ExcludedHost(h) {
			t.Errorf("%s should not be excluded", h)
		}
	}
	if !sc.ExcludedIP("10.1.2.3") {
		t.Error("10.1.2.3 should be excluded")
	}
	if sc.ExcludedIP("8.8.8.8") {
		t.Error("8.8.8.8 should not be excluded")
	}
}

func TestScopeRejectsBadDomain(t *testing.T) {
	_, err := Parse([]byte(`
organisation:
  name: X
  domains: ["not a domain"]
`))
	if err == nil {
		t.Fatal("expected error for a domain that is not registrable")
	}
}

func TestOwnerRulePrecedence(t *testing.T) {
	y := baseYAML() + `
owners:
  default_team: unowned
  rules:
    - name: partner
      team: vendor-mgmt
      class: partner
    - name: marketing
      team: marketing
      host_pattern: "(?i)promo"
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := cfg.OwnerRule("promo.example.com", "partner", nil, nil, nil)
	if r == nil || r.Team != "vendor-mgmt" {
		t.Errorf("class rule should win first, got %+v", r)
	}
	r = cfg.OwnerRule("promo.example.com", "company", nil, nil, nil)
	if r == nil || r.Team != "marketing" {
		t.Errorf("host pattern rule should match, got %+v", r)
	}
	r = cfg.OwnerRule("www.example.com", "company", nil, nil, nil)
	if r != nil {
		t.Errorf("no rule should match, got %+v", r)
	}
}

func TestHostSuffixBoundary(t *testing.T) {
	y := baseYAML() + `
owners:
  rules:
    - name: api
      team: platform
      host_suffix: api.example.com
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r := cfg.OwnerRule("api.example.com", "company", nil, nil, nil); r == nil {
		t.Error("exact suffix should match")
	}
	if r := cfg.OwnerRule("v2.api.example.com", "company", nil, nil, nil); r == nil {
		t.Error("subdomain of suffix should match")
	}
	if r := cfg.OwnerRule("notapi.example.com", "company", nil, nil, nil); r != nil {
		t.Error("lookalike suffix must not match")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"pay?ents.example.com", "payments.example.com", true},
		{"*", "anything", true},
		{"exact.example.com", "exact.example.com", true},
		{"exact.example.com", "other.example.com", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// TestDefaultProfileProbesOnlyOvernight pins the safe default: a profile that
// does not mention a scan window must not inherit permission to scan at any
// hour. This is a safety property, not a convenience.
func TestDefaultProfileProbesOnlyOvernight(t *testing.T) {
	cfg, err := Parse([]byte(`
organisation:
  name: Acme
  domains: [acme.example]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	noon := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if cfg.InWindow(noon) {
		t.Error("noon should be outside the default overnight window")
	}
	overnight := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	if !cfg.InWindow(overnight) {
		t.Error("03:00 should be inside the default overnight window")
	}
}

// TestExplicitEmptyWindowAllowsAnytime confirms the documented escape hatch.
func TestExplicitEmptyWindowAllowsAnytime(t *testing.T) {
	cfg, err := Parse([]byte(`
organisation:
  name: Acme
  domains: [acme.example]
safety:
  scan_window: ""
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.InWindow(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Error(`an explicit scan_window: "" should allow any time`)
	}
}
