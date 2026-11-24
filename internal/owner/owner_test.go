package owner

import (
	"strings"
	"testing"

	"asm/internal/config"
	"asm/internal/model"
)

func testRouter(t *testing.T) *Router {
	t.Helper()
	cfg := config.Default()
	cfg.Organisation = config.Organisation{Name: "Example Corp", Domains: []string{"example.com"}}
	cfg.Owners = config.Owners{
		DefaultTeam:    "unowned",
		DefaultContact: "security@example.com",
		Rules: []config.OwnerRule{
			{Name: "api", Team: "platform", HostSuffix: "api.example.com"},
			{Name: "nonprod", Team: "engineering", Tag: "nonprod"},
			{Name: "partner", Team: "vendor-mgmt", Class: "partner", Escalation: "contact the vendor"},
		},
	}
	if err := cfg.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return NewRouter(cfg)
}

func snap(name, class string, tags ...string) *model.Snapshot {
	s := &model.Snapshot{
		Host:        model.Host{Name: name},
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed, Class: model.Class(class)},
	}
	for _, tg := range tags {
		if tg == "nonprod" {
			// The router derives tags from the name; use a dev name.
			s.Host.Name = "dev." + name
		}
	}
	return s
}

func TestDefaultTeamIsUnowned(t *testing.T) {
	r := testRouter(t)
	o := r.Route(snap("www.example.com", "company"))
	if o.Team != "unowned" {
		t.Errorf("unmatched asset should be unowned, got %q", o.Team)
	}
	if o.Source != "default" {
		t.Errorf("source = %q", o.Source)
	}
	// Unowned assets still get a contact and an explanation, so the gap is
	// actionable rather than silent.
	if o.Contact == "" {
		t.Error("unowned asset should still carry the default contact")
	}
}

func TestHostSuffixRule(t *testing.T) {
	r := testRouter(t)
	o := r.Route(snap("v2.api.example.com", "third_party"))
	if o.Team != "platform" {
		t.Errorf("api rule should match, got %q", o.Team)
	}
	if !strings.HasPrefix(o.Source, "rule:") {
		t.Errorf("source = %q, want a rule source", o.Source)
	}
}

func TestNonProdTagRule(t *testing.T) {
	r := testRouter(t)
	o := r.Route(snap("staging.example.com", "third_party"))
	if o.Team != "engineering" {
		t.Errorf("nonprod rule should match a staging host, got %q", o.Team)
	}
}

func TestPartnerRuleAndEscalation(t *testing.T) {
	r := testRouter(t)
	o := r.Route(snap("promo.example.com", "partner"))
	if o.Team != "vendor-mgmt" {
		t.Errorf("partner rule should match, got %q", o.Team)
	}
	if o.Escalation == "" {
		t.Error("partner asset should carry an escalation note")
	}
}

func TestPartnerDefaultEscalation(t *testing.T) {
	// Even with no explicit partner rule, a partner-class asset must explain
	// that it cannot be fixed directly.
	cfg := config.Default()
	cfg.Organisation = config.Organisation{Name: "X", Domains: []string{"example.com"}}
	cfg.Owners.DefaultTeam = "unowned"
	if err := cfg.Compile(); err != nil {
		t.Fatal(err)
	}
	r := NewRouter(cfg)
	o := r.Route(snap("promo.example.com", "partner"))
	if o.Escalation == "" {
		t.Error("expected a default partner escalation")
	}
	if !strings.Contains(strings.ToLower(o.Escalation), "partner") {
		t.Errorf("escalation should mention the partner situation: %q", o.Escalation)
	}
}

func TestProdTagDerivedFromName(t *testing.T) {
	r := testRouter(t)
	// www is a prod-ish label; the default should apply, not the nonprod rule.
	o := r.Route(snap("www.example.com", "company"))
	if o.Team == "engineering" {
		t.Error("www should not be tagged nonprod")
	}
}
