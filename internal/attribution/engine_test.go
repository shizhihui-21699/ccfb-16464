package attribution

import (
	"testing"

	"asm/internal/config"
	"asm/internal/model"
)

func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Organisation = config.Organisation{
		Name:               "Example Corp",
		Domains:            []string{"example.com"},
		OrgNames:           []string{"example corp"},
		VerificationTokens: []string{"verify=abc123"},
		IPRanges:           []string{"203.0.113.0/24"},
		PartnerDomains:     []string{"partner.net"},
	}
	if err := cfg.Compile(); err != nil {
		panic(err)
	}
	return cfg
}

func host(name string, opts ...func(*model.Host)) *model.Host {
	h := &model.Host{Name: name, Resolvable: true}
	for _, o := range opts {
		o(h)
	}
	return h
}

func TestInOwnDomainIsConfirmed(t *testing.T) {
	e := NewEngine(testConfig())
	att := e.Evaluate(Input{Host: host("www.example.com")})
	if att.Verdict != model.VerdictProbable && att.Verdict != model.VerdictConfirmed {
		t.Errorf("expected in-scope verdict, got %s (score %.1f)", att.Verdict, att.Score)
	}
	if att.Class != model.ClassThirdParty {
		t.Errorf("expected third_party (no owned IP), got %s", att.Class)
	}
}

func TestOwnedIPWithOwnDomainIsConfirmed(t *testing.T) {
	e := NewEngine(testConfig())
	h := host("www.example.com")
	h.IPs = []string{"203.0.113.10"}
	att := e.Evaluate(Input{Host: h})
	if att.Verdict != model.VerdictConfirmed {
		t.Errorf("expected confirmed, got %s (score %.1f)", att.Verdict, att.Score)
	}
	if att.Class != model.ClassCompany {
		t.Errorf("expected company class, got %s", att.Class)
	}
}

func TestLookalikeDomainRejected(t *testing.T) {
	e := NewEngine(testConfig())
	att := e.Evaluate(Input{Host: host("example.com.evil.net")})
	if att.Verdict == model.VerdictConfirmed || att.Verdict == model.VerdictProbable {
		t.Errorf("lookalike must not be in scope: %s (%.1f)", att.Verdict, att.Score)
	}
}

func TestWildcardPhantomRejected(t *testing.T) {
	e := NewEngine(testConfig())
	h := host("anything.example.com", func(h *model.Host) {
		h.WildcardCatchall = true
		h.WildcardFrom = "example.com"
	})
	att := e.Evaluate(Input{Host: h})
	if att.Verdict == model.VerdictConfirmed || att.Verdict == model.VerdictProbable {
		t.Errorf("wildcard phantom must not be in scope: %s (%.1f)", att.Verdict, att.Score)
	}
	if att.Class != model.ClassWildcard {
		t.Errorf("expected wildcard class, got %s", att.Class)
	}
}

func TestNXDomainRejected(t *testing.T) {
	e := NewEngine(testConfig())
	h := host("gone.example.com", func(h *model.Host) { h.NXDomain = true })
	att := e.Evaluate(Input{Host: h})
	if att.Verdict != model.VerdictRejected {
		t.Errorf("nxdomain must be rejected, got %s", att.Verdict)
	}
}

func TestPartnerCNAME(t *testing.T) {
	e := NewEngine(testConfig())
	h := host("promo.example.com", func(h *model.Host) {
		h.CNAMEs = []string{"promo.partner.net"}
		h.IPs = []string{"198.51.100.10"}
	})
	att := e.Evaluate(Input{Host: h, CNAMEChain: []string{"promo.example.com", "promo.partner.net"}})
	if att.Class != model.ClassPartner {
		t.Errorf("expected partner class, got %s (verdict %s)", att.Class, att.Verdict)
	}
	if !InScope(att) {
		t.Errorf("partner asset under own domain should still be in scope, got %s", att.Verdict)
	}
}

func TestPartnerAssetIsPassiveOnly(t *testing.T) {
	cfg := testConfig()
	e := NewEngine(cfg)
	h := host("promo.example.com", func(h *model.Host) { h.CNAMEs = []string{"promo.partner.net"} })
	att := e.Evaluate(Input{Host: h, CNAMEChain: []string{"promo.example.com", "promo.partner.net"}})
	if ActiveAllowed(cfg, att) {
		t.Error("partner assets must not be actively probed by default")
	}
}

func TestVerificationTokenConfirmsPartnerHosted(t *testing.T) {
	e := NewEngine(testConfig())
	// A cloud-hosted name outside our own domains, proven ours by the TXT
	// record our provider told us to publish.
	h := host("portal.somecloud.io", func(h *model.Host) {
		h.TXT = []string{"google-site-verification=verify=abc123"}
	})
	att := e.Evaluate(Input{Host: h})
	if att.Verdict != model.VerdictConfirmed {
		t.Errorf("verification token should confirm ownership, got %s (score %.1f)", att.Verdict, att.Score)
	}
}

func TestCertSubjectOrgConfirms(t *testing.T) {
	e := NewEngine(testConfig())
	eng := Input{
		Host: host("portal.somecloud.io"),
		Services: []model.Service{{
			Port: 443,
			TLS:  &model.TLS{SubjectCN: "portal.somecloud.io", SubjectOrg: []string{"Example Corp"}},
		}},
	}
	att := e.Evaluate(eng)
	if att.Verdict != model.VerdictConfirmed {
		t.Errorf("cert subject org should confirm, got %s (score %.1f)", att.Verdict, att.Score)
	}
}

func TestSharedCertIsNotOwnership(t *testing.T) {
	e := NewEngine(testConfig())
	eng := Input{
		Host: host("random.cdn.example.net"),
		Services: []model.Service{{
			Port: 443,
			TLS:  &model.TLS{SubjectCN: "cdn.example.net", SharedCert: true, SANs: []string{"a.example.net", "b.example.net"}},
		}},
	}
	att := e.Evaluate(eng)
	if InScope(att) {
		t.Errorf("a shared CDN certificate must not put a host in scope: %s (%.1f)", att.Verdict, att.Score)
	}
}

func TestParkedPageExcluded(t *testing.T) {
	e := NewEngine(testConfig())
	eng := Input{
		Host: host("forsale.example.com"),
		Services: []model.Service{{
			Port: 443,
			HTTP: &model.HTTP{Title: "This domain is for sale!", Status: 200},
		}},
	}
	att := e.Evaluate(eng)
	if att.Verdict == model.VerdictConfirmed || att.Verdict == model.VerdictProbable {
		t.Errorf("parked page should not be in scope: %s (%.1f)", att.Verdict, att.Score)
	}
	if att.Class != model.ClassParked {
		t.Errorf("expected parked class, got %s", att.Class)
	}
}

func TestEvidenceIsExplainable(t *testing.T) {
	e := NewEngine(testConfig())
	h := host("www.example.com", func(h *model.Host) { h.IPs = []string{"203.0.113.10"} })
	att := e.Evaluate(Input{Host: h})
	if len(att.Evidence) == 0 {
		t.Fatal("expected evidence")
	}
	if att.Rationale == "" {
		t.Error("expected a rationale")
	}
	if att.Confidence <= 0 || att.Confidence > 1 {
		t.Errorf("confidence %v out of range", att.Confidence)
	}
}

func TestBarePublicSuffixRejected(t *testing.T) {
	e := NewEngine(testConfig())
	att := e.Evaluate(Input{Host: host("com")})
	if InScope(att) {
		t.Errorf("bare public suffix must not be in scope: %s", att.Verdict)
	}
}

func TestCertificateEvidenceCountedOnceAcrossPorts(t *testing.T) {
	e := NewEngine(testConfig())
	tlsInfo := &model.TLS{
		SubjectCN:         "app.somecloud.io",
		SubjectOrg:        []string{"Example Corp"},
		FingerprintSHA256: "same-fingerprint",
		HostnameValid:     true,
	}
	// The same certificate served on three ports is one certificate.
	att := e.Evaluate(Input{
		Host: host("app.somecloud.io"),
		Services: []model.Service{
			{Port: 443, TLS: tlsInfo},
			{Port: 8443, TLS: tlsInfo},
			{Port: 9443, TLS: tlsInfo},
		},
	})
	count := 0
	for _, ev := range att.Evidence {
		if ev.Signal == SigCertOrgSubject {
			count++
		}
	}
	if count != 1 {
		t.Errorf("certificate subject evidence counted %d times, want 1", count)
	}
}
