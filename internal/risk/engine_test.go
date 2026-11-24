package risk

import (
	"testing"
	"time"

	"asm/internal/config"
	"asm/internal/model"
)

func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Organisation = config.Organisation{Name: "Example Corp", Domains: []string{"example.com"}}
	if err := cfg.Compile(); err != nil {
		panic(err)
	}
	return cfg
}

func snap(name string, svcs ...model.Service) *model.Snapshot {
	return &model.Snapshot{
		Key:      "a-test",
		Host:     model.Host{Name: name, Resolvable: true},
		Services: svcs,
		LastSeen: time.Now(),
	}
}

func TestDatabasePortIsCritical(t *testing.T) {
	e := NewEngine(testConfig())
	s := snap("db.example.com", model.Service{Port: 3306, IP: "203.0.113.5"})
	a := e.Assess(Input{Snapshot: s, Attribution: model.Attribution{Verdict: model.VerdictConfirmed, Class: model.ClassCompany}})
	if a.Band != model.BandCritical && a.Band != model.BandHigh {
		t.Errorf("exposed mysql should rank high or critical, got %s (%.0f)", a.Band, a.Score)
	}
	if len(a.Factors) == 0 || a.Factors[0].Key != "port:mysql" {
		t.Errorf("expected the mysql factor to dominate, got %+v", a.Factors)
	}
}

func TestDockerAPIOutranksDatabase(t *testing.T) {
	e := NewEngine(testConfig())
	docker := e.Assess(Input{
		Snapshot:    snap("a.example.com", model.Service{Port: 2375}),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	mysql := e.Assess(Input{
		Snapshot:    snap("b.example.com", model.Service{Port: 3306}),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	if docker.Base <= mysql.Base {
		t.Errorf("docker API (%.0f) should outrank mysql (%.0f)", docker.Base, mysql.Base)
	}
}

func TestExposedEnvFile(t *testing.T) {
	e := NewEngine(testConfig())
	s := snap("app.example.com", model.Service{
		Port: 443,
		HTTP: &model.HTTP{
			Status: 200,
			Exposed: []model.ExposedPath{
				{Path: "/.env", Status: 200, Note: "environment file with secrets"},
			},
		},
	})
	a := e.Assess(Input{Snapshot: s, Attribution: model.Attribution{Verdict: model.VerdictConfirmed}})
	found := false
	for _, f := range a.Factors {
		if f.Title == "Sensitive file exposed" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a sensitive-file factor, got %+v", a.Factors)
	}
}

func TestOpenPanelIsAFindingProtectedPanelIsNotEntryPoint(t *testing.T) {
	e := NewEngine(testConfig())
	open := e.Assess(Input{
		Snapshot: snap("a.example.com", model.Service{
			Port: 443,
			HTTP: &model.HTTP{Status: 200, OpenPanels: []string{"/admin/"}},
		}),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	protected := e.Assess(Input{
		Snapshot: snap("b.example.com", model.Service{
			Port: 443,
			HTTP: &model.HTTP{Status: 200, ProtectedPanels: []string{"/admin/"}},
		}),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	if open.Base <= protected.Base {
		t.Errorf("open panel (%.0f) should outrank protected panel (%.0f)", open.Base, protected.Base)
	}
}

func TestNoHTTPSOnlyWhenPlaintextWebApp(t *testing.T) {
	e := NewEngine(testConfig())
	withWeb := e.Assess(Input{
		Snapshot:    snap("a.example.com", model.Service{Port: 80, HTTP: &model.HTTP{Status: 200}}),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
		HasHTTP:     true, HasWebPort: true,
	})
	// The reader should find the no-https factor.
	found := false
	for _, f := range withWeb.Factors {
		if f.Key == "no-https" {
			found = true
		}
	}
	if !found {
		t.Error("expected a no-https factor for a plaintext web app")
	}

	// A host with HTTP somewhere but not on port 80 (e.g. an API on 8080 over
	// plaintext only) is a different situation; without HasWebPort it should
	// not fire.
	noWeb := e.Assess(Input{
		Snapshot:    snap("b.example.com", model.Service{Port: 8080, HTTP: &model.HTTP{Status: 200}}),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
		HasHTTP:     true, HasWebPort: false,
	})
	for _, f := range noWeb.Factors {
		if f.Key == "no-https" {
			t.Error("no-https must not fire without a plaintext web port")
		}
	}
}

func TestDevPatternUplift(t *testing.T) {
	e := NewEngine(testConfig())
	dev := e.Assess(Input{
		Snapshot:    snap("staging.example.com"),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	prod := e.Assess(Input{
		Snapshot:    snap("www.example.com"),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	if dev.Base <= prod.Base {
		t.Errorf("dev host (%.0f) should score above prod (%.0f)", dev.Base, prod.Base)
	}
}

func TestDiminishingReturns(t *testing.T) {
	e := NewEngine(testConfig())
	// Three different exposed database services: each is its own door, but
	// they share one root cause (an exposed database tier), so the second and
	// third must not each score at full weight or every host with a backend
	// saturates at 100 and the ranking stops discriminating.
	many := e.Assess(Input{
		Snapshot: snap("a.example.com",
			model.Service{Port: 3306},  // mysql
			model.Service{Port: 5432},  // postgres
			model.Service{Port: 27017}, // mongodb
		),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	one := e.Assess(Input{
		Snapshot:    snap("b.example.com", model.Service{Port: 3306}),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	if many.Base >= one.Base*3 {
		t.Errorf("three database ports (%.1f) should not score three times one (%.1f)", many.Base, one.Base)
	}
	if many.Base <= one.Base {
		t.Errorf("three database ports (%.1f) should still score above one (%.1f)", many.Base, one.Base)
	}
}

func TestSameServiceOnManyPortsCountsOnce(t *testing.T) {
	e := NewEngine(testConfig())
	a := e.Assess(Input{
		Snapshot: snap("a.example.com",
			model.Service{Port: 6379},
			model.Service{Port: 6380},
			model.Service{Port: 6381},
		),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
	})
	for _, f := range a.Factors {
		if f.Key == "port:redis" && f.Weight >= wDatabasePort*2 {
			t.Errorf("redis on three ports should count once, got weight %.0f", f.Weight)
		}
	}
}

func TestPartnerMultiplierLowersScore(t *testing.T) {
	cfg := testConfig()
	e := NewEngine(cfg)
	svc := model.Service{Port: 6379}
	own := e.Assess(Input{
		Snapshot:    snap("a.example.com", svc),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed, Class: model.ClassCompany},
	})
	partner := e.Assess(Input{
		Snapshot:    snap("b.example.com", svc),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed, Class: model.ClassPartner},
	})
	if partner.Score >= own.Score {
		t.Errorf("partner score (%.0f) should be below own (%.0f)", partner.Score, own.Score)
	}
}

func TestFindingsFromSnapshot(t *testing.T) {
	e := NewEngine(testConfig())
	s := snap("a.example.com", model.Service{Port: 3306}, model.Service{Port: 443, TLS: &model.TLS{SelfSigned: true, HostnameValid: false}})
	s.Assessment = e.Assess(Input{Snapshot: s, Attribution: model.Attribution{Verdict: model.VerdictConfirmed}})
	findings := FindingsFromSnapshot(s)
	if len(findings) < 2 {
		t.Fatalf("expected at least two findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Key == "" || f.Title == "" || f.Remediation == "" {
			t.Errorf("finding missing fields: %+v", f)
		}
		if f.AssetKey != s.Key {
			t.Errorf("finding not linked to asset: %+v", f)
		}
	}
}

func TestExpiredCert(t *testing.T) {
	e := NewEngine(testConfig())
	s := snap("a.example.com", model.Service{
		Port: 443,
		TLS:  &model.TLS{NotAfter: time.Now().Add(-48 * time.Hour), HostnameValid: true},
	})
	a := e.Assess(Input{Snapshot: s, Attribution: model.Attribution{Verdict: model.VerdictConfirmed}})
	found := false
	for _, f := range a.Factors {
		if f.Title == "Expired TLS certificate" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an expired-cert factor, got %+v", a.Factors)
	}
}

func TestStaleAssetScoresHigher(t *testing.T) {
	e := NewEngine(testConfig())
	svc := model.Service{Port: 443, HTTP: &model.HTTP{Status: 200, Title: "Old App"}}
	fresh := e.Assess(Input{
		Snapshot:    snap("a.example.com", svc),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
		IsStale:     false,
	})
	stale := e.Assess(Input{
		Snapshot:    snap("a.example.com", svc),
		Attribution: model.Attribution{Verdict: model.VerdictConfirmed},
		IsStale:     true,
	})
	if stale.Base <= fresh.Base {
		t.Errorf("stale asset (%.0f) should score above fresh (%.0f)", stale.Base, fresh.Base)
	}
	found := false
	for _, f := range stale.Factors {
		if f.Key == "stale" {
			found = true
		}
	}
	if !found {
		t.Error("expected a stale factor")
	}
}
