package discovery

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"asm/internal/config"
	"asm/internal/model"
)

const testZone = `{
  "records": {
    "example.com":            {"a": ["203.0.113.1"], "txt": ["v=spf1 -all"], "mx": ["mail.example.com"]},
    "www.example.com":        {"cname": ["example.com"], "a": ["203.0.113.1"]},
    "api.example.com":        {"a": ["203.0.113.2"]},
    "mail.example.com":       {"a": ["203.0.113.3"]},
    "app.example.com":        {"a": ["203.0.113.4"], "txt": ["verify=abc123"]},
    "promo.example.com":      {"cname": ["promo.partner.net"]},
    "promo.partner.net":      {"a": ["198.51.100.1"]},
    "gone.example.com":       {"a": ["203.0.113.9"]}
  },
  "wildcards": {
    "legacy.example.com": {"a": ["203.0.113.99"]}
  },
  "nxdomain": ["gone.example.com"]
}`

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Organisation = config.Organisation{
		Name:           "Example Corp",
		Domains:        []string{"example.com"},
		PartnerDomains: []string{"partner.net"},
	}
	cfg.Discovery.CT.Enabled = false
	cfg.Discovery.DNS.MaxLabelsPerRun = 0
	cfg.Discovery.DNS.QPS = 1000
	cfg.Discovery.DNS.ProbeWildcard = boolPtr(true)
	if err := cfg.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func boolPtr(b bool) *bool { return &b }

func fixtureResolver(t *testing.T) *Resolver {
	t.Helper()
	ex, err := ParseFixtureExchanger([]byte(testZone))
	if err != nil {
		t.Fatal(err)
	}
	return NewResolver(ex, 1000)
}

func TestResolveCNAMEChain(t *testing.T) {
	r := fixtureResolver(t)
	ctx := context.Background()
	chain, err := r.CNAMEChain(ctx, "www.example.com", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[1] != "example.com" {
		t.Errorf("chain = %v", chain)
	}
}

func TestResolveLightDetectsNXDomain(t *testing.T) {
	r := fixtureResolver(t)
	ans, err := r.ResolveLight(context.Background(), "gone.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ans.NXDomain {
		t.Errorf("expected NXDOMAIN, got %+v", ans)
	}
}

func TestResolveFull(t *testing.T) {
	r := fixtureResolver(t)
	ans, err := r.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.A) != 1 || ans.A[0] != "203.0.113.1" {
		t.Errorf("A = %v", ans.A)
	}
	if len(ans.TXT) != 1 {
		t.Errorf("TXT = %v", ans.TXT)
	}
	if len(ans.MX) != 1 || ans.MX[0] != "mail.example.com" {
		t.Errorf("MX = %v", ans.MX)
	}
}

func TestWildcardDetection(t *testing.T) {
	r := fixtureResolver(t)
	profs := DetectWildcards(context.Background(), []string{"example.com", "legacy.example.com"}, r)
	if p, ok := profs["example.com"]; !ok {
		t.Fatal("example.com profile missing")
	} else if len(p.Addresses) != 0 {
		t.Errorf("example.com has no wildcard, but got addresses %v", p.Addresses)
	}
	if p, ok := profs["legacy.example.com"]; !ok {
		t.Fatal("legacy.example.com profile missing")
	} else if len(p.Addresses) != 1 || p.Addresses[0] != "203.0.113.99" {
		t.Errorf("legacy wildcard addresses = %v", p.Addresses)
	}
}

// TestWildcardPhantomIsNotAnAsset is the anti-noise test: a random name under
// a catch-all zone must not become an in-scope host.
func TestWildcardPhantomIsNotAnAsset(t *testing.T) {
	cfg := testConfig(t)
	inv := NewInventory()
	enum := NewEnumerator(cfg, fixtureResolver(t), inv, fixtureSource{names: []Candidate{
		{Name: "random-1.legacy.example.com"},
		{Name: "random-2.legacy.example.com"},
	}})
	if _, err := enum.Enumerate(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, h := range inv.Hosts() {
		if h.Name == "random-1.legacy.example.com" || h.Name == "random-2.legacy.example.com" {
			if !h.WildcardCatchall {
				t.Errorf("%s should be marked as a wildcard artefact", h.Name)
			}
			if h.PortHints != nil {
				t.Errorf("%s wildcard host should have port hints cleared", h.Name)
			}
		}
	}
}

// TestSubzoneWildcardIsDetected covers the case where the catch-all is not at
// the configured apex. The zone probe must follow the candidate up the tree.
func TestSubzoneWildcardIsDetected(t *testing.T) {
	cfg := testConfig(t)
	inv := NewInventory()
	// The candidate list includes a real name in the subzone and a phantom.
	enum := NewEnumerator(cfg, fixtureResolver(t), inv, fixtureSource{names: []Candidate{
		{Name: "real.legacy.example.com"}, // not in fixture -> phantom
		{Name: "www.example.com"},
	}})
	if _, err := enum.Enumerate(context.Background()); err != nil {
		t.Fatal(err)
	}
	prof, ok := enum.wildcards["legacy.example.com"]
	if !ok {
		t.Fatal("subzone legacy.example.com should have been probed for a wildcard")
	}
	if len(prof.Addresses) == 0 {
		t.Error("subzone wildcard should have been found")
	}
}

func TestCNAMEExpansionBringsTargetsIntoScope(t *testing.T) {
	cfg := testConfig(t)
	cfg.Organisation.Domains = []string{"example.com", "partner.net"}
	if err := cfg.Compile(); err != nil {
		t.Fatal(err)
	}
	inv := NewInventory()
	enum := NewEnumerator(cfg, fixtureResolver(t), inv, fixtureSource{names: []Candidate{
		{Name: "promo.example.com"},
	}})
	if _, err := enum.Enumerate(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range inv.Hosts() {
		if h.Name == "promo.partner.net" {
			found = true
		}
	}
	if !found {
		t.Error("CNAME target in scope should have been added")
	}
}

func TestSeedIsAlwaysIncluded(t *testing.T) {
	cfg := testConfig(t)
	cfg.Discovery.Seeds = []string{"app.example.com"}
	inv := NewInventory()
	enum := NewEnumerator(cfg, fixtureResolver(t), inv)
	if _, err := enum.Enumerate(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range inv.Hosts() {
		if h.Name == "app.example.com" {
			found = true
			if len(h.TXT) == 0 {
				t.Error("seed should have been resolved for TXT evidence")
			}
		}
	}
	if !found {
		t.Error("seed not in inventory")
	}
}

func TestResolveCacheAvoidsDuplicateQueries(t *testing.T) {
	counting := &countingExchanger{inner: fixtureResolverEx(t)}
	r := NewResolver(counting, 1000)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := r.ResolveLight(ctx, "api.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	q, _ := r.Stats()
	// Three record types, each queried once, then cached.
	if q > 6 {
		t.Errorf("expected caching to limit queries, issued %d", q)
	}
}

func TestFixturePTR(t *testing.T) {
	raw := `{"records":{},"ptrs":{"1.113.0.203.in-addr.arpa":["mail.example.com"]}}`
	ex, err := ParseFixtureExchanger([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	r := NewResolver(ex, 1000)
	names, err := r.Reverse(context.Background(), "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "mail.example.com" {
		t.Errorf("PTR = %v", names)
	}
}

// --- test doubles -------------------------------------------------------

type fixtureSource struct{ names []Candidate }

func (f fixtureSource) Name() string { return "fixture" }
func (f fixtureSource) Fetch(_ context.Context, _ string) ([]Candidate, error) {
	return f.names, nil
}

type countingExchanger struct {
	inner Exchanger
	mu    sync.Mutex
	calls int
}

func (c *countingExchanger) Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.inner.Exchange(ctx, name, qtype)
}

func fixtureResolverEx(t *testing.T) Exchanger {
	t.Helper()
	ex, err := ParseFixtureExchanger([]byte(testZone))
	if err != nil {
		t.Fatal(err)
	}
	return ex
}

var _ = time.Now
var _ = model.NormalizeName
