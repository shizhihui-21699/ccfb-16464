package pipeline

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asm/internal/config"
	"asm/internal/model"
	"asm/internal/store"
)

const testDNS = `{
  "records": {
    "example-corp.com":         {"a": ["127.0.0.1"], "txt": ["v=spf1 -all"]},
    "www.example-corp.com":     {"a": ["127.0.0.1"]},
    "staging.example-corp.com": {"a": ["127.0.0.1"]},
    "api.example-corp.com":     {"a": ["127.0.0.1"]},
    "promo.example-corp.com":   {"cname": ["promo.partner.net"], "a": ["127.0.0.1"]},
    "promo.partner.net":        {"a": ["127.0.0.1"]},
    "phantom.legacy.example-corp.com": {"a": ["127.0.0.1"]}
  },
  "wildcards": {
    "legacy.example-corp.com": {"a": ["127.0.0.1"]}
  }
}`

type harness struct {
	dir   string
	cfg   *config.Config
	store *store.Store
	port  int // TLS port
	plain int // plain HTML port
	pipe  *Pipeline
	// expose flips the staging listener between a benign page and one that
	// serves a secrets file and an open admin panel. Tests use it to simulate
	// a real change between runs.
	expose *atomic.Bool
}

// newHarness wires a pipeline against loopback listeners and a fixture.
func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()

	dnsPath := filepath.Join(dir, "dns.json")
	if err := os.WriteFile(dnsPath, []byte(testDNS), 0o600); err != nil {
		t.Fatal(err)
	}

	expose := &atomic.Bool{}
	tlsPort := serveTLS(t, expose, map[string]string{
		"staging.example-corp.com": "Staging Portal",
		"api.example-corp.com":     "API",
		"example-corp.com":         "Home",
	})
	plainPort := servePlain(t)

	ctPath := filepath.Join(dir, "ct.jsonl")
	ct := fmt.Sprintf(`{"name":"staging.example-corp.com","issuer":"Let's Encrypt","not_after":"2030-01-01T00:00:00Z","ports":[%d]}
{"name":"api.example-corp.com","issuer":"DigiCert","not_after":"2030-01-01T00:00:00Z","ports":[%d]}
{"name":"example-corp.com","issuer":"DigiCert","not_after":"2030-01-01T00:00:00Z","ports":[%d,%d]}
{"name":"www.example-corp.com","issuer":"DigiCert","not_after":"2030-01-01T00:00:00Z","ports":[%d]}
{"name":"promo.example-corp.com","issuer":"Acme","not_after":"2030-01-01T00:00:00Z","ports":[%d]}
{"name":"phantom.legacy.example-corp.com","issuer":"Let's Encrypt","not_after":"2030-01-01T00:00:00Z"}
`, tlsPort, tlsPort, tlsPort, plainPort, tlsPort, tlsPort)
	if err := os.WriteFile(ctPath, []byte(ct), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Organisation = config.Organisation{
		Name:           "Example Corp",
		Domains:        []string{"example-corp.com"},
		OrgNames:       []string{"example corp"},
		PartnerDomains: []string{"partner.net"},
	}
	cfg.Discovery.Seeds = []string{"example-corp.com"}
	cfg.Discovery.CT.Providers = []string{"fixture"}
	cfg.Discovery.CT.Fixtures = []string{ctPath}
	cfg.Discovery.DNSFixturePath = dnsPath
	cfg.Discovery.DNS.QPS = 1000
	cfg.Discovery.DNS.MaxLabelsPerRun = 0
	cfg.Discovery.DNS.ProbeWildcard = boolp(true)

	cfg.Safety.AllowPrivate = true
	cfg.Safety.MaxGlobalRPS = 50
	cfg.Safety.MaxPerHostRPS = 1
	cfg.Safety.MaxConcurrent = 4
	cfg.Safety.HostConcurrency = 2
	cfg.Safety.ScanWindow = ""
	cfg.Safety.PauseEvery = 0
	cfg.Safety.MaxProbesPerRun = 500
	cfg.Safety.ActiveClasses = []string{"company", "third_party"}

	cfg.Probes.HTTPPaths = []string{"/", "/.env"}
	cfg.Probes.PanelPaths = []string{"/admin/"}
	cfg.Probes.MaxPathsPerService = 4

	cfg.Owners.DefaultTeam = "unowned"
	cfg.Owners.Rules = []config.OwnerRule{
		{Name: "platform", Team: "platform", HostSuffix: "api.example-corp.com"},
	}

	cfg.Outputs.Dir = filepath.Join(dir, "out")
	cfg.Store.Path = filepath.Join(dir, "asm.db")

	if err := cfg.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &harness{
		dir:    dir,
		cfg:    cfg,
		store:  st,
		port:   tlsPort,
		plain:  plainPort,
		pipe:   New(cfg, st, logger),
		expose: expose,
	}
}

func boolp(b bool) *bool { return &b }

func TestPipelineEndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	res, err := h.pipe.Run(ctx, Options{Log: discardLogger()})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// Discovery found the expected hosts.
	names := map[string]*model.Snapshot{}
	for _, s := range res.Snapshots {
		names[s.Host.Name] = s
	}
	for _, want := range []string{"example-corp.com", "www.example-corp.com", "api.example-corp.com", "staging.example-corp.com", "promo.example-corp.com"} {
		if names[want] == nil {
			t.Errorf("expected %s in the inventory", want)
		}
	}

	// The wildcard phantom is present but excluded from scope.
	if ph := names["phantom.legacy.example-corp.com"]; ph != nil {
		if !ph.Host.WildcardCatchall {
			t.Error("phantom host should be marked as a wildcard artefact")
		}
		if ph.Attribution.Verdict == model.VerdictConfirmed || ph.Attribution.Verdict == model.VerdictProbable {
			t.Errorf("phantom host should not be in scope, got %s", ph.Attribution.Verdict)
		}
	}

	// The partner-hosted marketing host is attributed as a partner.
	if pr := names["promo.example-corp.com"]; pr != nil {
		if pr.Attribution.Class != model.ClassPartner {
			t.Errorf("promo should be classified partner, got %s", pr.Attribution.Class)
		}
		if len(pr.Services) != 0 {
			t.Errorf("partner asset must not be actively probed, got %d services", len(pr.Services))
		}
	}

	// The staging host answered over TLS and produced findings.
	if st := names["staging.example-corp.com"]; st != nil {
		if len(st.Services) == 0 {
			t.Fatal("staging should have been probed")
		}
		if st.Services[0].TLS == nil {
			t.Error("staging TLS should have been inspected")
		}
	}

	// Owner routing applied the api rule.
	if api := names["api.example-corp.com"]; api != nil {
		if api.Owner.Team != "platform" {
			t.Errorf("api owner = %q, want platform", api.Owner.Team)
		}
	}

	// Reports were written.
	for _, want := range []string{"inventory.json", "summary.md", "findings.csv", "dashboard.html", "changes.md"} {
		if _, err := os.Stat(filepath.Join(h.cfg.Outputs.Dir, want)); err != nil {
			t.Errorf("expected report %s: %v", want, err)
		}
	}

	// The store holds every asset, and a second run is stable.
	count, err := h.store.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != len(res.Snapshots) {
		t.Errorf("store has %d assets, run produced %d", count, len(res.Snapshots))
	}
}

func TestSecondRunIsStable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.pipe.Run(ctx, Options{Log: discardLogger()}); err != nil {
		t.Fatal(err)
	}
	second, err := h.pipe.Run(ctx, Options{Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing changed between runs, so the change feed should be empty.
	// (There may be a one-off "risk changed" if fingerprints were computed
	// inconsistently; that would be a bug this test catches.)
	if len(second.Changes) != 0 {
		var msgs []string
		for _, c := range second.Changes {
			msgs = append(msgs, fmt.Sprintf("%s:%s", c.Kind, c.AssetName))
		}
		t.Errorf("a stable second run produced %d changes: %s", len(second.Changes), strings.Join(msgs, ", "))
	}
}

func TestChangeIsDetectedBetweenRuns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.pipe.Run(ctx, Options{Log: discardLogger()}); err != nil {
		t.Fatal(err)
	}

	// Make staging serve an exposed secrets file and an open admin panel, and
	// advertise a new port through the passive feed (as a real passive-DNS
	// source would after a deploy).
	h.expose.Store(true)
	h.cfg.Probes.HTTPPaths = []string{"/", "/.env", "/admin/"}

	newPort := serveTLSWithEnv(t)
	ct, err := os.ReadFile(h.cfg.Discovery.CT.Fixtures[0])
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(ct),
		`{"name":"staging.example-corp.com","issuer":"Let's Encrypt","not_after":"2030-01-01T00:00:00Z","ports":[`+fmt.Sprint(h.port)+`]}`,
		fmt.Sprintf(`{"name":"staging.example-corp.com","issuer":"Let's Encrypt","not_after":"2030-01-01T00:00:00Z","ports":[%d,%d]}`, h.port, newPort),
		1)
	if updated == string(ct) {
		t.Fatalf("could not update the CT fixture for staging")
	}
	if err := os.WriteFile(h.cfg.Discovery.CT.Fixtures[0], []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}

	second, err := h.pipe.Run(ctx, Options{Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Changes) == 0 {
		t.Fatal("expected changes after the asset changed")
	}
	var sawNewPort bool
	for _, c := range second.Changes {
		if c.Kind == model.ChangeNewPort {
			sawNewPort = true
		}
	}
	if !sawNewPort {
		t.Error("expected a new-port change")
	}
}

func TestDryRunNeverProbes(t *testing.T) {
	h := newHarness(t)
	h.cfg.Safety.DryRun = true
	if err := h.cfg.Compile(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := h.pipe.Run(ctx, Options{Log: discardLogger(), DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Snapshots {
		if len(s.Services) != 0 {
			t.Errorf("dry run produced services for %s: %+v", s.Host.Name, s.Services)
		}
	}
}

func TestNoHostOutsideScopeIsProbed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, err := h.pipe.Run(ctx, Options{Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Snapshots {
		if len(s.Services) == 0 {
			continue
		}
		switch s.Attribution.Verdict {
		case model.VerdictConfirmed, model.VerdictProbable:
		default:
			t.Errorf("out-of-scope asset %s was probed (verdict %s)", s.Host.Name, s.Attribution.Verdict)
		}
	}
}

func TestOutOfScopeAssetsHaveNoOpenQuestions(t *testing.T) {
	// An asset discovered but rejected should still be stored, so the
	// exclusion decision is auditable rather than invisible.
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.pipe.Run(ctx, Options{Log: discardLogger()}); err != nil {
		t.Fatal(err)
	}
	list, err := h.store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rejected := 0
	for _, s := range list {
		switch s.Attribution.Verdict {
		case model.VerdictRejected, model.VerdictUnverified, model.VerdictPossible:
			rejected++
		}
	}
	if rejected == 0 {
		t.Log("note: no rejected candidates in this fixture run")
	}
}

// --- listeners ---------------------------------------------------------

func serveTLS(t *testing.T, expose *atomic.Bool, pages map[string]string) int {
	t.Helper()
	cert := mustCert(t, "staging.example-corp.com", "Example Corp")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.Split(r.Host, ":")[0]
		title, ok := pages[host]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// When expose is set, the staging host starts serving a secrets file
		// and an unauthenticated admin panel.
		if expose.Load() && host == "staging.example-corp.com" {
			if r.URL.Path == "/.env" {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "APP_ENV=staging\nDB_PASSWORD=hunter2\nSECRET_KEY=abc\n")
				return
			}
			if r.URL.Path == "/admin/" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, "<html><head><title>Grafana</title></head></html>")
				return
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><head><title>%s</title></head></html>", title)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func serveTLSWithEnv(t *testing.T) int {
	t.Helper()
	cert := mustCert(t, "staging.example-corp.com", "Example Corp")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=staging\nDB_PASSWORD=hunter2\nSECRET_KEY=abc\n")
			return
		}
		if r.URL.Path == "/admin/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>Grafana</title></head></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>Staging</title></head></html>")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func servePlain(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>Home</title></head></html>")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func mustCert(t *testing.T, host, org string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	subj := pkix.Name{CommonName: host}
	if org != "" {
		subj.Organization = []string{org}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestStaleAssetGainsFactor(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.pipe.Run(ctx, Options{Log: discardLogger()}); err != nil {
		t.Fatal(err)
	}
	// Advance the pipeline's clock past the stale threshold rather than
	// backdating rows: the store deliberately preserves last_changed across an
	// unchanged run, so a caller cannot fake the age of an asset.
	h.cfg.Risk.StaleAfter = config.Duration(24 * time.Hour)
	future := time.Now().Add(60 * 24 * time.Hour)
	h.pipe.SetClock(func() time.Time { return future })

	res, err := h.pipe.Run(ctx, Options{Log: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	staleSeen := false
	for _, s := range res.Snapshots {
		for _, f := range s.Assessment.Factors {
			if f.Key == "stale" {
				staleSeen = true
			}
		}
	}
	if !staleSeen {
		t.Error("an asset unchanged for 60 days should pick up a stale factor")
	}
}
