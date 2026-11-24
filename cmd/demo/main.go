// Command demo runs the full pipeline against a local, self-contained fixture.
//
// It gives a new operator something concrete to look at before pointing the
// tool at production, and it is the integration test that proves discovery,
// wildcard suppression, attribution, safe probing, scoring, routing,
// persistence, diffing and reporting all fit together.
//
// Everything is local. Two listeners on 127.0.0.1 act as a shared host, exactly
// as a real shared-hosting or partner platform does:
//
//   - an HTTPS listener that serves a distinct certificate and page per SNI
//     name (a staging portal, a legacy name, a partner portal)
//   - a plaintext HTTP listener that serves a Grafana-style admin panel, a
//     default nginx page, and an exposed /.env
//   - a bare TCP port that greets like redis
//
// The DNS fixture points every demo name at 127.0.0.1, and the CT fixture
// carries the port hints, so no real DNS or CT service is queried and no host
// outside loopback is contacted.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"asm/internal/config"
	"asm/internal/model"
	"asm/internal/pipeline"
	"asm/internal/store"
	"gopkg.in/yaml.v3"
)

func main() {
	out := flag.String("out", "", "output directory (default: a temp dir)")
	flag.Parse()

	dir := *out
	if dir == "" {
		var err error
		dir, err = os.MkdirTemp("", "asm-demo-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	} else if err := os.MkdirAll(dir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := run(dir); err != nil {
		fmt.Fprintln(os.Stderr, "demo failed:", err)
		os.Exit(1)
	}
}

// backend describes one virtual host served by the shared listeners.
type backend struct {
	Name    string
	Org     string // certificate subject organisation, "" for none
	Title   string
	Body    string
	EnvFile bool // serve an exposed /.env
	Panel   bool // serve a Grafana-style panel that requires auth
	Default bool // serve a default server page
	// ExtraPorts are additional ports the CT fixture advertises for this name.
	ExtraPorts func(cfg *ports) []int
}

func run(dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	fmt.Printf("demo workspace: %s\n\n", dir)

	backends := []*backend{
		{Name: "staging.example-corp.com", Org: "Example Corp", Title: "Staging Portal", Body: "internal preview", EnvFile: true},
		{Name: "legacy.example-corp.com", Org: "", Title: "Legacy App", Body: "old admin", Panel: true},
		{Name: "partner-portal.example-corp.com", Org: "Example Corp", Title: "Partner Portal", Body: "supplier access"},
		{Name: "example-corp.com", Org: "Example Corp", Title: "Example Corp", Body: "welcome"},
		{Name: "www.example-corp.com", Org: "Example Corp", Title: "Example Corp", Body: "welcome"},
		{Name: "old.example-corp.com", Org: "", Title: "Welcome to nginx!", Body: "", Default: true, EnvFile: true},
	}
	byName := map[string]*backend{}
	for _, b := range backends {
		byName[b.Name] = b
	}

	p := &ports{}
	tlsSrv, tlsPort, err := startTLS(byName)
	if err != nil {
		return fmt.Errorf("start tls server: %w", err)
	}
	defer tlsSrv.Close()
	p.tls = tlsPort

	plainSrv, plainPort, err := startPlain(byName)
	if err != nil {
		return fmt.Errorf("start plain server: %w", err)
	}
	defer plainSrv.Close()
	p.plain = plainPort

	redisLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start tcp listener: %w", err)
	}
	defer redisLn.Close()
	go fakeRedis(redisLn)
	p.redis = redisLn.Addr().(*net.TCPAddr).Port

	fmt.Printf("shared listeners:\n  https 127.0.0.1:%d\n  http  127.0.0.1:%d\n  tcp   127.0.0.1:%d (redis-like)\n\n", p.tls, p.plain, p.redis)

	// --- fixtures -------------------------------------------------------
	dnsFixture := filepath.Join(dir, "dns-fixture.json")
	if err := os.WriteFile(dnsFixture, []byte(dnsFixtureJSON()), 0o640); err != nil {
		return err
	}
	ctFixture := filepath.Join(dir, "ct-fixture.jsonl")
	if err := os.WriteFile(ctFixture, []byte(ctFixtureJSONL(p)), 0o640); err != nil {
		return err
	}

	// --- profile --------------------------------------------------------
	cfg := demoConfig(dir, dnsFixture, ctFixture)
	if err := cfg.Compile(); err != nil {
		return fmt.Errorf("compile demo profile: %w", err)
	}
	profileYAML, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal demo profile: %w", err)
	}
	cfgPath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(cfgPath, profileYAML, 0o640); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	st, err := store.Open(filepath.Join(dir, "demo.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	pipe := pipeline.New(cfg, st, log)

	fmt.Println("=== run 1: initial inventory ===")
	first, err := pipe.Run(ctx, pipeline.Options{Log: log})
	if err != nil {
		return err
	}
	printResult(first)

	// Between runs, a forgotten staging deploy gains an unauthenticated admin
	// panel and an exposed secrets file. Restarting the TLS listener with a
	// second port models the new deploy.
	fmt.Println("=== change: staging gains an open admin panel and a new port ===")
	// A second TLS listener models a new deploy. The passive feed is the part
	// that reports the new port, exactly as a real passive-DNS source would,
	// so the tool probes it without scanning the whole port list.
	tls2, port2, err := startTLS(byName)
	if err != nil {
		return err
	}
	defer tls2.Close()
	p.staging2 = port2
	redeploy(byName)
	if err := os.WriteFile(ctFixture, []byte(ctFixtureJSONL(p)), 0o640); err != nil {
		return err
	}

	fmt.Println("=== run 2: change detection ===")
	second, err := pipe.Run(ctx, pipeline.Options{Log: log})
	if err != nil {
		return err
	}
	printResult(second)

	fmt.Printf("changes detected in run 2: %d\n", len(second.Changes))
	shown := 0
	for _, c := range second.Changes {
		if shown >= 12 {
			fmt.Printf("  … and %d more\n", len(second.Changes)-shown)
			break
		}
		fmt.Printf("  [%s] %-18s %s\n", c.Severity, c.Kind, c.Summary)
		shown++
	}

	fmt.Printf("\ndemo complete.\n\nreports under %s\nstore: %s\nprofile: %s\n",
		cfg.Outputs.Dir, cfg.Store.Path, cfgPath)
	fmt.Printf("\ntry:\n  asm status -config %s\n  asm assets -config %s\n  asm assets -config %s -show staging.example-corp.com\n",
		cfgPath, cfgPath, cfgPath)
	return nil
}

type ports struct {
	tls, plain, redis int
	staging2          int // second deploy port, zero during run 1
}

func redeploy(byName map[string]*backend) {
	if b := byName["staging.example-corp.com"]; b != nil {
		b.Panel = true
		b.EnvFile = true
		b.Title = "Staging Admin"
	}
}

func printResult(res *pipeline.Result) {
	fmt.Printf("  run %s: %d in scope, %d changes, %dms\n",
		res.RunID, res.Stats.AssetsScoped, res.Stats.Changes, res.Stats.Duration.Milliseconds())
	fmt.Printf("  bands: critical=%d high=%d medium=%d low=%d info=%d\n",
		res.Stats.ByBand["critical"], res.Stats.ByBand["high"], res.Stats.ByBand["medium"],
		res.Stats.ByBand["low"], res.Stats.ByBand["info"])
	fmt.Printf("  gate:  %s\n", res.GateSummary)
	fmt.Printf("  ranked:\n")
	shown := 0
	for _, s := range res.Snapshots {
		if !isReportable(s) {
			continue
		}
		if shown >= 10 {
			break
		}
		fmt.Printf("    %-34s %-8s %3.0f  %-14s %-12s %s\n",
			s.Host.Name, s.Assessment.Band, s.Assessment.Score,
			s.Owner.Team, s.Attribution.Class, truncate(s.Assessment.Summary, 60))
		shown++
	}
	fmt.Println()
}

func isReportable(s *model.Snapshot) bool {
	switch s.Attribution.Verdict {
	case model.VerdictConfirmed, model.VerdictProbable, model.VerdictPossible:
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// demoConfig builds an in-memory profile pointed at the local services.
func demoConfig(dir, dnsFixture, ctFixture string) *config.Config {
	cfg := config.Default()
	cfg.Organisation = config.Organisation{
		Name:               "Example Corp",
		Handle:             "example",
		Domains:            []string{"example-corp.com"},
		OrgNames:           []string{"example corp", "example-corp"},
		VerificationTokens: []string{"example-verification=8f2ac1"},
		PartnerDomains:     []string{"acme-marketing.com", "partner-saas.net"},
		SaaSShareSuffixes:  []string{"cloudfront.net", "herokudns.com"},
	}
	cfg.Discovery.Seeds = []string{"example-corp.com"}
	cfg.Discovery.CT.Enabled = true
	cfg.Discovery.CT.Providers = []string{"fixture"}
	cfg.Discovery.CT.Fixtures = []string{ctFixture}
	cfg.Discovery.CT.IncludeExpired = true
	cfg.Discovery.DNSFixturePath = dnsFixture
	cfg.Discovery.DNS.QPS = 500
	cfg.Discovery.DNS.MaxLabelsPerRun = 0 // no brute force in the demo
	cfg.Discovery.DNS.ProbeWildcard = boolPtr(true)

	// The demo targets loopback only, so it uses the fastest rate the profile
	// validator permits rather than the production default. The ceilings
	// themselves are not bypassed: production runs get the same enforcement.
	cfg.Safety.MaxGlobalRPS = 50
	cfg.Safety.MaxPerHostRPS = 1.0
	cfg.Safety.MaxConcurrent = 8
	cfg.Safety.HostConcurrency = 4
	cfg.Safety.ScanWindow = "" // the demo runs whenever it is invoked
	cfg.Safety.AllowPrivate = true
	cfg.Safety.MaxProbesPerRun = 2000
	cfg.Safety.PauseEvery = 0
	cfg.Safety.ActiveClasses = []string{"company", "third_party"}

	cfg.Probes.HTTPPaths = []string{"/", "/.env", "/admin/"}
	cfg.Probes.PanelPaths = []string{"/login"}
	cfg.Probes.MaxPathsPerService = 6

	cfg.Owners = config.Owners{
		DefaultTeam:    "unowned",
		DefaultContact: "security@example-corp.com",
		Rules: []config.OwnerRule{
			// Host-specific rules come first: a named campaign page is owned by
			// the team that commissioned it, even when a partner hosts it.
			{Name: "marketing", Team: "marketing-web", Contact: "web@example-corp.com", HostPattern: `(?i)promo|marketing`},
			{Name: "partner", Team: "vendor-mgmt", Contact: "vendors@example-corp.com", Class: "partner"},
			{Name: "platform", Team: "platform", Contact: "platform@example-corp.com", HostSuffix: "api.example-corp.com"},
			{Name: "nonprod", Team: "engineering-nonprod", Contact: "eng@example-corp.com", Tag: "nonprod"},
		},
	}
	cfg.Outputs.Dir = filepath.Join(dir, "out")
	cfg.Store.Path = filepath.Join(dir, "demo.db")
	return cfg
}

func boolPtr(b bool) *bool { return &b }

func quietLog() *log.Logger { return log.New(io.Discard, "", 0) }

// --- listeners ---------------------------------------------------------

// startTLS serves a per-SNI certificate and page from one listener. Each name
// gets its own self-signed certificate, so the prober sees a distinct subject
// and SAN for each — which is what the attribution engine reasons about.
func startTLS(byName map[string]*backend) (*http.Server, int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	certs := map[string]tls.Certificate{}
	for name, b := range byName {
		cert, err := selfSignedCert(name, b.Org)
		if err != nil {
			ln.Close()
			return nil, 0, err
		}
		certs[name] = cert
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, ok := certs[strings.ToLower(hello.ServerName)]; ok {
				return &c, nil
			}
			// An unknown SNI name still gets a certificate: this is exactly how
			// shared hosting behaves, and it must not be mistaken for ownership.
			for _, c := range certs {
				cc := c
				return &cc, nil
			}
			return nil, fmt.Errorf("no cert")
		},
	}
	tlsLn := tls.NewListener(ln, tlsCfg)
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		b := byName[host]
		if b == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		// The TLS listener is the "app" tier. After a redeploy, staging also
		// answers panel and env paths here.
		if b.EnvFile && r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=staging\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123\n")
			return
		}
		if b.Panel && (r.URL.Path == "/admin/" || r.URL.Path == "/login") {
			// After redeploy the panel is open; before that it asks for auth.
			if b.Title == "Staging Admin" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, "<html><head><title>Grafana Admin</title></head><body>dashboard</body></html>")
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Grafana"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><head><title>%s</title></head><body>%s</body></html>", b.Title, b.Body)
	})
	// The prober deliberately tries plaintext first on some ports, so a TLS
	// listener will see (and reject) an HTTP request. That is normal probing
	// behaviour, not a demo error, so its log is discarded.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ErrorLog: quietLog()}
	go func() { _ = srv.Serve(tlsLn) }()
	return srv, ln.Addr().(*net.TCPAddr).Port, nil
}

// startPlain serves the plaintext tier: a default page, an admin panel and an
// exposed env file, depending on the virtual host.
func startPlain(byName map[string]*backend) (*http.Server, int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		b := byName[host]
		if b == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if b.Default {
			w.Header().Set("Server", "nginx/1.14.0")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>Welcome to nginx!</title></head><body>it works!</body></html>")
			return
		}
		if b.EnvFile && r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123\n")
			return
		}
		if b.Panel && (r.URL.Path == "/admin/" || r.URL.Path == "/login") {
			w.Header().Set("WWW-Authenticate", `Basic realm="Grafana"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "auth required")
			return
		}
		w.Header().Set("Server", "nginx/1.14.0")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><head><title>%s</title></head><body>%s</body></html>", b.Title, b.Body)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return srv, ln.Addr().(*net.TCPAddr).Port, nil
}

func fakeRedis(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
		time.Sleep(10 * time.Millisecond)
		conn.Close()
	}
}

func selfSignedCert(host, org string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	subject := pkix.Name{CommonName: host}
	if org != "" {
		subject.Organization = []string{org}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:              time.Now().Add(60 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// --- fixtures ----------------------------------------------------------

// dnsFixtureJSON describes a small, realistic zone: a normal apex, a wildcard
// legacy zone, a partner-hosted marketing host, a verification record and one
// name that does not exist.
func dnsFixtureJSON() string {
	return `{
  "records": {
    "example-corp.com":         {"a": ["127.0.0.1"], "txt": ["v=spf1 include:_spf.example-corp.com -all"], "ns": ["ns1.example-corp.com", "ns2.example-corp.com"], "mx": ["mail.example-corp.com"]},
    "www.example-corp.com":     {"cname": ["example-corp.com"], "a": ["127.0.0.1"]},
    "api.example-corp.com":     {"a": ["127.0.0.1"]},
    "mail.example-corp.com":    {"a": ["127.0.0.1"]},
    "staging.example-corp.com": {"a": ["127.0.0.1"]},
    "promo.example-corp.com":   {"cname": ["promo.acme-marketing.com"], "a": ["127.0.0.1"]},
    "promo.acme-marketing.com": {"a": ["127.0.0.1"]},
    "old.example-corp.com":     {"a": ["127.0.0.1"], "txt": ["example-verification=8f2ac1"]},
    "partner-portal.example-corp.com": {"cname": ["portal.partner-saas.net"], "a": ["127.0.0.1"]},
    "portal.partner-saas.net":  {"a": ["127.0.0.1"]},
    "legacy.example-corp.com":  {"a": ["127.0.0.1"]},
    "letsencrypt.example-corp.com": {"a": ["127.0.0.1"]}
  },
  "wildcards": {
    "legacy.example-corp.com": {"a": ["127.0.0.1"]}
  },
  "nxdomain": [
    "demo-gone.example-corp.com"
  ]
}`
}

// ctFixtureJSONL advertises the names along with the ports the passive feed
// already knows about. Each host is probed only on its own ports, which keeps
// the demo's active probe count tiny.
func ctFixtureJSONL(p *ports) string {
	now := time.Now()
	var lines []string
	add := func(name, issuer string, notAfter time.Time, wild bool, ports ...int) {
		portList := ""
		if len(ports) > 0 {
			parts := make([]string, len(ports))
			for i, n := range ports {
				parts[i] = fmt.Sprintf("%d", n)
			}
			portList = `,"ports":[` + strings.Join(parts, ",") + `]`
		}
		lines = append(lines, fmt.Sprintf(`{"name":%q,"issuer":%q,"not_after":%q,"wildcard":%v%s}`,
			name, issuer, notAfter.UTC().Format(time.RFC3339), wild, portList))
	}
	add("example-corp.com", "DigiCert", now.Add(200*24*time.Hour), false, p.tls, p.plain)
	add("www.example-corp.com", "DigiCert", now.Add(200*24*time.Hour), false, p.tls, p.plain)
	add("api.example-corp.com", "DigiCert", now.Add(200*24*time.Hour), false, p.tls)
	stagingPorts := []int{p.tls}
	if p.staging2 != 0 {
		stagingPorts = append(stagingPorts, p.staging2)
	}
	add("staging.example-corp.com", "Let's Encrypt", now.Add(60*24*time.Hour), false, stagingPorts...)
	add("old.example-corp.com", "Let's Encrypt", now.Add(-30*24*time.Hour), false, p.tls, p.plain)
	add("legacy.example-corp.com", "Let's Encrypt", now.Add(90*24*time.Hour), false, p.tls, p.redis)
	add("*.legacy.example-corp.com", "Let's Encrypt", now.Add(90*24*time.Hour), true)
	// A name under the legacy wildcard zone. It must be recognised as a
	// catch-all artefact and never probed, even though CT lists it.
	add("random-1.legacy.example-corp.com", "Let's Encrypt", now.Add(90*24*time.Hour), false)
	add("promo.example-corp.com", "Acme Marketing", now.Add(120*24*time.Hour), false, p.tls)
	add("partner-portal.example-corp.com", "Partner SaaS", now.Add(120*24*time.Hour), false, p.tls)
	add("demo-gone.example-corp.com", "Let's Encrypt", now.Add(30*24*time.Hour), false)
	add("letsencrypt.example-corp.com", "Let's Encrypt", now.Add(80*24*time.Hour), false, p.tls)
	return strings.Join(lines, "\n") + "\n"
}
