package probe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"asm/internal/config"
	"asm/internal/model"
)

// liveConfig builds a config suitable for probing a loopback test server.
func liveConfig(t *testing.T, ports []int) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Organisation = config.Organisation{Name: "Example Corp", Domains: []string{"example.com"}}
	cfg.Safety.AllowPrivate = true
	cfg.Safety.MaxGlobalRPS = 50
	cfg.Safety.MaxPerHostRPS = 1
	cfg.Safety.PauseEvery = 0
	cfg.Safety.ScanWindow = ""
	cfg.Safety.MaxProbesPerRun = 500
	cfg.Safety.HostConcurrency = 2
	cfg.Probes.Ports = ports
	cfg.Probes.TLSSNIPorts = ports
	cfg.Probes.MaxPathsPerService = 8
	cfg.Probes.HTTPPaths = []string{"/", "/.env", "/.git/config"}
	cfg.Probes.PanelPaths = []string{"/admin/"}

	// The rate limiter is compiled with the production ceiling (1/s/host);
	// a handful of probes on one port is fast enough for a unit test.
	if err := cfg.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func selfSigned(t *testing.T, host string, org string, extra ...string) tls.Certificate {
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
		DNSNames:              append([]string{host}, extra...),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
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

func startHTTP(t *testing.T, handler http.Handler) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func startHTTPS(t *testing.T, handler http.Handler, cert tls.Certificate) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// probeOne probes a single port with a real context and returns the service.
func probeOne(t *testing.T, cfg *config.Config, port int) *model.Service {
	t.Helper()
	g := NewGate(cfg)
	p := NewProber(cfg, g)
	h := &model.Host{Name: "test.example.com", IPs: []string{"127.0.0.1"}, Resolvable: true, PortHints: []int{port}}
	res := p.ProbeHost(t.Context(), h)
	for i := range res.Services {
		if res.Services[i].Port == port {
			return &res.Services[i]
		}
	}
	return nil
}

func TestProbeDetectsTLSAndCertDetails(t *testing.T) {
	cert := selfSigned(t, "test.example.com", "Example Corp")
	port := startHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><head><title>Hello</title></head></html>")
	}), cert)
	cfg := liveConfig(t, []int{port})

	svc := probeOne(t, cfg, port)
	if svc == nil {
		t.Fatal("port should have been detected")
	}
	if svc.TLS == nil {
		t.Fatal("TLS should have been detected")
	}
	if svc.TLS.SubjectOrg == nil || svc.TLS.SubjectOrg[0] != "Example Corp" {
		t.Errorf("expected subject org Example Corp, got %v", svc.TLS.SubjectOrg)
	}
	if !svc.TLS.SelfSigned {
		t.Error("certificate should be flagged self-signed")
	}
	if !svc.TLS.HostnameValid {
		t.Error("hostname should validate against the SAN")
	}
	if svc.HTTP == nil || svc.HTTP.Status != 200 {
		t.Errorf("expected an HTTP 200, got %+v", svc.HTTP)
	}
}

func TestProbeTLSOnNonStandardPort(t *testing.T) {
	// A TLS server on an arbitrary high port must still be fingerprinted.
	cert := selfSigned(t, "test.example.com", "")
	port := startHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>Staging</title></head></html>")
	}), cert)
	cfg := liveConfig(t, []int{port})

	svc := probeOne(t, cfg, port)
	if svc == nil || svc.TLS == nil {
		t.Fatalf("TLS on non-standard port not detected: %+v", svc)
	}
	if svc.HTTP == nil || svc.HTTP.Title != "Staging" {
		t.Errorf("expected the page title, got %+v", svc.HTTP)
	}
}

func TestProbePlainHTTP(t *testing.T) {
	port := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.14.0")
		fmt.Fprint(w, "<html><head><title>Welcome to nginx!</title></head></html>")
	}))
	cfg := liveConfig(t, []int{port})

	svc := probeOne(t, cfg, port)
	if svc == nil || svc.HTTP == nil {
		t.Fatalf("plain HTTP not detected: %+v", svc)
	}
	if svc.TLS != nil {
		t.Error("no TLS certificate should be reported for a plaintext server")
	}
	if svc.HTTP.Title != "Welcome to nginx!" {
		t.Errorf("title = %q", svc.HTTP.Title)
	}
}

// TestCatchAllAppDoesNotProduceExposures is the most important false-positive
// test: a single-page app answers 200 with HTML for every path. That must not
// be reported as an exposed .env or an open admin panel.
func TestCatchAllAppDoesNotProduceExposures(t *testing.T) {
	port := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>SPA</title></head><body><div id=root></div></body></html>")
	}))
	cfg := liveConfig(t, []int{port})

	svc := probeOne(t, cfg, port)
	if svc == nil || svc.HTTP == nil {
		t.Fatal("expected a web service")
	}
	if len(svc.HTTP.Exposed) != 0 {
		t.Errorf("catch-all app produced exposures: %+v", svc.HTTP.Exposed)
	}
	if len(svc.HTTP.OpenPanels) != 0 {
		t.Errorf("catch-all app produced open panels: %+v", svc.HTTP.OpenPanels)
	}
}

// TestRealDotEnvIsDetected is the positive counterpart: a genuine dotenv file
// must be caught, so the catch-all guard is not simply suppressing everything.
func TestRealDotEnvIsDetected(t *testing.T) {
	port := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123\n")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>App</title></head></html>")
	}))
	cfg := liveConfig(t, []int{port})

	svc := probeOne(t, cfg, port)
	if svc == nil || svc.HTTP == nil {
		t.Fatal("expected a web service")
	}
	found := false
	for _, ex := range svc.HTTP.Exposed {
		if ex.Path == "/.env" && strings.Contains(ex.Note, "secrets") {
			found = true
		}
	}
	if !found {
		t.Errorf("real .env not detected as an exposure: %+v", svc.HTTP.Exposed)
	}
}

// TestProtectedPanelIsNotOpen verifies that a 401 panel is recorded as
// protected, not as an open entry point.
func TestProtectedPanelIsNotOpen(t *testing.T) {
	port := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Grafana"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "<html><head><title>App</title></head></html>")
	}))
	cfg := liveConfig(t, []int{port})

	svc := probeOne(t, cfg, port)
	if svc == nil || svc.HTTP == nil {
		t.Fatal("expected a web service")
	}
	if len(svc.HTTP.OpenPanels) != 0 {
		t.Errorf("protected panel reported as open: %+v", svc.HTTP.OpenPanels)
	}
	if len(svc.HTTP.ProtectedPanels) == 0 {
		t.Errorf("protected panel not recorded: %+v", svc.HTTP.Exposed)
	}
}

// TestOpenPanelIsDetected verifies the positive case: an unauthenticated admin
// interface is an open panel.
func TestOpenPanelIsDetected(t *testing.T) {
	port := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>Grafana</title></head><body>dashboard</body></html>")
			return
		}
		fmt.Fprint(w, "<html><head><title>App</title></head></html>")
	}))
	cfg := liveConfig(t, []int{port})

	svc := probeOne(t, cfg, port)
	if svc == nil || svc.HTTP == nil {
		t.Fatal("expected a web service")
	}
	if len(svc.HTTP.OpenPanels) == 0 {
		t.Errorf("open admin panel not detected: %+v", svc.HTTP)
	}
}

func TestProbeClosedPortIsQuiet(t *testing.T) {
	// Find a port that is closed by binding and immediately closing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := liveConfig(t, []int{port})
	svc := probeOne(t, cfg, port)
	if svc != nil {
		t.Errorf("closed port should not produce a service: %+v", svc)
	}
}

func TestProbeRespectsDryRun(t *testing.T) {
	port := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><head><title>App</title></head></html>")
	}))
	cfg := liveConfig(t, []int{port})
	cfg.Safety.DryRun = true

	g := NewGate(cfg)
	p := NewProber(cfg, g)
	h := &model.Host{Name: "test.example.com", IPs: []string{"127.0.0.1"}, Resolvable: true, PortHints: []int{port}}
	res := p.ProbeHost(t.Context(), h)
	if len(res.Services) != 0 {
		t.Errorf("dry run probed anyway: %+v", res.Services)
	}
	if res.Skipped == 0 {
		t.Error("dry run should record a skip")
	}
}

func TestProbeRefusesPrivateWhenDisallowed(t *testing.T) {
	port := startHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>App</title>")
	}))
	cfg := liveConfig(t, []int{port})
	cfg.Safety.AllowPrivate = false
	if err := cfg.Compile(); err != nil {
		t.Fatal(err)
	}
	g := NewGate(cfg)
	p := NewProber(cfg, g)
	h := &model.Host{Name: "test.example.com", IPs: []string{"127.0.0.1"}, Resolvable: true, PortHints: []int{port}}
	res := p.ProbeHost(t.Context(), h)
	if len(res.Services) != 0 {
		t.Errorf("private address was probed despite allow_private=false: %+v", res.Services)
	}
}
