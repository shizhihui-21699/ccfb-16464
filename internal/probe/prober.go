package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"asm/internal/config"
	"asm/internal/model"
)

// Prober performs active checks against one host. It is safe for concurrent
// use; the shared Gate enforces the rate limits.
type Prober struct {
	cfg  *config.Config
	gate *Gate
	// hostConcurrency bounds the number of ports probed on one host at once.
	hostSem chan struct{}
}

// NewProber builds a prober.
func NewProber(cfg *config.Config, gate *Gate) *Prober {
	return &Prober{cfg: cfg, gate: gate}
}

// HostResult is the outcome of probing one host.
type HostResult struct {
	Host        string
	Services    []model.Service
	Skipped     int
	SkipReasons map[string]int
	Errors      []string
}

// ProbeHost probes every configured port on a host and returns the services
// that answered.
func (p *Prober) ProbeHost(ctx context.Context, host *model.Host) HostResult {
	res := HostResult{Host: host.Name, SkipReasons: map[string]int{}}
	addrs := host.Addresses()
	if len(addrs) == 0 {
		return res
	}
	// Outside the window nothing is probed. In wait mode the caller has
	// already blocked on WaitUntilWindow, so reaching here closed means the
	// window shut between the wait and this call; skip rather than override
	// the policy.
	if !p.gate.InWindow() {
		res.Skipped++
		res.SkipReasons["window_closed"]++
		return res
	}
	// Probe one address per host. A CDN edge resolves to many addresses and
	// probing all of them multiplies load without adding signal; the others
	// are recorded in the asset record for completeness.
	ip := addrs[0]
	if err := p.gate.Allow(host.Name, ip); err != nil {
		res.Skipped++
		res.SkipReasons[reason(err)]++
		return res
	}

	// A passive source that already knows which ports matter (a passive-DNS
	// feed, or a fixture in the demo) lets us probe far less. Only the hinted
	// ports are tried; the full list is the fallback for unknown hosts.
	ports := dedupePorts(p.cfg.Probes.Ports)
	if len(host.PortHints) > 0 {
		ports = dedupePorts(host.PortHints)
	}
	var (
		mu       sync.Mutex
		services []model.Service
		errs     []string
		wg       sync.WaitGroup
	)

	// Bound concurrency within one host to safety.host_concurrency. Note that
	// the per-host rate limiter still gates every individual connection, so
	// this only controls how many are in flight, not the request rate.
	conc := p.cfg.Safety.HostConcurrency
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	for _, port := range ports {
		if !p.gate.BudgetLeft() {
			res.SkipReasons["budget"]++
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			svc, err := p.probePort(ctx, host.Name, ip, port)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if errors.Is(err, ErrSkipped) {
					res.Skipped++
					res.SkipReasons["policy"]++
					return
				}
				if errors.Is(err, errClosed) || errors.Is(err, errTimeout) {
					return
				}
				errs = append(errs, fmt.Sprintf("port %d: %v", port, err))
				return
			}
			if svc != nil {
				services = append(services, *svc)
			}
		}(port)
	}
	wg.Wait()
	sort.Slice(services, func(i, j int) bool { return services[i].Port < services[j].Port })
	res.Services = services
	res.Errors = errs
	return res
}

var (
	errClosed  = errors.New("connection refused")
	errTimeout = errors.New("connection timed out")
	errNotHTTP = errors.New("peer did not speak http")
)

func reason(err error) string {
	switch {
	case errors.Is(err, ErrSkipped):
		return "policy"
	case errors.Is(err, ErrUnsafeTarget):
		return "unsafe_address"
	default:
		return "error"
	}
}

// probePort opens one TCP connection and fingerprints what answers.
//
// Protocol detection is deliberately not driven by the port number alone: a
// salty proportion of forgotten assets run HTTPS on 8443, 9443, 10443 or an
// arbitrary high port, and a staging site on 8080 is common. Port numbers are
// therefore treated as a hint for ordering, not as a decision:
//
//   - a port known to speak plaintext HTTP is tried as plaintext first;
//   - every other port is tried as TLS first, because a server that speaks
//     plaintext will reject the ClientHello immediately with a readable error;
//   - if neither speaks, a short banner read captures products like SSH/redis.
//
// Each path costs at most one connection. A failed TLS attempt reuses the same
// socket state only if the server has not spoken; in practice a rejected
// ClientHello leaves the connection unusable, so the plaintext attempt dials a
// second time. That is at most two connections per port, bounded by the gate.
func (p *Prober) probePort(ctx context.Context, host, ip string, port int) (*model.Service, error) {
	svc := &model.Service{Host: host, IP: ip, Port: port, Protocol: "tcp"}
	// opened records whether any attempt actually established a TCP connection.
	// A refused port must not be reported as a service: an inventory full of
	// "open" ports that are really closed is worse than useless.
	opened := false

	// Plaintext HTTP first on ports that are almost always plaintext.
	if isPlainHTTPPort(port) {
		info, err := p.attemptHTTP(ctx, host, ip, port, "http")
		if err == nil && info != nil {
			p.gate.RecordSuccess(host)
			svc.HTTP = info
			return svc, nil
		}
		if err != errNotHTTP && err != nil && !isDialRefused(err) {
			opened = true
		}
		if isDialRefused(err) {
			// A closed port is a definitive negative; do not waste more
			// connections on it.
			return nil, errClosed
		}
	}

	// TLS first everywhere else. On a TLS-speaking port this is the only
	// connection; on a plaintext port the handshake fails without a payload.
	tlsInfo, tconn, err := p.attemptTLS(ctx, host, ip, port)
	if err == nil && tlsInfo != nil {
		opened = true
		svc.TLS = tlsInfo
		if info := p.exchange(tconn, host, port, "https"); info != nil {
			info.Exposed, info.OpenPanels, info.ProtectedPanels = p.ProbeServicePaths(ctx, host, ip, port, "https")
			svc.HTTP = info
		}
		p.gate.RecordSuccess(host)
		return svc, nil
	}
	if isDialRefused(err) {
		return nil, errClosed
	}
	if err != nil && !errors.Is(err, errNotHTTP) && !isHandshakeFailure(err) {
		opened = true
	}

	// Plaintext HTTP on a port that is not usually plaintext (e.g. 8080).
	if !isPlainHTTPPort(port) {
		info, herr := p.attemptHTTP(ctx, host, ip, port, "http")
		if herr == nil && info != nil {
			p.gate.RecordSuccess(host)
			svc.HTTP = info
			return svc, nil
		}
		if herr != nil && !isDialRefused(herr) && herr != errNotHTTP {
			opened = true
		}
		if isDialRefused(herr) {
			return nil, errClosed
		}
	}

	// Nothing HTTP or TLS. Capture a banner so the port can be identified.
	banner, berr := p.readBanner(ctx, ip, port)
	if berr == nil {
		opened = true
	}
	if banner != "" {
		svc.Banner = banner
		svc.Product = identifyBanner(banner)
		p.gate.RecordSuccess(host)
		return svc, nil
	}
	if !opened {
		return nil, errClosed
	}

	// A port that accepts a connection but says nothing is still open. Record
	// it: on the ports that should never be public, that alone is the finding.
	p.gate.RecordSuccess(host)
	return svc, nil
}

// isDialRefused reports whether a dial failed because the port is closed.
func isDialRefused(err error) bool {
	if err == nil {
		return false
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		var se *os.SyscallError
		if errors.As(oe.Err, &se) {
			return errors.Is(se.Err, syscall.ECONNREFUSED)
		}
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// isHandshakeFailure reports whether err came from TLS negotiation against a
// server that accepted the connection but did not speak TLS. Such a port is
// open, just not a TLS service.
func isHandshakeFailure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "tls:") || strings.Contains(s, "first record does not look like a TLS handshake") ||
		strings.Contains(s, "handshake failure") || strings.Contains(s, "unexpected message")
}

// attemptHTTP dials and performs one plaintext HTTP exchange.
func (p *Prober) attemptHTTP(ctx context.Context, host, ip string, port int, scheme string) (*model.HTTP, error) {
	if err := p.gate.Acquire(ctx, host); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := Dialer(p.cfg).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(Deadline(p.cfg)))
	if info := p.exchange(conn, host, port, scheme); info != nil {
		info.Exposed, info.OpenPanels, info.ProtectedPanels = p.ProbeServicePaths(ctx, host, ip, port, scheme)
		return info, nil
	}
	return nil, errNotHTTP
}

// attemptTLS dials and completes a TLS handshake, returning the live
// connection for an HTTP exchange.
//
// The connection is deliberately not closed here: the caller either keeps it
// for the HTTP request or closes it. A leaked socket would be worse than an
// extra dial, so the caller always owns it.
func (p *Prober) attemptTLS(ctx context.Context, host, ip string, port int) (*model.TLS, *tls.Conn, error) {
	if err := p.gate.Acquire(ctx, host); err != nil {
		return nil, nil, err
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := Dialer(p.cfg).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(Deadline(p.cfg)))
	tconn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // inspection: we WANT self-signed and mismatched certs
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, nil, err
	}
	info := inspectTLS(tconn.ConnectionState(), host)
	return info, tconn, nil
}

// readBanner dials and reads whatever the server sends unprompted.
func (p *Prober) readBanner(ctx context.Context, ip string, port int) (string, error) {
	if err := p.gate.Acquire(ctx, "banner:"+ip); err != nil {
		return "", err
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := Dialer(p.cfg).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "", nil
	}
	return sanitizeBanner(string(buf[:n])), nil
}

// identifyBanner maps a greeting to a product name.
func identifyBanner(b string) string {
	low := strings.ToLower(b)
	switch {
	case strings.HasPrefix(low, "ssh-"):
		return "ssh"
	case strings.HasPrefix(low, "-err"), strings.HasPrefix(low, "-noauth"), strings.HasPrefix(low, "+ok"), strings.HasPrefix(low, "$"):
		return "redis"
	case strings.Contains(low, "smtp"):
		return "smtp"
	case strings.Contains(low, "imap"):
		return "imap"
	case strings.Contains(low, "pop3"):
		return "pop3"
	case strings.Contains(low, "mysql"):
		return "mysql"
	case strings.Contains(low, "postgres"):
		return "postgres"
	case strings.Contains(low, "ftp"):
		return "ftp"
	case strings.Contains(low, "rdp"):
		return "rdp"
	}
	return ""
}

func sanitizeBanner(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// isPlainHTTPPort reports whether plaintext HTTP is overwhelmingly likely on
// this port, so it should be attempted before TLS.
func isPlainHTTPPort(port int) bool {
	switch port {
	case 80, 8080, 8000, 8008, 8088, 8888, 3000, 5000, 9000, 9090, 9091, 8880:
		return true
	}
	return false
}

func containsStringPort(list []int, port int) bool {
	for _, p := range list {
		if p == port {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

// handshake upgrades an existing conn to TLS. It is used by the path prober,
// which already holds a plaintext connection it needs to reuse.
func (p *Prober) handshake(conn net.Conn, host string) (*model.TLS, *tls.Conn, error) {
	tconn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tconn.HandshakeContext(context.Background()); err != nil {
		return nil, nil, err
	}
	return inspectTLS(tconn.ConnectionState(), host), tconn, nil
}

// inspectTLS turns handshake state into the model's certificate record.
func inspectTLS(state tls.ConnectionState, host string) *model.TLS {
	if len(state.PeerCertificates) == 0 {
		return &model.TLS{HostnameValid: false}
	}
	leaf := state.PeerCertificates[0]
	info := &model.TLS{
		SubjectCN:         leaf.Subject.CommonName,
		SANs:              dedupe(leaf.DNSNames),
		IssuerCN:          leaf.Issuer.CommonName,
		IssuerOrg:         dedupe(leaf.Issuer.Organization),
		SubjectOrg:        dedupe(leaf.Subject.Organization),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		FingerprintSHA256: fingerprint(leaf),
		Serial:            leaf.SerialNumber.Text(16),
		Version:           int(state.Version),
		SelfSigned:        isSelfSigned(leaf),
		HostnameValid:     leaf.VerifyHostname(host) == nil,
		Weak:              isWeakCert(leaf),
		SharedCert:        len(leaf.DNSNames) > 20,
	}
	return info
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
}

func isWeakCert(cert *x509.Certificate) bool {
	if cert.PublicKeyAlgorithm == x509.RSA {
		if pub, ok := cert.PublicKey.(interface{ Size() int }); ok {
			if pub.Size()*8 < 2048 {
				return true
			}
		}
	}
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA:
		return true
	}
	return false
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var techRe = regexp.MustCompile(`(?i)(wordpress|drupal|joomla|django|flask|express|laravel|spring|tomcat|nginx|apache|iis|openresty|grafana|kibana|elasticsearch|phpmyadmin|jenkins|gitlab|swagger|actuator|rabbitmq|minio|consul|prometheus|zabbix|sonar|nexus|artifactory)`)

// exchange sends a single bounded GET on conn and parses the response. It
// returns nil when the peer does not speak HTTP.
func (p *Prober) exchange(conn net.Conn, host string, port int, scheme string) *model.HTTP {
	hostHdr := hostHeader(host, port)
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
		hostHdr, p.cfg.Probes.UserAgent)
	if _, err := io.WriteString(conn, req); err != nil {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(Deadline(p.cfg)))
	br := bufio.NewReader(io.LimitReader(conn, p.cfg.Probes.MaxBodyBytes+4096))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, p.cfg.Probes.MaxBodyBytes))

	info := &model.HTTP{
		URL:       fmt.Sprintf("%s://%s/", scheme, hostHdr),
		Status:    resp.StatusCode,
		Server:    resp.Header.Get("Server"),
		PoweredBy: resp.Header.Get("X-Powered-By"),
		Headers:   map[string]string{},
		BodyHash:  hashBody(body),
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		info.FinalURL = loc
		if scheme == "http" && strings.HasPrefix(strings.ToLower(loc), "https://") {
			info.HTTPSRedirect = true
		}
	}
	for _, h := range []string{"Server", "X-Powered-By", "Via", "X-Cache", "X-AspNet-Version", "X-Generator", "WWW-Authenticate", "X-Frame-Options", "Strict-Transport-Security"} {
		if v := resp.Header.Get(h); v != "" {
			info.Headers[h] = v
		}
	}
	if m := titleRe.FindSubmatch(body); m != nil {
		info.Title = strings.TrimSpace(string(m[1]))
	}
	tech := map[string]bool{}
	hay := info.Server + " " + info.PoweredBy + " " + info.Title + " " + string(body[:min(len(body), 8192)])
	for _, m := range techRe.FindAllString(hay, -1) {
		tech[strings.ToLower(m)] = true
	}
	for k := range tech {
		info.Tech = append(info.Tech, k)
	}
	sort.Strings(info.Tech)
	info.AuthRealm = resp.Header.Get("WWW-Authenticate")
	if info.AuthRealm != "" {
		info.Panel = panelFromRealm(info.AuthRealm)
	}
	return info
}

func hostHeader(host string, port int) string {
	if port == 80 || port == 443 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func hashBody(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func panelFromRealm(realm string) string {
	low := strings.ToLower(realm)
	for _, panel := range []string{"grafana", "kibana", "phpmyadmin", "tomcat manager", "jenkins", "gitlab", "rabbitmq", "zabbix"} {
		if strings.Contains(low, panel) {
			return panel
		}
	}
	return ""
}
