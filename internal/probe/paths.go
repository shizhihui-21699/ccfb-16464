package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"asm/internal/model"
)

// PathKind classifies why a path is being probed. The distinction matters:
// a landing page answering 200 is normal, an admin panel answering 200 is an
// entry point, and an environment file answering 200 is a data breach.
type PathKind int

const (
	// PathLanding is a benign page. It is fetchable but never a finding.
	PathLanding PathKind = iota
	// PathSensitive is a path that should never be public (source control
	// metadata, environment files, diagnostics, API docs).
	PathSensitive
	// PathPanel is a management interface. Reachable is notable; reachable
	// without authentication is a finding of its own.
	PathPanel
)

// sensitivePathRe matches the paths whose public availability can be a
// finding. The list is deliberately concrete: a pattern that fires on every
// landing page is worse than no pattern.
var sensitivePathRe = regexp.MustCompile(`(?i)^/(\.git/config|\.git/HEAD|\.env(\.\w+)?|server-status|actuator(/.*)?|swagger-ui\.html|v2/api-docs|\.svn/entries|\.DS_Store|phpinfo\.php|web\.config|backup\.(zip|sql|tar\.gz|gz)|\.aws/credentials|id_rsa|docker-compose\.yml)$`)

// panelPathRe recognises management interfaces by name. Configuring every
// variant is fragile (/admin/, /admin, /administrator, /wp-admin, /console), so
// the shape is what matters.
var panelPathRe = regexp.MustCompile(`(?i)/(admin|administrator|wp-admin|manager|console|login|signin|dashboard|phpmyadmin|adminer|grafana|kibana|jenkins|gitlab|zabbix|rabbitmq|webmin|cpanel)(/|$|\?)`)

// classifyPath decides the kind of a configured path.
func classifyPath(p string, panelPaths []string) PathKind {
	switch {
	case p == "" || p == "/":
		return PathLanding
	case sensitivePathRe.MatchString(p):
		return PathSensitive
	case panelPathRe.MatchString(p):
		return PathPanel
	}
	for _, panel := range panelPaths {
		if p == panel {
			return PathPanel
		}
	}
	return PathLanding
}

// PathProbe is one read-only request against a known web service.
type PathProbe struct {
	Path   string
	Kind   PathKind
	Status int
	Note   string
	Title  string
	// Confirmed means the response body corroborated the expected content.
	// Without this, a single-page app that answers 200 for every URL would
	// generate a critical finding on every host.
	Confirmed bool
}

// ProbeServicePaths runs the bounded, read-only path checks for one service.
// It uses a fresh connection per path: a path that is slow or blocking cannot
// stall the rest of the run, and each request is independently rate-limited.
//
// Every request is a GET. Validation in config rejects anything that could
// mutate state, so this function never needs a second opinion.
//
// It returns only results worth recording: sensitive paths whose body
// corroborates the deployment, and panels that responded.
func (p *Prober) ProbeServicePaths(ctx context.Context, host, ip string, port int, scheme string) (exposed []model.ExposedPath, openPanels, protectedPanels []string) {
	type candidate struct {
		path string
		kind PathKind
	}
	var cands []candidate
	for _, path := range dedupeStrings(p.cfg.Probes.HTTPPaths) {
		cands = append(cands, candidate{path, classifyPath(path, p.cfg.Probes.PanelPaths)})
	}
	for _, path := range dedupeStrings(p.cfg.Probes.PanelPaths) {
		cands = append(cands, candidate{path, PathPanel})
	}
	if max := p.cfg.Probes.MaxPathsPerService; max > 0 && len(cands) > max {
		cands = cands[:max]
	}

	for _, c := range cands {
		if !p.gate.BudgetLeft() {
			break
		}
		if err := p.gate.Allow(host, ip); err != nil {
			continue
		}
		pp := p.probePath(ctx, host, ip, port, scheme, c.path, c.kind)
		if pp.Status == 0 {
			continue
		}
		switch c.kind {
		case PathSensitive:
			// Require content corroboration. A 200 with an HTML shell is a
			// catch-all router, not an exposed secret.
			if pp.Confirmed {
				exposed = append(exposed, model.ExposedPath{Path: c.path, Status: pp.Status, Note: pp.Note})
			}
		case PathPanel:
			if pp.Status == http.StatusNotFound || pp.Status == http.StatusBadGateway {
				continue
			}
			// A panel only counts when its body or challenge looks like a
			// management interface; a catch-all 200 does not.
			if !pp.Confirmed {
				continue
			}
			if pp.Status >= 200 && pp.Status < 300 {
				openPanels = append(openPanels, c.path)
			} else {
				protectedPanels = append(protectedPanels, c.path)
			}
		}
	}
	sort.Slice(exposed, func(i, j int) bool { return exposed[i].Path < exposed[j].Path })
	return exposed, dedupeStrings(openPanels), dedupeStrings(protectedPanels)
}

// probePath requests one path and classifies the answer.
func (p *Prober) probePath(ctx context.Context, host, ip string, port int, scheme, path string, kind PathKind) PathProbe {
	out := PathProbe{Path: path}
	if err := p.gate.Acquire(ctx, host); err != nil {
		return out
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	d := Dialer(p.cfg)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.gate.RecordFailure(host)
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(Deadline(p.cfg)))

	var rw io.ReadWriter = conn
	if scheme == "https" {
		_, tlsConn, err := p.handshake(conn, host)
		if err != nil || tlsConn == nil {
			return out
		}
		defer tlsConn.Close()
		rw = tlsConn
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
		path, hostHeader(host, port), p.cfg.Probes.UserAgent)
	if _, err := io.WriteString(rw, req); err != nil {
		return out
	}
	_ = conn.SetDeadline(time.Now().Add(Deadline(p.cfg)))
	br := bufio.NewReader(io.LimitReader(rw, p.cfg.Probes.MaxBodyBytes+4096))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, p.cfg.Probes.MaxBodyBytes))
	out.Status = resp.StatusCode
	if m := titleRe.FindSubmatch(body); m != nil {
		out.Title = strings.TrimSpace(string(m[1]))
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if kind == PathPanel {
			// A panel answering 2xx is open only if the page really is a
			// management interface. A catch-all app answers 200 everywhere.
			out.Confirmed = looksLikePanel(path, resp, body, out.Title)
			if out.Confirmed {
				out.Note = "open without authentication"
			}
		} else {
			out.Note, out.Confirmed = classifyBody(path, resp, body)
		}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		out.Note = "protected"
		out.Confirmed = looksLikePanel(path, resp, body, out.Title)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc := strings.ToLower(resp.Header.Get("Location"))
		if strings.Contains(loc, "login") || strings.Contains(loc, "auth") || strings.Contains(loc, "sso") {
			out.Note = "redirects to login"
		} else {
			out.Note = "redirect"
		}
		out.Confirmed = true
	}
	return out
}

// classifyBody decides whether a 2xx response really is the sensitive thing we
// asked for, and describes it. Content corroboration is the whole point: a
// catch-all app returns 200 for /.env, but its body is HTML.
func classifyBody(path string, resp *http.Response, body []byte) (note string, confirmed bool) {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	low := strings.ToLower(string(head))
	isHTML := strings.Contains(low, "<html") || strings.Contains(low, "<!doctype") || strings.Contains(low, "<body")

	switch {
	case strings.HasPrefix(path, "/.git/"):
		if strings.Contains(low, "[core]") || strings.Contains(low, "ref: refs") {
			return "git repository metadata (source disclosure)", true
		}
		return "", false
	case strings.HasPrefix(path, "/.env"):
		if isHTML {
			return "", false
		}
		if looksLikeDotEnv(head) {
			if containsAny(low, "password", "secret", "token", "api_key", "apikey", "private_key", "db_") {
				return "environment file with secrets", true
			}
			return "environment file", true
		}
		return "", false
	case strings.Contains(path, "actuator"):
		if strings.Contains(low, `"_links"`) || strings.Contains(low, `"status"`) || strings.Contains(low, "actuator") {
			return "spring boot actuator", true
		}
		return "", false
	case strings.HasSuffix(path, "/server-status"):
		if strings.Contains(low, "apache server status") || strings.Contains(low, "server version") {
			return "apache mod_status", true
		}
		return "", false
	case strings.Contains(path, "swagger") || strings.Contains(path, "api-docs"):
		if strings.Contains(low, `"swagger"`) || strings.Contains(low, `"openapi"`) || strings.Contains(low, `"paths"`) {
			return "API documentation", true
		}
		return "", false
	case strings.HasSuffix(path, "/phpinfo.php"):
		if strings.Contains(low, "php version") || strings.Contains(low, "phpinfo()") {
			return "phpinfo disclosure", true
		}
		return "", false
	case strings.Contains(path, "credentials") || strings.Contains(path, "id_rsa"):
		if strings.Contains(low, "aws_access_key_id") || strings.Contains(low, "private key") {
			return "credential material", true
		}
		return "", false
	}
	return "", false
}

// looksLikeDotEnv reports whether the body is a KEY=value file rather than an
// arbitrary page. Dotenv files are plain text with a high ratio of assignments.
func looksLikeDotEnv(body []byte) bool {
	lines := strings.Split(string(body), "\n")
	if len(lines) == 0 {
		return false
	}
	assignments := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			// A line that is not a comment or an assignment disqualifies the
			// whole body (markup, prose, JSON all end up here).
			return false
		}
		key := line[:eq]
		if strings.ContainsAny(key, " <>\"'{}[]()") {
			return false
		}
		assignments++
	}
	return assignments >= 2
}

// looksLikePanel reports whether a 401/403 or a 2xx page is a management
// interface: a login title, an auth realm naming a known product, or a known
// product's page markers.
func looksLikePanel(path string, resp *http.Response, body []byte, title string) bool {
	realm := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
	for _, product := range []string{"grafana", "kibana", "phpmyadmin", "tomcat", "jenkins", "gitlab", "rabbitmq", "zabbix", "elastic"} {
		if strings.Contains(realm, product) {
			return true
		}
	}
	if realm != "" && (strings.Contains(path, "admin") || strings.Contains(path, "manager") || strings.Contains(path, "login")) {
		return true
	}
	low := strings.ToLower(title + " " + string(body[:min(len(body), 2048)]))
	for _, marker := range []string{"grafana", "kibana", "phpmyadmin", "tomcat manager", "jenkins", "gitlab", "rabbitmq management", "zabbix", "sign in", "log in", "login"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
