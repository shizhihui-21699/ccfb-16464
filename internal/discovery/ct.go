package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"asm/internal/model"
)

// CTEntry is a normalised certificate-transparency observation.
type CTEntry struct {
	Name       string    `json:"name"`
	Issuer     string    `json:"issuer,omitempty"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
	Expired    bool      `json:"expired,omitempty"`
	Wildcard   bool      `json:"wildcard,omitempty"`
	CertID     string    `json:"cert_id,omitempty"`
	CommonName string    `json:"common_name,omitempty"`
	// Ports, when present, are ports a passive-DNS feed associated with this
	// name. CT itself does not know ports; a combined feed may.
	Ports []int `json:"ports,omitempty"`
}

// CTSource pulls candidate names from certificate transparency.
type CTSource struct {
	providers      []ctProvider
	maxPerApex     int
	includeExpired bool
	log            func(format string, args ...any)
}

type ctProvider interface {
	Name() string
	Names(ctx context.Context, apex string) ([]CTEntry, error)
}

// NewCTSource builds a CT source from config. Unknown provider names are an
// error so a typo does not silently disable a source.
func NewCTSource(cfg CTConfig, logf func(string, ...any)) (*CTSource, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &CTSource{maxPerApex: cfg.MaxEntries, includeExpired: cfg.IncludeExpired, log: logf}
	if s.maxPerApex <= 0 {
		s.maxPerApex = 5000
	}
	for _, name := range cfg.Providers {
		switch strings.ToLower(name) {
		case "crtsh":
			s.providers = append(s.providers, newCrtSh(cfg.Timeout))
		case "certspotter":
			s.providers = append(s.providers, newCertSpotter(cfg.Timeout))
		case "fixture", "file":
			for _, path := range cfg.Fixtures {
				p, err := newFixtureProvider(path)
				if err != nil {
					return nil, err
				}
				s.providers = append(s.providers, p)
			}
		default:
			return nil, fmt.Errorf("discovery.ct.providers: unknown provider %q", name)
		}
	}
	return s, nil
}

// CTConfig is the subset of config the source needs, kept small so this
// package does not import the whole config tree into its tests.
type CTConfig struct {
	Providers      []string
	Fixtures       []string
	MaxEntries     int
	IncludeExpired bool
	Timeout        time.Duration
}

// Name implements HostSource.
func (s *CTSource) Name() string { return "ct" }

// Fetch implements HostSource. Names are returned as candidates; wildcard
// entries are flagged so the enumerator can discard them rather than probing.
func (s *CTSource) Fetch(ctx context.Context, apex string) ([]Candidate, error) {
	var out []Candidate
	seen := map[string]bool{}
	var errs []error
	for _, p := range s.providers {
		entries, err := p.Names(ctx, apex)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			continue
		}
		for _, e := range entries {
			name := model.NormalizeName(e.Name)
			if name == "" || seen[name] {
				continue
			}
			if e.Expired && !s.includeExpired {
				continue
			}
			seen[name] = true
			out = append(out, Candidate{
				Name:     name,
				Wildcard: e.Wildcard || strings.Contains(name, "*"),
				Ports:    e.Ports,
				Detail:   e.Issuer,
			})
			if len(out) >= s.maxPerApex {
				s.log("ct: %s hit max_entries=%d, truncating", apex, s.maxPerApex)
				sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
				return out, joinErrs(errs)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, joinErrs(errs)
}

// --- crt.sh -------------------------------------------------------------

type crtShProvider struct {
	client *http.Client
}

func newCrtSh(timeout time.Duration) *crtShProvider {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &crtShProvider{client: &http.Client{Timeout: timeout}}
}

func (c *crtShProvider) Name() string { return "crt.sh" }

type crtShRow struct {
	NameValue  string    `json:"name_value"`
	IssuerCA   string    `json:"issuer_ca_id"`
	IssuerName string    `json:"issuer_name"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Serial     string    `json:"serial_number"`
}

func (c *crtShProvider) Names(ctx context.Context, apex string) ([]CTEntry, error) {
	q := url.Values{}
	q.Set("q", "%."+apex)
	q.Set("output", "json")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://crt.sh/?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "asm-inventory/1.0 (attack-surface management)")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("crt.sh rate limited (429); back off and retry next run")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var rows []crtShRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("decode crt.sh response: %w", err)
	}
	now := time.Now()
	var out []CTEntry
	for _, row := range rows {
		// name_value can hold several newline-separated names, including
		// wildcards.
		for _, n := range strings.Split(row.NameValue, "\n") {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			out = append(out, CTEntry{
				Name:      n,
				Issuer:    row.IssuerName,
				NotBefore: row.NotBefore,
				NotAfter:  row.NotAfter,
				Expired:   !row.NotAfter.IsZero() && row.NotAfter.Before(now),
				Wildcard:  strings.HasPrefix(n, "*."),
				CertID:    row.Serial,
			})
		}
	}
	return out, nil
}

// --- certspotter --------------------------------------------------------

type certSpotter struct {
	client *http.Client
}

func newCertSpotter(timeout time.Duration) *certSpotter {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &certSpotter{client: &http.Client{Timeout: timeout}}
}

func (c *certSpotter) Name() string { return "certspotter" }

type csIssuance struct {
	ID        string    `json:"id"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
	Issuer    struct {
		Name         string `json:"name"`
		FriendlyName string `json:"friendly_name"`
	} `json:"issuer"`
}

func (c *certSpotter) Names(ctx context.Context, apex string) ([]CTEntry, error) {
	q := url.Values{}
	// CertSpotter supports a domain= filter which is much cheaper than a
	// substring match and returns only names for that registrable domain.
	q.Set("domain", apex)
	q.Set("include_subdomains", "true")
	q.Set("expand", "dns_names")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.certspotter.com/v1/issuances?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "asm-inventory/1.0 (attack-surface management)")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query certspotter: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("certspotter rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var rows []csIssuance
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("decode certspotter response: %w", err)
	}
	now := time.Now()
	var out []CTEntry
	for _, row := range rows {
		issuer := row.Issuer.FriendlyName
		if issuer == "" {
			issuer = row.Issuer.Name
		}
		for _, n := range row.DNSNames {
			out = append(out, CTEntry{
				Name:      strings.TrimSpace(n),
				Issuer:    issuer,
				NotBefore: row.NotBefore,
				NotAfter:  row.NotAfter,
				Expired:   !row.NotAfter.IsZero() && row.NotAfter.Before(now),
				Wildcard:  strings.HasPrefix(n, "*."),
				CertID:    row.ID,
			})
		}
	}
	return out, nil
}

// --- fixture provider ---------------------------------------------------

// fixtureProvider replays a JSONL of CT entries. Each line is one CTEntry.
// This is how the repository demo and the tests exercise the CT path without
// network access, and it is also useful for replaying an exported log during
// incident review.
type fixtureProvider struct {
	path string
}

func newFixtureProvider(path string) (*fixtureProvider, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("discovery.ct.fixtures: %w", err)
	}
	return &fixtureProvider{path: path}, nil
}

func (f *fixtureProvider) Name() string { return "fixture:" + f.path }

func (f *fixtureProvider) Names(_ context.Context, apex string) ([]CTEntry, error) {
	fh, err := os.Open(f.path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []CTEntry
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	now := time.Now()
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var e CTEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("%s: bad JSON line: %w", f.path, err)
		}
		if !strings.HasSuffix(strings.ToLower(strings.TrimPrefix(e.Name, "*.")), "."+apex) &&
			strings.ToLower(strings.TrimPrefix(e.Name, "*.")) != apex {
			continue
		}
		if e.Expired || (!e.NotAfter.IsZero() && e.NotAfter.Before(now)) {
			e.Expired = true
		}
		if e.Wildcard || strings.HasPrefix(e.Name, "*.") {
			e.Wildcard = true
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
