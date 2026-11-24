// Package config loads, defaults, validates and compiles the scan profile.
//
// A profile is the safety contract for a run: what we are allowed to look at,
// how fast we may look, when we may look, and who gets the results. Compiling
// the profile once turns the human-friendly YAML into fast matchers and makes
// every unsafe combination fail before a single packet is sent.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from YAML strings like "5s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		// Accept a bare number as seconds, for convenience.
		var n int64
		if err2 := node.Decode(&n); err2 != nil {
			return fmt.Errorf("duration must be a string like \"5s\" or a number of seconds: %w", err)
		}
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Std returns the standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the full profile.
type Config struct {
	Organisation Organisation `yaml:"organisation"`
	Discovery    Discovery    `yaml:"discovery"`
	Safety       Safety       `yaml:"safety"`
	Probes       Probes       `yaml:"probes"`
	Attribution  Attribution  `yaml:"attribution"`
	Risk         Risk         `yaml:"risk"`
	Owners       Owners       `yaml:"owners"`
	Outputs      Outputs      `yaml:"outputs"`
	Store        Store        `yaml:"store"`

	// compiled state, populated by Compile.
	scope *Scope `yaml:"-"`
}

// Organisation describes who "we" are. It is the root of all attribution.
type Organisation struct {
	Name    string   `yaml:"name"`
	Handle  string   `yaml:"handle,omitempty"` // short slug used in ids/reports
	Domains []string `yaml:"domains"`

	// OrgNames are the legal / trading names that may appear in a certificate
	// subject O or OU field. Matching is case-insensitive and covers accents.
	OrgNames []string `yaml:"org_names,omitempty"`

	// VerificationTokens are strings whose presence in a DNS TXT record proves
	// control of a name (cloud provider site-verification, DKIM selectors,
	// SPF includes for owned domains, etc.).
	VerificationTokens []string `yaml:"verification_tokens,omitempty"`

	// IPRanges are prefixes we own or lease directly (from RIR allocations).
	IPRanges []string `yaml:"ip_ranges,omitempty"`

	// ASNs we own. Used only for advisory evidence; an ASN match alone never
	// confirms ownership because cloud ranges are shared.
	ASNs []int `yaml:"asns,omitempty"`

	// PartnerDomains are registrable domains operated by partners/vendors that
	// legitimately host assets for us. A host that CNAMEs into one of these is
	// attributed as a partner asset, not silently dropped.
	PartnerDomains []string `yaml:"partner_domains,omitempty"`

	// SaaSShareSuffixes are wildcard suffixes belonging to shared hosting or
	// CDN platforms. A certificate covering one of these is weak evidence.
	SaaSShareSuffixes []string `yaml:"saas_share_suffixes,omitempty"`
}

// Discovery configures passive and semi-passive enumeration.
type Discovery struct {
	Seeds []string `yaml:"seeds,omitempty"`

	CT  CT  `yaml:"ct"`
	DNS DNS `yaml:"dns"`

	// DNSFixture replays a deterministic DNS fixture instead of querying real
	// resolvers. It exists for the offline demo and the test suite; a
	// production profile leaves it empty and names its resolvers instead.
	DNSFixturePath string `yaml:"dns_fixture,omitempty"`
}

// DNSFixture returns the configured fixture path.
func (d Discovery) DNSFixture() string { return d.DNSFixturePath }

// CT configures certificate-transparency harvesting.
type CT struct {
	Enabled bool `yaml:"enabled"`
	// Providers are queried in order. "crtsh" and "certspotter" use the public
	// APIs; "file" replays a local JSONL fixture (used for demos and tests).
	Providers    []string `yaml:"providers,omitempty"`
	Fixtures     []string `yaml:"fixtures,omitempty"`
	PollInterval Duration `yaml:"poll_interval,omitempty"`
	// MaxEntries caps how many new names one apex may contribute per run so a
	// noisy log cannot flood the run.
	MaxEntries int      `yaml:"max_entries,omitempty"`
	Timeout    Duration `yaml:"timeout,omitempty"`
	// IncludeExpired keeps names from expired certs; they frequently reveal
	// forgotten environments, which is exactly what we are hunting.
	IncludeExpired bool `yaml:"include_expired"`
}

// DNS configures name resolution and enumeration.
type DNS struct {
	Enabled   bool     `yaml:"enabled"`
	Resolvers []string `yaml:"resolvers,omitempty"`
	QPS       float64  `yaml:"qps,omitempty"`
	Timeout   Duration `yaml:"timeout,omitempty"`
	// Wordlist is a file of candidate labels; a small built-in list is used
	// when empty. Brute force is bounded by max_labels_per_run.
	Wordlist string `yaml:"wordlist,omitempty"`
	// MaxLabelsPerRun bounds brute-force label count. 0 disables brute force
	// entirely (CT + seeds + CNAME expansion only).
	MaxLabelsPerRun int `yaml:"max_labels_per_run,omitempty"`
	// ProbeWildcard controls random-label wildcard detection per apex. It is
	// on by default and should stay on: without it a catch-all zone inflates
	// the inventory with thousands of phantom hosts.
	ProbeWildcard *bool `yaml:"probe_wildcard,omitempty"`
}

// Safety is the part of the profile that protects production.
type Safety struct {
	MaxGlobalRPS    float64  `yaml:"max_global_rps"`
	MaxPerHostRPS   float64  `yaml:"max_per_host_rps"`
	MaxConcurrent   int      `yaml:"max_concurrent"`
	HostConcurrency int      `yaml:"host_concurrency"`
	RequestTimeout  Duration `yaml:"request_timeout,omitempty"`
	DialTimeout     Duration `yaml:"dial_timeout,omitempty"`

	// ScanWindow, in the profile timezone, restricts when active probes may
	// run. "01:00-05:00" is the normal shape. Empty means always.
	ScanWindow string `yaml:"scan_window,omitempty"`
	Timezone   string `yaml:"timezone,omitempty"`
	// WaitForWindow makes an out-of-window run wait instead of deferring the
	// active stage to the next run. Default false (defer).
	WaitForWindow bool `yaml:"wait_for_window"`

	MaxProbesPerRun int `yaml:"max_probes_per_run,omitempty"`
	MaxHostsPerRun  int `yaml:"max_hosts_per_run,omitempty"`
	// PauseEvery/PauseDuration injects an intentional pause after N probes,
	// smoothing load and making the traffic pattern look less like a scan.
	PauseEvery    int      `yaml:"pause_every,omitempty"`
	PauseDuration Duration `yaml:"pause_duration,omitempty"`

	// ExcludeHosts are glob patterns for names that must never be probed.
	ExcludeHosts []string `yaml:"exclude_hosts,omitempty"`
	// ExcludeIPs are CIDRs that must never be probed.
	ExcludeIPs []string `yaml:"exclude_ips,omitempty"`
	// AllowPrivate permits probing private/loopback/link-local addresses. It
	// exists for the offline demo and lab use; validation warns loudly.
	AllowPrivate bool `yaml:"allow_private"`
	// DryRun discovers and attributes but never sends a probe packet.
	DryRun bool `yaml:"dry_run"`

	// ActiveClasses lists which attribution classes may be actively probed.
	// Partner assets default to passive-only: we cannot scan someone else's
	// infrastructure without their agreement.
	ActiveClasses []string `yaml:"active_classes,omitempty"`

	// RespectRobots marks a host quarantined for the rest of the run after
	// repeated transport failures, so a flapping production box is not hammered.
	FailureThreshold int      `yaml:"failure_threshold,omitempty"`
	Cooldown         Duration `yaml:"cooldown,omitempty"`
}

// Probes configures what an active probe does.
type Probes struct {
	Ports           []int  `yaml:"ports"`
	TLSSNIPorts     []int  `yaml:"tls_sni_ports,omitempty"`
	UserAgent       string `yaml:"user_agent,omitempty"`
	FollowRedirects bool   `yaml:"follow_redirects"`
	MaxRedirects    int    `yaml:"max_redirects,omitempty"`
	MaxBodyBytes    int64  `yaml:"max_body_bytes,omitempty"`

	// HTTPPaths are safe GET requests appended to each web root. They are all
	// read-only; anything that could change state is excluded by validation.
	HTTPPaths []string `yaml:"http_paths,omitempty"`
	// PanelPaths are probed to identify a login surface (a panel behind auth
	// is still a finding: it is an unmanaged entry point).
	PanelPaths []string `yaml:"panel_paths,omitempty"`
	// MaxPathsPerService bounds the path probes for one service.
	MaxPathsPerService int `yaml:"max_paths_per_service,omitempty"`
}

// Attribution configures the ownership engine.
type Attribution struct {
	// ScopeThreshold is the minimum score at which an asset is treated as in
	// scope for reporting. Below it the asset stays in the "candidate" list.
	ScopeThreshold float64 `yaml:"scope_threshold"`
	// ProbableThreshold is the score for a "probable" verdict.
	ProbableThreshold float64 `yaml:"probable_threshold"`
	// ActiveThreshold is the minimum score required before active probing.
	ActiveThreshold float64 `yaml:"active_threshold"`
	// WildcardPenalty is applied when a name only exists due to a catch-all.
	WildcardPenalty float64 `yaml:"wildcard_penalty"`
}

// Risk configures scoring.
type Risk struct {
	BandThresholds map[string]float64 `yaml:"band_thresholds,omitempty"`
	// DevPatterns are hostname patterns that mark ephemeral or test
	// environments, which are weighted up because they are usually unowned.
	DevPatterns []string `yaml:"dev_patterns,omitempty"`
	// ExposureMultiplier scales all network-exposure findings.
	ExposureMultiplier float64 `yaml:"exposure_multiplier,omitempty"`
	// PartnerMultiplier adjusts risk for partner-hosted assets. The business
	// risk is real, but the org cannot fix it directly, so it is surfaced with
	// an escalation rather than at the very top of the engineer queue.
	PartnerMultiplier float64 `yaml:"partner_multiplier,omitempty"`
	// StaleAfter marks an asset whose observable state has not changed for
	// this long as stale, which adds a risk factor. Stale assets are usually
	// forgotten ones, the primary target of this tool.
	StaleAfter Duration `yaml:"stale_after,omitempty"`
}

// Owners configures routing to responsible teams.
type Owners struct {
	DefaultTeam    string      `yaml:"default_team"`
	DefaultContact string      `yaml:"default_contact,omitempty"`
	Rules          []OwnerRule `yaml:"rules,omitempty"`
}

// OwnerRule maps matching assets to a team. The first matching rule wins.
type OwnerRule struct {
	Name    string `yaml:"name,omitempty"`
	Team    string `yaml:"team"`
	Contact string `yaml:"contact,omitempty"`
	// Match fields are ANDed. Empty fields are ignored.
	HostSuffix  string `yaml:"host_suffix,omitempty"`
	HostPattern string `yaml:"host_pattern,omitempty"`
	Class       string `yaml:"class,omitempty"`
	Tag         string `yaml:"tag,omitempty"`
	Port        int    `yaml:"port,omitempty"`
	Tech        string `yaml:"tech,omitempty"`
	Escalation  string `yaml:"escalation,omitempty"`

	pattern *regexp.Regexp `yaml:"-"`
}

// Outputs configures report generation.
type Outputs struct {
	Dir         string   `yaml:"dir"`
	Formats     []string `yaml:"formats,omitempty"`
	SplitByTeam bool     `yaml:"split_by_team"`
	// TopN limits rows in the human-facing summary; machine formats always
	// contain everything.
	TopN int `yaml:"top_n,omitempty"`
}

// Store configures persistence.
type Store struct {
	Path string `yaml:"path"`
}

// Default returns a profile with safe defaults applied. The organisation is
// intentionally empty and must be filled in.
func Default() *Config {
	return &Config{
		Organisation: Organisation{
			Handle: "org",
		},
		Discovery: Discovery{
			CT: CT{
				Enabled:        true,
				Providers:      []string{"crtsh"},
				PollInterval:   Duration(6 * time.Hour),
				MaxEntries:     5000,
				Timeout:        Duration(30 * time.Second),
				IncludeExpired: true,
			},
			DNS: DNS{
				Enabled:         true,
				Resolvers:       []string{"1.1.1.1:53", "8.8.8.8:53"},
				QPS:             15,
				Timeout:         Duration(3 * time.Second),
				MaxLabelsPerRun: 2000,
			},
		},
		Safety: Safety{
			MaxGlobalRPS:    3,
			MaxPerHostRPS:   0.2,
			MaxConcurrent:   16,
			HostConcurrency: 1,
			RequestTimeout:  Duration(6 * time.Second),
			DialTimeout:     Duration(4 * time.Second),
			// The safe default is to probe only overnight. This matters
			// because a hand-written profile that sets only rate limits would
			// otherwise inherit "no window", i.e. permission to scan
			// production at any hour. An operator who genuinely wants
			// anytime scanning sets scan_window: "" explicitly, which is an
			// obvious, reviewable act.
			ScanWindow:       "01:00-05:00",
			Timezone:         "UTC",
			MaxProbesPerRun:  20000,
			MaxHostsPerRun:   5000,
			PauseEvery:       200,
			PauseDuration:    Duration(500 * time.Millisecond),
			ActiveClasses:    []string{"company", "third_party"},
			FailureThreshold: 4,
			Cooldown:         Duration(10 * time.Minute),
		},
		Probes: Probes{
			Ports:        []int{443, 80, 22, 8080, 8443, 3389, 3306, 6379, 9200, 27017, 2375, 9000, 5000},
			TLSSNIPorts:  []int{443, 8443, 9443},
			UserAgent:    "asm-inventory/1.0 (+security-team; polite single-request probe)",
			MaxRedirects: 2,
			MaxBodyBytes: 128 << 10,
			HTTPPaths: []string{
				"/", "/.git/config", "/.env", "/server-status", "/actuator/env",
				"/swagger-ui.html", "/v2/api-docs", "/.well-known/security.txt",
			},
			PanelPaths:         []string{"/admin/", "/login", "/phpmyadmin/", "/manager/html", "/grafana/"},
			MaxPathsPerService: 8,
		},
		Attribution: Attribution{
			ScopeThreshold:    2.5,
			ProbableThreshold: 1.5,
			ActiveThreshold:   2.0,
			WildcardPenalty:   4.0,
		},
		Risk: Risk{
			// Thresholds are calibrated against the risk engine's soft
			// saturation curve (see internal/risk): a single catastrophic
			// finding (exposed secrets, unauthenticated Docker API) lands in
			// "critical"; an exposed database alone lands in "high"; remote
			// management and plaintext auth in "medium"; certificate and
			// hygiene issues in "low".
			BandThresholds: map[string]float64{
				"critical": 70, "high": 55, "medium": 30, "low": 10,
			},
			DevPatterns: []string{
				`(?i)(^|[.\-_])(dev|test|staging|stage|uat|qa|demo|sandbox|temp|tmp|old|legacy|backup|bak|pre|beta|canary)([.\-_]|$)`,
			},
			ExposureMultiplier: 1.0,
			PartnerMultiplier:  0.8,
			StaleAfter:         Duration(180 * 24 * time.Hour),
		},
		Owners: Owners{
			DefaultTeam: "unowned",
		},
		Outputs: Outputs{
			Dir:         "out",
			Formats:     []string{"markdown", "json", "csv", "html"},
			SplitByTeam: true,
			TopN:        50,
		},
		Store: Store{Path: "asm.db"},
	}
}

// Load reads a YAML profile, applies defaults, and compiles it.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	return Parse(raw)
}

// Parse decodes YAML over the defaults and compiles.
func Parse(raw []byte) (*Config, error) {
	cfg := Default()
	// Decode twice conceptually: the defaults are the base, and the document
	// overlays them. yaml.v3 fills pointer-free structs field by field, which
	// gives us merge semantics only at the top level, so sections present in
	// the document replace the corresponding default section wholesale. That is
	// predictable; validation catches the cases where it matters.
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	cfg.applySectionDefaults()
	if err := cfg.Compile(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applySectionDefaults() {
	d := Default()
	if len(c.Discovery.CT.Providers) == 0 && c.Discovery.CT.Enabled {
		c.Discovery.CT.Providers = d.Discovery.CT.Providers
	}
	if c.Discovery.CT.MaxEntries == 0 {
		c.Discovery.CT.MaxEntries = d.Discovery.CT.MaxEntries
	}
	if c.Discovery.CT.Timeout == 0 {
		c.Discovery.CT.Timeout = d.Discovery.CT.Timeout
	}
	if c.Discovery.DNS.QPS == 0 {
		c.Discovery.DNS.QPS = d.Discovery.DNS.QPS
	}
	if c.Discovery.DNS.Timeout == 0 {
		c.Discovery.DNS.Timeout = d.Discovery.DNS.Timeout
	}
	if len(c.Discovery.DNS.Resolvers) == 0 {
		c.Discovery.DNS.Resolvers = d.Discovery.DNS.Resolvers
	}
	if c.Safety.MaxGlobalRPS == 0 {
		c.Safety.MaxGlobalRPS = d.Safety.MaxGlobalRPS
	}
	if c.Safety.MaxPerHostRPS == 0 {
		c.Safety.MaxPerHostRPS = d.Safety.MaxPerHostRPS
	}
	if c.Safety.MaxConcurrent == 0 {
		c.Safety.MaxConcurrent = d.Safety.MaxConcurrent
	}
	if c.Safety.HostConcurrency == 0 {
		c.Safety.HostConcurrency = d.Safety.HostConcurrency
	}
	if c.Safety.RequestTimeout == 0 {
		c.Safety.RequestTimeout = d.Safety.RequestTimeout
	}
	if c.Safety.DialTimeout == 0 {
		c.Safety.DialTimeout = d.Safety.DialTimeout
	}
	if c.Safety.MaxProbesPerRun == 0 {
		c.Safety.MaxProbesPerRun = d.Safety.MaxProbesPerRun
	}
	if c.Safety.MaxHostsPerRun == 0 {
		c.Safety.MaxHostsPerRun = d.Safety.MaxHostsPerRun
	}
	if c.Safety.FailureThreshold == 0 {
		c.Safety.FailureThreshold = d.Safety.FailureThreshold
	}
	if c.Safety.Cooldown == 0 {
		c.Safety.Cooldown = d.Safety.Cooldown
	}
	if len(c.Safety.ActiveClasses) == 0 {
		c.Safety.ActiveClasses = d.Safety.ActiveClasses
	}
	if len(c.Probes.Ports) == 0 {
		c.Probes.Ports = d.Probes.Ports
	}
	if len(c.Probes.TLSSNIPorts) == 0 {
		c.Probes.TLSSNIPorts = d.Probes.TLSSNIPorts
	}
	if c.Probes.UserAgent == "" {
		c.Probes.UserAgent = d.Probes.UserAgent
	}
	if c.Probes.MaxRedirects == 0 {
		c.Probes.MaxRedirects = d.Probes.MaxRedirects
	}
	if c.Probes.MaxBodyBytes == 0 {
		c.Probes.MaxBodyBytes = d.Probes.MaxBodyBytes
	}
	if len(c.Probes.HTTPPaths) == 0 {
		c.Probes.HTTPPaths = d.Probes.HTTPPaths
	}
	if len(c.Probes.PanelPaths) == 0 {
		c.Probes.PanelPaths = d.Probes.PanelPaths
	}
	if c.Probes.MaxPathsPerService == 0 {
		c.Probes.MaxPathsPerService = d.Probes.MaxPathsPerService
	}
	if c.Attribution.ScopeThreshold == 0 {
		c.Attribution.ScopeThreshold = d.Attribution.ScopeThreshold
	}
	if c.Attribution.ProbableThreshold == 0 {
		c.Attribution.ProbableThreshold = d.Attribution.ProbableThreshold
	}
	if c.Attribution.ActiveThreshold == 0 {
		c.Attribution.ActiveThreshold = d.Attribution.ActiveThreshold
	}
	if c.Attribution.WildcardPenalty == 0 {
		c.Attribution.WildcardPenalty = d.Attribution.WildcardPenalty
	}
	if len(c.Risk.BandThresholds) == 0 {
		c.Risk.BandThresholds = d.Risk.BandThresholds
	}
	if len(c.Risk.DevPatterns) == 0 {
		c.Risk.DevPatterns = d.Risk.DevPatterns
	}
	if c.Risk.ExposureMultiplier == 0 {
		c.Risk.ExposureMultiplier = d.Risk.ExposureMultiplier
	}
	if c.Risk.PartnerMultiplier == 0 {
		c.Risk.PartnerMultiplier = d.Risk.PartnerMultiplier
	}
	if c.Risk.StaleAfter == 0 {
		c.Risk.StaleAfter = d.Risk.StaleAfter
	}
	if c.Outputs.Dir == "" {
		c.Outputs.Dir = d.Outputs.Dir
	}
	if len(c.Outputs.Formats) == 0 {
		c.Outputs.Formats = d.Outputs.Formats
	}
	if c.Outputs.TopN == 0 {
		c.Outputs.TopN = d.Outputs.TopN
	}
	if c.Store.Path == "" {
		c.Store.Path = d.Store.Path
	}
	if c.Organisation.Handle == "" {
		c.Organisation.Handle = "org"
	}
}

// Compile validates the profile and builds derived state.
func (c *Config) Compile() error {
	var errs []error

	if strings.TrimSpace(c.Organisation.Name) == "" {
		errs = append(errs, errors.New("organisation.name is required"))
	}
	if len(c.Organisation.Domains) == 0 {
		errs = append(errs, errors.New("organisation.domains is required"))
	}

	scope, err := NewScope(c.Organisation.Domains, c.Organisation.IPRanges, c.Safety.ExcludeHosts, c.Safety.ExcludeIPs)
	if err != nil {
		errs = append(errs, err)
	} else {
		c.scope = scope
	}

	if c.Safety.MaxGlobalRPS <= 0 {
		errs = append(errs, errors.New("safety.max_global_rps must be > 0"))
	}
	if c.Safety.MaxPerHostRPS <= 0 {
		errs = append(errs, errors.New("safety.max_per_host_rps must be > 0"))
	}
	if c.Safety.MaxGlobalRPS > 50 {
		errs = append(errs, fmt.Errorf("safety.max_global_rps=%v is above the hard ceiling of 50; lower it or split the run", c.Safety.MaxGlobalRPS))
	}
	if c.Safety.MaxPerHostRPS > 1 {
		errs = append(errs, fmt.Errorf("safety.max_per_host_rps=%v exceeds 1 request/second/host, which can affect production; lower it", c.Safety.MaxPerHostRPS))
	}
	if c.Safety.MaxConcurrent <= 0 {
		errs = append(errs, errors.New("safety.max_concurrent must be > 0"))
	}
	if c.Safety.HostConcurrency <= 0 {
		c.Safety.HostConcurrency = 1
	}
	if c.Safety.ScanWindow != "" {
		if err := validateWindow(c.Safety.ScanWindow); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Safety.Timezone != "" {
		if _, err := time.LoadLocation(c.Safety.Timezone); err != nil {
			errs = append(errs, fmt.Errorf("safety.timezone %q: %w", c.Safety.Timezone, err))
		}
	}
	for _, cls := range c.Safety.ActiveClasses {
		switch cls {
		case "company", "third_party", "partner", "parked", "wildcard", "unknown":
		default:
			errs = append(errs, fmt.Errorf("safety.active_classes: unknown class %q", cls))
		}
	}
	if len(c.Safety.ExcludeHosts) == 0 {
		// An empty exclusion list is a common misconfiguration, not an error.
	}
	if !c.Safety.AllowPrivate {
		// nothing to validate; private targets are filtered at probe time
	}

	for _, p := range c.Probes.Ports {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("probes.ports: %d is out of range", p))
		}
	}
	for _, p := range c.Probes.TLSSNIPorts {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("probes.tls_sni_ports: %d is out of range", p))
		}
	}
	for _, p := range append(append([]string{}, c.Probes.HTTPPaths...), c.Probes.PanelPaths...) {
		if unsafePath(p) {
			errs = append(errs, fmt.Errorf("probes: path %q is not a safe read-only probe (no mutating verbs, no query strings that change state)", p))
		}
	}

	for i := range c.Owners.Rules {
		r := &c.Owners.Rules[i]
		if r.Team == "" {
			errs = append(errs, fmt.Errorf("owners.rules[%d]: team is required", i))
		}
		if r.HostPattern != "" {
			re, err := regexp.Compile(r.HostPattern)
			if err != nil {
				errs = append(errs, fmt.Errorf("owners.rules[%d].host_pattern: %w", i, err))
			} else {
				r.pattern = re
			}
		}
		switch r.Class {
		case "", "company", "third_party", "partner", "parked", "wildcard", "unknown":
		default:
			errs = append(errs, fmt.Errorf("owners.rules[%d].class: unknown class %q", i, r.Class))
		}
	}
	if c.Owners.DefaultTeam == "" {
		c.Owners.DefaultTeam = "unowned"
	}

	for _, pat := range c.Risk.DevPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			errs = append(errs, fmt.Errorf("risk.dev_patterns: %w", err))
		}
	}

	switch strings.ToLower(filepath.Ext(c.Store.Path)) {
	case ".db", ".sqlite", ".sqlite3", "":
	default:
		errs = append(errs, fmt.Errorf("store.path %q must end in .db, .sqlite or .sqlite3", c.Store.Path))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid profile:\n  %w", errors.Join(errs...))
	}
	return nil
}

// Scope returns the compiled scope matcher.
func (c *Config) Scope() *Scope { return c.scope }

// Location returns the configured timezone, or UTC.
func (c *Config) Location() *time.Location {
	if c.Safety.Timezone == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(c.Safety.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// InWindow reports whether t is inside the configured scan window. It returns
// (true, ...) when no window is configured. Windows may cross midnight.
func (c *Config) InWindow(t time.Time) bool {
	if c.Safety.ScanWindow == "" {
		return true
	}
	loc := c.Location()
	local := t.In(loc)
	start, end, ok := parseWindow(c.Safety.ScanWindow)
	if !ok {
		return true
	}
	mins := local.Hour()*60 + local.Minute()
	if start <= end {
		return mins >= start && mins < end
	}
	// crosses midnight
	return mins >= start || mins < end
}

// NextWindowStart returns the next time the scan window opens after t.
func (c *Config) NextWindowStart(t time.Time) time.Time {
	if c.Safety.ScanWindow == "" {
		return t
	}
	start, _, ok := parseWindow(c.Safety.ScanWindow)
	if !ok {
		return t
	}
	loc := c.Location()
	local := t.In(loc)
	next := time.Date(local.Year(), local.Month(), local.Day(), start/60, start%60, 0, 0, loc)
	if !next.After(local) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

func validateWindow(w string) error {
	_, _, ok := parseWindow(w)
	if !ok {
		return fmt.Errorf("safety.scan_window %q must be HH:MM-HH:MM", w)
	}
	return nil
}

func parseWindow(w string) (startMin, endMin int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(w), "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	s, ok1 := parseHHMM(parts[0])
	e, ok2 := parseHHMM(parts[1])
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	return s, e, true
}

func parseHHMM(s string) (int, bool) {
	s = strings.TrimSpace(s)
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// unsafePath rejects probe paths that could change server state.
func unsafePath(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return true
	}
	low := strings.ToLower(p)
	if strings.ContainsAny(low, "?#") {
		return true
	}
	for _, bad := range []string{"/delete", "/remove", "/drop", "/shutdown", "/reboot", "/install", "/upload", "/exec", "/reset", "/logout", "/unlock"} {
		if strings.Contains(low, bad) {
			return true
		}
	}
	return false
}

// OwnerRule returns the first rule that matches the asset, or nil.
func (c *Config) OwnerRule(name string, class string, tags []string, ports []int, tech []string) *OwnerRule {
	lname := strings.ToLower(name)
	for i := range c.Owners.Rules {
		r := &c.Owners.Rules[i]
		if r.HostSuffix != "" && !strings.HasSuffix(lname, strings.ToLower(strings.TrimPrefix(r.HostSuffix, "."))) {
			continue
		}
		if r.HostSuffix != "" {
			// ensure the suffix is on a label boundary
			suf := strings.ToLower(strings.TrimPrefix(r.HostSuffix, "."))
			if lname != suf && !strings.HasSuffix(lname, "."+suf) {
				continue
			}
		}
		if r.HostPattern != "" && (r.pattern == nil || !r.pattern.MatchString(name)) {
			continue
		}
		if r.Class != "" && r.Class != class {
			continue
		}
		if r.Tag != "" && !containsFold(tags, r.Tag) {
			continue
		}
		if r.Port != 0 && !containsInt(ports, r.Port) {
			continue
		}
		if r.Tech != "" && !containsFold(tech, r.Tech) {
			continue
		}
		return r
	}
	return nil
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func containsInt(list []int, want int) bool {
	for _, n := range list {
		if n == want {
			return true
		}
	}
	return false
}

// Scope is the compiled in-scope matcher.
type Scope struct {
	Apexes       map[string]bool
	registrable  map[string]bool
	ipNets       []*net.IPNet
	excludeNets  []*net.IPNet
	excludeGlobs []string
}

// NewScope compiles domains and ranges into matchers.
func NewScope(domains, ipRanges, excludeHosts, excludeIPs []string) (*Scope, error) {
	s := &Scope{
		Apexes:      map[string]bool{},
		registrable: map[string]bool{},
	}
	for _, d := range domains {
		d = normalizeDomain(d)
		if d == "" {
			continue
		}
		s.Apexes[d] = true
		reg, err := publicsuffix.EffectiveTLDPlusOne(d)
		if err != nil {
			return nil, fmt.Errorf("organisation.domains: %q is not a registrable domain: %w", d, err)
		}
		s.registrable[reg] = true
	}
	for _, r := range ipRanges {
		ip, n, err := net.ParseCIDR(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("organisation.ip_ranges: %q: %w", r, err)
		}
		n.IP = ip
		s.ipNets = append(s.ipNets, n)
	}
	for _, r := range excludeIPs {
		ip, n, err := net.ParseCIDR(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("safety.exclude_ips: %q: %w", r, err)
		}
		n.IP = ip
		s.excludeNets = append(s.excludeNets, n)
	}
	for _, g := range excludeHosts {
		g = strings.ToLower(strings.TrimSpace(g))
		if g != "" {
			s.excludeGlobs = append(s.excludeGlobs, g)
		}
	}
	return s, nil
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, ".")
	return d
}

// InDomain reports whether name is the apex or beneath any configured apex.
func (s *Scope) InDomain(name string) bool {
	name = normalizeDomain(name)
	if name == "" {
		return false
	}
	for apex := range s.Apexes {
		if name == apex || strings.HasSuffix(name, "."+apex) {
			return true
		}
	}
	return false
}

// ApexFor returns the most specific configured apex containing name.
func (s *Scope) ApexFor(name string) string {
	name = normalizeDomain(name)
	best := ""
	for apex := range s.Apexes {
		if name == apex || strings.HasSuffix(name, "."+apex) {
			if len(apex) > len(best) {
				best = apex
			}
		}
	}
	return best
}

// Registrable returns the effective TLD+1 for name.
func (s *Scope) Registrable(name string) string {
	reg, err := publicsuffix.EffectiveTLDPlusOne(normalizeDomain(name))
	if err != nil {
		return ""
	}
	return reg
}

// InRegistrableDomain reports whether name shares a registrable domain with
// the organisation. This is broader than InDomain: it catches names under a
// registered brand domain that is not itself a configured apex.
func (s *Scope) InRegistrableDomain(name string) bool {
	reg := s.Registrable(name)
	return reg != "" && s.registrable[reg]
}

// IPInScope reports whether ip is in an owned range.
func (s *Scope) IPInScope(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range s.ipNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ExcludedHost reports whether name matches an exclusion glob.
func (s *Scope) ExcludedHost(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, g := range s.excludeGlobs {
		if globMatch(g, name) {
			return true
		}
	}
	return false
}

// ExcludedIP reports whether ip is in an exclusion range.
func (s *Scope) ExcludedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	for _, n := range s.excludeNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// globMatch implements '*' and '?' wildcards over the whole string.
func globMatch(pattern, s string) bool {
	// Iterative backtracking avoids regexp escaping surprises for hostnames.
	var pi, si, star, match int
	star = -1
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == s[si] || pattern[pi] == '?'):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			match = si
			pi++
		case star != -1:
			pi = star + 1
			match++
			si = match
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
