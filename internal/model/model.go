// Package model defines the domain types shared across the attack-surface
// pipeline: hosts discovered from passive and active sources, the services
// observed on them, the evidence used to attribute them to the organisation,
// and the risk assessment attached to each asset.
//
// The types here are deliberately dependency-free so that every downstream
// package (attribution, risk, reporting, the store) can be reasoned about and
// tested in isolation.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Discovery records how an asset entered the inventory. The provenance matters
// for attribution: a host found in a CT log for the company's own certificate
// is stronger evidence than a host found by brute-force enumeration of a
// wildcard-enabled zone.
type Discovery string

const (
	DiscoverySeed   Discovery = "seed"
	DiscoveryCT     Discovery = "ct"
	DiscoveryDNS    Discovery = "dns"
	DiscoveryCNAME  Discovery = "cname"
	DiscoveryManual Discovery = "manual"
)

// Verdict is the attribution outcome for an asset: how sure are we that this
// asset is operated by, or on behalf of, the organisation?
type Verdict string

const (
	// VerdictConfirmed means at least one strong ownership signal (certificate
	// issued to the org, DNS verification record, address in an owned range)
	// was observed and nothing contradicts it.
	VerdictConfirmed Verdict = "confirmed"
	// VerdictProbable means the weight of evidence points to the org but no
	// single strong signal was seen.
	VerdictProbable Verdict = "probable"
	// VerdictPossible means weak signals only; treat as candidate, not scope.
	VerdictPossible Verdict = "possible"
	// VerdictUnverified means it was discovered but nothing ties it to us.
	VerdictUnverified Verdict = "unverified"
	// VerdictRejected means positive evidence of non-ownership (parked page,
	// wildcard catch-all, NXDOMAIN, unrelated shared certificate).
	VerdictRejected Verdict = "rejected"
)

// Class describes the hosting situation, which drives how the asset should be
// handled even when ownership is clear. A partner-managed asset is owned but
// cannot be remediated by us directly.
type Class string

const (
	ClassCompany    Class = "company"     // company-owned hosting
	ClassThirdParty Class = "third_party" // company-owned, hosted on a cloud/CDN
	ClassPartner    Class = "partner"     // operated by a partner or vendor
	ClassParked     Class = "parked"      // domain squatter / parking page
	ClassWildcard   Class = "wildcard"    // wildcard DNS catch-all artefact
	ClassUnknown    Class = "unknown"
)

// Band is the coarse risk bucket. Bands are ordered; Critical sorts first.
type Band string

const (
	BandCritical Band = "critical"
	BandHigh     Band = "high"
	BandMedium   Band = "medium"
	BandLow      Band = "low"
	BandInfo     Band = "info"
)

// Rank returns a sort key for the band, lower is more severe.
func (b Band) Rank() int {
	switch b {
	case BandCritical:
		return 0
	case BandHigh:
		return 1
	case BandMedium:
		return 2
	case BandLow:
		return 3
	default:
		return 4
	}
}

// Severity is used for changes and findings.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 0
	case SevHigh:
		return 1
	case SevMedium:
		return 2
	case SevLow:
		return 3
	default:
		return 4
	}
}

// Host is one name in the inventory plus its DNS observations.
type Host struct {
	Name       string      `json:"name"`
	Apex       string      `json:"apex,omitempty"`
	Discovery  []Discovery `json:"discovery,omitempty"`
	IPs        []string    `json:"ips,omitempty"`
	AAAAs      []string    `json:"aaaas,omitempty"`
	CNAMEs     []string    `json:"cnames,omitempty"`
	MX         []string    `json:"mx,omitempty"`
	NS         []string    `json:"ns,omitempty"`
	TXT        []string    `json:"txt,omitempty"`
	PTR        []string    `json:"ptr,omitempty"`
	Resolvable bool        `json:"resolvable"`
	NXDomain   bool        `json:"nxdomain,omitempty"`
	// PortHints are port numbers supplied by a passive source (a passive-DNS
	// feed, or a DNS fixture in a demo). When non-empty they replace the
	// default port list for this host, which keeps active probing minimal.
	PortHints []int `json:"port_hints,omitempty"`
	// WildcardCatchall is true when the name only resolves because the parent
	// zone answers every name with the same address set. Such a host must not
	// be treated as an independent asset.
	WildcardCatchall bool      `json:"wildcard_catchall,omitempty"`
	WildcardFrom     string    `json:"wildcard_from,omitempty"` // the apex zone with the wildcard
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

// Addresses returns the de-duplicated union of A and AAAA records.
func (h *Host) Addresses() []string {
	seen := map[string]bool{}
	var out []string
	for _, ip := range append(append([]string{}, h.IPs...), h.AAAAs...) {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// AddDiscovery records provenance without duplicating it.
func (h *Host) AddDiscovery(d Discovery) {
	for _, x := range h.Discovery {
		if x == d {
			return
		}
	}
	h.Discovery = append(h.Discovery, d)
}

// TLS holds the certificate observations from a single probe.
type TLS struct {
	SubjectCN         string    `json:"subject_cn,omitempty"`
	SANs              []string  `json:"sans,omitempty"`
	IssuerCN          string    `json:"issuer_cn,omitempty"`
	IssuerOrg         []string  `json:"issuer_org,omitempty"`
	SubjectOrg        []string  `json:"subject_org,omitempty"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	Serial            string    `json:"serial,omitempty"`
	Version           int       `json:"version,omitempty"`
	SelfSigned        bool      `json:"self_signed,omitempty"`
	HostnameValid     bool      `json:"hostname_valid,omitempty"`
	Weak              bool      `json:"weak,omitempty"` // RSA < 2048 or SHA-1 signature
	// SharedCert is set when one certificate covers many unrelated names, the
	// hallmark of a shared hosting/CDN certificate. It is weak evidence of
	// ownership and must not be used to claim an asset.
	SharedCert bool `json:"shared_cert,omitempty"`
}

// ExpiresIn returns the remaining lifetime; negative if already expired.
func (t *TLS) ExpiresIn(now time.Time) time.Duration {
	if t == nil || t.NotAfter.IsZero() {
		return 0
	}
	return t.NotAfter.Sub(now)
}

// ExposedPath records a sensitive path that answered.
type ExposedPath struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Note   string `json:"note,omitempty"`
}

// HTTP holds the web fingerprint from a probe.
type HTTP struct {
	URL       string            `json:"url,omitempty"`
	FinalURL  string            `json:"final_url,omitempty"`
	Status    int               `json:"status,omitempty"`
	Title     string            `json:"title,omitempty"`
	Server    string            `json:"server,omitempty"`
	PoweredBy string            `json:"powered_by,omitempty"`
	Tech      []string          `json:"tech,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	// Exposed holds sensitive files that are genuinely served (source control
	// metadata, environment files, diagnostics). Management panels are tracked
	// separately below so they are not double-counted.
	Exposed []ExposedPath `json:"exposed,omitempty"`
	// OpenPanels lists management paths that answered 2xx without
	// authentication: a direct entry point.
	OpenPanels []string `json:"open_panels,omitempty"`
	// ProtectedPanels lists management paths that exist but require auth or
	// redirect to a login. Inventory, not exposure.
	ProtectedPanels []string `json:"protected_panels,omitempty"`
	Panel           string   `json:"panel,omitempty"` // e.g. "phpmyadmin", "grafana"
	AuthRealm       string   `json:"auth_realm,omitempty"`
	BodyHash        string   `json:"body_hash,omitempty"`
	HTTPSRedirect   bool     `json:"https_redirect,omitempty"`
	PlaintextAuth   bool     `json:"plaintext_auth,omitempty"`
}

// Service is one reachable port on one host.
type Service struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // tcp
	TLS      *TLS   `json:"tls,omitempty"`
	HTTP     *HTTP  `json:"http,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Addr returns "ip:port".
func (s Service) Addr() string { return net.JoinHostPort(s.IP, fmt.Sprintf("%d", s.Port)) }

// Key is a stable identifier for the service within its host.
func (s Service) Key() string {
	return fmt.Sprintf("%s:%d/%s", strings.ToLower(s.Host), s.Port, strings.ToLower(s.Protocol))
}

// Finding is a discrete, actionable issue on an asset.
type Finding struct {
	Key         string    `json:"key"`
	Title       string    `json:"title"`
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"` // exposure, crypto, component, panel, data
	AssetKey    string    `json:"asset_key"`
	AssetName   string    `json:"asset_name"`
	Service     string    `json:"service,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	CVE         []string  `json:"cve,omitempty"`
	DetectedAt  time.Time `json:"detected_at"`
}

// Evidence is one signal in the attribution model. Weight is signed: positive
// signals argue for ownership, negative signals argue against.
type Evidence struct {
	Signal  string  `json:"signal"`
	Weight  float64 `json:"weight"`
	Detail  string  `json:"detail,omitempty"`
	Service string  `json:"service,omitempty"`
}

// Attribution is the explainable conclusion of the ownership engine.
type Attribution struct {
	Score      float64    `json:"score"`
	Confidence float64    `json:"confidence"` // 0..1, normalised
	Verdict    Verdict    `json:"verdict"`
	Class      Class      `json:"class"`
	Evidence   []Evidence `json:"evidence,omitempty"`
	// Rationale is a one-line human summary suitable for a ticket.
	Rationale string `json:"rationale,omitempty"`
}

// Factor is one contribution to the risk score, retained so a report can
// explain exactly why an asset ranks where it does.
type Factor struct {
	Key     string  `json:"key"`
	Title   string  `json:"title"`
	Weight  float64 `json:"weight"`
	Detail  string  `json:"detail,omitempty"`
	Finding string  `json:"finding,omitempty"`
}

// Assessment is the ranked risk view of an asset.
type Assessment struct {
	Base       float64  `json:"base"`
	Multiplier float64  `json:"multiplier"`
	Score      float64  `json:"score"`
	Band       Band     `json:"band"`
	Factors    []Factor `json:"factors,omitempty"`
	Summary    string   `json:"summary,omitempty"`
}

// Owner is the team responsible for an asset.
type Owner struct {
	Team    string `json:"team,omitempty"`
	Contact string `json:"contact,omitempty"`
	Source  string `json:"source,omitempty"` // rule:..., default, unowned
	Rule    string `json:"rule,omitempty"`
	// Escalation notes why a partner-managed asset cannot be fixed directly.
	Escalation string `json:"escalation,omitempty"`
}

// Snapshot is the persisted state for one asset. It is the unit that the store
// versions and the diff engine compares between runs.
type Snapshot struct {
	Key         string      `json:"key"`
	Host        Host        `json:"host"`
	Services    []Service   `json:"services,omitempty"`
	Findings    []Finding   `json:"findings,omitempty"`
	Attribution Attribution `json:"attribution"`
	Assessment  Assessment  `json:"assessment"`
	Owner       Owner       `json:"owner"`

	// StateFingerprint covers only observable facts (DNS answers, open
	// services, certificate identity, HTTP fingerprint). It is what drives
	// "asset changed" detection, independent of risk or owner churn.
	StateFingerprint string `json:"state_fingerprint"`

	RunID       string    `json:"run_id,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	LastChanged time.Time `json:"last_changed"`
}

// Name returns the asset's display name.
func (s *Snapshot) Name() string { return s.Host.Name }

// ServiceAt returns the service on the given port, or nil.
func (s *Snapshot) ServiceAt(port int) *Service {
	for i := range s.Services {
		if s.Services[i].Port == port {
			return &s.Services[i]
		}
	}
	return nil
}

// ChangeKind enumerates the typed differences the diff engine can emit.
type ChangeKind string

const (
	ChangeNewAsset        ChangeKind = "new_asset"
	ChangeGoneAsset       ChangeKind = "gone_asset"
	ChangeNewPort         ChangeKind = "new_port"
	ChangePortClosed      ChangeKind = "port_closed"
	ChangeCertChanged     ChangeKind = "cert_changed"
	ChangeCertExpiring    ChangeKind = "cert_expiring"
	ChangeContentChanged  ChangeKind = "content_changed"
	ChangeIPChanged       ChangeKind = "ip_changed"
	ChangeDNSChanged      ChangeKind = "dns_changed"
	ChangeOwnershipChange ChangeKind = "ownership_changed"
	ChangeRiskIncreased   ChangeKind = "risk_increased"
	ChangeRiskDecreased   ChangeKind = "risk_decreased"
	ChangeNewFinding      ChangeKind = "new_finding"
	ChangeFindingFixed    ChangeKind = "finding_fixed"
)

// Change is one entry in the daily change feed.
type Change struct {
	RunID     string     `json:"run_id"`
	At        time.Time  `json:"at"`
	Kind      ChangeKind `json:"kind"`
	AssetKey  string     `json:"asset_key"`
	AssetName string     `json:"asset_name"`
	Severity  Severity   `json:"severity"`
	Summary   string     `json:"summary"`
	Detail    string     `json:"detail,omitempty"`
	Team      string     `json:"team,omitempty"`
	// Previous and Current hold the relevant values for before/after display.
	Previous string `json:"previous,omitempty"`
	Current  string `json:"current,omitempty"`
}

// RunStats summarises one pipeline execution.
type RunStats struct {
	AssetsSeen     int            `json:"assets_seen"`
	AssetsNew      int            `json:"assets_new"`
	AssetsGone     int            `json:"assets_gone"`
	AssetsScoped   int            `json:"assets_scoped"`
	ServicesProbed int            `json:"services_probed"`
	ProbesIssued   int            `json:"probes_issued"`
	ProbesSkipped  int            `json:"probes_skipped"`
	Changes        int            `json:"changes"`
	Findings       int            `json:"findings"`
	ByBand         map[Band]int   `json:"by_band"`
	ByTeam         map[string]int `json:"by_team"`
	Errors         []string       `json:"errors,omitempty"`
	Duration       time.Duration  `json:"duration_ns,omitempty"`
}

// StableID derives a short, stable, human-referenceable identifier from a
// canonical key. The same asset gets the same id across runs and hosts.
func StableID(prefix, canonical string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(prefix)) + ":" + strings.ToLower(strings.TrimSpace(canonical))))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

// NormalizeName lowercases and strips a trailing dot, the canonical form used
// for keys and comparisons.
func NormalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
