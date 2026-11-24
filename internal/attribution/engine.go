// Package attribution decides whether a discovered host belongs to the
// organisation, and if so how it is hosted.
//
// This is the hardest part of an external attack-surface programme. A host can
// be reachable, useful and clearly "ours" in spirit while being operated by a
// partner, sitting behind a third-party CDN, or existing only because a
// wildcard record answers every name. naively treating every resolvable name
// as scope produces a queue nobody trusts; dropping everything that is not
// literally in the org's own IP space misses exactly the partner-hosted assets
// that cause incidents.
//
// The engine therefore scores independent evidence, keeps every contribution so
// a human can audit the conclusion, and returns a verdict plus a hosting class.
// Signals are intentionally coarse-grained and few; each one is a fact an
// analyst could verify by hand.
package attribution

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"asm/internal/config"
	"asm/internal/model"
)

// Signal identifiers.
const (
	SigInOrgDomain      = "in_org_domain"
	SigInRegistrable    = "in_registrable_domain"
	SigSeed             = "declared_seed"
	SigCTOrgCert        = "ct_org_certificate"
	SigCertSANOurs      = "cert_san_owned_name"
	SigCertOrgSubject   = "cert_org_subject"
	SigVerificationTXT  = "dns_verification_record"
	SigOwnedIP          = "owned_ip_range"
	SigCNAMESelf        = "cname_to_org"
	SigWildcardCatchall = "wildcard_catchall"
	SigParked           = "parked_page"
	SigSharedCert       = "shared_hosting_certificate"
	SigPublicSuffixOnly = "bare_public_suffix"
	SigNXDomain         = "nxdomain"
	SigPartnerCNAME     = "cname_to_partner"
	SigPartnerDomain    = "partner_domain"
)

// Signal weights. The scale is arbitrary but the ordering matters: a signal
// above ~1.5 alone can carry an asset into "probable"; anything at or below
// zero is evidence against ownership.
const (
	wInOrgDomain      = 3.0
	wInRegistrable    = 1.5
	wSeed             = 3.0
	wCTOrgCert        = 2.0
	wCertSANOurs      = 1.5
	wCertOrgSubject   = 2.5
	wVerificationTXT  = 2.5
	wOwnedIP          = 2.5
	wCNAMESelf        = 1.5
	wPartnerCNAME     = -0.5
	wPartnerDomain    = -0.5
	wWildcardCatchall = -4.0
	wParked           = -3.5
	wSharedCert       = -1.0
	wNXDomain         = -5.0
	wBarePublicSuffix = -5.0
)

// Engine evaluates hosts against the organisation profile.
type Engine struct {
	cfg   *config.Config
	scope *config.Scope
	// partnerSuffixes and saasSuffixes are lower-cased, dot-prefixed.
	partnerSuffixes []string
	saasSuffixes    []string
	orgNames        []string
	tokens          []string
}

// NewEngine builds an engine from the profile.
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{cfg: cfg, scope: cfg.Scope()}
	for _, d := range cfg.Organisation.PartnerDomains {
		e.partnerSuffixes = append(e.partnerSuffixes, "."+strings.ToLower(strings.Trim(d, ".* ")))
	}
	for _, d := range cfg.Organisation.SaaSShareSuffixes {
		e.saasSuffixes = append(e.saasSuffixes, "."+strings.ToLower(strings.Trim(d, ".* ")))
	}
	for _, n := range cfg.Organisation.OrgNames {
		e.orgNames = append(e.orgNames, strings.ToLower(strings.TrimSpace(n)))
	}
	for _, t := range cfg.Organisation.VerificationTokens {
		e.tokens = append(e.tokens, strings.ToLower(strings.TrimSpace(t)))
	}
	return e
}

// Input is everything the engine may look at for one asset.
type Input struct {
	Host     *model.Host
	Services []model.Service
	// CNAMEChain is the resolution chain for the host name (host first).
	CNAMEChain []string
	// CTNames are names observed in CT entries that also name this host; they
	// are used to detect that the host is a SAN of an org certificate.
	CTNames []string
	// CTIssuer is the most relevant certificate issuer seen in CT.
	CTIssuer string
}

// Evaluate returns an explainable attribution.
func (e *Engine) Evaluate(in Input) model.Attribution {
	var ev []model.Evidence
	add := func(sig string, w float64, detail string) {
		if w == 0 {
			return
		}
		ev = append(ev, model.Evidence{Signal: sig, Weight: w, Detail: detail})
	}

	h := in.Host
	name := model.NormalizeName(h.Name)

	// --- Ownership signals ------------------------------------------------

	if h.WildcardCatchall {
		add(SigWildcardCatchall, wWildcardCatchall, "name only resolves because of a catch-all record at "+h.WildcardFrom)
	}
	if h.NXDomain {
		add(SigNXDomain, wNXDomain, "name does not exist in DNS")
	}

	inOrgDomain := e.scope.InDomain(name)
	inRegistrable := e.scope.InRegistrableDomain(name)
	switch {
	case inOrgDomain:
		add(SigInOrgDomain, wInOrgDomain, "name is under a declared organisation apex")
	case inRegistrable:
		add(SigInRegistrable, wInRegistrable, "name shares a registrable domain with the organisation but is not a declared apex")
	}

	for _, d := range h.Discovery {
		if d == model.DiscoverySeed || d == model.DiscoveryManual {
			add(SigSeed, wSeed, "name was declared as a seed by the security team")
			break
		}
	}

	// Certificate evidence, evaluated once per distinct fingerprint. The same
	// certificate is routinely served on several ports; scoring it once per
	// port would let one certificate outvote everything else.
	seenCert := map[string]bool{}
	for _, svc := range in.Services {
		if svc.TLS == nil {
			continue
		}
		fp := svc.TLS.FingerprintSHA256
		if fp == "" {
			// No fingerprint (rare): fall back to the subject so two ports
			// serving what looks like the same cert are still deduplicated.
			fp = svc.TLS.SubjectCN + "|" + strings.Join(svc.TLS.SANs, ",")
		}
		if seenCert[fp] {
			continue
		}
		seenCert[fp] = true
		switch {
		case e.orgNameMatch(svc.TLS.SubjectOrg) || e.orgNameMatch([]string{svc.TLS.SubjectCN}):
			add(SigCertOrgSubject, wCertOrgSubject, "certificate subject names the organisation: "+firstNonEmpty(svc.TLS.SubjectCN, strings.Join(svc.TLS.SubjectOrg, ",")))
		case svc.TLS.SharedCert:
			add(SigSharedCert, wSharedCert, "certificate carries a large shared SAN set")
		default:
			for _, san := range svc.TLS.SANs {
				if e.scope.InDomain(san) {
					add(SigCertSANOurs, wCertSANOurs, "certificate includes an organisation name: "+san)
					break
				}
			}
		}
	}

	if len(in.CTNames) > 0 {
		// A CT entry covering this name that was issued for the org apex adds
		// modest evidence; a wildcard cert for the apex is the common case.
		for _, n := range in.CTNames {
			base := strings.TrimPrefix(strings.ToLower(n), "*.")
			if e.scope.InDomain(base) && base != name {
				add(SigCTOrgCert, wCTOrgCert, "certificate transparency entry also covers "+base)
				break
			}
		}
	}

	// DNS verification tokens are the strongest non-DNS proof: they are
	// written by whoever controls the org's cloud/identity provider.
	for _, txt := range h.TXT {
		low := strings.ToLower(txt)
		for _, tok := range e.tokens {
			if tok != "" && strings.Contains(low, tok) {
				add(SigVerificationTXT, wVerificationTXT, "DNS TXT record contains organisation verification token")
				break
			}
		}
	}

	// Address ownership.
	ownedIP := false
	for _, ip := range h.Addresses() {
		if e.scope.IPInScope(ip) {
			ownedIP = true
			add(SigOwnedIP, wOwnedIP, "resolves into an organisation-owned address range: "+ip)
			break
		}
	}
	_ = ownedIP
	if len(e.cfg.Organisation.ASNs) > 0 {
		// ASN evidence is advisory only; we cannot observe it from a hostname
		// probe, so it is recorded by the caller that enriched the IP.
	}

	// CNAME into our own space proves the origin is a name we control.
	rest := in.CNAMEChain
	if len(rest) > 0 {
		rest = rest[1:]
	}
	for _, target := range rest {
		if e.scope.InDomain(target) {
			add(SigCNAMESelf, wCNAMESelf, "CNAME chain resolves into organisation DNS: "+target)
			break
		}
	}

	// --- Disqualifying signals -------------------------------------------

	if e.isBarePublicSuffix(name) {
		add(SigPublicSuffixOnly, wBarePublicSuffix, "name is a bare public suffix, not a registrable domain")
	}

	if parked, why := e.looksParked(in.Services); parked {
		add(SigParked, wParked, why)
	}

	partner := false
	for _, target := range rest {
		if e.isPartner(target) {
			partner = true
			add(SigPartnerCNAME, wPartnerCNAME, "CNAME points at partner infrastructure: "+target)
			break
		}
	}
	if e.isPartner(name) {
		partner = true
		add(SigPartnerDomain, wPartnerDomain, "name is under a partner-operated domain")
	}

	score := 0.0
	for _, s := range ev {
		score += s.Weight
	}
	// Round to avoid floating noise in reports and comparisons.
	score = math.Round(score*100) / 100

	att := model.Attribution{Score: score, Evidence: ev}
	att.Verdict = e.verdict(score, ev)
	att.Class = e.classify(name, in.Services, h, partner, att.Verdict)
	att.Confidence = confidence(score, ev)
	att.Rationale = e.rationale(att, in)
	return att
}

func (e *Engine) verdict(score float64, ev []model.Evidence) model.Verdict {
	for _, s := range ev {
		if s.Weight <= wNXDomain {
			return model.VerdictRejected
		}
	}
	hasStrong := false
	for _, s := range ev {
		switch s.Signal {
		case SigOwnedIP, SigVerificationTXT, SigCertOrgSubject, SigSeed:
			if s.Weight > 0 {
				hasStrong = true
			}
		}
	}
	switch {
	case score >= e.cfg.Attribution.ScopeThreshold && hasStrong:
		return model.VerdictConfirmed
	case score >= e.cfg.Attribution.ScopeThreshold:
		// High score but no single strong signal: still in scope, but flag it
		// as probable so a reviewer knows to double-check the hosting story.
		return model.VerdictProbable
	case score >= e.cfg.Attribution.ProbableThreshold:
		return model.VerdictProbable
	case score > 0:
		return model.VerdictPossible
	default:
		return model.VerdictUnverified
	}
}

func (e *Engine) classify(name string, services []model.Service, h *model.Host, partner bool, verdict model.Verdict) model.Class {
	if h.WildcardCatchall {
		return model.ClassWildcard
	}
	// A parking page is conclusive regardless of the name: whoever publishes
	// "this domain is for sale" is not operating an asset for us, even on a
	// name inside our own registrable domain (that is precisely the expired-
	// domain case worth catching).
	if parked, _ := e.looksParked(services); parked {
		return model.ClassParked
	}
	if verdict == model.VerdictRejected {
		return model.ClassUnknown
	}
	if partner {
		return model.ClassPartner
	}
	// A host that resolves into an owned range is company hosting regardless of
	// whose brand name it carries.
	for _, ip := range h.Addresses() {
		if e.scope.IPInScope(ip) {
			return model.ClassCompany
		}
	}
	// A name under an org apex or registrable domain that is not on an owned IP
	// is either cloud-hosted by us or operated by someone else; the certificate
	// and CNAME evidence distinguishes third-party hosting from a partner.
	if e.scope.InDomain(name) || e.scope.InRegistrableDomain(name) {
		for _, target := range h.CNAMEs {
			if e.isPartner(target) {
				return model.ClassPartner
			}
		}
		return model.ClassThirdParty
	}
	return model.ClassUnknown
}

func (e *Engine) isPartner(name string) bool {
	low := "." + strings.ToLower(strings.Trim(name, "."))
	for _, suf := range e.partnerSuffixes {
		if strings.HasSuffix(low, suf) || low == suf {
			return true
		}
	}
	return false
}

func (e *Engine) isBarePublicSuffix(name string) bool {
	reg := e.scope.Registrable(name)
	return reg == "" || reg == name && !e.scope.InDomain(name)
	// A bare suffix like "com" has no registrable domain; names that equal
	// their registrable domain are kept only if declared as an apex.
}

func (e *Engine) orgNameMatch(values []string) bool {
	for _, v := range values {
		lv := strings.ToLower(v)
		for _, n := range e.orgNames {
			if n != "" && (lv == n || strings.Contains(lv, n)) {
				return true
			}
		}
	}
	return false
}

// parkedMarkers identify the common parking and squatter pages.
var parkedMarkers = []string{
	"domain is for sale", "buy this domain", "this domain may be for sale",
	"parked free", "domain parking", "sedoparking", "hugedomains",
	"afternic", "dan.com", "domain for sale", "godaddy.com/domainsearch",
	"this page is parked", "related searches", "sponsored listings",
}

func (e *Engine) looksParked(services []model.Service) (bool, string) {
	for _, svc := range services {
		if svc.HTTP == nil {
			continue
		}
		hay := strings.ToLower(svc.HTTP.Title + " " + svc.HTTP.Server + " " + svc.HTTP.PoweredBy)
		for _, m := range parkedMarkers {
			if strings.Contains(hay, m) {
				return true, "page matches parking marker: " + m
			}
		}
		if svc.HTTP.Headers != nil {
			if _, ok := svc.HTTP.Headers["X-Parking"]; ok {
				return true, "parking header present"
			}
		}
	}
	return false, ""
}

func confidence(score float64, ev []model.Evidence) float64 {
	n := 0
	mass := 0.0
	for _, s := range ev {
		n++
		mass += math.Abs(s.Weight)
	}
	if n == 0 {
		return 0
	}
	// Confidence rises with agreement between signals and with how far the
	// score is from zero; a single weak signal is not confident.
	c := math.Abs(score) / (mass + 1e-9)
	scale := math.Min(1, float64(n)/4)
	return math.Round(c*scale*100) / 100
}

func (e *Engine) rationale(att model.Attribution, in Input) string {
	if len(att.Evidence) == 0 {
		return "no ownership evidence observed"
	}
	// Summarise the two strongest signals, signed by direction.
	sorted := append([]model.Evidence{}, att.Evidence...)
	sort.Slice(sorted, func(i, j int) bool { return math.Abs(sorted[i].Weight) > math.Abs(sorted[j].Weight) })
	var pos, neg []string
	for _, s := range sorted {
		if s.Weight > 0 && len(pos) < 2 {
			pos = append(pos, humanSignal(s.Signal))
		}
		if s.Weight < 0 && len(neg) < 2 {
			neg = append(neg, humanSignal(s.Signal))
		}
	}
	switch att.Verdict {
	case model.VerdictConfirmed:
		return fmt.Sprintf("confirmed %s-owned: %s", strings.ToLower(string(att.Class)), strings.Join(pos, "; "))
	case model.VerdictProbable:
		return fmt.Sprintf("probably ours (%s): %s", strings.Join(pos, "; "), joinOrNone(neg))
	case model.VerdictPossible:
		return fmt.Sprintf("possible, weak evidence: %s", joinOrNone(pos))
	case model.VerdictRejected:
		return fmt.Sprintf("excluded: %s", strings.Join(append(neg, pos...), "; "))
	default:
		return "no ownership evidence observed"
	}
}

func joinOrNone(list []string) string {
	if len(list) == 0 {
		return "no contradicting signal"
	}
	return strings.Join(list, "; ")
}

var signalLabels = map[string]string{
	SigInOrgDomain:      "under an owned apex",
	SigInRegistrable:    "same registrable domain",
	SigSeed:             "declared seed",
	SigCTOrgCert:        "CT certificate covers owned name",
	SigCertSANOurs:      "certificate SAN is owned",
	SigCertOrgSubject:   "certificate subject is the org",
	SigVerificationTXT:  "DNS verification token",
	SigOwnedIP:          "owned IP range",
	SigCNAMESelf:        "CNAME into owned DNS",
	SigWildcardCatchall: "wildcard catch-all",
	SigParked:           "parking page",
	SigSharedCert:       "shared hosting certificate",
	SigPublicSuffixOnly: "bare public suffix",
	SigNXDomain:         "does not resolve",
	SigPartnerCNAME:     "CNAME to partner",
	SigPartnerDomain:    "partner domain",
}

func humanSignal(sig string) string {
	if l, ok := signalLabels[sig]; ok {
		return l
	}
	return sig
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// InScope reports whether an attribution qualifies for reporting.
func InScope(att model.Attribution) bool {
	switch att.Verdict {
	case model.VerdictConfirmed, model.VerdictProbable:
		return true
	default:
		return false
	}
}

// ActiveAllowed reports whether the profile permits actively probing this
// attribution. Partner and parked assets are passive-only by default.
func ActiveAllowed(cfg *config.Config, att model.Attribution) bool {
	if !InScope(att) {
		return false
	}
	if att.Score < cfg.Attribution.ActiveThreshold {
		return false
	}
	for _, c := range cfg.Safety.ActiveClasses {
		if c == string(att.Class) {
			return true
		}
	}
	return false
}
