// Package risk turns observed facts about an asset into a ranked, explainable
// score.
//
// The scoring model is deliberately additive-with-multipliers rather than a
// black box: every contribution is retained as a Factor, so a report can show
// exactly why an asset ranks where it does. An engineer who disagrees with a
// ranking can point at the factor responsible, and a rule can be tuned without
// re-running the whole history.
//
// The model separates two things that are often conflated:
//
//   - base risk: how exposed and outdated the asset is, independent of who owns
//     it. This is the part an incident responder cares about.
//   - context multiplier: whether the asset is in the right hands. An asset
//     nobody owns, or one managed by a partner we cannot fix directly, is not
//     more technically risky, but it is a worse operational risk because it
//     lingers. The multiplier encodes that without letting it dominate.
package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"asm/internal/config"
	"asm/internal/model"
)

// Factor weights. These are the tunable knobs of the model, calibrated
// against the band thresholds below so that a single finding lands where a
// security engineer would put it:
//
//   - an exposed secrets file or an unauthenticated Docker API is critical on
//     its own;
//   - an internet-exposed database is high on its own and critical with any
//     aggravating factor;
//   - remote management (SSH/RDP) is medium-to-high, since it is normal for
//     some organisations but should never be assumed safe;
//   - certificate and hygiene issues are low-to-medium, because they rarely
//     lead directly to compromise but correlate strongly with neglect.
//
// Changing a weight here changes the ranking everywhere; the tests in
// engine_test.go pin the important relationships.
const (
	wSensitivePort = 35
	wDatabasePort  = 60
	wDockerAPI     = 85
	wRemoteMgmt    = 35

	wExposedData    = 80
	wAdminPanel     = 70
	wProtectedPanel = 8

	wExpiredCert   = 25
	wExpiringCert  = 8
	wSelfSigned    = 15
	wWeakCrypto    = 20
	wNoHTTPS       = 10
	wPlaintextAuth = 30

	wDevEnvironment = 10
	wStaleContent   = 3
	wDefaultPage    = 8
)

// sensitivePorts should never be reachable from the public internet.
var sensitivePorts = map[int]string{
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	9200:  "elasticsearch",
	27017: "mongodb",
	2375:  "docker daemon (unauthenticated API)",
	2379:  "etcd",
	11211: "memcached",
	5984:  "couchdb",
	8500:  "consul",
	5601:  "kibana",
	9000:  "minio/php-fpm",
	8080:  "http alt",
	8443:  "https alt",
	3389:  "rdp",
	22:    "ssh",
	5900:  "vnc",
	1433:  "mssql",
	1521:  "oracle",
	2181:  "zookeeper",
	7001:  "weblogic",
	9090:  "prometheus",
	3000:  "grafana",
	8888:  "jupyter",
	50070: "hadoop namenode",
}

// Engine scores assets.
type Engine struct {
	cfg *config.Config
}

// NewEngine builds a scoring engine.
func NewEngine(cfg *config.Config) *Engine { return &Engine{cfg: cfg} }

// Input is everything the scorer may use.
type Input struct {
	Snapshot    *model.Snapshot
	Findings    []model.Finding
	Attribution model.Attribution
	// Observations captured during probing that are not themselves findings.
	HasHTTPS bool
	HasHTTP  bool
	// HasWebPort is true when a service answered HTTP on the standard
	// plaintext web port (80), which is what makes "no HTTPS" meaningful.
	HasWebPort bool
	// IsStale is set by the pipeline when the asset's observable state has not
	// changed for risk.stale_after while it is still reachable.
	IsStale bool
}

// Assess produces the ranked assessment.
func (e *Engine) Assess(in Input) model.Assessment {
	var factors []model.Factor
	add := func(key, title string, weight float64, detail string) {
		if weight == 0 {
			return
		}
		factors = append(factors, model.Factor{Key: key, Title: title, Weight: weight, Detail: detail})
	}

	// One factor per distinct root cause. A host with redis on 6379 and 6380
	// should not score twice for "exposed database".
	seenFactor := map[string]bool{}
	markSeen := func(key string) {
		seenFactor[key] = true
	}
	isSeen := func(key string) bool { return seenFactor[key] }

	for _, svc := range in.Snapshot.Services {
		if label, ok := sensitivePorts[svc.Port]; ok {
			key := fmt.Sprintf("port:%s", label)
			if isSeen(key) {
				continue
			}
			markSeen(key)
			weight := float64(wSensitivePort)
			switch svc.Port {
			case 2375, 2379:
				weight = wDockerAPI
			case 3306, 5432, 6379, 9200, 27017, 11211, 5984, 1433, 1521, 2181, 7001:
				weight = wDatabasePort
			case 22, 3389, 5900:
				weight = wRemoteMgmt
			}
			add(key, "Sensitive port exposed: "+label, weight, fmt.Sprintf("port %d is reachable from the internet", svc.Port))
		}

		if svc.TLS != nil {
			if !svc.TLS.SelfSigned && svc.TLS.ExpiresIn(nowOf(in)) < 0 {
				add(fmt.Sprintf("cert-expired:%d", svc.Port), "Expired TLS certificate", wExpiredCert,
					fmt.Sprintf("certificate expired %s", svc.TLS.NotAfter.UTC().Format("2006-01-02")))
			} else if d := svc.TLS.ExpiresIn(nowOf(in)); d >= 0 && d < 30*24*3600*1e9 {
				add(fmt.Sprintf("cert-expiring:%d", svc.Port), "TLS certificate expiring soon", wExpiringCert,
					fmt.Sprintf("certificate expires in %d days", int(d/(24*3600*1e9))))
			}
			if svc.TLS.SelfSigned {
				add(fmt.Sprintf("selfsigned:%d", svc.Port), "Self-signed certificate", wSelfSigned,
					"self-signed certificate is presented on a public endpoint")
			}
			if svc.TLS.Weak {
				add(fmt.Sprintf("weakcrypto:%d", svc.Port), "Weak TLS cryptography", wWeakCrypto,
					"certificate uses RSA < 2048 or a SHA-1/MD5 signature")
			}
		}

		if svc.HTTP != nil {
			// One finding per exposed path. The path is the root cause; two
			// secrets files on one port should not score twice for "exposure"
			// as a category, but each is individually actionable, so each is a
			// factor with its own capped weight.
			for _, ex := range svc.HTTP.Exposed {
				add("exposed:"+svc.Host+":"+fmt.Sprint(svc.Port)+ex.Path, "Sensitive file exposed", wExposedData,
					fmt.Sprintf("%s on port %d: %s", ex.Path, svc.Port, ex.Note))
			}
			// A management panel is one entry point regardless of how many
			// paths lead into it, so it is keyed per service, not per path.
			if len(svc.HTTP.OpenPanels) > 0 {
				add("panel:"+svc.Host+":"+fmt.Sprint(svc.Port), "Management panel open without authentication", wAdminPanel,
					fmt.Sprintf("%s answered without auth on port %d", strings.Join(svc.HTTP.OpenPanels, ", "), svc.Port))
			} else if len(svc.HTTP.ProtectedPanels) > 0 {
				add("panel-protected:"+svc.Host+":"+fmt.Sprint(svc.Port), "Management panel reachable (protected)", wProtectedPanel,
					fmt.Sprintf("%s requires authentication on port %d", strings.Join(svc.HTTP.ProtectedPanels, ", "), svc.Port))
			}
			if svc.HTTP.BodyHash != "" && isDefaultPage(svc.HTTP) {
				add("default:"+svc.Host+":"+fmt.Sprint(svc.Port), "Default server page", wDefaultPage,
					"web server is serving its default page: likely an unmanaged deployment")
			}
			if svc.HTTP.PlaintextAuth {
				add("plaintext:"+svc.Host, "Credentials over plaintext", wPlaintextAuth,
					"login form served without HTTPS")
			}
		}
	}

	// Only call out missing HTTPS when the host clearly serves a web app over
	// plaintext. A host that answered only on a non-web port (redis, ssh) is
	// not a "no HTTPS" problem, and a host with no HTTP at all is not either.
	if in.HasHTTP && !in.HasHTTPS && in.HasWebPort {
		add("no-https", "No HTTPS service", wNoHTTPS, "a plaintext web service answered on the standard HTTP port with no TLS equivalent")
	}

	// Development / staging names are weighted up: they are usually unowned and
	// patched last.
	for _, pat := range e.cfg.Risk.DevPatterns {
		if matchesPattern(pat, in.Snapshot.Host.Name) {
			add("dev-env", "Ephemeral or test environment name", wDevEnvironment,
				"name matches a dev/test/staging pattern, which correlates with neglected assets")
			break
		}
	}

	if in.IsStale {
		add("stale", "Unchanged content over a long period", wStaleContent,
			"page content has not changed across many runs, suggesting an abandoned deployment")
	}

	// Diminishing returns within a category. Two ports hosting the same
	// exposed secrets file are one root cause, not two: without this, a host
	// with many similar issues saturates at 100 and the ranking stops
	// discriminating between differently-bad assets.
	factors = applyDiminishingReturns(factors)

	rawBase := 0.0
	for _, f := range factors {
		rawBase += f.Weight
	}
	// Soft saturation instead of a hard clamp. A hard cap at 100 makes every
	// sufficiently-bad host tie at 100, which is exactly where a ranking tool
	// must still discriminate (an exposed .env plus an open admin panel is
	// worse than an exposed .env alone). The curve is the identity below the
	// knee and compresses smoothly above it, so:
	//
	//   - scores below the knee are their literal sum, keeping the calibration
	//     of the individual weights intact;
	//   - scores above it stay distinct and asymptotically approach 100;
	//   - ordering is preserved because the curve is strictly monotonic.
	const knee = 50.0
	base := rawBase
	if rawBase > knee {
		// headroom * (1 - e^(-(raw-knee)/headroom)) keeps the derivative
		// continuous at the knee and caps at 100.
		const headroom = 100.0 - knee
		base = knee + headroom*(1-math.Exp(-(rawBase-knee)/headroom))
	}

	// Context multiplier: ownership and hosting change urgency, not exposure.
	mult := 1.0
	var ctx []string
	if in.Attribution.Verdict == model.VerdictPossible || in.Attribution.Verdict == model.VerdictUnverified {
		mult *= 1.15
		ctx = append(ctx, "ownership uncertain")
	}
	switch in.Attribution.Class {
	case model.ClassPartner:
		mult *= e.cfg.Risk.PartnerMultiplier
		ctx = append(ctx, "partner-managed (escalation required)")
	case model.ClassUnknown:
		mult *= 1.1
		ctx = append(ctx, "hosting class unknown")
	}
	if len(ctx) > 0 {
		factors = append(factors, model.Factor{
			Key:    "context",
			Title:  "Ownership context multiplier",
			Weight: math.Round((mult-1)*100) / 100,
			Detail: strings.Join(ctx, ", "),
		})
	}

	// Re-apply soft saturation after the context multiplier so a multiplier
	// above 1 can still push a high asset past a lower one without clipping.
	score := base * mult
	if score > knee {
		const headroom = 100.0 - knee
		score = knee + headroom*(1-math.Exp(-(score-knee)/headroom))
	}
	score = math.Round(math.Min(100, score))
	band := e.band(score)

	sort.SliceStable(factors, func(i, j int) bool { return factors[i].Weight > factors[j].Weight })

	return model.Assessment{
		Base:       math.Round(base*10) / 10,
		Multiplier: math.Round(mult*100) / 100,
		Score:      score,
		Band:       band,
		Factors:    factors,
		Summary:    summarise(band, factors),
	}
}

// diminishingFactor is what each additional same-category factor is worth
// relative to the strongest one.
const diminishingFactor = 0.3

// applyDiminishingReturns scales down repeated factors within one category and
// rewrites their weights so the displayed factors still sum to the base score.
// The strongest factor in each category keeps its full weight.
func applyDiminishingReturns(factors []model.Factor) []model.Factor {
	byCat := map[string][]int{}
	for i, f := range factors {
		if f.Key == "context" {
			continue
		}
		cat := categoryFor(f.Key)
		byCat[cat] = append(byCat[cat], i)
	}
	for _, idxs := range byCat {
		if len(idxs) < 2 {
			continue
		}
		sort.Slice(idxs, func(a, b int) bool { return factors[idxs[a]].Weight > factors[idxs[b]].Weight })
		for rank, i := range idxs {
			if rank == 0 {
				continue
			}
			scaled := math.Round(factors[i].Weight*diminishingFactor*10) / 10
			if scaled < 1 {
				scaled = 1
			}
			factors[i].Weight = scaled
			if factors[i].Detail != "" {
				factors[i].Detail += " (same category as a stronger finding, scored at reduced weight)"
			}
		}
	}
	return factors
}

func (e *Engine) band(score float64) model.Band {
	t := e.cfg.Risk.BandThresholds
	switch {
	case score >= t["critical"]:
		return model.BandCritical
	case score >= t["high"]:
		return model.BandHigh
	case score >= t["medium"]:
		return model.BandMedium
	case score >= t["low"]:
		return model.BandLow
	default:
		return model.BandInfo
	}
}

func nowOf(in Input) time.Time {
	if !in.Snapshot.LastSeen.IsZero() {
		return in.Snapshot.LastSeen
	}
	return timeNow()
}

func hasPanel(h *model.HTTP) bool {
	if h == nil {
		return false
	}
	for _, t := range h.Tech {
		switch t {
		case "grafana", "kibana", "phpmyadmin", "jenkins", "gitlab", "tomcat", "zabbix", "rabbitmq", "consul":
			return true
		}
	}
	for _, ex := range h.Exposed {
		low := strings.ToLower(ex.Path)
		if strings.Contains(low, "admin") || strings.Contains(low, "manager") || strings.Contains(low, "login") {
			if ex.Status >= 200 && ex.Status < 400 {
				return true
			}
		}
	}
	return false
}

var defaultPageMarkers = []string{
	"it works!", "welcome to nginx", "apache2 ubuntu default page", "iis windows server",
	"test page for the apache", "default web site page", "welcome to openresty",
}

func isDefaultPage(h *model.HTTP) bool {
	if h == nil {
		return false
	}
	low := strings.ToLower(h.Title)
	for _, m := range defaultPageMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func summarise(band model.Band, factors []model.Factor) string {
	if len(factors) == 0 {
		return "no elevated risk factors observed"
	}
	var titles []string
	for i, f := range factors {
		if i >= 3 {
			break
		}
		titles = append(titles, f.Title)
	}
	return fmt.Sprintf("%s risk: %s", band, strings.Join(titles, ", "))
}

// FindingsFromSnapshot converts the ranked factors into discrete findings that
// can be assigned and tracked individually.
func FindingsFromSnapshot(s *model.Snapshot) []model.Finding {
	var out []model.Finding
	now := timeNow()
	for _, f := range s.Assessment.Factors {
		if f.Key == "context" || f.Weight <= 0 {
			continue
		}
		sev := sevForWeight(f.Weight)
		out = append(out, model.Finding{
			Key:         model.StableID("f", s.Key+"|"+f.Key),
			Title:       f.Title,
			Severity:    sev,
			Category:    categoryFor(f.Key),
			AssetKey:    s.Key,
			AssetName:   s.Host.Name,
			Evidence:    f.Detail,
			Remediation: remediationFor(f.Key),
			DetectedAt:  now,
		})
	}
	return out
}

func sevForWeight(w float64) model.Severity {
	switch {
	case w >= 20:
		return model.SevCritical
	case w >= 12:
		return model.SevHigh
	case w >= 6:
		return model.SevMedium
	case w > 0:
		return model.SevLow
	default:
		return model.SevInfo
	}
}

func categoryFor(key string) string {
	switch {
	case strings.HasPrefix(key, "port:"):
		return "exposure"
	case strings.HasPrefix(key, "exposed:"):
		return "data"
	case strings.HasPrefix(key, "panel"), strings.HasPrefix(key, "default:"):
		return "panel"
	case strings.HasPrefix(key, "cert"), strings.HasPrefix(key, "selfsigned"), strings.HasPrefix(key, "weakcrypto"), strings.HasPrefix(key, "no-https"), strings.HasPrefix(key, "plaintext"):
		return "crypto"
	case strings.HasPrefix(key, "dev-env"):
		return "lifecycle"
	case strings.HasPrefix(key, "stale"):
		return "lifecycle"
	default:
		return "exposure"
	}
}

func remediationFor(key string) string {
	switch {
	case strings.HasPrefix(key, "port:"):
		return "Restrict the port to VPN or an allowlisted management network, or decommission the service."
	case strings.HasPrefix(key, "exposed:"):
		return "Remove the path from the public document root or require authentication; check for data disclosure."
	case strings.HasPrefix(key, "panel"):
		return "Put the management interface behind SSO/VPN and confirm it is patched."
	case strings.HasPrefix(key, "cert-expired"), strings.HasPrefix(key, "cert-expiring"):
		return "Renew the certificate and automate renewal to prevent recurrence."
	case strings.HasPrefix(key, "selfsigned"):
		return "Issue a certificate from the managed CA."
	case strings.HasPrefix(key, "no-https"), strings.HasPrefix(key, "plaintext"):
		return "Serve the site over HTTPS and redirect HTTP to it."
	case strings.HasPrefix(key, "dev-env"):
		return "Confirm the environment is needed; decommission if unused, otherwise bring it under patch management."
	case strings.HasPrefix(key, "default:"):
		return "Remove the default page and confirm whether the deployment is still in use."
	case strings.HasPrefix(key, "stale"):
		return "Verify ownership and purpose; stale content often marks an abandoned deployment."
	default:
		return "Review the finding with the owning team."
	}
}
