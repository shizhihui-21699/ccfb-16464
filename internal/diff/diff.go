// Package diff compares two inventories and emits typed changes.
//
// Change detection is the feature that makes continuous operation worth it: a
// list of assets is a snapshot, but "a new admin panel appeared on a
// partner-hosted staging host at 02:14" is something a team can act on.
//
// Every change carries a severity derived from what changed and how exposed the
// asset is, so the daily feed can be triaged without re-reading the whole
// inventory.
package diff

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"asm/internal/model"
)

// Comparer diffs snapshots.
type Comparer struct {
	now func() time.Time
}

// New returns a comparer.
func New() *Comparer { return &Comparer{now: time.Now} }

// SetClock replaces the clock in tests.
func (c *Comparer) SetClock(fn func() time.Time) { c.now = fn }

// Result is the outcome of a comparison.
type Result struct {
	Changes []model.Change
	New     []*model.Snapshot
	Gone    []*model.Snapshot
	Changed []*model.Snapshot
}

// Compare diffs previous (keyed) against current (ordered).
func (c *Comparer) Compare(previous map[string]*model.Snapshot, current []*model.Snapshot, runID string) Result {
	var res Result
	now := c.now()
	currentKeys := map[string]bool{}

	for _, cur := range current {
		currentKeys[cur.Key] = true
		prev, existed := previous[cur.Key]
		if !existed {
			res.New = append(res.New, cur)
			if cur.Attribution.Verdict != model.VerdictRejected {
				res.Changes = append(res.Changes, model.Change{
					RunID:     runID,
					At:        now,
					Kind:      model.ChangeNewAsset,
					AssetKey:  cur.Key,
					AssetName: cur.Host.Name,
					Severity:  sevForBand(cur.Assessment.Band),
					Summary:   fmt.Sprintf("New asset discovered: %s (%s)", cur.Host.Name, cur.Assessment.Band),
					Detail:    fmt.Sprintf("verdict=%s class=%s score=%.0f", cur.Attribution.Verdict, cur.Attribution.Class, cur.Assessment.Score),
					Team:      cur.Owner.Team,
				})
			}
			continue
		}

		assetChanges := c.compareAsset(prev, cur, runID, now)
		if len(assetChanges) > 0 {
			res.Changed = append(res.Changed, cur)
			res.Changes = append(res.Changes, assetChanges...)
		}
	}

	for key, prev := range previous {
		if currentKeys[key] {
			continue
		}
		// Only assets that were previously in scope are worth a disappearance
		// event; rejected candidates churn constantly and mean nothing.
		if !wasInScope(prev) {
			continue
		}
		res.Gone = append(res.Gone, prev)
		res.Changes = append(res.Changes, model.Change{
			RunID:     runID,
			At:        now,
			Kind:      model.ChangeGoneAsset,
			AssetKey:  prev.Key,
			AssetName: prev.Host.Name,
			Severity:  model.SevLow,
			Summary:   fmt.Sprintf("Asset no longer observed: %s", prev.Host.Name),
			Detail:    "the name did not resolve or did not answer this run; it may have been decommissioned or its DNS changed",
			Team:      prev.Owner.Team,
		})
	}

	sort.Slice(res.Changes, func(i, j int) bool {
		if res.Changes[i].Severity.Rank() != res.Changes[j].Severity.Rank() {
			return res.Changes[i].Severity.Rank() < res.Changes[j].Severity.Rank()
		}
		return res.Changes[i].AssetName < res.Changes[j].AssetName
	})
	return res
}

func (c *Comparer) compareAsset(prev, cur *model.Snapshot, runID string, now time.Time) []model.Change {
	var out []model.Change
	mk := func(kind model.ChangeKind, sev model.Severity, summary, detail, before, after string) {
		out = append(out, model.Change{
			RunID:     runID,
			At:        now,
			Kind:      kind,
			AssetKey:  cur.Key,
			AssetName: cur.Host.Name,
			Severity:  sev,
			Summary:   summary,
			Detail:    detail,
			Team:      cur.Owner.Team,
			Previous:  before,
			Current:   after,
		})
	}

	// Ports.
	prevPorts := portSet(prev.Services)
	curPorts := portSet(cur.Services)
	for _, svc := range cur.Services {
		if !prevPorts[svc.Port] {
			sev := sevForPort(svc.Port, cur.Assessment.Band)
			mk(model.ChangeNewPort, sev,
				fmt.Sprintf("New port open: %d on %s", svc.Port, cur.Host.Name),
				describeService(svc), "", fmt.Sprintf("%d", svc.Port))
		}
	}
	for _, svc := range prev.Services {
		if !curPorts[svc.Port] {
			mk(model.ChangePortClosed, model.SevInfo,
				fmt.Sprintf("Port closed: %d on %s", svc.Port, cur.Host.Name),
				"the port no longer answers", fmt.Sprintf("%d", svc.Port), "")
		}
	}

	// DNS changes. Address and CNAME are reported separately because they mean
	// different things: an IP change can be a CDN shift, while a CNAME change
	// often means the asset was re-pointed at a new (possibly unmanaged) host.
	prevIPs, curIPs := strings.Join(prev.Host.Addresses(), ","), strings.Join(cur.Host.Addresses(), ",")
	if prevIPs != curIPs && curIPs != "" {
		mk(model.ChangeIPChanged, model.SevInfo,
			fmt.Sprintf("Address changed for %s", cur.Host.Name),
			"the name now resolves to a different address set", prevIPs, curIPs)
	}
	prevCNAME, curCNAME := strings.Join(prev.Host.CNAMEs, ","), strings.Join(cur.Host.CNAMEs, ",")
	if prevCNAME != curCNAME && curCNAME != "" && prevCNAME != "" {
		mk(model.ChangeDNSChanged, model.SevMedium,
			fmt.Sprintf("CNAME changed for %s", cur.Host.Name),
			"the name now points at different infrastructure; confirm the new target is expected",
			prevCNAME, curCNAME)
	}

	// Certificate identity.
	prevCert, curCert := primaryCert(prev), primaryCert(cur)
	if prevCert != "" && curCert != "" && prevCert != curCert {
		mk(model.ChangeCertChanged, model.SevMedium,
			fmt.Sprintf("TLS certificate changed on %s", cur.Host.Name),
			"the certificate fingerprint on the primary HTTPS port changed", short(prevCert), short(curCert))
	}

	// Content fingerprint on the primary web service.
	prevBody, curBody := primaryBody(prev), primaryBody(cur)
	if prevBody != "" && curBody != "" && prevBody != curBody {
		mk(model.ChangeContentChanged, model.SevInfo,
			fmt.Sprintf("Page content changed on %s", cur.Host.Name),
			"the landing page body hash changed", prevBody, curBody)
	}

	// Findings set.
	prevFindings := findingMap(prev.Findings)
	curFindings := findingMap(cur.Findings)
	for k, f := range curFindings {
		if _, ok := prevFindings[k]; !ok {
			mk(model.ChangeNewFinding, f.Severity,
				fmt.Sprintf("New finding: %s", f.Title),
				f.Evidence, "", f.Title)
		}
	}
	for k, f := range prevFindings {
		if _, ok := curFindings[k]; !ok {
			mk(model.ChangeFindingFixed, model.SevInfo,
				fmt.Sprintf("Finding resolved: %s", f.Title),
				"the condition that produced this finding is no longer observed", f.Title, "")
		}
	}

	// Risk movement.
	if prev.Assessment.Band != cur.Assessment.Band {
		dir := cur.Assessment.Band.Rank() < prev.Assessment.Band.Rank()
		kind := model.ChangeRiskDecreased
		sev := model.SevInfo
		word := "decreased"
		if dir {
			kind = model.ChangeRiskIncreased
			sev = sevForBand(cur.Assessment.Band)
			word = "increased"
		}
		mk(kind, sev,
			fmt.Sprintf("Risk %s: %s is now %s", word, cur.Host.Name, cur.Assessment.Band),
			cur.Assessment.Summary, string(prev.Assessment.Band), string(cur.Assessment.Band))
	}

	// Ownership change is worth flagging even when risk is flat: it means a
	// different team now needs to care.
	if prev.Owner.Team != cur.Owner.Team {
		mk(model.ChangeOwnershipChange, model.SevLow,
			fmt.Sprintf("Responsible team changed for %s", cur.Host.Name),
			"routing changed, usually because attribution or an owner rule changed",
			prev.Owner.Team, cur.Owner.Team)
	}

	return out
}

func wasInScope(s *model.Snapshot) bool {
	switch s.Attribution.Verdict {
	case model.VerdictConfirmed, model.VerdictProbable:
		return true
	default:
		return false
	}
}

func portSet(services []model.Service) map[int]bool {
	m := map[int]bool{}
	for _, s := range services {
		m[s.Port] = true
	}
	return m
}

func findingMap(findings []model.Finding) map[string]model.Finding {
	m := map[string]model.Finding{}
	for _, f := range findings {
		m[f.Key] = f
	}
	return m
}

func primaryCert(s *model.Snapshot) string {
	for _, svc := range s.Services {
		if svc.TLS != nil && svc.TLS.FingerprintSHA256 != "" && (svc.Port == 443 || svc.Port == 8443) {
			return svc.TLS.FingerprintSHA256
		}
	}
	return ""
}

func primaryBody(s *model.Snapshot) string {
	for _, svc := range s.Services {
		if svc.HTTP != nil && svc.HTTP.BodyHash != "" && svc.Port == 443 {
			return svc.HTTP.BodyHash
		}
	}
	for _, svc := range s.Services {
		if svc.HTTP != nil && svc.HTTP.BodyHash != "" && svc.Port == 80 {
			return svc.HTTP.BodyHash
		}
	}
	return ""
}

func describeService(svc model.Service) string {
	var parts []string
	if svc.TLS != nil {
		parts = append(parts, "TLS")
	}
	if svc.HTTP != nil {
		p := fmt.Sprintf("HTTP %d", svc.HTTP.Status)
		if svc.HTTP.Title != "" {
			p += " " + strings.TrimSpace(svc.HTTP.Title)
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		parts = append(parts, "TCP open")
	}
	return strings.Join(parts, ", ")
}

// sevForPort rates a newly-open port by how dangerous it is to expose.
func sevForPort(port int, band model.Band) model.Severity {
	switch port {
	case 2375, 2376, 2379, 6379, 9200, 27017, 11211, 3306, 5432, 1433, 1521, 2181:
		return model.SevCritical
	case 22, 3389, 5900, 7001, 5984, 8500, 5601, 8888:
		if band == model.BandCritical || band == model.BandHigh {
			return model.SevCritical
		}
		return model.SevHigh
	case 80, 443, 8080, 8443:
		// A new web port on an already-high-risk asset is more significant
		// than one on a benign host.
		if band == model.BandCritical {
			return model.SevHigh
		}
		return model.SevMedium
	default:
		return model.SevLow
	}
}

func sevForBand(b model.Band) model.Severity {
	switch b {
	case model.BandCritical:
		return model.SevCritical
	case model.BandHigh:
		return model.SevHigh
	case model.BandMedium:
		return model.SevMedium
	case model.BandLow:
		return model.SevLow
	default:
		return model.SevInfo
	}
}

func short(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}
