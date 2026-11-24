package report

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"

	"asm/internal/model"
)

// writeHTML renders a single self-contained dashboard: no external assets, no
// JavaScript, so it can be archived, emailed and opened offline. It is the
// artefact a security review meeting actually looks at.
func (w *Writer) writeHTML(d Data) (string, error) {
	path := w.path("dashboard.html")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	snaps := reportableOnly(d.Snapshots)
	sort.SliceStable(snaps, func(i, j int) bool {
		if snaps[i].Assessment.Band.Rank() != snaps[j].Assessment.Band.Rank() {
			return snaps[i].Assessment.Band.Rank() < snaps[j].Assessment.Band.Rank()
		}
		return snaps[i].Assessment.Score > snaps[j].Assessment.Score
	})
	counts := bandCounts(snaps)

	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack surface — `)
	b.WriteString(html.EscapeString(d.Organisation))
	b.WriteString(`</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--fg:#e6e9ef;--muted:#8b93a7;--crit:#e5484d;--high:#f76b15;--med:#ffb224;--low:#3e9dd6;--info:#6e7681;--line:#262b36}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{padding:24px 28px;border-bottom:1px solid var(--line)}
h1{margin:0 0 4px;font-size:20px;font-weight:600}
.sub{color:var(--muted);font-size:13px}
.wrap{padding:20px 28px;max-width:1200px;margin:0 auto}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:600}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;margin:14px 0 28px;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--line);padding:8px 10px}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:hover td{background:#1b1f28}
.band{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase}
.b-critical{background:rgba(229,72,77,.16);color:var(--crit)}
.b-high{background:rgba(247,107,21,.16);color:var(--high)}
.b-medium{background:rgba(255,178,36,.16);color:var(--med)}
.b-low{background:rgba(62,157,214,.16);color:var(--low)}
.b-info{background:rgba(110,118,129,.16);color:var(--info)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.score{font-variant-numeric:tabular-nums;font-weight:600}
.why{color:var(--muted);font-size:12px}
details summary{cursor:pointer;color:var(--muted);font-size:12px}
.tag{display:inline-block;padding:0 6px;border-radius:4px;background:#22262f;color:var(--muted);font-size:11px;margin-right:4px}
h2{font-size:15px;font-weight:600;margin:26px 0 6px}
</style></head><body>`)

	b.WriteString("<header><h1>" + html.EscapeString(d.Organisation) + " — External attack surface</h1>")
	b.WriteString(`<div class="sub">Generated ` + html.EscapeString(d.GeneratedAt.Format(time.RFC1123)) +
		` · run <span class="mono">` + html.EscapeString(d.RunID) + `</span>`)
	if d.GateSummary != "" {
		b.WriteString(" · " + html.EscapeString(d.GateSummary))
	}
	b.WriteString("</div></header>")
	b.WriteString(`<div class="wrap">`)

	// Headline numbers.
	b.WriteString(`<div class="cards">`)
	for _, pair := range []struct {
		label string
		n     int
	}{{"Critical", counts[model.BandCritical]}, {"High", counts[model.BandHigh]}, {"Medium", counts[model.BandMedium]}, {"Low", counts[model.BandLow]}, {"Changes", len(d.Changes)}} {
		fmt.Fprintf(&b, `<div class="card"><div class="n">%d</div><div class="l">%s</div></div>`, pair.n, pair.label)
	}
	b.WriteString(`</div>`)

	// Ranked assets.
	b.WriteString(`<h2>Ranked assets</h2><table><thead><tr><th>Asset</th><th>Band</th><th>Score</th><th>Owner</th><th>Why it ranks here</th></tr></thead><tbody>`)
	for _, s := range snaps {
		fmt.Fprintf(&b, `<tr><td><span class="mono">%s</span>`, html.EscapeString(s.Host.Name))
		if len(s.Host.Addresses()) > 0 {
			fmt.Fprintf(&b, `<div class="why mono">%s</div>`, html.EscapeString(strings.Join(s.Host.Addresses(), ", ")))
		}
		b.WriteString(`</td>`)
		fmt.Fprintf(&b, `<td><span class="band b-%s">%s</span></td>`, s.Assessment.Band, s.Assessment.Band)
		fmt.Fprintf(&b, `<td class="score">%.0f</td>`, s.Assessment.Score)
		fmt.Fprintf(&b, `<td>%s<div class="why">%s</div>`, html.EscapeString(s.Owner.Team), html.EscapeString(string(s.Attribution.Class)))
		if s.Owner.Escalation != "" {
			fmt.Fprintf(&b, `<div class="why">⚠ %s</div>`, html.EscapeString(s.Owner.Escalation))
		}
		b.WriteString(`</td><td>`)
		for i, f := range s.Assessment.Factors {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, `<span class="tag">%s</span>`, html.EscapeString(f.Title))
		}
		if s.Attribution.Rationale != "" {
			fmt.Fprintf(&b, `<div class="why">%s</div>`, html.EscapeString(s.Attribution.Rationale))
		}
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)

	// Changes.
	if len(d.Changes) > 0 {
		b.WriteString(`<h2>Change feed</h2><table><thead><tr><th>Severity</th><th>Change</th><th>Asset</th><th>Team</th></tr></thead><tbody>`)
		for _, c := range d.Changes {
			fmt.Fprintf(&b, `<tr><td><span class="band b-%s">%s</span></td><td>%s<div class="why">%s</div></td><td class="mono">%s</td><td>%s</td></tr>`,
				toBand(c.Severity), c.Severity, html.EscapeString(c.Summary), html.EscapeString(c.Detail), html.EscapeString(c.AssetName), html.EscapeString(c.Team))
		}
		b.WriteString(`</tbody></table>`)
	}

	// Candidates, so exclusions are visible.
	var candidates []*model.Snapshot
	for _, s := range d.Snapshots {
		if !reportable(s) {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) > 0 {
		b.WriteString(`<h2>Out of scope (reviewable)</h2><details><summary>` + fmt.Sprintf("%d candidate assets were discovered but not attributed", len(candidates)) + `</summary><table><thead><tr><th>Asset</th><th>Verdict</th><th>Score</th><th>Why</th></tr></thead><tbody>`)
		for _, s := range candidates {
			fmt.Fprintf(&b, `<tr><td class="mono">%s</td><td>%s</td><td class="score">%.1f</td><td class="why">%s</td></tr>`,
				html.EscapeString(s.Host.Name), s.Attribution.Verdict, s.Attribution.Score, html.EscapeString(s.Attribution.Rationale))
		}
		b.WriteString(`</tbody></table></details>`)
	}

	b.WriteString(`</div></body></html>`)
	if _, err := f.WriteString(b.String()); err != nil {
		return "", err
	}
	return path, nil
}

func toBand(s model.Severity) string { return string(s) }

func reportableOnly(snaps []*model.Snapshot) []*model.Snapshot {
	var out []*model.Snapshot
	for _, s := range snaps {
		if reportable(s) {
			out = append(out, s)
		}
	}
	return out
}
