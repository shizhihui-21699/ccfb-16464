// Package report renders inventory, findings and changes into formats that the
// people who act on them can use: per-team markdown tickets and CSV for
// ticketing imports, JSON for pipelines, and a single self-contained HTML
// dashboard for review meetings.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"asm/internal/config"
	"asm/internal/model"
)

// Data is everything a report needs.
type Data struct {
	RunID        string
	GeneratedAt  time.Time
	Organisation string
	Snapshots    []*model.Snapshot
	Changes      []model.Change
	Stats        model.RunStats
	// GateSummary explains what the safety gate allowed this run.
	GateSummary string
}

// Writer renders one or more formats to disk.
type Writer struct {
	cfg *config.Config
	dir string
	now time.Time
}

// NewWriter builds a writer.
func NewWriter(cfg *config.Config) *Writer {
	return &Writer{cfg: cfg, dir: cfg.Outputs.Dir, now: time.Now()}
}

// Render writes all configured formats and returns the files written.
func (w *Writer) Render(d Data) ([]string, error) {
	if err := os.MkdirAll(w.dir, 0o750); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	var written []string
	for _, format := range w.cfg.Outputs.Formats {
		var path string
		var err error
		switch strings.ToLower(format) {
		case "json":
			path, err = w.writeJSON(d)
		case "csv":
			path, err = w.writeCSV(d)
		case "markdown", "md":
			path, err = w.writeMarkdown(d)
		case "html":
			path, err = w.writeHTML(d)
		case "changes", "changelog":
			path, err = w.writeChanges(d)
		default:
			err = fmt.Errorf("unknown output format %q", format)
		}
		if err != nil {
			return written, err
		}
		written = append(written, path)
	}
	if w.cfg.Outputs.SplitByTeam {
		paths, err := w.writeTeamBundles(d)
		if err != nil {
			return written, err
		}
		written = append(written, paths...)
	}
	return written, nil
}

func (w *Writer) path(name string) string {
	return filepath.Join(w.dir, name)
}

// --- JSON ---------------------------------------------------------------

type jsonReport struct {
	RunID        string         `json:"run_id"`
	GeneratedAt  time.Time      `json:"generated_at"`
	Organisation string         `json:"organisation"`
	Stats        model.RunStats `json:"stats"`
	Gate         string         `json:"gate_summary,omitempty"`
	Assets       []assetJSON    `json:"assets"`
	Changes      []model.Change `json:"changes"`
}

type assetJSON struct {
	Key        string           `json:"key"`
	Name       string           `json:"name"`
	Verdict    model.Verdict    `json:"verdict"`
	Class      model.Class      `json:"class"`
	Score      float64          `json:"score"`
	Band       model.Band       `json:"band"`
	Team       string           `json:"team"`
	Contact    string           `json:"contact,omitempty"`
	Rationale  string           `json:"rationale,omitempty"`
	Summary    string           `json:"summary,omitempty"`
	FirstSeen  time.Time        `json:"first_seen"`
	LastSeen   time.Time        `json:"last_seen"`
	Services   []serviceJSON    `json:"services,omitempty"`
	Findings   []model.Finding  `json:"findings,omitempty"`
	Evidence   []model.Evidence `json:"evidence,omitempty"`
	Factors    []model.Factor   `json:"factors,omitempty"`
	Escalation string           `json:"escalation,omitempty"`
}

type serviceJSON struct {
	Port    int         `json:"port"`
	IP      string      `json:"ip"`
	Product string      `json:"product,omitempty"`
	TLS     *model.TLS  `json:"tls,omitempty"`
	HTTP    *model.HTTP `json:"http,omitempty"`
}

func toAssetJSON(s *model.Snapshot) assetJSON {
	a := assetJSON{
		Key:        s.Key,
		Name:       s.Host.Name,
		Verdict:    s.Attribution.Verdict,
		Class:      s.Attribution.Class,
		Score:      s.Assessment.Score,
		Band:       s.Assessment.Band,
		Team:       s.Owner.Team,
		Contact:    s.Owner.Contact,
		Rationale:  s.Attribution.Rationale,
		Summary:    s.Assessment.Summary,
		FirstSeen:  s.FirstSeen,
		LastSeen:   s.LastSeen,
		Findings:   s.Findings,
		Evidence:   s.Attribution.Evidence,
		Factors:    s.Assessment.Factors,
		Escalation: s.Owner.Escalation,
	}
	for _, svc := range s.Services {
		a.Services = append(a.Services, serviceJSON{Port: svc.Port, IP: svc.IP, Product: svc.Product, TLS: svc.TLS, HTTP: svc.HTTP})
	}
	return a
}

func (w *Writer) writeJSON(d Data) (string, error) {
	rep := jsonReport{
		RunID: d.RunID, GeneratedAt: d.GeneratedAt, Organisation: d.Organisation,
		Stats: d.Stats, Gate: d.GateSummary, Changes: d.Changes,
	}
	for _, s := range d.Snapshots {
		rep.Assets = append(rep.Assets, toAssetJSON(s))
	}
	path := w.path("inventory.json")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return "", err
	}
	return path, nil
}

// --- CSV ----------------------------------------------------------------

// csvHeader is the column order expected by the usual ticketing import
// templates (team, asset, severity, evidence).
var csvHeader = []string{
	"asset_key", "asset_name", "team", "contact", "band", "score", "verdict", "class",
	"port", "service", "finding", "severity", "evidence", "remediation", "escalation", "first_seen", "last_seen",
}

func (w *Writer) writeCSV(d Data) (string, error) {
	path := w.path("findings.csv")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	cw := csv.NewWriter(f)
	defer cw.Flush()
	if err := cw.Write(csvHeader); err != nil {
		return "", err
	}
	for _, s := range d.Snapshots {
		if !reportable(s) {
			continue
		}
		ports := make([]int, 0, len(s.Services))
		for _, svc := range s.Services {
			ports = append(ports, svc.Port)
		}
		portStr := joinInts(ports)
		if len(s.Findings) == 0 {
			row := []string{
				s.Key, s.Host.Name, s.Owner.Team, s.Owner.Contact, string(s.Assessment.Band),
				fmt.Sprintf("%.0f", s.Assessment.Score), string(s.Attribution.Verdict), string(s.Attribution.Class),
				portStr, "", "", "", s.Assessment.Summary, "", s.Owner.Escalation,
				s.FirstSeen.Format(time.RFC3339), s.LastSeen.Format(time.RFC3339),
			}
			if err := cw.Write(row); err != nil {
				return "", err
			}
			continue
		}
		for _, fd := range s.Findings {
			row := []string{
				s.Key, s.Host.Name, s.Owner.Team, s.Owner.Contact, string(s.Assessment.Band),
				fmt.Sprintf("%.0f", s.Assessment.Score), string(s.Attribution.Verdict), string(s.Attribution.Class),
				portStr, fd.Service, fd.Title, string(fd.Severity), fd.Evidence, fd.Remediation, s.Owner.Escalation,
				s.FirstSeen.Format(time.RFC3339), s.LastSeen.Format(time.RFC3339),
			}
			if err := cw.Write(row); err != nil {
				return "", err
			}
		}
	}
	return path, cw.Error()
}

// --- markdown -----------------------------------------------------------

func (w *Writer) writeMarkdown(d Data) (string, error) {
	path := w.path("summary.md")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return path, w.markdown(f, d, "")
}

// writeTeamBundles writes one markdown file per team plus a change feed.
func (w *Writer) writeTeamBundles(d Data) ([]string, error) {
	byTeam := groupByTeam(d.Snapshots)
	var paths []string

	// The change feed is organisation-wide; it is not split per team because a
	// new asset often arrives before anyone knows whose it is.
	chPath, err := w.writeChanges(d)
	if err != nil {
		return paths, err
	}
	paths = append(paths, chPath)

	teams := make([]string, 0, len(byTeam))
	for t := range byTeam {
		teams = append(teams, t)
	}
	sort.Strings(teams)

	teamDir := filepath.Join(w.dir, "teams")
	if err := os.MkdirAll(teamDir, 0o750); err != nil {
		return paths, err
	}
	for _, team := range teams {
		name := sanitize(team)
		p := filepath.Join(teamDir, name+".md")
		f, err := os.Create(p)
		if err != nil {
			return paths, err
		}
		err = w.markdown(f, d, team)
		f.Close()
		if err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func (w *Writer) markdown(out io.Writer, d Data, team string) error {
	snaps := d.Snapshots
	if team != "" {
		snaps = groupByTeam(d.Snapshots)[team]
	}
	fmt.Fprintf(out, "# External attack surface — %s\n\n", d.Organisation)
	if team != "" {
		fmt.Fprintf(out, "**Team:** %s  \n", team)
	}
	fmt.Fprintf(out, "**Generated:** %s  \n", d.GeneratedAt.Format(time.RFC1123))
	fmt.Fprintf(out, "**Run:** `%s`  \n", d.RunID)
	if d.GateSummary != "" {
		fmt.Fprintf(out, "**Safety gate:** %s  \n", d.GateSummary)
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "## Summary")
	fmt.Fprintln(out)
	counts := bandCounts(snaps)
	fmt.Fprintln(out, "| Band | Assets |")
	fmt.Fprintln(out, "|------|--------|")
	for _, b := range []model.Band{model.BandCritical, model.BandHigh, model.BandMedium, model.BandLow, model.BandInfo} {
		fmt.Fprintf(out, "| %s | %d |\n", b, counts[b])
	}
	fmt.Fprintln(out)

	if team == "" {
		fmt.Fprintln(out, "## Recommended actions by team")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "| Team | Critical | High | Highest score |")
		fmt.Fprintln(out, "|------|----------|------|---------------|")
		for _, t := range teamOrder(snaps) {
			list := groupByTeam(snaps)[t]
			top := 0.0
			crit, high := 0, 0
			for _, s := range list {
				if s.Assessment.Score > top {
					top = s.Assessment.Score
				}
				switch s.Assessment.Band {
				case model.BandCritical:
					crit++
				case model.BandHigh:
					high++
				}
			}
			fmt.Fprintf(out, "| %s | %d | %d | %.0f |\n", t, crit, high, top)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintln(out, "## Ranked assets")
	fmt.Fprintln(out)
	// Sort a copy, then apply TopN. Slicing before sorting would take the
	// first N in arrival order rather than the N riskiest, and sorting a
	// subslice would mutate the shared backing array that later sections read.
	source := d.Snapshots
	if team != "" {
		source = snaps
	}
	top := append([]*model.Snapshot(nil), source...)
	sort.SliceStable(top, func(i, j int) bool {
		if top[i].Assessment.Band.Rank() != top[j].Assessment.Band.Rank() {
			return top[i].Assessment.Band.Rank() < top[j].Assessment.Band.Rank()
		}
		return top[i].Assessment.Score > top[j].Assessment.Score
	})
	// A per-team bundle already contains only that team's assets and should be
	// complete; TopN applies to the organisation-wide summary.
	if team == "" && w.cfg.Outputs.TopN > 0 && len(top) > w.cfg.Outputs.TopN {
		top = top[:w.cfg.Outputs.TopN]
	}
	for _, s := range top {
		if !reportable(s) {
			continue
		}
		writeAssetMD(out, s)
	}

	fmt.Fprintln(out, "## Candidate assets outside scope")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "These were discovered but are not attributed to the organisation. They are listed so the")
	fmt.Fprintln(out, "decision to exclude them is visible and reviewable, not implicit.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| Asset | Verdict | Score | Why |")
	fmt.Fprintln(out, "|-------|---------|-------|-----|")
	shown := 0
	for _, s := range d.Snapshots {
		if reportable(s) {
			continue
		}
		if team != "" && s.Owner.Team != team {
			continue
		}
		if shown >= 25 {
			fmt.Fprintf(out, "| … | | | %d more |\n", countCandidates(d.Snapshots, team)-shown)
			break
		}
		fmt.Fprintf(out, "| %s | %s | %.0f | %s |\n", esc(s.Host.Name), s.Attribution.Verdict, s.Attribution.Score, esc(s.Attribution.Rationale))
		shown++
	}
	return nil
}

func writeAssetMD(out io.Writer, s *model.Snapshot) {
	fmt.Fprintf(out, "### %s — %s (score %.0f)\n\n", esc(s.Host.Name), s.Assessment.Band, s.Assessment.Score)
	fmt.Fprintf(out, "- **Asset id:** `%s`\n", s.Key)
	fmt.Fprintf(out, "- **Owner:** %s (%s)\n", esc(s.Owner.Team), esc(s.Owner.Contact))
	fmt.Fprintf(out, "- **Attribution:** %s / %s (score %.1f) — %s\n",
		s.Attribution.Verdict, s.Attribution.Class, s.Attribution.Score, esc(s.Attribution.Rationale))
	if s.Owner.Escalation != "" {
		fmt.Fprintf(out, "- **Escalation:** %s\n", esc(s.Owner.Escalation))
	}
	if len(s.Host.Addresses()) > 0 {
		fmt.Fprintf(out, "- **Addresses:** %s\n", strings.Join(s.Host.Addresses(), ", "))
	}
	fmt.Fprintln(out)
	if len(s.Assessment.Factors) > 0 {
		fmt.Fprintln(out, "| Factor | Weight | Detail |")
		fmt.Fprintln(out, "|--------|--------|--------|")
		for _, f := range s.Assessment.Factors {
			fmt.Fprintf(out, "| %s | %.0f | %s |\n", esc(f.Title), f.Weight, esc(f.Detail))
		}
		fmt.Fprintln(out)
	}
	if len(s.Findings) > 0 {
		for _, fd := range s.Findings {
			fmt.Fprintf(out, "- **[%s]** %s — %s\n", fd.Severity, esc(fd.Title), esc(fd.Evidence))
			fmt.Fprintf(out, "  - _Fix:_ %s\n", esc(fd.Remediation))
		}
		fmt.Fprintln(out)
	}
}

// --- changes ------------------------------------------------------------

func (w *Writer) writeChanges(d Data) (string, error) {
	path := w.path("changes.md")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fmt.Fprintf(f, "# Change feed — %s\n\n", d.Organisation)
	fmt.Fprintf(f, "**Generated:** %s  \n**Run:** `%s`\n\n", d.GeneratedAt.Format(time.RFC1123), d.RunID)
	if len(d.Changes) == 0 {
		fmt.Fprintln(f, "No changes since the previous run.")
		return path, nil
	}
	fmt.Fprintln(f, "| Severity | Change | Asset | Team | Detail |")
	fmt.Fprintln(f, "|----------|--------|-------|------|--------|")
	for _, c := range d.Changes {
		fmt.Fprintf(f, "| %s | %s | %s | %s | %s |\n",
			c.Severity, esc(c.Summary), esc(c.AssetName), esc(c.Team), esc(c.Detail))
	}
	return path, nil
}

// --- helpers ------------------------------------------------------------

// reportable reports whether an asset belongs in the ranked, dispatched
// sections. It must agree with attribution.InScope: an asset we would not scan
// is not one we hand to a team as a confirmed problem. "Possible" candidates
// are still listed, but in the reviewable out-of-scope section, with the reason
// they were not promoted.
func reportable(s *model.Snapshot) bool {
	switch s.Attribution.Verdict {
	case model.VerdictConfirmed, model.VerdictProbable:
		return true
	default:
		return false
	}
}

func groupByTeam(snaps []*model.Snapshot) map[string][]*model.Snapshot {
	m := map[string][]*model.Snapshot{}
	for _, s := range snaps {
		if !reportable(s) {
			continue
		}
		team := s.Owner.Team
		if team == "" {
			team = "unowned"
		}
		m[team] = append(m[team], s)
	}
	return m
}

func teamOrder(snaps []*model.Snapshot) []string {
	byTeam := groupByTeam(snaps)
	type stat struct {
		crit, high int
		top        float64
	}
	stats := map[string]stat{}
	for team, list := range byTeam {
		var st stat
		for _, s := range list {
			switch s.Assessment.Band {
			case model.BandCritical:
				st.crit++
			case model.BandHigh:
				st.high++
			}
			if s.Assessment.Score > st.top {
				st.top = s.Assessment.Score
			}
		}
		stats[team] = st
	}
	teams := make([]string, 0, len(stats))
	for t := range stats {
		teams = append(teams, t)
	}
	sort.Slice(teams, func(i, j int) bool {
		si, sj := stats[teams[i]], stats[teams[j]]
		if si.crit != sj.crit {
			return si.crit > sj.crit
		}
		if si.high != sj.high {
			return si.high > sj.high
		}
		return teams[i] < teams[j]
	})
	return teams
}

func bandCounts(snaps []*model.Snapshot) map[model.Band]int {
	m := map[model.Band]int{}
	for _, s := range snaps {
		if reportable(s) {
			m[s.Assessment.Band]++
		}
	}
	return m
}

func countCandidates(snaps []*model.Snapshot, team string) int {
	n := 0
	for _, s := range snaps {
		if !reportable(s) && (team == "" || s.Owner.Team == team) {
			n++
		}
	}
	return n
}

func esc(s string) string {
	// Markdown table cells must not contain raw pipes or newlines.
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func sanitize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '/':
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "unowned"
	}
	return b.String()
}

func joinInts(in []int) string {
	parts := make([]string, len(in))
	for i, n := range in {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, " ")
}
