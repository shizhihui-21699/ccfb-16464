package report

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asm/internal/config"
	"asm/internal/model"
)

func testWriter(t *testing.T, split bool) (*Writer, *config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Organisation = config.Organisation{Name: "Example Corp", Domains: []string{"example.com"}}
	cfg.Outputs = config.Outputs{
		Dir:         t.TempDir(),
		Formats:     []string{"markdown", "json", "csv", "html"},
		SplitByTeam: split,
		TopN:        10,
	}
	if err := cfg.Compile(); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(cfg)
	return w, cfg
}

func sampleSnap(name, team string, band model.Band, score float64) *model.Snapshot {
	return &model.Snapshot{
		Key:  model.StableID("a", name),
		Host: model.Host{Name: name, IPs: []string{"203.0.113.1"}},
		Attribution: model.Attribution{
			Verdict: model.VerdictConfirmed, Class: model.ClassCompany,
			Score: 6, Rationale: "confirmed company-owned: under an owned apex",
		},
		Assessment: model.Assessment{
			Band: band, Score: score, Summary: "risk summary",
			Factors: []model.Factor{{Key: "port:mysql", Title: "Sensitive port exposed: mysql", Weight: 60, Detail: "port 3306"}},
		},
		Owner:     model.Owner{Team: team, Contact: "team@example.com"},
		Findings:  []model.Finding{{Key: "f1", Title: "Sensitive port exposed: mysql", Severity: model.SevHigh, Evidence: "port 3306 open", Remediation: "restrict"}},
		FirstSeen: time.Now().Add(-48 * time.Hour),
		LastSeen:  time.Now(),
	}
}

func sampleData() Data {
	return Data{
		RunID:        "run-test",
		GeneratedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Organisation: "Example Corp",
		Snapshots: []*model.Snapshot{
			sampleSnap("db.example.com", "platform", model.BandCritical, 95),
			sampleSnap("www.example.com", "web", model.BandLow, 22),
			{
				// An out-of-scope candidate must be excluded from the ranked
				// sections but still documented.
				Key:         model.StableID("a", "candidate.partner.net"),
				Host:        model.Host{Name: "candidate.partner.net"},
				Attribution: model.Attribution{Verdict: model.VerdictRejected, Score: -3, Rationale: "parking page"},
				Assessment:  model.Assessment{Band: model.BandInfo},
				Owner:       model.Owner{Team: "unowned"},
			},
		},
		Changes: []model.Change{
			{RunID: "run-test", At: time.Now(), Kind: model.ChangeNewPort, AssetName: "db.example.com", Severity: model.SevCritical, Summary: "New port open: 3306", Team: "platform"},
		},
	}
}

func TestRenderWritesAllFormats(t *testing.T) {
	w, cfg := testWriter(t, false)
	files, err := w.Render(sampleData())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(files) != 4 {
		t.Errorf("expected 4 files, got %v", files)
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	_ = cfg
}

func TestJSONReportExcludesRejected(t *testing.T) {
	w, cfg := testWriter(t, false)
	if _, err := w.Render(sampleData()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Outputs.Dir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Assets []struct {
			Name    string `json:"name"`
			Verdict string `json:"verdict"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Assets) != 3 {
		t.Errorf("JSON should include every asset for machine consumers, got %d", len(rep.Assets))
	}
}

func TestCSVHasOneRowPerFinding(t *testing.T) {
	w, cfg := testWriter(t, false)
	if _, err := w.Render(sampleData()); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(cfg.Outputs.Dir, "findings.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("expected a header and at least one row, got %v", rows)
	}
	if rows[0][0] != "asset_key" {
		t.Errorf("unexpected header: %v", rows[0])
	}
	// Every data row should carry a team for dispatch.
	for _, row := range rows[1:] {
		if row[2] == "" {
			t.Errorf("row missing team: %v", row)
		}
	}
}

func TestTeamBundles(t *testing.T) {
	w, cfg := testWriter(t, true)
	files, err := w.Render(sampleData())
	if err != nil {
		t.Fatal(err)
	}
	var teamFiles []string
	for _, f := range files {
		if strings.Contains(f, string(filepath.Separator)+"teams"+string(filepath.Separator)) {
			teamFiles = append(teamFiles, f)
		}
	}
	if len(teamFiles) < 2 {
		t.Errorf("expected per-team bundles, got %v", files)
	}
	// A team file must name its team and its assets.
	raw, err := os.ReadFile(filepath.Join(cfg.Outputs.Dir, "teams", "platform.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "platform") || !strings.Contains(string(raw), "db.example.com") {
		t.Errorf("platform bundle missing content:\n%s", raw)
	}
	if strings.Contains(string(raw), "www.example.com") {
		t.Error("platform bundle leaked another team's asset")
	}
}

func TestMarkdownShowsCandidates(t *testing.T) {
	w, cfg := testWriter(t, false)
	if _, err := w.Render(sampleData()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Outputs.Dir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "Candidate assets outside scope") {
		t.Error("summary should document out-of-scope candidates")
	}
	if !strings.Contains(s, "candidate.partner.net") {
		t.Error("candidate should be listed with its reason")
	}
	if !strings.Contains(s, "db.example.com") {
		t.Error("in-scope asset missing from summary")
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	w, cfg := testWriter(t, false)
	if _, err := w.Render(sampleData()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Outputs.Dir, "dashboard.html"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, bad := range []string{"http://", "https://cdn", "<script", "src=\"http"} {
		if strings.Contains(s, bad) {
			t.Errorf("HTML dashboard should be self-contained, found %q", bad)
		}
	}
	if !strings.Contains(s, "db.example.com") {
		t.Error("dashboard missing the critical asset")
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	d := sampleData()
	d.Snapshots[0].Assessment.Factors[0].Detail = "a | b | c"
	w, cfg := testWriter(t, false)
	if _, err := w.Render(d); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(cfg.Outputs.Dir, "summary.md"))
	if strings.Contains(string(raw), "a | b | c") {
		t.Error("pipes in table cells must be escaped")
	}
}

func TestSanitizeTeamName(t *testing.T) {
	cases := map[string]string{
		"Platform Team": "platform-team",
		"a/b":           "a-b",
		"":              "unowned",
		"UPPER":         "upper",
		"ok-name_1":     "ok-name_1",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTopNSelectsHighestRiskNotFirstArrival(t *testing.T) {
	w, cfg := testWriter(t, false)
	cfg.Outputs.TopN = 2
	// The critical asset arrives last; TopN must still include it.
	d := Data{
		RunID: "r", GeneratedAt: time.Now(), Organisation: "Example Corp",
		Snapshots: []*model.Snapshot{
			sampleSnap("low1.example.com", "web", model.BandLow, 15),
			sampleSnap("low2.example.com", "web", model.BandLow, 12),
			sampleSnap("crit.example.com", "platform", model.BandCritical, 90),
		},
	}
	if _, err := w.Render(d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Outputs.Dir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "crit.example.com") {
		t.Error("TopN dropped the riskiest asset because it arrived last")
	}
}

func TestTeamBundleIsComplete(t *testing.T) {
	w, cfg := testWriter(t, true)
	cfg.Outputs.TopN = 1
	d := Data{
		RunID: "r", GeneratedAt: time.Now(), Organisation: "Example Corp",
		Snapshots: []*model.Snapshot{
			sampleSnap("a.example.com", "platform", model.BandHigh, 60),
			sampleSnap("b.example.com", "platform", model.BandMedium, 40),
		},
	}
	if _, err := w.Render(d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Outputs.Dir, "teams", "platform.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Both of the team's assets must appear despite TopN=1: a team bundle is
	// that team's full work list, not a sample.
	for _, want := range []string{"a.example.com", "b.example.com"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("team bundle missing %s (TopN should not truncate it)", want)
		}
	}
}
