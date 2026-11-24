package diff

import (
	"testing"
	"time"

	"asm/internal/model"
)

var fixedNow = time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)

func newComparer() *Comparer {
	c := New()
	c.SetClock(func() time.Time { return fixedNow })
	return c
}

func snap(key, name string) *model.Snapshot {
	return &model.Snapshot{
		Key:              key,
		Host:             model.Host{Name: name, IPs: []string{"203.0.113.1"}},
		Attribution:      model.Attribution{Verdict: model.VerdictConfirmed, Class: model.ClassCompany},
		Assessment:       model.Assessment{Band: model.BandLow, Score: 20},
		Owner:            model.Owner{Team: "platform"},
		FirstSeen:        fixedNow.Add(-48 * time.Hour),
		LastSeen:         fixedNow,
		StateFingerprint: "fp-1",
	}
}

func kinds(changes []model.Change) map[model.ChangeKind]int {
	m := map[model.ChangeKind]int{}
	for _, c := range changes {
		m[c.Kind]++
	}
	return m
}

func TestNewAndGoneAssets(t *testing.T) {
	prev := map[string]*model.Snapshot{"a-old": snap("a-old", "old.example.com")}
	cur := []*model.Snapshot{snap("a-new", "new.example.com")}
	res := newComparer().Compare(prev, cur, "run-1")
	k := kinds(res.Changes)
	if k[model.ChangeNewAsset] != 1 {
		t.Errorf("expected one new asset, got %v", k)
	}
	if k[model.ChangeGoneAsset] != 1 {
		t.Errorf("expected one gone asset, got %v", k)
	}
}

func TestNewPortIsHighForDatabase(t *testing.T) {
	prevSnap := snap("a-1", "db.example.com")
	prev := map[string]*model.Snapshot{"a-1": prevSnap}
	cur := []*model.Snapshot{snap("a-1", "db.example.com")}
	cur[0].Services = []model.Service{{Port: 3306}}

	res := newComparer().Compare(prev, cur, "run-2")
	var newPort *model.Change
	for i := range res.Changes {
		if res.Changes[i].Kind == model.ChangeNewPort {
			newPort = &res.Changes[i]
		}
	}
	if newPort == nil {
		t.Fatal("expected a new-port change")
	}
	if newPort.Severity != model.SevCritical {
		t.Errorf("a newly exposed mysql port should be critical, got %s", newPort.Severity)
	}
}

func TestPortClosed(t *testing.T) {
	prevSnap := snap("a-1", "app.example.com")
	prevSnap.Services = []model.Service{{Port: 8080}}
	prev := map[string]*model.Snapshot{"a-1": prevSnap}
	cur := []*model.Snapshot{snap("a-1", "app.example.com")}

	res := newComparer().Compare(prev, cur, "run-2")
	if kinds(res.Changes)[model.ChangePortClosed] != 1 {
		t.Errorf("expected a port-closed change, got %v", kinds(res.Changes))
	}
}

func TestCertChange(t *testing.T) {
	prevSnap := snap("a-1", "app.example.com")
	prevSnap.Services = []model.Service{{Port: 443, TLS: &model.TLS{FingerprintSHA256: "aaa"}}}
	prev := map[string]*model.Snapshot{"a-1": prevSnap}
	cur := []*model.Snapshot{snap("a-1", "app.example.com")}
	cur[0].Services = []model.Service{{Port: 443, TLS: &model.TLS{FingerprintSHA256: "bbb"}}}

	res := newComparer().Compare(prev, cur, "run-2")
	if kinds(res.Changes)[model.ChangeCertChanged] != 1 {
		t.Errorf("expected a cert-changed change, got %v", kinds(res.Changes))
	}
}

func TestFindingAddedAndFixed(t *testing.T) {
	prevSnap := snap("a-1", "app.example.com")
	prevSnap.Findings = []model.Finding{{Key: "f1", Title: "Old issue", Severity: model.SevMedium}}
	prev := map[string]*model.Snapshot{"a-1": prevSnap}

	cur := []*model.Snapshot{snap("a-1", "app.example.com")}
	cur[0].Findings = []model.Finding{{Key: "f2", Title: "New issue", Severity: model.SevHigh}}

	res := newComparer().Compare(prev, cur, "run-2")
	k := kinds(res.Changes)
	if k[model.ChangeNewFinding] != 1 {
		t.Errorf("expected one new finding, got %v", k)
	}
	if k[model.ChangeFindingFixed] != 1 {
		t.Errorf("expected one fixed finding, got %v", k)
	}
}

func TestRiskBandChange(t *testing.T) {
	prev := map[string]*model.Snapshot{"a-1": snap("a-1", "app.example.com")}
	cur := []*model.Snapshot{snap("a-1", "app.example.com")}
	cur[0].Assessment = model.Assessment{Band: model.BandCritical, Score: 95}

	res := newComparer().Compare(prev, cur, "run-2")
	var risk *model.Change
	for i := range res.Changes {
		if res.Changes[i].Kind == model.ChangeRiskIncreased {
			risk = &res.Changes[i]
		}
	}
	if risk == nil {
		t.Fatal("expected a risk-increase change")
	}
	if risk.Severity != model.SevCritical {
		t.Errorf("critical band should yield critical severity, got %s", risk.Severity)
	}
}

func TestOwnershipChange(t *testing.T) {
	prev := map[string]*model.Snapshot{"a-1": snap("a-1", "app.example.com")}
	cur := []*model.Snapshot{snap("a-1", "app.example.com")}
	cur[0].Owner = model.Owner{Team: "network"}

	res := newComparer().Compare(prev, cur, "run-2")
	if kinds(res.Changes)[model.ChangeOwnershipChange] != 1 {
		t.Errorf("expected an ownership change, got %v", kinds(res.Changes))
	}
}

func TestNoChangeWhenStable(t *testing.T) {
	prevSnap := snap("a-1", "app.example.com")
	prevSnap.Services = []model.Service{{Port: 443, TLS: &model.TLS{FingerprintSHA256: "aaa"}}}
	prev := map[string]*model.Snapshot{"a-1": prevSnap}
	cur := []*model.Snapshot{snap("a-1", "app.example.com")}
	cur[0].Services = []model.Service{{Port: 443, TLS: &model.TLS{FingerprintSHA256: "aaa"}}}
	cur[0].Assessment = prevSnap.Assessment
	cur[0].Owner = prevSnap.Owner
	cur[0].Attribution = prevSnap.Attribution

	res := newComparer().Compare(prev, cur, "run-2")
	if len(res.Changes) != 0 {
		t.Errorf("stable asset produced changes: %+v", res.Changes)
	}
}

// TestRejectedAssetsDoNotChurnGoneEvents keeps the feed honest: candidates
// that were never in scope must not spam "asset gone" every run.
func TestRejectedAssetsDoNotChurnGoneEvents(t *testing.T) {
	prev := snap("a-x", "candidate.example.com")
	prev.Attribution = model.Attribution{Verdict: model.VerdictRejected}
	prevMap := map[string]*model.Snapshot{"a-x": prev}

	res := newComparer().Compare(prevMap, nil, "run-2")
	if len(res.Changes) != 0 {
		t.Errorf("rejected asset produced gone events: %+v", res.Changes)
	}
}

func TestChangesSortedBySeverity(t *testing.T) {
	prev := map[string]*model.Snapshot{"a-1": snap("a-1", "app.example.com")}
	cur := []*model.Snapshot{snap("a-1", "app.example.com")}
	cur[0].Services = []model.Service{{Port: 3306}, {Port: 8080}}
	cur[0].Assessment = model.Assessment{Band: model.BandCritical}

	res := newComparer().Compare(prev, cur, "run-2")
	if len(res.Changes) < 2 {
		t.Fatal("expected several changes")
	}
	for i := 1; i < len(res.Changes); i++ {
		if res.Changes[i-1].Severity.Rank() > res.Changes[i].Severity.Rank() {
			t.Errorf("changes not sorted by severity at %d: %s then %s",
				i, res.Changes[i-1].Severity, res.Changes[i].Severity)
		}
	}
}
