package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"asm/internal/model"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testSnapshot(name string) *model.Snapshot {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.Snapshot{
		Key:              model.StableID("a", name),
		Host:             model.Host{Name: name, Apex: "example.com", IPs: []string{"203.0.113.1"}},
		Attribution:      model.Attribution{Verdict: model.VerdictConfirmed, Class: model.ClassCompany, Score: 5},
		Assessment:       model.Assessment{Band: model.BandHigh, Score: 70},
		Owner:            model.Owner{Team: "platform"},
		StateFingerprint: "fp-1",
		LastSeen:         now,
	}
}

func TestSaveAndGet(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	snap := testSnapshot("app.example.com")

	res, err := s.Save(ctx, snap)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if !res.Created {
		t.Error("first save should report Created")
	}

	got, err := s.Get(ctx, snap.Key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("snapshot not found")
	}
	if got.Host.Name != "app.example.com" {
		t.Errorf("name = %q", got.Host.Name)
	}
	if got.Assessment.Score != 70 {
		t.Errorf("score = %v", got.Assessment.Score)
	}
}

func TestFirstSeenIsPreservedAcrossRuns(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	snap := testSnapshot("app.example.com")
	firstSeen := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	snap.LastSeen = firstSeen
	if _, err := s.Save(ctx, snap); err != nil {
		t.Fatal(err)
	}

	// A later run re-observes the asset with the same state.
	later := testSnapshot("app.example.com")
	later.LastSeen = time.Now().UTC().Truncate(time.Second)
	later.StateFingerprint = "fp-1"
	res, err := s.Save(ctx, later)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Error("unchanged fingerprint should not report a change")
	}

	got, _ := s.Get(ctx, snap.Key)
	if diff := got.FirstSeen.Sub(firstSeen); diff > time.Second || diff < -time.Second {
		t.Errorf("first_seen not preserved: %s vs %s", got.FirstSeen, firstSeen)
	}
	// last_changed should stay at the original observation, not move forward.
	if got.LastChanged.After(firstSeen.Add(2 * time.Second)) {
		t.Errorf("last_changed moved without a state change: %s", got.LastChanged)
	}
}

func TestChangedFingerprintUpdatesLastChanged(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	snap := testSnapshot("app.example.com")
	snap.StateFingerprint = "fp-1"
	if _, err := s.Save(ctx, snap); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	changed := testSnapshot("app.example.com")
	changed.StateFingerprint = "fp-2"
	changed.LastSeen = time.Now().UTC().Truncate(time.Second)
	res, err := s.Save(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Error("a new fingerprint should report Changed")
	}
	got, _ := s.Get(ctx, snap.Key)
	if !got.LastChanged.Equal(changed.LastSeen) {
		t.Errorf("last_changed = %s, want %s", got.LastChanged, changed.LastSeen)
	}
}

func TestListOrdersBySeverity(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	crit := testSnapshot("crit.example.com")
	crit.Assessment = model.Assessment{Band: model.BandCritical, Score: 95}
	low := testSnapshot("low.example.com")
	low.Assessment = model.Assessment{Band: model.BandLow, Score: 25}
	for _, snap := range []*model.Snapshot{low, crit} {
		if _, err := s.Save(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Host.Name != "crit.example.com" {
		t.Errorf("expected critical first, got %v", list)
	}
}

func TestEvents(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	c := model.Change{
		At:        time.Now().UTC(),
		Kind:      model.ChangeNewPort,
		AssetKey:  "a-1",
		AssetName: "app.example.com",
		Severity:  model.SevHigh,
		Summary:   "New port 3306",
	}
	if err := s.AppendEvent(ctx, c, "run-1"); err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Summary != "New port 3306" {
		t.Errorf("events = %+v", events)
	}
	timeline, err := s.Timeline(ctx, "a-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline) != 1 {
		t.Errorf("timeline = %+v", timeline)
	}
}

func TestRuns(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Second)
	if err := s.StartRun(ctx, "run-1", start); err != nil {
		t.Fatal(err)
	}
	stats := model.RunStats{AssetsSeen: 10, AssetsScoped: 7}
	if err := s.FinishRun(ctx, "run-1", start.Add(time.Minute), stats); err != nil {
		t.Fatal(err)
	}
	id, got, at, err := s.LastRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id != "run-1" {
		t.Errorf("id = %q", id)
	}
	if got.AssetsSeen != 10 || got.AssetsScoped != 7 {
		t.Errorf("stats = %+v", got)
	}
	if at.IsZero() {
		t.Error("finish time not recorded")
	}
}

func TestStableIDsAreStable(t *testing.T) {
	a := model.StableID("a", "www.example.com")
	b := model.StableID("a", "WWW.Example.com")
	if a != b {
		t.Errorf("id should be case-insensitive and stable: %q vs %q", a, b)
	}
	c := model.StableID("a", "api.example.com")
	if a == c {
		t.Error("different assets should have different ids")
	}
}

func TestConcurrentSaves(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			_, err := s.Save(ctx, testSnapshot("host-"+string(rune('a'+i))+".example.com"))
			errs <- err
		}(i)
	}
	for i := 0; i < 20; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent save failed: %v", err)
		}
	}
	n, err := s.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 20 {
		t.Errorf("expected 20 assets, got %d", n)
	}
}
