package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCTFixtureFiltersByApex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.jsonl")
	now := time.Now()
	content := `{"name":"a.example.com","issuer":"LE","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}
{"name":"b.other.com","issuer":"LE","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}
{"name":"*.example.com","issuer":"LE","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `","wildcard":true}
{"name":"expired.example.com","issuer":"LE","not_after":"` + now.Add(-time.Hour).Format(time.RFC3339) + `"}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewCTSource(CTConfig{
		Providers:      []string{"fixture"},
		Fixtures:       []string{path},
		MaxEntries:     100,
		IncludeExpired: true,
		Timeout:        time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Fetch(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	names := map[string]Candidate{}
	for _, c := range got {
		names[c.Name] = c
	}
	if _, ok := names["b.other.com"]; ok {
		t.Error("CT source returned a name outside the apex")
	}
	if c, ok := names["a.example.com"]; !ok {
		t.Error("missing in-apex name")
	} else if c.Wildcard {
		t.Error("a.example.com should not be flagged wildcard")
	}
	if c, ok := names["*.example.com"]; ok && !c.Wildcard {
		t.Error("wildcard entry should be flagged wildcard")
	}
	if _, ok := names["expired.example.com"]; !ok {
		t.Error("expired names should be kept when include_expired is true")
	}
}

func TestCTFixtureExcludesExpiredWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.jsonl")
	now := time.Now()
	content := `{"name":"old.example.com","issuer":"LE","not_after":"` + now.Add(-time.Hour).Format(time.RFC3339) + `"}
{"name":"new.example.com","issuer":"LE","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewCTSource(CTConfig{
		Providers:      []string{"fixture"},
		Fixtures:       []string{path},
		MaxEntries:     100,
		IncludeExpired: false,
		Timeout:        time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := src.Fetch(context.Background(), "example.com")
	for _, c := range got {
		if c.Name == "old.example.com" {
			t.Error("expired name should be excluded when include_expired is false")
		}
	}
}

func TestCTSourceRejectsUnknownProvider(t *testing.T) {
	_, err := NewCTSource(CTConfig{Providers: []string{"nope"}}, nil)
	if err == nil {
		t.Fatal("unknown provider should be an error, not a silent no-op")
	}
}

func TestCTMaxEntriesIsRespected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.jsonl")
	now := time.Now()
	content := ""
	for i := 0; i < 50; i++ {
		content += `{"name":"h` + string(rune('a'+i%26)) + `-` + string(rune('a'+i/26)) + `.example.com","issuer":"LE","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}` + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewCTSource(CTConfig{
		Providers:      []string{"fixture"},
		Fixtures:       []string{path},
		MaxEntries:     5,
		IncludeExpired: true,
		Timeout:        time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := src.Fetch(context.Background(), "example.com")
	if len(got) > 5 {
		t.Errorf("max_entries not enforced: got %d", len(got))
	}
}
