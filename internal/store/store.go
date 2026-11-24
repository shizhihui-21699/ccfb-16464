// Package store persists snapshots between runs so that the tool can tell
// what changed since yesterday.
//
// The store keeps two kinds of history per asset: the latest materialised
// snapshot (fast to load, used by the scheduler) and an append-only event log
// (used to answer "when did this port open" and to build a timeline for an
// incident). Run records make each pipeline execution auditable.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"asm/internal/model"
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create store dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// A long-running daemon has one writer; a small pool keeps reads cheap.
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS assets (
	key              TEXT PRIMARY KEY,
	name             TEXT NOT NULL,
	apex             TEXT,
	verdict          TEXT NOT NULL,
	class            TEXT NOT NULL,
	score            REAL NOT NULL,
	band             TEXT NOT NULL,
	team             TEXT,
	state_fingerprint TEXT NOT NULL,
	first_seen       TEXT NOT NULL,
	last_seen        TEXT NOT NULL,
	last_changed     TEXT NOT NULL,
	snapshot         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_band ON assets(band, score DESC);
CREATE INDEX IF NOT EXISTS idx_assets_team ON assets(team);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(name);
CREATE INDEX IF NOT EXISTS idx_assets_verdict ON assets(verdict);

CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	asset_key  TEXT NOT NULL,
	asset_name TEXT NOT NULL,
	kind       TEXT NOT NULL,
	at         TEXT NOT NULL,
	severity   TEXT,
	summary    TEXT,
	detail     TEXT,
	run_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset_key, at DESC);
CREATE INDEX IF NOT EXISTS idx_events_at ON events(at DESC);

CREATE TABLE IF NOT EXISTS runs (
	id          TEXT PRIMARY KEY,
	started_at  TEXT NOT NULL,
	finished_at TEXT,
	stats       TEXT
);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}
	return nil
}

// SaveResult reports what changed when a snapshot was saved.
type SaveResult struct {
	Created bool
	Updated bool
	Changed bool // state fingerprint differs from the stored one
}

// Save materialises a snapshot, replacing the prior row.
func (s *Store) Save(ctx context.Context, snap *model.Snapshot) (SaveResult, error) {
	var res SaveResult
	var prevFP, prevFirst string
	err := s.db.QueryRowContext(ctx, `SELECT state_fingerprint, first_seen FROM assets WHERE key = ?`, snap.Key).
		Scan(&prevFP, &prevFirst)
	switch {
	case err == sql.ErrNoRows:
		res.Created = true
	case err != nil:
		return res, fmt.Errorf("read prior asset: %w", err)
	default:
		res.Updated = true
		if prevFP != snap.StateFingerprint {
			res.Changed = true
		}
	}
	if res.Created {
		if snap.FirstSeen.IsZero() {
			snap.FirstSeen = snap.LastSeen
		}
		if snap.LastChanged.IsZero() {
			snap.LastChanged = snap.LastSeen
		}
	} else {
		// Preserve the original first-seen; it is the asset's age.
		var prevChanged string
		_ = s.db.QueryRowContext(ctx, `SELECT last_changed FROM assets WHERE key = ?`, snap.Key).Scan(&prevChanged)
		if t, err := time.Parse(time.RFC3339Nano, prevFirst); err == nil {
			snap.FirstSeen = t
		}
		if res.Changed {
			// The observable state moved, so this observation is the change
			// time. The caller supplies it in LastSeen.
			if snap.LastChanged.IsZero() {
				snap.LastChanged = snap.LastSeen
			}
		} else if t, err := time.Parse(time.RFC3339Nano, prevChanged); err == nil {
			// Unchanged: last_changed tracks observable change, not mere
			// re-observation, so it keeps its previous value.
			snap.LastChanged = t
		}
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		return res, fmt.Errorf("marshal snapshot: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO assets (key, name, apex, verdict, class, score, band, team, state_fingerprint, first_seen, last_seen, last_changed, snapshot)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
	name=excluded.name, apex=excluded.apex, verdict=excluded.verdict, class=excluded.class,
	score=excluded.score, band=excluded.band, team=excluded.team,
	state_fingerprint=excluded.state_fingerprint, first_seen=excluded.first_seen,
	last_seen=excluded.last_seen, last_changed=excluded.last_changed, snapshot=excluded.snapshot`,
		snap.Key, snap.Host.Name, snap.Host.Apex, string(snap.Attribution.Verdict), string(snap.Attribution.Class),
		snap.Assessment.Score, string(snap.Assessment.Band), snap.Owner.Team,
		snap.StateFingerprint,
		snap.FirstSeen.UTC().Format(time.RFC3339Nano), snap.LastSeen.UTC().Format(time.RFC3339Nano),
		snap.LastChanged.UTC().Format(time.RFC3339Nano), string(raw))
	if err != nil {
		return res, fmt.Errorf("save asset: %w", err)
	}
	return res, nil
}

// Get returns one snapshot by key.
func (s *Store) Get(ctx context.Context, key string) (*model.Snapshot, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT snapshot FROM assets WHERE key = ?`, key).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var snap model.Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snap, nil
}

// Previous returns all snapshots from the last completed run, keyed by asset
// key. It is what the diff engine compares against.
func (s *Store) Previous(ctx context.Context) (map[string]*model.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, snapshot FROM assets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*model.Snapshot{}
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		var snap model.Snapshot
		if err := json.Unmarshal([]byte(raw), &snap); err != nil {
			return nil, err
		}
		out[key] = &snap
	}
	return out, rows.Err()
}

// List returns snapshots ordered by band severity then score, descending.
func (s *Store) List(ctx context.Context) ([]*model.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT snapshot FROM assets
ORDER BY CASE band WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, score DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Snapshot
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var snap model.Snapshot
		if err := json.Unmarshal([]byte(raw), &snap); err != nil {
			return nil, err
		}
		out = append(out, &snap)
	}
	return out, rows.Err()
}

// AppendEvent records one change event.
func (s *Store) AppendEvent(ctx context.Context, c model.Change, runID string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO events (asset_key, asset_name, kind, at, severity, summary, detail, run_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.AssetKey, c.AssetName, string(c.Kind), c.At.UTC().Format(time.RFC3339Nano),
		string(c.Severity), c.Summary, c.Detail, runID)
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return nil
}

// Events returns recent events, most recent first.
func (s *Store) Events(ctx context.Context, limit int) ([]model.Change, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT asset_key, asset_name, kind, at, severity, summary, detail, run_id
FROM events ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Change
	for rows.Next() {
		var c model.Change
		var kind, sev, at string
		if err := rows.Scan(&c.AssetKey, &c.AssetName, &kind, &at, &sev, &c.Summary, &c.Detail, &c.RunID); err != nil {
			return nil, err
		}
		c.Kind = model.ChangeKind(kind)
		c.Severity = model.Severity(sev)
		if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
			c.At = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Timeline returns the event history for one asset.
func (s *Store) Timeline(ctx context.Context, assetKey string, limit int) ([]model.Change, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT asset_key, asset_name, kind, at, severity, summary, detail, run_id
FROM events WHERE asset_key = ? ORDER BY at DESC LIMIT ?`, assetKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Change
	for rows.Next() {
		var c model.Change
		var kind, sev, at string
		if err := rows.Scan(&c.AssetKey, &c.AssetName, &kind, &at, &sev, &c.Summary, &c.Detail, &c.RunID); err != nil {
			return nil, err
		}
		c.Kind = model.ChangeKind(kind)
		c.Severity = model.Severity(sev)
		if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
			c.At = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// StartRun records a run start.
func (s *Store) StartRun(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO runs (id, started_at) VALUES (?, ?)`,
		id, at.UTC().Format(time.RFC3339Nano))
	return err
}

// FinishRun records a run's completion and stats.
func (s *Store) FinishRun(ctx context.Context, id string, at time.Time, stats model.RunStats) error {
	raw, _ := json.Marshal(stats)
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET finished_at = ?, stats = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339Nano), string(raw), id)
	return err
}

// LastRun returns the most recent completed run's id, stats and finish time.
func (s *Store) LastRun(ctx context.Context) (id string, stats model.RunStats, at time.Time, err error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, stats, finished_at FROM runs WHERE finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1`)
	var statsRaw, finishedAt string
	if err = row.Scan(&id, &statsRaw, &finishedAt); err != nil {
		if err == sql.ErrNoRows {
			return "", stats, time.Time{}, nil
		}
		return "", stats, time.Time{}, err
	}
	if statsRaw != "" {
		_ = json.Unmarshal([]byte(statsRaw), &stats)
	}
	if t, perr := time.Parse(time.RFC3339Nano, finishedAt); perr == nil {
		at = t
	}
	return id, stats, at, nil
}

// MarkGone records that an asset was not observed this run without deleting
// it; the row keeps its history and is excluded from active reports.
func (s *Store) MarkGone(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE assets SET band = 'info', score = 0 WHERE key = ?`, key)
	return err
}

// Delete removes an asset and its events. Used only when an operator asks.
func (s *Store) Delete(ctx context.Context, key string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE asset_key = ?`, key); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM assets WHERE key = ?`, key)
	return err
}

// Count returns the number of stored assets.
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets`).Scan(&n)
	return n, err
}
