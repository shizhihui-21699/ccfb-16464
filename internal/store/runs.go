package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"asm/internal/model"
)

// RunRecord describes a stored run.
type RunRecord struct {
	ID         string
	StartedAt  time.Time
	FinishedAt time.Time
	Stats      model.RunStats
}

// Runs returns recent runs, newest first.
func (s *Store) Runs(ctx context.Context, limit int) ([]RunRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, started_at, COALESCE(finished_at,''), COALESCE(stats,'') FROM runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	var out []RunRecord
	for rows.Next() {
		var r RunRecord
		var started, finished, stats string
		if err := rows.Scan(&r.ID, &started, &finished, &stats); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, started); err == nil {
			r.StartedAt = t
		}
		if finished != "" {
			if t, err := time.Parse(time.RFC3339Nano, finished); err == nil {
				r.FinishedAt = t
			}
		}
		if stats != "" {
			_ = json.Unmarshal([]byte(stats), &r.Stats)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
