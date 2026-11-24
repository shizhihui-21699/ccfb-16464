// Package pipeline orchestrates one end-to-end run: discover, attribute,
// probe (safely), score, route, persist, diff and report.
//
// The pipeline is written to be run repeatedly by a scheduler. Every stage is
// idempotent and every stage degrades gracefully: a failed passive source or a
// single unreachable host never aborts the run, because an inventory that is
// missing one data point is still far more useful than no inventory at all.
package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"asm/internal/attribution"
	"asm/internal/config"
	"asm/internal/diff"
	"asm/internal/discovery"
	"asm/internal/model"
	"asm/internal/owner"
	"asm/internal/probe"
	"asm/internal/report"
	"asm/internal/risk"
	"asm/internal/store"
)

// Options control one run.
type Options struct {
	// DryRun overrides the profile to disable active probing entirely.
	DryRun bool
	// NoDiscovery reuses the stored inventory and only re-probes. Useful for a
	// mid-day re-check after a security advisory.
	NoDiscovery bool
	// NoProbe discovery and attribution only.
	NoProbe bool
	// OnlyTeam limits active probing to one team's assets (a focus run).
	OnlyTeam string
	// Log is the structured logger.
	Log *slog.Logger
}

// Pipeline holds the wired components.
type Pipeline struct {
	cfg      *config.Config
	store    *store.Store
	attr     *attribution.Engine
	risk     *risk.Engine
	router   *owner.Router
	gate     *probe.Gate
	prober   *probe.Prober
	comparer *diff.Comparer
	report   *report.Writer
	now      func() time.Time
}

// New wires a pipeline.
func New(cfg *config.Config, st *store.Store, log *slog.Logger) *Pipeline {
	gate := probe.NewGate(cfg)
	return &Pipeline{
		cfg:      cfg,
		store:    st,
		attr:     attribution.NewEngine(cfg),
		risk:     risk.NewEngine(cfg),
		router:   owner.NewRouter(cfg),
		gate:     gate,
		prober:   probe.NewProber(cfg, gate),
		comparer: diff.New(),
		report:   report.NewWriter(cfg),
		now:      time.Now,
	}
}

// SetClock replaces the clock in tests.
func (p *Pipeline) SetClock(fn func() time.Time) {
	p.now = fn
	p.gate.SetClock(fn)
	p.comparer.SetClock(fn)
}

// Result is what a run produced.
type Result struct {
	RunID       string
	Snapshots   []*model.Snapshot
	Changes     []model.Change
	Stats       model.RunStats
	ReportFiles []string
	GateSummary string
}

// Run executes the pipeline once.
func (p *Pipeline) Run(ctx context.Context, opts Options) (*Result, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	started := p.now()
	runID := newRunID(started)
	stats := model.RunStats{ByBand: map[model.Band]int{}, ByTeam: map[string]int{}}

	if err := p.store.StartRun(ctx, runID, started); err != nil {
		log.Warn("could not record run start", "err", err)
	}

	previous, err := p.store.Previous(ctx)
	if err != nil {
		return nil, fmt.Errorf("load previous inventory: %w", err)
	}
	log.Info("run started", "run", runID, "previous_assets", len(previous))

	// --- discovery ------------------------------------------------------
	var hosts []*model.Host
	if opts.NoDiscovery {
		for _, snap := range previous {
			hosts = append(hosts, &snap.Host)
		}
		log.Info("discovery skipped, reusing stored inventory", "hosts", len(hosts))
	} else {
		inv, derr := p.discover(ctx, log)
		if derr != nil {
			log.Warn("discovery completed with errors", "err", derr)
		}
		hosts = inv.Hosts()
	}
	stats.AssetsSeen = len(hosts)

	// --- attribution ----------------------------------------------------
	works := make([]workItem, 0, len(hosts))
	for _, h := range hosts {
		h.FirstSeen = started
		h.LastSeen = started
		att := p.attr.Evaluate(attribution.Input{Host: h, CNAMEChain: append([]string{h.Name}, h.CNAMEs...)})
		works = append(works, workItem{host: h, att: att})
	}

	// --- active probing -------------------------------------------------
	// Only assets that are in scope and whose class permits active probing are
	// touched. Probing happens after attribution precisely so that evidence
	// from passive sources decides what we are allowed to contact.
	services := map[string][]model.Service{}
	if !opts.NoProbe && !p.cfg.Safety.DryRun && !opts.DryRun {
		services = p.probeAll(ctx, works, opts, log, &stats)
	} else {
		// Reuse previously observed services so reports do not regress to
		// empty when a run runs in dry-run mode.
		for _, w := range works {
			if prev, ok := previous[model.StableID("a", w.host.Name)]; ok {
				services[w.host.Name] = prev.Services
			}
		}
		log.Info("active probing skipped", "dry_run", p.cfg.Safety.DryRun || opts.DryRun, "no_probe", opts.NoProbe)
	}

	// --- score, route, persist -----------------------------------------
	var snaps []*model.Snapshot
	for _, w := range works {
		svcs := services[w.host.Name]
		// Re-evaluate attribution with probe evidence: a certificate subject
		// naming the org is often only visible after an active handshake.
		att := p.attr.Evaluate(attribution.Input{
			Host:       w.host,
			Services:   svcs,
			CNAMEChain: append([]string{w.host.Name}, w.host.CNAMEs...),
		})
		snap := &model.Snapshot{
			Key:         model.StableID("a", w.host.Name),
			Host:        *w.host,
			Services:    svcs,
			Attribution: att,
			RunID:       runID,
			FirstSeen:   w.host.FirstSeen,
			LastSeen:    w.host.LastSeen,
		}
		hasHTTPS, hasHTTP, hasWebPort := false, false, false
		for _, s := range svcs {
			if s.TLS != nil {
				hasHTTPS = true
			}
			if s.HTTP != nil {
				hasHTTP = true
				if s.Port == 80 {
					hasWebPort = true
				}
			}
		}
		// An asset whose observable state has not moved in a long time is
		// probably abandoned. That is the exact profile of the forgotten
		// staging host this tool exists to find, so the age of the last change
		// feeds the score.
		stale := false
		if prev, ok := previous[snap.Key]; ok && !prev.LastChanged.IsZero() {
			if started.Sub(prev.LastChanged) >= p.cfg.Risk.StaleAfter.Std() && p.cfg.Risk.StaleAfter.Std() > 0 {
				stale = true
			}
		}
		assess := p.risk.Assess(risk.Input{
			Snapshot: snap, Attribution: att,
			HasHTTPS: hasHTTPS, HasHTTP: hasHTTP, HasWebPort: hasWebPort,
			IsStale: stale,
		})
		snap.Assessment = assess
		snap.Findings = risk.FindingsFromSnapshot(snap)
		snap.Owner = p.router.Route(snap)
		snap.StateFingerprint = fingerprint(snap)
		snap.LastChanged = started
		snaps = append(snaps, snap)
	}

	sort.Slice(snaps, func(i, j int) bool {
		if snaps[i].Assessment.Band.Rank() != snaps[j].Assessment.Band.Rank() {
			return snaps[i].Assessment.Band.Rank() < snaps[j].Assessment.Band.Rank()
		}
		return snaps[i].Assessment.Score > snaps[j].Assessment.Score
	})

	for _, snap := range snaps {
		if _, err := p.store.Save(ctx, snap); err != nil {
			log.Warn("save asset failed", "asset", snap.Host.Name, "err", err)
			stats.Errors = append(stats.Errors, err.Error())
			continue
		}
		if isInScope(snap.Attribution) {
			stats.AssetsScoped++
			stats.ByBand[snap.Assessment.Band]++
			stats.ByTeam[snap.Owner.Team]++
			stats.Findings += len(snap.Findings)
		}
	}

	// --- diff -----------------------------------------------------------
	res := p.comparer.Compare(previous, snaps, runID)
	for _, c := range res.Changes {
		if err := p.store.AppendEvent(ctx, c, runID); err != nil {
			log.Warn("append event failed", "err", err)
		}
	}
	stats.AssetsNew = len(res.New)
	stats.AssetsGone = len(res.Gone)
	stats.Changes = len(res.Changes)

	// --- report ---------------------------------------------------------
	stats.Duration = p.now().Sub(started)
	gateSummary := p.gate.Summary()
	files, rerr := p.report.Render(report.Data{
		RunID:        runID,
		GeneratedAt:  p.now(),
		Organisation: p.cfg.Organisation.Name,
		Snapshots:    snaps,
		Changes:      res.Changes,
		Stats:        stats,
		GateSummary:  gateSummary,
	})
	if rerr != nil {
		log.Warn("report rendering failed", "err", rerr)
	}
	if err := p.store.FinishRun(ctx, runID, p.now(), stats); err != nil {
		log.Warn("could not record run finish", "err", err)
	}

	log.Info("run complete",
		"run", runID,
		"assets", stats.AssetsSeen,
		"scoped", stats.AssetsScoped,
		"critical", stats.ByBand[model.BandCritical],
		"high", stats.ByBand[model.BandHigh],
		"changes", stats.Changes,
		"duration", stats.Duration.Round(time.Millisecond),
	)

	return &Result{
		RunID:       runID,
		Snapshots:   snaps,
		Changes:     res.Changes,
		Stats:       stats,
		ReportFiles: files,
		GateSummary: gateSummary,
	}, nil
}

// discover builds the inventory from passive sources.
func (p *Pipeline) discover(ctx context.Context, log *slog.Logger) (*discovery.Inventory, error) {
	var ex discovery.Exchanger
	if len(p.cfg.Discovery.CT.Fixtures) > 0 {
		// A DNS fixture always accompanies a CT fixture (demo / test).
	}
	if fx := p.cfg.Discovery.DNSFixture(); fx != "" {
		fe, err := discovery.LoadFixtureExchanger(fx)
		if err != nil {
			return nil, err
		}
		ex = fe
	} else {
		ex = discovery.NewLiveExchanger(p.cfg.Discovery.DNS.Resolvers, p.cfg.Discovery.DNS.Timeout.Std())
	}
	res := discovery.NewResolver(ex, p.cfg.Discovery.DNS.QPS)
	inv := discovery.NewInventory()

	var sources []discovery.HostSource
	if p.cfg.Discovery.CT.Enabled {
		ct, err := discovery.NewCTSource(discovery.CTConfig{
			Providers:      p.cfg.Discovery.CT.Providers,
			Fixtures:       p.cfg.Discovery.CT.Fixtures,
			MaxEntries:     p.cfg.Discovery.CT.MaxEntries,
			IncludeExpired: p.cfg.Discovery.CT.IncludeExpired,
			Timeout:        p.cfg.Discovery.CT.Timeout.Std(),
		}, log.Info)
		if err != nil {
			log.Warn("certificate transparency disabled", "err", err)
		} else {
			sources = append(sources, ct)
		}
	}

	enum := discovery.NewEnumerator(p.cfg, res, inv, sources...)
	if _, err := enum.Enumerate(ctx); err != nil {
		return inv, err
	}
	q, f := res.Stats()
	log.Info("discovery complete", "hosts", inv.Len(), "dns_queries", q, "dns_failures", f)
	return inv, nil
}

// workItem pairs a host with its passive attribution.
type workItem struct {
	host *model.Host
	att  model.Attribution
}

// probeAll probes in-scope hosts with bounded concurrency.
func (p *Pipeline) probeAll(ctx context.Context, works []workItem, opts Options, log *slog.Logger, stats *model.RunStats) map[string][]model.Service {
	out := map[string][]model.Service{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	jobs := make(chan workItem)

	sem := make(chan struct{}, p.cfg.Safety.MaxConcurrent)
	workers := p.cfg.Safety.MaxConcurrent
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if !p.gate.InWindow() {
					if !p.cfg.Safety.WaitForWindow {
						// Deferred policy: outside the window, stop pulling
						// work rather than burn through the queue skipping each
						// host.
						return
					}
					// Wait policy: block until the window opens. The first
					// worker to get here pauses all of them, since no probes
					// are issued while waiting.
					if err := p.gate.WaitUntilWindow(ctx); err != nil {
						return
					}
				}
				res := p.prober.ProbeHost(ctx, j.host)
				mu.Lock()
				out[j.host.Name] = res.Services
				stats.ServicesProbed += len(res.Services)
				stats.ProbesSkipped += res.Skipped
				if len(res.Errors) > 0 {
					stats.Errors = append(stats.Errors, res.Errors...)
				}
				mu.Unlock()
			}
		}()
	}

	queued := 0
	for _, w := range works {
		if !attribution.InScope(w.att) || !attribution.ActiveAllowed(p.cfg, w.att) {
			// Record the host with no services so it still appears in the
			// inventory with its passive evidence.
			mu.Lock()
			out[w.host.Name] = nil
			mu.Unlock()
			continue
		}
		if w.host.NXDomain || !w.host.Resolvable || w.host.WildcardCatchall {
			mu.Lock()
			out[w.host.Name] = nil
			mu.Unlock()
			continue
		}
		if opts.OnlyTeam != "" {
			// Focus runs filter after attribution; team routing needs services,
			// so this is a best-effort filter on hostname tags.
			if !strings.Contains(w.host.Name, opts.OnlyTeam) {
				continue
			}
		}
		select {
		case jobs <- w:
			queued++
			sem <- struct{}{}
			<-sem
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return out
		}
	}
	close(jobs)
	wg.Wait()
	stats.ProbesIssued = p.gate.Probes()
	log.Info("probing complete",
		"hosts_probed", queued,
		"probes_issued", stats.ProbesIssued,
		"skipped", stats.ProbesSkipped,
		"gate", p.gate.Summary())
	return out
}

func isInScope(att model.Attribution) bool {
	switch att.Verdict {
	case model.VerdictConfirmed, model.VerdictProbable:
		return true
	}
	return false
}

// fingerprint captures only observable facts, so cosmetic changes in risk or
// ownership do not look like asset churn.
func fingerprint(s *model.Snapshot) string {
	var b strings.Builder
	b.WriteString(strings.Join(s.Host.Addresses(), ","))
	b.WriteString("|")
	for _, svc := range s.Services {
		fmt.Fprintf(&b, "%d;", svc.Port)
		if svc.TLS != nil {
			b.WriteString(svc.TLS.FingerprintSHA256)
			b.WriteString(";")
		}
		if svc.HTTP != nil {
			b.WriteString(svc.HTTP.BodyHash)
			b.WriteString(";")
		}
	}
	return model.StableID("fp", b.String())
}

func newRunID(t time.Time) string {
	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	return fmt.Sprintf("run-%s-%s", t.UTC().Format("20060102T150405"), hex.EncodeToString(suffix))
}
