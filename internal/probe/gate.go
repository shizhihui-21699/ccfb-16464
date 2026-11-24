// Package probe performs bounded, polite active checks against assigned
// targets.
//
// The design constraint is that scanning must never look like an outage to a
// production service. Four mechanisms enforce that:
//
//  1. A global token bucket caps total probes per second.
//  2. A per-host token bucket caps probes per second for any one host, so a
//     busy asset is never hit in a burst.
//  3. A scan window defers active work outside business-hours policy.
//  4. A circuit breaker quarantines a host after repeated transport failures,
//     so a service that is struggling is not retried into the ground.
//
// Every probe is a single request with a short timeout. There are no retries on
// a failing target, no state-changing requests, and no payloads.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"asm/internal/config"
	"asm/internal/model"
)

// ErrSkipped is returned when policy prevents a probe (window, budget,
// exclusion, circuit breaker). It is not a failure of the target.
var ErrSkipped = errors.New("probe skipped by policy")

// ErrUnsafeTarget is returned when the resolved address is private or
// otherwise not permitted by the profile.
var ErrUnsafeTarget = errors.New("target address not permitted")

// Gate centralises every rate and safety decision. All probe goroutines share
// one Gate.
type Gate struct {
	cfg *config.Config

	global *rate.Limiter

	mu          sync.Mutex
	perHost     map[string]*rate.Limiter
	failures    map[string]int
	quarantined map[string]time.Time
	probes      int64
	skipped     int64
	paused      int64

	now func() time.Time
}

// NewGate builds a gate from the profile.
func NewGate(cfg *config.Config) *Gate {
	g := &Gate{
		cfg:         cfg,
		global:      rate.NewLimiter(rate.Limit(cfg.Safety.MaxGlobalRPS), 1),
		perHost:     map[string]*rate.Limiter{},
		failures:    map[string]int{},
		quarantined: map[string]time.Time{},
		now:         time.Now,
	}
	return g
}

// SetClock replaces the clock; tests use it to exercise windows.
func (g *Gate) SetClock(fn func() time.Time) { g.now = fn }

// Probes returns the number of probes admitted so far.
func (g *Gate) Probes() int { return int(atomic.LoadInt64(&g.probes)) }

// Skipped returns the number skipped by policy.
func (g *Gate) Skipped() int { return int(atomic.LoadInt64(&g.skipped)) }

// InWindow reports whether active sweeping is currently allowed.
func (g *Gate) InWindow() bool { return g.cfg.InWindow(g.now()) }

// NextWindow returns when active sweeping next becomes allowed.
func (g *Gate) NextWindow() time.Time { return g.cfg.NextWindowStart(g.now()) }

// WaitUntilWindow blocks until the scan window is open or ctx is done. It is a
// no-op when the window is already open or no window is configured. Callers
// that honour safety.wait_for_window use this to start active work at the
// window boundary instead of skipping it.
func (g *Gate) WaitUntilWindow(ctx context.Context) error {
	for !g.InWindow() {
		wait := time.Until(g.NextWindow())
		if wait <= 0 {
			wait = time.Second
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// BudgetLeft reports whether the run still has probe budget.
func (g *Gate) BudgetLeft() bool {
	max := g.cfg.Safety.MaxProbesPerRun
	if max <= 0 {
		return true
	}
	return atomic.LoadInt64(&g.probes) < int64(max)
}

// Allow performs the non-network admission checks for one probe: scan window,
// run budget, exclusion lists and circuit breaker. It does not consume rate.
//
// Callers must call Allow before Acquire. Splitting the two lets the scheduler
// decide whether a target is worth the rate slot at all.
func (g *Gate) Allow(host string, ip string) error {
	if g.cfg.Safety.DryRun {
		return ErrSkipped
	}
	if g.cfg.Scope().ExcludedHost(host) {
		atomic.AddInt64(&g.skipped, 1)
		return ErrSkipped
	}
	if ip != "" && g.cfg.Scope().ExcludedIP(ip) {
		atomic.AddInt64(&g.skipped, 1)
		return ErrSkipped
	}
	if !g.cfg.Safety.AllowPrivate {
		if ip != "" && isRestrictedIP(ip) {
			atomic.AddInt64(&g.skipped, 1)
			return ErrUnsafeTarget
		}
	}
	if !g.InWindow() {
		// Allow is non-blocking and has no context, so it must never admit a
		// probe outside the window regardless of wait_for_window. Callers that
		// honour wait mode use WaitUntilWindow before calling Allow; this check
		// is the backstop that makes the guarantee hold for every caller.
		atomic.AddInt64(&g.skipped, 1)
		return ErrSkipped
	}
	if !g.BudgetLeft() {
		atomic.AddInt64(&g.skipped, 1)
		return ErrSkipped
	}
	key := model.NormalizeName(host)
	g.mu.Lock()
	if until, ok := g.quarantined[key]; ok && g.now().Before(until) {
		g.mu.Unlock()
		atomic.AddInt64(&g.skipped, 1)
		return ErrSkipped
	}
	g.mu.Unlock()
	return nil
}

// Acquire blocks until the global and per-host token buckets both admit one
// probe, or ctx is done.
func (g *Gate) Acquire(ctx context.Context, host string) error {
	key := model.NormalizeName(host)
	g.mu.Lock()
	lim, ok := g.perHost[key]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(g.cfg.Safety.MaxPerHostRPS), 1)
		g.perHost[key] = lim
	}
	g.mu.Unlock()

	if err := lim.Wait(ctx); err != nil {
		return err
	}
	if err := g.global.Wait(ctx); err != nil {
		return err
	}
	n := atomic.AddInt64(&g.probes, 1)
	// Inject an occasional pause so the aggregate traffic pattern is smooth
	// rather than a continuous maximum-rate stream.
	if pe := g.cfg.Safety.PauseEvery; pe > 0 && int(n)%pe == 0 {
		atomic.StoreInt64(&g.paused, 1)
		select {
		case <-time.After(g.cfg.Safety.PauseDuration.Std()):
			atomic.StoreInt64(&g.paused, 0)
		case <-ctx.Done():
			atomic.StoreInt64(&g.paused, 0)
			return ctx.Err()
		}
	}
	return nil
}

// RecordFailure notes a transport failure and quarantines the host once the
// threshold is crossed.
func (g *Gate) RecordFailure(host string) {
	key := model.NormalizeName(host)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failures[key]++
	if g.cfg.Safety.FailureThreshold > 0 && g.failures[key] >= g.cfg.Safety.FailureThreshold {
		g.quarantined[key] = g.now().Add(g.cfg.Safety.Cooldown.Std())
	}
}

// RecordSuccess clears the failure streak for a host.
func (g *Gate) RecordSuccess(host string) {
	key := model.NormalizeName(host)
	g.mu.Lock()
	delete(g.failures, key)
	g.mu.Unlock()
}

// Quarantined reports hosts currently in cooldown.
func (g *Gate) Quarantined() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for h, until := range g.quarantined {
		if g.now().Before(until) {
			out = append(out, h)
		}
	}
	return out
}

// isRestrictedIP reports whether ip is in a range that should never be
// probed: loopback, private, link-local, CGNAT, multicast, or unspecified.
func isRestrictedIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10 carrier-grade NAT
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	// 0.0.0.0/8, 172.16/12 handled by IsPrivate
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 0 {
		return true
	}
	return false
}

// IsRestrictedIP is the exported form used by the scheduler to explain skips.
func IsRestrictedIP(s string) bool { return isRestrictedIP(s) }

// ResolveTargets resolves a host and returns addresses that are permitted by
// the profile. A partner or cloud name often resolves to a CDN edge; probing
// the edge is fine, probing a private address is not.
func ResolveTargets(ctx context.Context, host string, resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}, allowPrivate bool) ([]string, error) {
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if !allowPrivate && isRestrictedIP(a) {
			continue
		}
		out = append(out, a)
	}
	return dedupe(out), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Dialer returns a dialer configured with the profile timeouts. Keeping one
// place for dial config means a change to safety limits applies everywhere.
func Dialer(cfg *config.Config) *net.Dialer {
	return &net.Dialer{
		Timeout:   cfg.Safety.DialTimeout.Std(),
		KeepAlive: -1, // do not hold idle connections open against a target
	}
}

// Deadline returns a per-request deadline.
func Deadline(cfg *config.Config) time.Duration {
	d := cfg.Safety.RequestTimeout.Std()
	if d <= 0 {
		d = 6 * time.Second
	}
	return d
}

// ClassAllowedActive reports whether the profile permits active probing of an
// asset with the given attribution class.
func ClassAllowedActive(cfg *config.Config, class model.Class) bool {
	for _, c := range cfg.Safety.ActiveClasses {
		if c == string(class) {
			return true
		}
	}
	return false
}

// Summary is a one-line description of the gate's current state, used in run
// logs so an operator can see exactly why the scanner is or is not active.
func (g *Gate) Summary() string {
	state := "active"
	if !g.InWindow() {
		state = fmt.Sprintf("window-closed(opens %s)", g.NextWindow().Format(time.RFC3339))
	}
	if g.cfg.Safety.DryRun {
		state = "dry-run"
	}
	return fmt.Sprintf("gate=%s global_rps=%.2f per_host_rps=%.2f probes=%d skipped=%d quarantined=%d",
		state, g.cfg.Safety.MaxGlobalRPS, g.cfg.Safety.MaxPerHostRPS,
		g.Probes(), g.Skipped(), len(g.Quarantined()))
}

// normalizePorts turns a port list into a set.
func normalizePorts(ports []int) map[int]bool {
	m := make(map[int]bool, len(ports))
	for _, p := range ports {
		m[p] = true
	}
	return m
}

// dedupePorts returns sorted unique ports.
func dedupePorts(ports []int) []int {
	m := normalizePorts(ports)
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
