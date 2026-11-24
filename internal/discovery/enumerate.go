package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"asm/internal/config"
	"asm/internal/model"
)

// randomLabel returns a label that will not exist in any real zone.
func randomLabel() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is fatal for correctness; the static fallback
		// still gives a low-collision shape and never crashes a run.
		return "asm-probe-0000000000000000"
	}
	return "asm-probe-" + hex.EncodeToString(b)
}

// DetectWildcards probes each apex with two random labels. Two probes guard
// against a single unlucky collision and let us distinguish a deterministic
// catch-all from a load-balanced one (both answers are recorded).
//
// Without this step a single catch-all zone under a large brand domain can
// generate tens of thousands of phantom "assets" and swamp the review queue.
func DetectWildcards(ctx context.Context, apexes []string, r *Resolver) map[string]*WildcardProfile {
	out := make(map[string]*WildcardProfile, len(apexes))
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 8)
	for _, apex := range apexes {
		apex = model.NormalizeName(apex)
		if apex == "" {
			continue
		}
		wg.Add(1)
		go func(apex string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			prof := &WildcardProfile{Apex: apex, Probed: true}
			var addrSets [][]string
			var cnameSet []string
			for i := 0; i < 2; i++ {
				name := randomLabel() + "." + apex
				ans, err := r.ResolveLight(ctx, name)
				if err != nil {
					// A transient resolver failure is not proof of absence;
					// leave Probed=false so callers treat names conservatively.
					prof.Probed = false
					continue
				}
				addrs := ans.Addresses()
				if len(addrs) > 0 {
					addrSets = append(addrSets, addrs)
				}
				cnameSet = append(cnameSet, ans.CNAME...)
			}
			if len(addrSets) == 2 && !equalStrings(addrSets[0], addrSets[1]) {
				// The zone answers random names with different addresses each
				// time (round-robin / CDN). Only the intersection is safe to
				// treat as a catch-all signature.
				prof.Addresses = intersect(addrSets[0], addrSets[1])
			} else if len(addrSets) > 0 {
				prof.Addresses = addrSets[0]
			}
			prof.CNAME = dedupeSorted(cnameSet)
			mu.Lock()
			out[apex] = prof
			mu.Unlock()
		}(apex)
	}
	wg.Wait()
	return out
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range b {
		set[s] = true
	}
	var out []string
	for _, s := range a {
		if set[s] {
			out = append(out, s)
		}
	}
	return dedupeSorted(out)
}

// Inventory accumulates hosts during a run.
type Inventory struct {
	mu    sync.Mutex
	hosts map[string]*model.Host
}

// NewInventory returns an empty inventory.
func NewInventory() *Inventory {
	return &Inventory{hosts: map[string]*model.Host{}}
}

// Upsert merges observations into the inventory and returns the host.
func (inv *Inventory) Upsert(name string) *model.Host {
	name = model.NormalizeName(name)
	inv.mu.Lock()
	defer inv.mu.Unlock()
	h, ok := inv.hosts[name]
	if !ok {
		h = &model.Host{Name: name}
		inv.hosts[name] = h
	}
	return h
}

// Add records a discovered name with its provenance.
func (inv *Inventory) Add(name string, d model.Discovery) *model.Host {
	h := inv.Upsert(name)
	inv.mu.Lock()
	h.AddDiscovery(d)
	inv.mu.Unlock()
	return h
}

// Hosts returns a stable, name-sorted snapshot.
func (inv *Inventory) Hosts() []*model.Host {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := make([]*model.Host, 0, len(inv.hosts))
	for _, h := range inv.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Len returns the number of distinct names.
func (inv *Inventory) Len() int {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return len(inv.hosts)
}

// Enumerator runs the discovery stage.
type Enumerator struct {
	cfg    *config.Config
	res    *Resolver
	inv    *Inventory
	source HostSource

	wildcards map[string]*WildcardProfile
}

// HostSource supplies candidate names from passive datasets. It is an
// interface so the CT client, file fixtures and passive-DNS feeds are
// interchangeable.
type HostSource interface {
	Name() string
	// Fetch returns candidate names for an apex.
	Fetch(ctx context.Context, apex string) ([]Candidate, error)
}

// Candidate is a name proposed by a passive source.
type Candidate struct {
	Name string
	// Wildcard is true when the source already knows the name is a wildcard
	// expansion artefact (for example the CT entry "*.example.com").
	Wildcard bool
	// Ports are ports the source already knows to be open on this name. A
	// passive-DNS feed that carries port data saves active probing entirely;
	// when empty the configured default port list is used.
	Ports  []int
	Detail string
}

// NewEnumerator builds the discovery stage.
func NewEnumerator(cfg *config.Config, res *Resolver, inv *Inventory, sources ...HostSource) *Enumerator {
	return &Enumerator{cfg: cfg, res: res, inv: inv, source: multiSource(sources), wildcards: map[string]*WildcardProfile{}}
}

type multiSource []HostSource

func (m multiSource) Name() string {
	names := make([]string, 0, len(m))
	for _, s := range m {
		names = append(names, s.Name())
	}
	return strings.Join(names, "+")
}

func (m multiSource) Fetch(ctx context.Context, apex string) ([]Candidate, error) {
	var out []Candidate
	var errs []error
	for _, s := range m {
		c, err := s.Fetch(ctx, apex)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
			continue
		}
		out = append(out, c...)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, joinErrs(errs)
	}
	return out, nil
}

func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// Enumerate performs the full discovery pass and returns the hosts.
//
// Order matters: seeds and CT names are free and authoritative; only names
// that survive scope filtering and wildcard detection are expanded further.
// Brute force runs last and is bounded.
func (e *Enumerator) Enumerate(ctx context.Context) (*Inventory, error) {
	apexes := e.apexes()
	if len(apexes) == 0 {
		return e.inv, fmt.Errorf("no apexes configured")
	}

	// 1. Seeds are always in scope, even if they sit on a partner domain or a
	// domain that is not otherwise listed.
	for _, seed := range e.cfg.Discovery.Seeds {
		seed = model.NormalizeName(seed)
		if seed == "" {
			continue
		}
		e.inv.Add(seed, model.DiscoverySeed)
	}

	wildcardProbe := true
	if e.cfg.Discovery.DNS.ProbeWildcard != nil {
		wildcardProbe = *e.cfg.Discovery.DNS.ProbeWildcard
	}
	if wildcardProbe {
		e.wildcards = DetectWildcards(ctx, apexes, e.res)
	}

	// 2. Passive sources (CT logs, passive DNS) per apex.
	var candidates []Candidate
	for _, apex := range apexes {
		if e.source == nil {
			break
		}
		got, err := e.source.Fetch(ctx, apex)
		if err != nil {
			// A failed passive source must not abort the run: the inventory we
			// already have is still useful, and the next run will retry.
			continue
		}
		for _, c := range got {
			if c.Wildcard {
				continue
			}
			candidates = append(candidates, c)
		}
	}

	// 3. Filter, resolve and record.
	//
	// Candidate names may sit under a subzone with its own catch-all (a
	// wildcard does not have to be at the configured apex). Those zones only
	// become visible once a candidate resolves, so each newly-seen parent zone
	// is probed for a wildcard before its children are trusted.
	seen := map[string]bool{}
	for _, c := range candidates {
		name := model.NormalizeName(c.Name)
		if name == "" || seen[name] {
			continue
		}
		if strings.HasPrefix(name, "*.") {
			continue
		}
		if !e.inScope(name) {
			continue
		}
		seen[name] = true
		e.ensureParentWildcards(ctx, name)
		h := e.inv.Add(name, model.DiscoveryCT)
		if len(c.Ports) > 0 {
			h.PortHints = dedupeInts(c.Ports)
		}
		if err := e.resolveInto(ctx, h, true); err != nil {
			continue
		}
	}

	// 4. Resolve seeds as well, so a manually supplied name gets attribution
	// evidence even when no passive source knows it.
	for _, seed := range e.cfg.Discovery.Seeds {
		h := e.inv.Add(model.NormalizeName(seed), model.DiscoverySeed)
		_ = e.resolveInto(ctx, h, true)
	}

	// 5. CNAME expansion: a name that points into an org domain makes the
	// target an asset too, and a name that points into a partner domain tells
	// us the class of the origin.
	if err := e.expandCNAMEs(ctx); err != nil {
		return e.inv, err
	}

	// 6. Bounded brute force.
	if e.cfg.Discovery.DNS.MaxLabelsPerRun > 0 {
		e.bruteForce(ctx, apexes)
	}

	// 7. Reconcile wildcards. A zone's catch-all may have been discovered only
	// after some of its children were already admitted (candidates are not
	// guaranteed to be ordered parent-first). Every host is re-checked against
	// the final wildcard map, and a phantom host loses its port hints so it is
	// never actively probed.
	e.reconcileWildcards(ctx)

	return e.inv, nil
}

// reconcileWildcards re-evaluates every host against the final wildcard map.
func (e *Enumerator) reconcileWildcards(ctx context.Context) {
	if len(e.wildcards) == 0 {
		return
	}
	for _, h := range e.inv.Hosts() {
		if h.WildcardCatchall {
			h.PortHints = nil
			continue
		}
		if h.Name == h.Apex || h.NXDomain {
			continue
		}
		ans := &Answer{Name: h.Name, A: h.IPs, AAAA: h.AAAAs, CNAME: h.CNAMEs}
		for zone, prof := range e.wildcards {
			if !strings.HasSuffix(h.Name, "."+zone) || h.Name == zone {
				continue
			}
			if prof.Matches(ans) {
				h.WildcardCatchall = true
				h.WildcardFrom = zone
				h.PortHints = nil
				break
			}
		}
	}
	_ = ctx
}

// ensureParentWildcards probes every ancestor zone of name that has not been
// checked yet. A wildcard at "legacy.example.com" is invisible from the apex
// probe, yet can manufacture thousands of phantom hosts under that subzone.
func (e *Enumerator) ensureParentWildcards(ctx context.Context, name string) {
	if e.noWildcardProbe() {
		return
	}
	labels := strings.Split(name, ".")
	// From the immediate parent up to, but not including, the level of the
	// most specific configured apex (that one is already covered).
	stopAt := 1
	if apex := e.cfg.Scope().ApexFor(name); apex != "" {
		stopAt = len(strings.Split(apex, "."))
	}
	var toProbe []string
	for i := 1; i <= len(labels)-stopAt; i++ {
		zone := strings.Join(labels[i:], ".")
		if zone == "" {
			continue
		}
		if _, done := e.wildcards[zone]; done {
			continue
		}
		toProbe = append(toProbe, zone)
	}
	if len(toProbe) == 0 {
		return
	}
	found := DetectWildcards(ctx, toProbe, e.res)
	for zone, prof := range found {
		// Mark as probed even when nothing answered, so the same zone is not
		// re-probed for every sibling candidate.
		e.wildcards[zone] = prof
	}
}

func (e *Enumerator) noWildcardProbe() bool {
	if e.cfg.Discovery.DNS.ProbeWildcard == nil {
		return false
	}
	return !*e.cfg.Discovery.DNS.ProbeWildcard
}

func (e *Enumerator) apexes() []string {
	var out []string
	for d := range e.cfg.Scope().Apexes {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func (e *Enumerator) inScope(name string) bool {
	sc := e.cfg.Scope()
	if sc.ExcludedHost(name) {
		return false
	}
	return sc.InDomain(name) || sc.InRegistrableDomain(name)
}

// resolveInto fills a host from DNS and marks wildcard catch-alls.
func (e *Enumerator) resolveInto(ctx context.Context, h *model.Host, _ bool) error {
	ans, err := e.res.Resolve(ctx, h.Name)
	if err != nil {
		return err
	}
	if ans.NXDomain {
		h.NXDomain = true
		h.Resolvable = false
		return nil
	}
	h.Resolvable = ans.Exists
	h.IPs = ans.A
	h.AAAAs = ans.AAAA
	h.CNAMEs = ans.CNAME
	h.TXT = ans.TXT
	h.MX = ans.MX
	h.NS = ans.NS
	h.Apex = e.cfg.Scope().ApexFor(h.Name)

	// Wildcard check: only a name that is a descendant of a probed zone can
	// be a phantom. An apex itself always legitimately exists.
	if h.Name != h.Apex {
		for apex, prof := range e.wildcards {
			if !strings.HasSuffix(h.Name, "."+apex) || h.Name == apex {
				continue
			}
			if prof.Matches(ans) {
				h.WildcardCatchall = true
				h.WildcardFrom = apex
				break
			}
			// A wildcard that CNAMEs everything to the same target is equally
			// phantom; compare only when the name has no independent A record.
			if len(prof.Addresses) == 0 && len(prof.CNAME) > 0 && len(ans.CNAME) > 0 && equalStrings(ans.CNAME, prof.CNAME) {
				h.WildcardCatchall = true
				h.WildcardFrom = apex
				break
			}
		}
	}
	return nil
}

// expandCNAMEs adds CNAME targets that fall in scope and resolves chains.
func (e *Enumerator) expandCNAMEs(ctx context.Context) error {
	// Track what has been seen in this expansion so several hosts pointing at
	// the same target do not resolve it repeatedly, and so membership is O(1)
	// instead of a scan of the whole inventory on every candidate.
	known := map[string]bool{}
	for _, h := range e.inv.Hosts() {
		known[h.Name] = true
	}
	for {
		var toAdd []string
		for _, h := range e.inv.Hosts() {
			for _, target := range h.CNAMEs {
				if known[target] || !e.inScope(target) {
					continue
				}
				known[target] = true
				toAdd = append(toAdd, target)
			}
		}
		if len(toAdd) == 0 {
			return nil
		}
		for _, name := range toAdd {
			h := e.inv.Add(name, model.DiscoveryCNAME)
			_ = e.resolveInto(ctx, h, false)
		}
		// Bound the loop: a CNAME cycle cannot grow the set forever because
		// each name is only added once, but a very large zone could still
		// iterate many times.
		if e.inv.Len() >= e.cfg.Safety.MaxHostsPerRun {
			return nil
		}
	}
}

// bruteForce probes wordlist labels against each apex. It is deliberately the
// last and smallest source: it is the only one that generates load on the
// authoritative servers.
func (e *Enumerator) bruteForce(ctx context.Context, apexes []string) {
	words := e.words()
	if len(words) == 0 {
		return
	}
	budget := e.cfg.Discovery.DNS.MaxLabelsPerRun

	type job struct {
		apex string
		word string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	remaining := budget
	var added int

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				name := j.word + "." + j.apex
				ans, err := e.res.ResolveLight(ctx, name)
				if err != nil || !ans.Exists || ans.NXDomain {
					continue
				}
				if e.isWildcardAnswer(name, ans) {
					continue
				}
				if !e.inScope(name) {
					continue
				}
				h := e.inv.Add(name, model.DiscoveryDNS)
				_ = e.resolveInto(ctx, h, false)
				mu.Lock()
				added++
				mu.Unlock()
			}
		}()
	}

	dispatched := 0
outer:
	for _, apex := range apexes {
		for _, w := range words {
			mu.Lock()
			if dispatched >= budget || e.inv.Len() >= e.cfg.Safety.MaxHostsPerRun {
				mu.Unlock()
				break outer
			}
			dispatched++
			mu.Unlock()
			select {
			case jobs <- job{apex: apex, word: w}:
			case <-ctx.Done():
				break outer
			}
		}
	}
	close(jobs)
	wg.Wait()
	_ = remaining
	_ = added
}

func (e *Enumerator) isWildcardAnswer(name string, ans *Answer) bool {
	for apex, prof := range e.wildcards {
		if strings.HasSuffix(name, "."+apex) && name != apex && prof.Matches(ans) {
			return true
		}
	}
	return false
}

// builtinWords is a compact, high-signal list. It favours names that commonly
// become forgotten assets over exhaustiveness.
func builtinWords() []string {
	return []string{
		"www", "api", "app", "admin", "portal", "vpn", "mail", "webmail", "smtp", "imap",
		"dev", "test", "staging", "stage", "uat", "qa", "demo", "sandbox", "beta", "pre",
		"old", "legacy", "backup", "bak", "tmp", "temp", "internal", "intranet", "extranet",
		"git", "gitlab", "jenkins", "ci", "cd", "build", "registry", "docker", "k8s", "kube",
		"grafana", "prometheus", "kibana", "elastic", "monitor", "metrics", "status", "nagios",
		"jira", "confluence", "wiki", "docs", "support", "help", "crm", "erp", "hr", "finance",
		"db", "mysql", "postgres", "redis", "mongo", "elasticsearch", "rabbitmq", "kafka",
		"ftp", "sftp", "ssh", "rdp", "vpn2", "remote", "gateway", "proxy", "lb", "cdn",
		"static", "assets", "img", "media", "upload", "files", "s3", "storage", "nas",
		"shop", "store", "pay", "payment", "billing", "invoice", "account", "auth", "sso", "login",
		"mobile", "m", "wap", "open", "partner", "vendor", "api2", "v2", "v1", "graphql",
		"swagger", "actuator", "health", "debug", "phpmyadmin", "adminer", "webmin", "cpanel",
	}
}

func (e *Enumerator) words() []string {
	if e.cfg.Discovery.DNS.Wordlist == "" {
		return builtinWords()
	}
	raw, err := readLines(e.cfg.Discovery.DNS.Wordlist)
	if err != nil || len(raw) == 0 {
		return builtinWords()
	}
	return raw
}
