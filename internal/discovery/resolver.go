// Package discovery finds candidate hostnames from passive and semi-passive
// sources and turns them into a de-duplicated, wildcard-aware inventory.
//
// Nothing here touches a host directly. Everything is either a query to a
// third-party dataset (certificate transparency, a passive-DNS feed) or a DNS
// lookup against a public resolver. That separation is deliberate: discovery
// is cheap, repeatable and safe to run continuously, while active probing is
// rate-limited, windowed and guarded.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"

	"asm/internal/model"
)

// QType aliases make call sites readable.
const (
	qA     = dns.TypeA
	qAAAA  = dns.TypeAAAA
	qCNAME = dns.TypeCNAME
	qTXT   = dns.TypeTXT
	qMX    = dns.TypeMX
	qNS    = dns.TypeNS
	qSOA   = dns.TypeSOA
	qPTR   = dns.TypePTR
)

// Answer is the normalised result of resolving one name.
type Answer struct {
	Name     string
	A        []string
	AAAA     []string
	CNAME    []string
	TXT      []string
	MX       []string
	NS       []string
	PTR      []string
	NXDomain bool
	// Exists is true when the name has any record at all. NXDomain names do
	// not exist; a name that exists but has no A record is still a real asset
	// (it may be MX-only or CNAME to a name that is down).
	Exists bool
}

// Addresses returns A+AAAA.
func (a *Answer) Addresses() []string {
	out := append(append([]string{}, a.A...), a.AAAA...)
	sort.Strings(out)
	return out
}

// Key returns a canonical string for change detection.
func (a *Answer) Key() string {
	parts := [][]string{a.A, a.AAAA, a.CNAME, a.TXT, a.MX}
	var b strings.Builder
	for _, p := range parts {
		s := append([]string{}, p...)
		sort.Strings(s)
		b.WriteString(strings.Join(s, ","))
		b.WriteString("|")
	}
	return b.String()
}

// Exchanger issues a single DNS query. It exists so tests and the offline
// demo can substitute a deterministic fixture without touching the network.
type Exchanger interface {
	Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// LiveExchanger queries real resolvers with failover.
type LiveExchanger struct {
	Servers []string
	Timeout time.Duration
	// EDNS0UDPSize keeps responses small; a smaller buffer is less likely to
	// be dropped by a conservative middlebox.
	EDNS0UDPSize uint16
}

// NewLiveExchanger builds an exchanger from resolver addresses.
func NewLiveExchanger(servers []string, timeout time.Duration) *LiveExchanger {
	norm := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s = net.JoinHostPort(s, "53")
		}
		norm = append(norm, s)
	}
	if len(norm) == 0 {
		norm = []string{"1.1.1.1:53"}
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &LiveExchanger{Servers: norm, Timeout: timeout}
}

// Exchange implements Exchanger with round-robin failover.
func (e *LiveExchanger) Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	if e.EDNS0UDPSize > 0 {
		m.SetEdns0(e.EDNS0UDPSize, false)
	}
	var lastErr error
	for _, server := range e.Servers {
		c := &dns.Client{Timeout: e.Timeout, Net: "udp"}
		resp, _, err := c.ExchangeContext(ctx, m, server)
		if err == nil && resp != nil {
			if resp.Truncated {
				tc := &dns.Client{Timeout: e.Timeout, Net: "tcp"}
				if tr, _, err2 := tc.ExchangeContext(ctx, m, server); err2 == nil && tr != nil {
					return tr, nil
				}
			}
			return resp, nil
		}
		// A SERVFAIL from one resolver is worth retrying elsewhere; a NXDOMAIN
		// is an answer, not an error, and is handled by the caller.
		if err == nil && resp != nil && resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no resolver answered")
	}
	return nil, lastErr
}

// FixtureData is the on-disk shape of a deterministic DNS fixture used by the
// offline demo and by tests.
type FixtureData struct {
	// Records maps a lower-case name to its records.
	Records map[string]FixtureRecord `json:"records"`
	// Wildcards maps an apex to the records every non-existent name beneath it
	// receives. This is what makes a catch-all zone behave realistically.
	Wildcards map[string]FixtureRecord `json:"wildcards,omitempty"`
	// NXDomain forces a name to be reported as non-existent even if it would
	// otherwise fall under a wildcard.
	NXDomain []string `json:"nxdomain,omitempty"`
	// PTRs maps an IP to host names, served for reverse lookups.
	PTRs map[string][]string `json:"ptrs,omitempty"`
}

// FixtureRecord is one name's records.
type FixtureRecord struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	SOA   bool     `json:"soa,omitempty"`
}

// FixtureExchanger answers from a fixture file.
type FixtureExchanger struct {
	data     FixtureData
	nxdomain map[string]bool
}

// LoadFixtureExchanger reads a fixture file.
func LoadFixtureExchanger(path string) (*FixtureExchanger, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dns fixture: %w", err)
	}
	return ParseFixtureExchanger(raw)
}

// ParseFixtureExchanger decodes fixture JSON.
func ParseFixtureExchanger(raw []byte) (*FixtureExchanger, error) {
	var d FixtureData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("parse dns fixture: %w", err)
	}
	f := &FixtureExchanger{data: d, nxdomain: map[string]bool{}}
	for _, n := range d.NXDomain {
		f.nxdomain[model.NormalizeName(n)] = true
	}
	return f, nil
}

// Exchange implements Exchanger.
func (f *FixtureExchanger) Exchange(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	name = model.NormalizeName(name)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Response = true

	// Reverse records live in their own table: the query name is an
	// in-addr.arpa name that will never appear in Records.
	if qtype == qPTR {
		if ptrs, ok := f.data.PTRs[name]; ok {
			for _, p := range ptrs {
				m.Answer = append(m.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
					Ptr: dns.Fqdn(p),
				})
			}
			return m, nil
		}
	}

	if f.nxdomain[name] {
		m.Rcode = dns.RcodeNameError
		return m, nil
	}

	rec, ok := f.data.Records[name]
	if !ok {
		// Walk up to the nearest apex carrying a wildcard. A single-label
		// wildcard at the apex is what a catch-all zone looks like.
		rec, ok = f.lookupWildcard(name)
		if !ok {
			m.Rcode = dns.RcodeNameError
			return m, nil
		}
	}

	for _, ip := range rec.A {
		if qtype == qA || qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
		}
	}
	for _, ip := range rec.AAAA {
		if qtype == qAAAA || qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP(ip),
			})
		}
	}
	for _, target := range rec.CNAME {
		if qtype == qCNAME || qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: dns.Fqdn(target),
			})
		}
	}
	for _, txt := range rec.TXT {
		if qtype == qTXT || qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txt},
			})
		}
	}
	for _, mx := range rec.MX {
		if qtype == qMX || qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Preference: 10,
				Mx:         dns.Fqdn(mx),
			})
		}
	}
	for _, ns := range rec.NS {
		if qtype == qNS || qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  dns.Fqdn(ns),
			})
		}
	}
	if qtype == qSOA && rec.SOA {
		m.Answer = append(m.Answer, &dns.SOA{
			Hdr:    dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:     dns.Fqdn("ns1." + name),
			Mbox:   dns.Fqdn("hostmaster." + name),
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
		})
	}
	if len(m.Answer) == 0 && qtype != qSOA {
		// The name exists (it matched records or a wildcard) but has no record
		// of this type: NOERROR with an empty answer is correct.
		m.Rcode = dns.RcodeSuccess
	}
	return m, nil
}

func (f *FixtureExchanger) lookupWildcard(name string) (FixtureRecord, bool) {
	best := ""
	for apex := range f.data.Wildcards {
		apex = model.NormalizeName(apex)
		if name == apex {
			continue
		}
		if strings.HasSuffix(name, "."+apex) && len(apex) > len(best) {
			best = apex
		}
	}
	if best == "" {
		return FixtureRecord{}, false
	}
	return f.data.Wildcards[best], true
}

// Resolver performs cached, rate-limited DNS lookups through an Exchanger.
type Resolver struct {
	ex    Exchanger
	lim   *rate.Limiter
	cache sync.Map // cacheKey -> *Answer
	// counters for the run report
	mu       sync.Mutex
	queries  int
	failures int
	group    singleflight.Group
}

type cacheKey struct {
	name  string
	qtype uint16
}

// NewResolver wraps an exchanger with a QPS limiter.
func NewResolver(ex Exchanger, qps float64) *Resolver {
	if qps <= 0 {
		qps = 10
	}
	return &Resolver{ex: ex, lim: rate.NewLimiter(rate.Limit(qps), 1)}
}

// Stats returns the number of queries issued and how many failed.
func (r *Resolver) Stats() (queries, failures int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queries, r.failures
}

// raw issues one query, caching the parsed message and coalescing concurrent
// lookups of the same key.
//
// Coalescing matters: resolve() fans out several record types in parallel and
// the enumerator runs many names at once, so the same name can be in flight on
// several goroutines. Without singleflight the cache would only help after the
// first response landed, and a brute-force pass would multiply its query load.
func (r *Resolver) raw(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	key := cacheKey{model.NormalizeName(name), qtype}
	if v, ok := r.cache.Load(key); ok {
		return v.(*dns.Msg), nil
	}

	val, err, _ := r.group.Do(key.String(), func() (any, error) {
		// Re-check: another goroutine may have populated the cache while we
		// waited for the flight slot.
		if v, ok := r.cache.Load(key); ok {
			return v, nil
		}
		if err := r.lim.Wait(ctx); err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.queries++
		r.mu.Unlock()
		msg, err := r.ex.Exchange(ctx, name, qtype)
		if err != nil {
			r.mu.Lock()
			r.failures++
			r.mu.Unlock()
			return nil, err
		}
		r.cache.Store(key, msg)
		return msg, nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*dns.Msg), nil
}

// String renders a cache key for the singleflight group.
func (k cacheKey) String() string { return k.name + "|" + strconv.Itoa(int(k.qtype)) }

// ResolveLight fetches only A, AAAA and CNAME. It is used for brute-force and
// CT-derived candidates where the goal is "does this name exist".
func (r *Resolver) ResolveLight(ctx context.Context, name string) (*Answer, error) {
	return r.resolve(ctx, name, []uint16{qA, qAAAA, qCNAME})
}

// Resolve fetches the full record set used for attribution.
func (r *Resolver) Resolve(ctx context.Context, name string) (*Answer, error) {
	return r.resolve(ctx, name, []uint16{qA, qAAAA, qCNAME, qTXT, qMX, qNS})
}

func (r *Resolver) resolve(ctx context.Context, name string, qtypes []uint16) (*Answer, error) {
	ans := &Answer{Name: model.NormalizeName(name)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	for _, qt := range qtypes {
		wg.Add(1)
		go func(qt uint16) {
			defer wg.Done()
			msg, err := r.raw(ctx, name, qt)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if msg.Rcode == dns.RcodeNameError {
				ans.NXDomain = true
				return
			}
			ans.Exists = true
			for _, rr := range msg.Answer {
				switch v := rr.(type) {
				case *dns.A:
					if ip := v.A.String(); ip != "" {
						ans.A = append(ans.A, ip)
					}
				case *dns.AAAA:
					if ip := v.AAAA.String(); ip != "" {
						ans.AAAA = append(ans.AAAA, ip)
					}
				case *dns.CNAME:
					ans.CNAME = append(ans.CNAME, model.NormalizeName(v.Target))
				case *dns.TXT:
					ans.TXT = append(ans.TXT, strings.Join(v.Txt, ""))
				case *dns.MX:
					ans.MX = append(ans.MX, model.NormalizeName(v.Mx))
				case *dns.NS:
					ans.NS = append(ans.NS, model.NormalizeName(v.Ns))
				}
			}
		}(qt)
	}
	wg.Wait()
	ans.A = dedupeSorted(ans.A)
	ans.AAAA = dedupeSorted(ans.AAAA)
	ans.CNAME = dedupeSorted(ans.CNAME)
	ans.TXT = dedupeSorted(ans.TXT)
	ans.MX = dedupeSorted(ans.MX)
	ans.NS = dedupeSorted(ans.NS)
	if ans.Exists {
		ans.NXDomain = false
	}
	if !ans.Exists && ans.NXDomain {
		return ans, nil
	}
	if !ans.Exists && firstErr != nil {
		return ans, firstErr
	}
	return ans, nil
}

// Reverse looks up PTR names for an IP.
func (r *Resolver) Reverse(ctx context.Context, ip string) ([]string, error) {
	rev, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, err
	}
	msg, err := r.raw(ctx, rev, qPTR)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range msg.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			out = append(out, model.NormalizeName(p.Ptr))
		}
	}
	return dedupeSorted(out), nil
}

// CNAMEChain follows CNAMEs from name up to maxDepth hops, returning the chain
// including the starting name.
func (r *Resolver) CNAMEChain(ctx context.Context, name string, maxDepth int) ([]string, error) {
	if maxDepth <= 0 {
		maxDepth = 8
	}
	chain := []string{model.NormalizeName(name)}
	seen := map[string]bool{chain[0]: true}
	cur := chain[0]
	for depth := 0; depth < maxDepth; depth++ {
		msg, err := r.raw(ctx, cur, qCNAME)
		if err != nil {
			return chain, err
		}
		next := ""
		for _, rr := range msg.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				next = model.NormalizeName(c.Target)
				break
			}
		}
		if next == "" || seen[next] {
			break
		}
		chain = append(chain, next)
		seen[next] = true
		cur = next
	}
	return chain, nil
}

// WildcardProfile describes a zone's catch-all behaviour.
type WildcardProfile struct {
	Apex string
	// Addresses is the answer set every random label received. When non-empty,
	// a name whose answer equals this set is almost certainly phantom.
	Addresses []string
	CNAME     []string
	Probed    bool
}

// Matches reports whether ans looks like a wildcard answer for this zone.
func (w *WildcardProfile) Matches(ans *Answer) bool {
	if w == nil || !w.Probed || len(w.Addresses) == 0 {
		return false
	}
	got := ans.Addresses()
	want := append([]string{}, w.Addresses...)
	sort.Strings(got)
	sort.Strings(want)
	return equalStrings(got, want)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
