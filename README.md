# asm — external attack-surface inventory

`asm` continuously discovers the organisation's internet-facing assets, decides
which of them actually belong to the organisation, ranks them by risk, and
routes the results to the team responsible for each one.

It is built for the messy reality of a large estate: thousands of names, many
of them forgotten staging and campaign pages, a meaningful fraction hosted on
cloud platforms or run by partners, and a scope decision that is genuinely
ambiguous for each of them. The tool treats that ambiguity as the central
problem rather than an afterthought: every asset carries an audit trail of
*why* it was judged in scope or out, so a reviewer can disagree with the tool
and see exactly what to correct.

## Why the design looks the way it does

Four requirements shaped almost every decision.

**Attribution is the hard part.** A resolvable name is not an asset. It might be
a wildcard artefact, a parked domain, a partner's marketing microsite, or a
shared-CDN certificate covering thousands of unrelated names. Treating all of
these as in scope produces a queue nobody trusts; dropping everything that is
not literally in the org's own IP space misses exactly the partner-hosted assets
that cause incidents. `internal/attribution` therefore scores independent,
verifiable signals, keeps every contribution, and returns a verdict
(`confirmed` / `probable` / `possible` / `unverified` / `rejected`) plus a hosting
class (`company` / `third_party` / `partner` / `parked` / `wildcard`).

**Scanning must not hurt production.** `internal/probe` enforces four
independent brakes: a global token bucket, a per-host token bucket, a
business-hours scan window, and a circuit breaker that quarantines a host after
repeated failures. The per-host limit is not configurable above 1 request per
second — the profile validator rejects it outright, because that is a safety
property, not a tuning preference. Every probe is a single request; there are no
retries against a failing target and no state-changing requests (the profile
validator rejects mutating paths).

**The estate changes daily.** `internal/store` persists snapshots and an
append-only event log; `internal/diff` turns two snapshots into typed changes —
a new port, a certificate rotation, a finding resolved, a new asset in a
partner's range. A stable run produces zero changes, which is asserted by the
test suite.

**Results must be dispatchable.** `internal/owner` routes each asset to a team by
rule (hostname pattern, suffix, class, tag, port, tech). Assets no rule claims
go to `unowned` deliberately. `internal/report` renders per-team markdown
bundles, a CSV with one row per finding (ready for a ticketing import), JSON for
pipelines, and a single self-contained HTML dashboard.

## Quick start

```sh
go build ./cmd/asm

asm init -name "Acme Ltd" -domain acme.example   # writes asm.yaml
# edit organisation.domains, org_names, verification_tokens, partner_domains,
# ip_ranges — this section is the root of all attribution
asm validate -config asm.yaml
asm run -config asm.yaml -dry-run                 # discovery + attribution only
asm run -config asm.yaml                          # full run, inside the scan window
asm status -config asm.yaml
asm assets -config asm.yaml --band critical
asm assets -config asm.yaml --show staging.acme.example
asm changes -config asm.yaml --severity high
```

For a run that keeps going:

```sh
asm daemon -config asm.yaml --interval 24h --reprobe 4h
```

Full discovery runs every `--interval`; between them a lighter re-probe reuses
the stored inventory and only re-checks what was already found.

## Try it without touching anything real

```sh
go run ./cmd/demo -out /tmp/asm-demo
```

The demo starts local loopback listeners (a TLS app with a per-SNI certificate,
a plaintext admin panel, a redis-like TCP port) and drives the real pipeline
against a DNS and certificate-transparency fixture. It runs twice, changing an
asset between runs, so you can see change detection fire. Nothing outside
loopback is contacted. The workspace it leaves behind can be inspected with the
`asm` CLI.

## How a run proceeds

1. **Seeds** declared in the profile are always in scope.
2. **Wildcard detection** probes each zone, and each newly-seen subzone, with
   random labels. A catch-all that answers every name is recorded; names that
   only resolve because of it are marked as artefacts and never probed. Without
   this one misconfigured zone can manufacture tens of thousands of phantom
   assets.
3. **Certificate transparency** and passive sources supply candidate names.
4. **DNS resolution** fills in A/AAAA/CNAME/TXT/MX/NS. CNAME targets in scope are
   added; targets in partner domains mark the origin as partner-hosted. Lookups
   are cached and concurrent identical lookups are coalesced.
5. **Attribution** runs on passive evidence, so the decision of what may be
   contacted is made *before* anything is contacted.
6. **Active probing** touches only confirmed/probable assets whose class is in
   `safety.active_classes` (partner assets are passive-only by default). Ports
   are fingerprinted protocol-first, not by port number: TLS is attempted
   wherever a port is not known to be plaintext, so HTTPS on an arbitrary port
   is still found. A short banner read identifies non-web services.
7. **Re-attribution** with probe evidence, then **risk scoring**, **owner
   routing**, **persistence**, **diffing** and **reporting**.

## The attribution model

Each signal carries a signed weight; the sum is the score, and the verdict is
derived from the score and which strong signals are present. Signals include:

| Signal | Weight | Meaning |
|---|---|---|
| `owned_ip_range` | +2.5 | resolves into a prefix from your RIR allocation |
| `dns_verification_record` | +2.5 | a TXT record contains a token your cloud/identity provider issued |
| `cert_org_subject` | +2.5 | certificate subject O/OU names the legal entity |
| `in_org_domain` | +3.0 | under a declared apex |
| `cname_to_org` | +1.5 | CNAME chain lands in your DNS |
| `ct_org_certificate` / `cert_san_owned_name` | +1.5–2.0 | a certificate also covers a name you own |
| `in_registrable_domain` | +1.5 | same registrable domain, not a declared apex |
| `cname_to_partner` / `partner_domain` | −0.5 | points at partner infrastructure (class, not disqualifier) |
| `shared_hosting_certificate` | −1.0 | a large shared SAN set is not evidence of ownership |
| `parked_page` | −3.5 | "this domain is for sale" and friends |
| `wildcard_catchall` | −4.0 | only exists because of a catch-all |
| `nxdomain` / `bare_public_suffix` | −5.0 | does not resolve, or is not a domain |

`confirmed` requires the score to clear the scope threshold **and** at least one
strong signal (owned IP, verification token, org-subject certificate, or a
declared seed). A high score with only weak signals is `probable` — in scope, but
flagged for a human to double-check the hosting story.

Every asset's report shows its evidence with weights and a one-line rationale,
so a disagreement points at a specific signal.

## The risk model

Risk is an additive base (how exposed and outdated the asset is) times a context
multiplier (whether it is in the right hands).

The base weights are calibrated so that a single finding lands where a security
engineer would put it: an exposed secrets file or an unauthenticated Docker API
is critical on its own; an internet-exposed database is high alone and critical
with any aggravation; remote management is medium-to-high; certificate and
hygiene issues are low. Two refinements keep the ranking meaningful:

- **Diminishing returns within a category** — three exposed database services
  are three doors to shut but one root cause. Repeats are scored at 30% of the
  strongest, so a host with a back-end tier does not saturate.
- **Soft saturation** — above a knee the score compresses smoothly instead of
  clamping at 100. An exposed `.env` plus an open admin panel outranks an
  exposed `.env` alone; a hard cap would tie them, precisely where
  discrimination matters most.

The context multiplier raises the score for uncertain ownership and lowers it
for partner-managed assets (which get an explicit escalation note instead, since
the team that must act is not the team that can change the server).

Band thresholds are in `risk.band_thresholds` and are calibrated to this curve.

## Safety model

The profile is a contract, and validation refuses unsafe combinations before a
packet is sent:

- `max_per_host_rps` must be ≤ 1; `max_global_rps` must be ≤ 50.
- `scan_window` (`HH:MM-HH:MM`, timezone-aware, may cross midnight) restricts
  active work. The default is `01:00-05:00 UTC`, so a profile that never
  mentions a window still cannot scan during the day; setting `scan_window: ""`
  is the explicit, reviewable way to allow anytime scanning. Outside the
  window, active probing is skipped; with `wait_for_window: true` the run
  blocks until the window opens instead. Either way, nothing is probed outside
  the window: the gate refuses it for every caller.
- `exclude_hosts` / `exclude_ips` are honoured before anything else.
- Private, loopback, link-local, CGNAT and multicast addresses are refused
  unless `allow_private` is set (the demo and lab use need it).
- `http_paths` / `panel_paths` must be read-only GETs; query strings and
  mutating verbs are rejected.
- `max_probes_per_run` caps a run; `pause_every` / `pause_duration` smooth the
  traffic.
- `dry_run` performs discovery and attribution only.
- `active_classes` defaults to `[company, third_party]`; partner assets are not
  probed.

The gate's state is printed in every run summary so an operator can always see
why the scanner did or did not act.

## Reports

Written to `outputs.dir`:

- `summary.md` — ranked assets, per-team action table, and the reviewable
  out-of-scope candidates with their exclusion reasons.
- `teams/<team>.md` — one bundle per team, containing only their assets.
- `findings.csv` — one row per finding, with team, contact, severity, evidence
  and remediation; shaped for a ticketing import.
- `inventory.json` — every asset, including evidence, factors and services.
- `dashboard.html` — a single self-contained file (no scripts, no external
  assets) for review meetings.
- `changes.md` — the change feed for this run.

## Package map

```
cmd/asm          CLI
cmd/demo         offline, self-contained end-to-end demo
internal/model      shared types; no dependencies
internal/config     profile parsing, validation, scope matcher
internal/discovery  DNS/CT/passive sources, wildcard detection, inventory
internal/attribution explainable ownership scoring
internal/probe      rate gating, TLS/HTTP fingerprinting, path checks
internal/risk       explainable risk scoring and findings
internal/owner      routing assets to teams
internal/store      SQLite persistence and event log
internal/diff       typed change detection between runs
internal/report     markdown / CSV / JSON / HTML
internal/pipeline   orchestration
```

## Testing

```sh
go test ./...
go test -race ./...
```

The suite covers the properties that matter for a security tool: the rate
limiter actually serialises probes on one host while allowing distinct hosts
through; a catch-all app returning 200 for every path does not produce
"exposed .env" findings; a real `.env` still does; protected panels are not open
panels; wildcard phantoms stay out of scope including on subzones; lookalike
domains are rejected; a stable second run produces no changes; the pipeline
never probes an out-of-scope host. `go test -race` is clean.

## Known limitations

- Passive sources are `crt.sh` and CertSpotter over the public APIs. Both rate
  limit aggressively; a production deployment should add a paid passive-DNS feed
  (which also supplies the port hints the probe layer already understands).
- Brute force is a compact built-in wordlist. It is the noisiest source and is
  bounded by `max_labels_per_run`; run it only when you need it.
- The store is a single SQLite file. That is right for one scheduler, not for a
  fleet of concurrent scanners; the schema would carry over to Postgres.
- Protocol fingerprinting identifies HTTP/TLS and common banners. It does not
  attempt version-level component detection, so "outdated component" findings
  depend on what a banner or page reveals.
