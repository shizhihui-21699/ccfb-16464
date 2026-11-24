// Command asm is a continuously running external attack-surface inventory and
// risk-ranking tool.
//
// Subcommands:
//
//	asm init      write a starter profile
//	asm run       execute one discovery → attribution → probe → report cycle
//	asm daemon    run the cycle on a schedule forever
//	asm status    show the last run and headline numbers
//	asm assets    list or inspect assets from the store
//	asm changes   show the change feed
//	asm validate  check a profile without touching the network
//
// The binary is designed to be safe by default: active probing is limited by a
// global and per-host rate, a scan window and a run budget, and the default
// profile never probes partner-managed assets.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"asm/internal/config"
	"asm/internal/model"
	"asm/internal/pipeline"
	"asm/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const usage = `asm — external attack surface inventory

usage: asm <command> [options]

commands:
  init       write a starter profile (asm.yaml)
  validate   parse and check a profile, no network activity
  run        run one discovery → attribution → probe → report cycle
  daemon     run the cycle on a schedule
  status     show the last run and headline counts
  assets     list assets (or show one asset's detail)
  changes    show the recent change feed

run "asm <command> -h" for command options.
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "validate":
		return cmdValidate(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "daemon":
		return cmdDaemon(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "assets":
		return cmdAssets(args[1:])
	case "changes":
		return cmdChanges(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}

func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// --- init ---------------------------------------------------------------

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	out := fs.String("out", "asm.yaml", "path to write the starter profile")
	domain := fs.String("domain", "example.com", "primary organisation domain")
	name := fs.String("name", "Example Corp", "organisation name")
	force := fs.Bool("force", false, "overwrite an existing profile")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s already exists (use -force to overwrite)", *out)
	}
	profile := starterProfile(*name, *domain)
	if err := os.WriteFile(*out, []byte(profile), 0o640); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n\nnext:\n  1. edit organisation.domains, org_names and partner_domains\n  2. asm validate -config %s\n  3. asm run -config %s -dry-run\n", *out, *out, *out)
	return nil
}

func starterProfile(name, domain string) string {
	return fmt.Sprintf(`# External attack-surface profile.
# Read every section before the first real run: this file is the safety
# contract for what may be contacted and how fast.

organisation:
  name: %q
  handle: %s
  domains:
    - %s
  # Legal/trading names as they appear in certificate subject O/OU fields.
  org_names:
    - %q
  # Strings that appear in DNS TXT records your cloud/identity provider asks
  # you to publish (site verification, DKIM selectors). These prove control of
  # a name even when it is hosted elsewhere.
  verification_tokens: []
  # Prefixes you own or lease, from RIR allocations. Used to separate company
  # hosting from cloud/partner hosting.
  ip_ranges: []
  # Domains operated by partners that legitimately host assets for you. Hosts
  # that CNAME here are attributed as partner assets, never silently ignored.
  partner_domains: []
  # Wildcard suffixes of shared hosting / CDN platforms.
  saas_share_suffixes: []

discovery:
  seeds: []
  ct:
    enabled: true
    providers: [crtsh]
    poll_interval: 6h
    max_entries: 5000
    include_expired: true
  dns:
    enabled: true
    resolvers: ["1.1.1.1:53", "8.8.8.8:53"]
    qps: 15
    # 0 disables brute force (CT + seeds + CNAME expansion only).
    max_labels_per_run: 2000
    probe_wildcard: true

safety:
  # Total probes per second across the whole run.
  max_global_rps: 3
  # Probes per second against any single host. Keep this well under 1.
  max_per_host_rps: 0.2
  max_concurrent: 16
  host_concurrency: 1
  request_timeout: 6s
  dial_timeout: 4s
  # Active probing only inside this local window. This is the safe default:
  # omitting it keeps 01:00-05:00 UTC, and clearing it to "" is an explicit
  # decision to allow scanning at any hour.
  scan_window: "01:00-05:00"
  timezone: UTC
  max_probes_per_run: 20000
  max_hosts_per_run: 5000
  pause_every: 200
  pause_duration: 500ms
  # Never contact these, regardless of attribution.
  exclude_hosts: []
  exclude_ips: []
  allow_private: false
  dry_run: false
  # Partner assets are passive-only: we do not scan someone else's servers.
  active_classes: [company, third_party]
  failure_threshold: 4
  cooldown: 10m

probes:
  ports: [443, 80, 22, 8080, 8443, 3389, 3306, 6379, 9200, 27017, 2375, 9000, 5000]
  tls_sni_ports: [443, 8443, 9443]
  user_agent: "asm-inventory/1.0 (+security-team; polite single-request probe)"
  max_redirects: 2
  max_body_bytes: 131072
  http_paths: ["/", "/.git/config", "/.env", "/server-status", "/actuator/env", "/swagger-ui.html", "/v2/api-docs", "/.well-known/security.txt"]
  panel_paths: ["/admin/", "/login", "/phpmyadmin/", "/manager/html", "/grafana/"]
  max_paths_per_service: 8

attribution:
  scope_threshold: 2.5
  probable_threshold: 1.5
  active_threshold: 2.0
  wildcard_penalty: 4.0

risk:
  band_thresholds:
    critical: 80
    high: 60
    medium: 40
    low: 20
  exposure_multiplier: 1.0
  partner_multiplier: 0.8

owners:
  default_team: unowned
  default_contact: ""
  rules: []
    # - name: corp-vpn
    #   team: it-network
    #   contact: netops@example.com
    #   host_pattern: "(?i)^vpn"

outputs:
  dir: out
  formats: [markdown, json, csv, html]
  split_by_team: true
  top_n: 50

store:
  path: asm.db
`, name, slug(name), domain, name)
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "org"
	}
	return out
}

// --- validate -----------------------------------------------------------

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("config", "asm.yaml", "profile path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	fmt.Printf("profile OK: %s\n", cfg.Organisation.Name)
	fmt.Printf("  apexes:      %d\n", len(cfg.Scope().Apexes))
	fmt.Printf("  global rps:  %.2f\n", cfg.Safety.MaxGlobalRPS)
	fmt.Printf("  per-host rps:%.2f\n", cfg.Safety.MaxPerHostRPS)
	if cfg.Safety.ScanWindow != "" {
		fmt.Printf("  scan window: %s (%s)\n", cfg.Safety.ScanWindow, cfg.Safety.Timezone)
	} else {
		fmt.Printf("  scan window: none (active probing allowed at any time)\n")
	}
	if cfg.Safety.DryRun {
		fmt.Printf("  dry run:     yes (no active probing)\n")
	}
	if cfg.Safety.AllowPrivate {
		fmt.Printf("  WARNING: allow_private is on; private addresses may be probed\n")
	}
	fmt.Printf("  active classes: %s\n", strings.Join(cfg.Safety.ActiveClasses, ", "))
	fmt.Printf("  ports:       %v\n", cfg.Probes.Ports)
	return nil
}

// --- run ----------------------------------------------------------------

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("config", "asm.yaml", "profile path")
	dryRun := fs.Bool("dry-run", false, "discovery and attribution only, no active probing")
	noDiscovery := fs.Bool("no-discovery", false, "reuse stored inventory, re-probe only")
	noProbe := fs.Bool("no-probe", false, "discovery and attribution only")
	verbose := fs.Bool("verbose", false, "debug logging")
	team := fs.String("team", "", "focus active probing on names matching this team slug")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger(*verbose)
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	if *dryRun {
		cfg.Safety.DryRun = true
	}
	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	p := pipeline.New(cfg, st, log)
	res, err := p.Run(ctx, pipeline.Options{
		DryRun:      *dryRun,
		NoDiscovery: *noDiscovery,
		NoProbe:     *noProbe,
		OnlyTeam:    *team,
		Log:         log,
	})
	if err != nil {
		return err
	}
	fmt.Printf("\nrun %s complete in %s\n", res.RunID, res.Stats.Duration.Round(time.Millisecond))
	fmt.Printf("  assets in scope: %d (critical %d, high %d, medium %d)\n",
		res.Stats.AssetsScoped,
		res.Stats.ByBand[model.BandCritical], res.Stats.ByBand[model.BandHigh], res.Stats.ByBand[model.BandMedium])
	fmt.Printf("  changes:         %d\n", res.Stats.Changes)
	fmt.Printf("  gate:            %s\n", res.GateSummary)
	if len(res.ReportFiles) > 0 {
		fmt.Printf("  reports:\n")
		for _, f := range res.ReportFiles {
			fmt.Printf("    %s\n", f)
		}
	}
	return nil
}

// --- daemon -------------------------------------------------------------

func cmdDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	path := fs.String("config", "asm.yaml", "profile path")
	interval := fs.Duration("interval", 24*time.Hour, "time between full discovery runs")
	reprobe := fs.Duration("reprobe", 4*time.Hour, "between lightweight re-probes (0 disables)")
	verbose := fs.Bool("verbose", false, "debug logging")
	once := fs.Bool("once", false, "run one cycle and exit (for cron)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger(*verbose)
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	p := pipeline.New(cfg, st, log)

	runOnce := func(opts pipeline.Options) bool {
		opts.Log = log
		runCtx, runCancel := context.WithTimeout(ctx, 6*time.Hour)
		defer runCancel()
		if _, err := p.Run(runCtx, opts); err != nil {
			log.Error("run failed", "err", err)
			return false
		}
		return true
	}

	if *once {
		return errOrNil(runOnce(pipeline.Options{}))
	}

	fullTick := time.NewTicker(*interval)
	defer fullTick.Stop()
	var probeTick *time.Ticker
	if *reprobe > 0 {
		probeTick = time.NewTicker(*reprobe)
		defer probeTick.Stop()
	}

	log.Info("daemon started", "interval", *interval, "reprobe", *reprobe)
	runOnce(pipeline.Options{})

	for {
		select {
		case <-ctx.Done():
			log.Info("daemon stopping")
			return nil
		case <-fullTick.C:
			runOnce(pipeline.Options{})
		case <-tickChan(probeTick):
			runOnce(pipeline.Options{NoDiscovery: true})
		}
	}
}

func tickChan(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func errOrNil(ok bool) error {
	if ok {
		return nil
	}
	return errors.New("run failed")
}

// --- status -------------------------------------------------------------

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	path := fs.String("config", "asm.yaml", "profile path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	id, stats, at, err := st.LastRun(ctx)
	if err != nil {
		return err
	}
	count, err := st.Count(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("store:  %s (%d assets)\n", cfg.Store.Path, count)
	if id == "" {
		fmt.Println("last run: none recorded")
		return nil
	}
	fmt.Printf("last run: %s at %s (%s)\n", id, at.Local().Format(time.RFC1123), stats.Duration.Round(time.Millisecond))
	fmt.Printf("  seen %d, in scope %d, new %d, gone %d\n", stats.AssetsSeen, stats.AssetsScoped, stats.AssetsNew, stats.AssetsGone)
	fmt.Printf("  bands:")
	for _, b := range []model.Band{model.BandCritical, model.BandHigh, model.BandMedium, model.BandLow, model.BandInfo} {
		fmt.Printf(" %s=%d", b, stats.ByBand[b])
	}
	fmt.Println()
	if len(stats.ByTeam) > 0 {
		fmt.Printf("  teams:\n")
		for team, n := range stats.ByTeam {
			fmt.Printf("    %-24s %d\n", team, n)
		}
	}
	return nil
}

// --- assets -------------------------------------------------------------

func cmdAssets(args []string) error {
	fs := flag.NewFlagSet("assets", flag.ExitOnError)
	path := fs.String("config", "asm.yaml", "profile path")
	show := fs.String("show", "", "show one asset by key or name")
	team := fs.String("team", "", "filter by team")
	band := fs.String("band", "", "filter by band")
	limit := fs.Int("limit", 100, "max rows")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	if *show != "" {
		return showAsset(ctx, st, *show)
	}
	list, err := st.List(ctx)
	if err != nil {
		return err
	}
	printed := 0
	fmt.Printf("%-4s %-6s %-30s %-20s %-16s %s\n", "SCORE", "BAND", "ASSET", "TEAM", "CLASS", "TOP FACTOR")
	for _, s := range list {
		if *team != "" && s.Owner.Team != *team {
			continue
		}
		if *band != "" && string(s.Assessment.Band) != *band {
			continue
		}
		if printed >= *limit {
			break
		}
		top := ""
		if len(s.Assessment.Factors) > 0 {
			top = s.Assessment.Factors[0].Title
		}
		fmt.Printf("%-4.0f %-6s %-30s %-20s %-16s %s\n",
			s.Assessment.Score, s.Assessment.Band, truncate(s.Host.Name, 30),
			truncate(s.Owner.Team, 20), s.Attribution.Class, truncate(top, 48))
		printed++
	}
	return nil
}

func showAsset(ctx context.Context, st *store.Store, ref string) error {
	// Accept either a key (a-xxxx) or a hostname.
	snap, err := st.Get(ctx, ref)
	if err != nil {
		return err
	}
	if snap == nil {
		list, err := st.List(ctx)
		if err != nil {
			return err
		}
		for _, s := range list {
			if s.Host.Name == model.NormalizeName(ref) {
				snap = s
				break
			}
		}
	}
	if snap == nil {
		return fmt.Errorf("no asset matching %q", ref)
	}
	fmt.Printf("%s  [%s]\n", snap.Host.Name, snap.Key)
	fmt.Printf("  score %.0f (%s) — %s\n", snap.Assessment.Score, snap.Assessment.Band, snap.Assessment.Summary)
	fmt.Printf("  owner %s (%s)\n", snap.Owner.Team, snap.Owner.Contact)
	if snap.Owner.Escalation != "" {
		fmt.Printf("  escalation: %s\n", snap.Owner.Escalation)
	}
	fmt.Printf("  attribution %s / %s (score %.1f, confidence %.2f)\n",
		snap.Attribution.Verdict, snap.Attribution.Class, snap.Attribution.Score, snap.Attribution.Confidence)
	fmt.Printf("  rationale: %s\n", snap.Attribution.Rationale)
	fmt.Printf("  addresses: %s\n", strings.Join(snap.Host.Addresses(), ", "))
	fmt.Printf("  first seen %s, last seen %s\n", snap.FirstSeen.Local().Format(time.RFC3339), snap.LastSeen.Local().Format(time.RFC3339))
	if len(snap.Services) > 0 {
		fmt.Printf("  services:\n")
		for _, svc := range snap.Services {
			desc := fmt.Sprintf("%d/tcp", svc.Port)
			if svc.TLS != nil {
				desc += " tls"
				if svc.TLS.SubjectCN != "" {
					desc += " cn=" + svc.TLS.SubjectCN
				}
			}
			if svc.HTTP != nil {
				desc += fmt.Sprintf(" http=%d", svc.HTTP.Status)
				if svc.HTTP.Title != "" {
					desc += " " + truncate(svc.HTTP.Title, 40)
				}
			}
			fmt.Printf("    %s\n", desc)
		}
	}
	if len(snap.Assessment.Factors) > 0 {
		fmt.Printf("  risk factors:\n")
		for _, f := range snap.Assessment.Factors {
			fmt.Printf("    %+5.0f  %-40s %s\n", f.Weight, truncate(f.Title, 40), f.Detail)
		}
	}
	fmt.Printf("  attribution evidence:\n")
	for _, e := range snap.Attribution.Evidence {
		fmt.Printf("    %+5.1f  %-28s %s\n", e.Weight, e.Signal, e.Detail)
	}
	events, err := st.Timeline(ctx, snap.Key, 20)
	if err == nil && len(events) > 0 {
		fmt.Printf("  recent events:\n")
		for _, e := range events {
			fmt.Printf("    %s  %-16s %s\n", e.At.Local().Format("2006-01-02 15:04"), e.Kind, e.Summary)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// --- changes ------------------------------------------------------------

func cmdChanges(args []string) error {
	fs := flag.NewFlagSet("changes", flag.ExitOnError)
	path := fs.String("config", "asm.yaml", "profile path")
	limit := fs.Int("limit", 50, "max entries")
	sev := fs.String("severity", "", "filter: critical, high, medium, low, info")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return err
	}
	defer st.Close()
	events, err := st.Events(context.Background(), *limit)
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-10s %-26s %-16s %s\n", "WHEN", "SEVERITY", "ASSET", "TEAM", "CHANGE")
	for _, e := range events {
		if *sev != "" && string(e.Severity) != *sev {
			continue
		}
		fmt.Printf("%-16s %-10s %-26s %-16s %s\n",
			e.At.Local().Format("01-02 15:04"), e.Severity, truncate(e.AssetName, 26), truncate(e.Team, 16), truncate(e.Summary, 60))
	}
	return nil
}

var _ = filepath.Join
