package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/onoz1169/1scan/internal/abuseipdb"
	"github.com/onoz1169/1scan/internal/cve"
	"github.com/onoz1169/1scan/internal/report"
	"github.com/onoz1169/1scan/internal/scanner"
	"github.com/onoz1169/1scan/internal/scanner/llm"
	"github.com/onoz1169/1scan/internal/scanner/network"
	"github.com/onoz1169/1scan/internal/scanner/webapp"
	"github.com/onoz1169/1scan/internal/toolcheck"
	"github.com/onoz1169/1scan/internal/virustotal"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	target          string
	layers          []string
	outputFormat    string
	outputFile      string
	timeout         int
	verbose         bool
	failOn          string
	quiet           bool
	noColor         bool
	severityFilter  string
	noNmap          bool
	nmapPath        string
	nmapFlags       string
	noNuclei        bool
	nucleiTemplates string
	showTools       bool
	configFile      string
	cveLookup       bool
	nvdAPIKey       string
	noShodan        bool
	abuseipdbKey    string
	vtAPIKey        string
	lang            string
	llmReport       bool
	llmKey          string
	llmModel        string
	authHeader      string
	authToken       string
	authCookie      string
)

// ScanConfig mirrors the CLI flags for YAML config file support.
type ScanConfig struct {
	Target          string   `yaml:"target"`
	Layers          []string `yaml:"layers"`
	Timeout         int      `yaml:"timeout"`
	Format          string   `yaml:"format"`
	Output          string   `yaml:"output"`
	FailOn          string   `yaml:"fail-on"`
	Severity        string   `yaml:"severity"`
	NoNmap          bool     `yaml:"no-nmap"`
	NmapPath        string   `yaml:"nmap-path"`
	NmapFlags       string   `yaml:"nmap-flags"`
	NoNuclei        bool     `yaml:"no-nuclei"`
	NucleiTemplates string   `yaml:"nuclei-templates"`
	NoShodan        bool     `yaml:"no-shodan"`
	AbuseIPDBKey    string   `yaml:"abuseipdb-key"`
	VTAPIKey        string   `yaml:"vt-api-key"`
}

// applyConfig reads a YAML config file and applies values for flags not explicitly
// set on the command line (CLI flags always take precedence).
func applyConfig(cmd *cobra.Command, cfgPath string) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	var cfg ScanConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	setIfUnset := func(name string, apply func()) {
		if !cmd.Flags().Changed(name) {
			apply()
		}
	}

	if cfg.Target != "" {
		setIfUnset("target", func() { target = cfg.Target })
	}
	if len(cfg.Layers) > 0 {
		setIfUnset("layers", func() { layers = cfg.Layers })
	}
	if cfg.Timeout != 0 {
		setIfUnset("timeout", func() { timeout = cfg.Timeout })
	}
	if cfg.Format != "" {
		setIfUnset("format", func() { outputFormat = cfg.Format })
	}
	if cfg.Output != "" {
		setIfUnset("output", func() { outputFile = cfg.Output })
	}
	if cfg.FailOn != "" {
		setIfUnset("fail-on", func() { failOn = cfg.FailOn })
	}
	if cfg.Severity != "" {
		setIfUnset("severity", func() { severityFilter = cfg.Severity })
	}
	if cfg.NoNmap {
		setIfUnset("no-nmap", func() { noNmap = true })
	}
	if cfg.NmapPath != "" {
		setIfUnset("nmap-path", func() { nmapPath = cfg.NmapPath })
	}
	if cfg.NmapFlags != "" {
		setIfUnset("nmap-flags", func() { nmapFlags = cfg.NmapFlags })
	}
	if cfg.NoNuclei {
		setIfUnset("no-nuclei", func() { noNuclei = true })
	}
	if cfg.NucleiTemplates != "" {
		setIfUnset("nuclei-templates", func() { nucleiTemplates = cfg.NucleiTemplates })
	}
	if cfg.NoShodan {
		setIfUnset("no-shodan", func() { noShodan = true })
	}
	if cfg.AbuseIPDBKey != "" {
		setIfUnset("abuseipdb-key", func() { abuseipdbKey = cfg.AbuseIPDBKey })
	}
	if cfg.VTAPIKey != "" {
		setIfUnset("vt-api-key", func() { vtAPIKey = cfg.VTAPIKey })
	}
	return nil
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scan against a target",
	Long:  `Run a multi-layer security scan covering network ports, web application headers/TLS, and LLM endpoint probes.`,
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "Target URL or hostname (required)")
	scanCmd.Flags().StringSliceVarP(&layers, "layers", "l", []string{"network", "webapp", "llm"}, "Which layers to run")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "F", "terminal", "Output format: terminal, json, markdown, sarif, html")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (stdout if empty, format auto-detected)")
	scanCmd.Flags().IntVar(&timeout, "timeout", 10, "Timeout per scan in seconds")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "high", "Exit code 1 if findings at or above this severity: critical, high, medium, low, none")
	scanCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress banner and progress output")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output")
	scanCmd.Flags().StringVarP(&severityFilter, "severity", "s", "", "Only show findings at or above: critical, high, medium, low, info")

	scanCmd.Flags().BoolVar(&noNmap, "no-nmap", false, "Disable nmap enrichment even if installed")
	scanCmd.Flags().StringVar(&nmapPath, "nmap-path", "", "Path to nmap binary (overrides PATH)")
	scanCmd.Flags().StringVar(&nmapFlags, "nmap-flags", "", "Additional nmap flags")
	scanCmd.Flags().BoolVar(&noNuclei, "no-nuclei", false, "Disable nuclei scan even if installed")
	scanCmd.Flags().StringVar(&nucleiTemplates, "nuclei-templates", "", "Nuclei template categories (default: cves,misconfiguration,exposed-panels)")
	scanCmd.Flags().StringVar(&configFile, "config", "", "Path to YAML config file (CLI flags override config)")
	scanCmd.Flags().BoolVar(&cveLookup, "cve-lookup", false, "Enrich nmap findings with NVD CVE data (requires --nvd-api-key or NVD_API_KEY env)")
	scanCmd.Flags().StringVar(&nvdAPIKey, "nvd-api-key", "", "NVD API key for CVE lookups (or set NVD_API_KEY env var)")
	scanCmd.Flags().BoolVar(&noShodan, "no-shodan", false, "Disable Shodan InternetDB enrichment")
	scanCmd.Flags().StringVar(&abuseipdbKey, "abuseipdb-key", "", "AbuseIPDB API key for IP reputation checks (or set ABUSEIPDB_API_KEY env var)")
	scanCmd.Flags().StringVar(&vtAPIKey, "vt-api-key", "", "VirusTotal API key for URL reputation checks (or set VT_API_KEY env var)")

	// Authentication flags (passed to all scanner layers)
	scanCmd.Flags().StringVar(&authHeader, "auth-header", "", "Auth header injected into every request, e.g. \"X-API-Key: mykey\" or \"Authorization: Bearer tok\"")
	scanCmd.Flags().StringVar(&authToken, "auth-token", "", "Shorthand for Authorization: Bearer <token>")
	scanCmd.Flags().StringVar(&authCookie, "auth-cookie", "", "Cookie header value injected into every request, e.g. \"session=abc; csrftoken=xyz\"")

	// Language and LLM-enhanced report flags
	scanCmd.Flags().StringVar(&lang, "lang", "en", "Report language: en, ja")
	scanCmd.Flags().BoolVar(&llmReport, "llm-report", false, "Generate LLM-enhanced executive report (requires --llm-key)")
	scanCmd.Flags().StringVar(&llmKey, "llm-key", "", "Anthropic API key for LLM report (or set ANTHROPIC_API_KEY env var)")
	scanCmd.Flags().StringVar(&llmModel, "llm-model", "claude-sonnet-4-6", "Model for LLM report generation")

	rootCmd.Flags().BoolVar(&showTools, "show-tools", false, "Show detected optional tools and exit")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if showTools {
		printToolStatus()
		return nil
	}

	// Load config file: explicit --config, then auto-detect .1scan.yaml
	cfgPath := configFile
	if cfgPath == "" {
		for _, candidate := range []string{".1scan.yaml", ".1scan.yml", "1scan.yaml"} {
			if _, err := os.Stat(candidate); err == nil {
				cfgPath = candidate
				break
			}
		}
	}
	if cfgPath != "" {
		if err := applyConfig(cmd, cfgPath); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}

	if target == "" {
		return fmt.Errorf("required flag --target not set (provide via flag or config file)")
	}

	if noColor {
		color.NoColor = true
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "1scan v%s — All-in-one Security Scanner\n", version)
		fmt.Fprintf(os.Stderr, "Scanning: %s\n\n", target)
	}

	scanners := buildScanners(layers)

	result := &scanner.ScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	for _, sc := range scanners {
		var s *spinner.Spinner
		if !quiet {
			s = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
			s.Suffix = fmt.Sprintf(" Scanning %s layer...", sc.Name())
			s.Start()
		}

		lr, err := sc.Scan(target, timeout)

		if s != nil {
			s.Stop()
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "  [!] %s scan error: %v\n", sc.Name(), err)
			result.Layers = append(result.Layers, scanner.LayerResult{
				Layer:  sc.Name(),
				Target: target,
				Errors: []string{err.Error()},
			})
			continue
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "  [+] %s: %d findings\n", sc.Name(), len(lr.Findings))
		}

		result.Layers = append(result.Layers, *lr)
	}

	result.EndTime = time.Now()

	// Detect cross-layer attack chains
	result.AttackChains = scanner.DetectChains(result)

	// Apply severity filter if set
	if severityFilter != "" {
		filterFindings(result, severityFilter)
	}

	reportLang := report.ParseLang(lang)

	if err := writeReport(result, outputFormat, outputFile, reportLang); err != nil {
		return err
	}

	// Generate LLM-enhanced report if requested
	if llmReport {
		apiKey := llmKey
		if apiKey == "" {
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		}
		if apiKey == "" {
			fmt.Fprintln(os.Stderr, "  [!] --llm-report requires --llm-key or ANTHROPIC_API_KEY env var; skipping")
		} else {
			if !quiet {
				fmt.Fprintln(os.Stderr, "\nGenerating LLM-enhanced report...")
			}
			text, err := report.GenerateLLMReport(result, report.LLMReportConfig{
				APIKey: apiKey,
				Model:  llmModel,
				Lang:   reportLang,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "  [!] LLM report error: %v\n", err)
			} else {
				fmt.Println("\n" + strings.Repeat("─", 50))
				fmt.Println("  LLM-Enhanced Report")
				fmt.Println(strings.Repeat("─", 50))
				fmt.Println(text)
			}
		}
	}

	// Exit with code 1 based on --fail-on threshold
	if shouldFail(result, failOn) {
		os.Exit(1)
	}

	return nil
}

func shouldFail(result *scanner.ScanResult, failOn string) bool {
	if strings.ToLower(failOn) == "none" {
		return false
	}
	threshold := severityRank(severityFromString(failOn, scanner.SeverityHigh))
	for _, layer := range result.Layers {
		for _, f := range layer.Findings {
			if severityRank(f.Severity) >= threshold {
				return true
			}
		}
	}
	return false
}

func severityFromString(s string, fallback scanner.Severity) scanner.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return scanner.SeverityCritical
	case "high":
		return scanner.SeverityHigh
	case "medium":
		return scanner.SeverityMedium
	case "low":
		return scanner.SeverityLow
	case "info":
		return scanner.SeverityInfo
	default:
		return fallback
	}
}

func severityRank(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 5
	case scanner.SeverityHigh:
		return 4
	case scanner.SeverityMedium:
		return 3
	case scanner.SeverityLow:
		return 2
	case scanner.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func filterFindings(result *scanner.ScanResult, minSeverity string) {
	threshold := severityRank(severityFromString(minSeverity, scanner.SeverityInfo))
	for i, layer := range result.Layers {
		var filtered []scanner.Finding
		for _, f := range layer.Findings {
			if severityRank(f.Severity) >= threshold {
				filtered = append(filtered, f)
			}
		}
		result.Layers[i].Findings = filtered
	}
}

type reportWriteFn func(*scanner.ScanResult, string) error

type fileReportSpec struct {
	defaultFile string
	write       reportWriteFn
}

var fileReports = map[string]fileReportSpec{
	"json":     {"1scan-report.json", report.WriteJSON},
	"markdown": {"1scan-report.md", report.WriteMarkdown},
	"sarif":    {"1scan-results.sarif", report.WriteSARIF},
	"html":     {"1scan-report.html", report.WriteHTML},
}

func writeReport(result *scanner.ScanResult, format, outFile string, reportLang report.Lang) error {
	spec, ok := fileReports[format]
	if !ok {
		report.PrintTerminal(result, reportLang)
		return nil
	}
	if outFile == "" {
		outFile = spec.defaultFile
	}
	if err := spec.write(result, outFile); err != nil {
		return fmt.Errorf("write %s report: %w", format, err)
	}
	fmt.Fprintf(os.Stderr, "\nReport written to %s\n", outFile)
	return nil
}

func buildAuthOpts() scanner.AuthOptions {
	return scanner.AuthOptions{
		Header: authHeader,
		Token:  authToken,
		Cookie: authCookie,
	}
}

func buildScanners(layers []string) []scanner.Scanner {
	// Resolve NVD API key: flag > env var
	nvdKey := nvdAPIKey
	if nvdKey == "" {
		nvdKey = os.Getenv("NVD_API_KEY")
	}
	var cveClient *cve.Client
	if cveLookup && nvdKey != "" {
		cveClient = cve.New(nvdKey)
	} else if cveLookup && nvdKey == "" {
		fmt.Fprintln(os.Stderr, "  [!] --cve-lookup requires --nvd-api-key or NVD_API_KEY env var; skipping CVE lookup")
	}

	// Resolve AbuseIPDB key: flag > env var
	abuseKey := abuseipdbKey
	if abuseKey == "" {
		abuseKey = os.Getenv("ABUSEIPDB_API_KEY")
	}
	var abuseClient *abuseipdb.Client
	if abuseKey != "" {
		abuseClient = abuseipdb.New(abuseKey)
	}

	// Resolve VirusTotal key: flag > env var
	vtKey := vtAPIKey
	if vtKey == "" {
		vtKey = os.Getenv("VT_API_KEY")
	}
	var vtClient *virustotal.Client
	if vtKey != "" {
		vtClient = virustotal.New(vtKey)
	}

	var scanners []scanner.Scanner
	auth := buildAuthOpts()

	for _, l := range layers {
		switch l {
		case "network":
			scanners = append(scanners, network.NewWithAuth(
				network.NmapOptions{
					Disabled:   noNmap,
					Path:       nmapPath,
					ExtraFlags: nmapFlags,
					CVEClient:  cveClient,
				},
				network.NetworkEnrichmentOptions{
					ShodanEnabled: !noShodan,
					AbuseIPDB:     abuseClient,
				},
				auth,
			))
		case "webapp":
			scanners = append(scanners, webapp.NewWithAll(
				webapp.NucleiOptions{
					Disabled:  noNuclei,
					Templates: nucleiTemplates,
				},
				vtClient,
				auth,
			))
		case "llm":
			scanners = append(scanners, llm.NewWithAuth(auth))
		default:
			fmt.Fprintf(os.Stderr, "[!] Unknown layer: %s (skipping)\n", l)
		}
	}
	return scanners
}

func printToolStatus() {
	tools := []struct {
		name    string
		install string
	}{
		{"nmap", "brew install nmap  /  apt install nmap"},
		{"nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	}
	fmt.Println("Optional tools:")
	for _, t := range tools {
		path, ok := toolcheck.Available(t.name)
		if ok {
			fmt.Printf("  [+] %-12s %s\n", t.name, path)
		} else {
			fmt.Printf("  [-] %-12s not installed -- %s\n", t.name, t.install)
		}
	}
}
