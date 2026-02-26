package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/onoz1169/aiscan/internal/report"
	"github.com/onoz1169/aiscan/internal/scanner"
	"github.com/onoz1169/aiscan/internal/scanner/llm"
	"github.com/onoz1169/aiscan/internal/scanner/network"
	"github.com/onoz1169/aiscan/internal/scanner/webapp"
	"github.com/onoz1169/aiscan/internal/toolcheck"
	"github.com/spf13/cobra"
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
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scan against a target",
	Long:  `Run a multi-layer security scan covering network ports, web application headers/TLS, and LLM endpoint probes.`,
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "Target URL or hostname (required)")
	scanCmd.Flags().StringSliceVarP(&layers, "layers", "l", []string{"network", "webapp", "llm"}, "Which layers to run")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "F", "terminal", "Output format: terminal, json, markdown, sarif")
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

	scanCmd.MarkFlagRequired("target")

	rootCmd.Flags().BoolVar(&showTools, "show-tools", false, "Show detected optional tools and exit")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if showTools {
		printToolStatus()
		return nil
	}

	if noColor {
		color.NoColor = true
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "aiscan v%s — All-in-one Security Scanner\n", version)
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

	// Apply severity filter if set
	if severityFilter != "" {
		filterFindings(result, severityFilter)
	}

	if err := writeReport(result, outputFormat, outputFile); err != nil {
		return err
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
	"json":     {"aiscan-report.json", report.WriteJSON},
	"markdown": {"aiscan-report.md", report.WriteMarkdown},
	"sarif":    {"aiscan-results.sarif", report.WriteSARIF},
}

func writeReport(result *scanner.ScanResult, format, outFile string) error {
	spec, ok := fileReports[format]
	if !ok {
		report.PrintTerminal(result)
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

func buildScanners(layers []string) []scanner.Scanner {
	var scanners []scanner.Scanner
	for _, l := range layers {
		switch l {
		case "network":
			scanners = append(scanners, network.NewWithOptions(network.NmapOptions{
				Disabled:   noNmap,
				Path:       nmapPath,
				ExtraFlags: nmapFlags,
			}))
		case "webapp":
			scanners = append(scanners, webapp.NewWithOptions(webapp.NucleiOptions{
				Disabled:  noNuclei,
				Templates: nucleiTemplates,
			}))
		case "llm":
			scanners = append(scanners, llm.New())
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
