package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/onoz1169/aiscan/internal/report"
	"github.com/onoz1169/aiscan/internal/scanner"
	"github.com/onoz1169/aiscan/internal/scanner/llm"
	"github.com/onoz1169/aiscan/internal/scanner/network"
	"github.com/onoz1169/aiscan/internal/scanner/webapp"
	"github.com/spf13/cobra"
)

var (
	target     string
	layers     []string
	output     string
	outputFile string
	timeout    int
	verbose    bool
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
	scanCmd.Flags().StringVarP(&output, "output", "o", "terminal", "Output format: terminal, json, markdown")
	scanCmd.Flags().StringVarP(&outputFile, "output-file", "f", "aiscan-report", "Output filename (without extension)")
	scanCmd.Flags().IntVar(&timeout, "timeout", 10, "Timeout per scan in seconds")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	scanCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	fmt.Printf("aiscan v%s — All-in-one Security Scanner\n", version)
	fmt.Printf("Scanning: %s\n\n", target)

	scanners := buildScanners(layers)

	result := &scanner.ScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	for _, s := range scanners {
		if verbose {
			fmt.Printf("[*] Running %s scan...\n", s.Name())
		}

		lr, err := s.Scan(target, timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s scan error: %v\n", s.Name(), err)
			result.Layers = append(result.Layers, scanner.LayerResult{
				Layer:  s.Name(),
				Target: target,
				Errors: []string{err.Error()},
			})
			continue
		}

		if verbose {
			fmt.Printf("[+] %s scan complete: %d findings\n", s.Name(), len(lr.Findings))
		}

		result.Layers = append(result.Layers, *lr)
	}

	result.EndTime = time.Now()

	switch output {
	case "json":
		path := outputFile + ".json"
		if err := report.WriteJSON(result, path); err != nil {
			return fmt.Errorf("write json report: %w", err)
		}
		fmt.Printf("\nReport written to %s\n", path)
	case "markdown":
		path := outputFile + ".md"
		if err := report.WriteMarkdown(result, path); err != nil {
			return fmt.Errorf("write markdown report: %w", err)
		}
		fmt.Printf("\nReport written to %s\n", path)
	default:
		report.PrintTerminal(result)
	}

	// Exit with code 1 if any CRITICAL or HIGH findings
	counts := result.TotalFindings()
	if counts[scanner.SeverityCritical] > 0 || counts[scanner.SeverityHigh] > 0 {
		os.Exit(1)
	}

	return nil
}

func buildScanners(layers []string) []scanner.Scanner {
	var scanners []scanner.Scanner
	for _, l := range layers {
		switch l {
		case "network":
			scanners = append(scanners, network.New())
		case "webapp":
			scanners = append(scanners, webapp.New())
		case "llm":
			scanners = append(scanners, llm.New())
		default:
			fmt.Fprintf(os.Stderr, "[!] Unknown layer: %s (skipping)\n", l)
		}
	}
	return scanners
}
