package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/onoz1169/aiscan/internal/scanner"
)

var (
	separator = strings.Repeat("\u2501", 46)

	colorCritical    = color.New(color.FgRed, color.Bold)
	colorHigh        = color.New(color.FgRed)
	colorMedium      = color.New(color.FgYellow)
	colorLow         = color.New(color.FgCyan)
	colorInfo        = color.New(color.FgWhite)
	colorLayerHeader = color.New(color.FgBlue, color.Bold)
)

func severityColor(s scanner.Severity) *color.Color {
	switch s {
	case scanner.SeverityCritical:
		return colorCritical
	case scanner.SeverityHigh:
		return colorHigh
	case scanner.SeverityMedium:
		return colorMedium
	case scanner.SeverityLow:
		return colorLow
	default:
		return colorInfo
	}
}

func layerDisplayName(layer string) string {
	switch strings.ToLower(layer) {
	case "network":
		return "NETWORK LAYER"
	case "webapp":
		return "WEBAPP LAYER"
	case "llm":
		return "LLM LAYER"
	default:
		return strings.ToUpper(layer) + " LAYER"
	}
}

// PrintTerminal outputs a colored security report to the terminal.
func PrintTerminal(result *scanner.ScanResult) {
	duration := result.EndTime.Sub(result.StartTime)

	fmt.Println(separator)
	fmt.Println("  aiscan — Security Scan Report")
	fmt.Printf("  Target: %s\n", result.Target)
	fmt.Printf("  Duration: %.1fs\n", duration.Seconds())
	fmt.Println(separator)

	for _, layer := range result.Layers {
		fmt.Println()
		colorLayerHeader.Printf("[%s]\n", layerDisplayName(layer.Layer))
		for _, f := range layer.Findings {
			sc := severityColor(f.Severity)
			fmt.Printf("  ● %-42s ", f.Title)
			sc.Println(string(f.Severity))
		}
	}

	counts := result.TotalFindings()
	fmt.Println()
	fmt.Println(separator)
	fmt.Println("  SUMMARY")
	fmt.Print("  ")
	colorCritical.Printf("CRITICAL: %d", counts[scanner.SeverityCritical])
	fmt.Print("  ")
	colorHigh.Printf("HIGH: %d", counts[scanner.SeverityHigh])
	fmt.Print("  ")
	colorMedium.Printf("MEDIUM: %d", counts[scanner.SeverityMedium])
	fmt.Print("  ")
	colorLow.Printf("LOW: %d", counts[scanner.SeverityLow])
	fmt.Print("  ")
	colorInfo.Printf("INFO: %d", counts[scanner.SeverityInfo])
	fmt.Println()
	fmt.Println(separator)
}

// WriteJSON writes the scan result as indented JSON to the given path.
func WriteJSON(result *scanner.ScanResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write json file: %w", err)
	}
	return nil
}

// WriteMarkdown writes the scan result as a Markdown report to the given path.
func WriteMarkdown(result *scanner.ScanResult, path string) error {
	var b strings.Builder
	duration := result.EndTime.Sub(result.StartTime)

	b.WriteString("# aiscan Security Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s  \n", result.Target))
	b.WriteString(fmt.Sprintf("**Scan Date:** %s  \n", result.StartTime.Format("2006-01-02")))
	b.WriteString(fmt.Sprintf("**Duration:** %.1fs  \n\n", duration.Seconds()))

	// Summary table
	counts := result.TotalFindings()
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	for _, sev := range []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	} {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, counts[sev]))
	}
	b.WriteString("\n")

	// Per-layer sections
	for _, layer := range result.Layers {
		if len(layer.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("## %s\n\n", layerDisplayName(layer.Layer)))

		// Layer summary table
		b.WriteString("| ID | Title | Severity | Reference |\n")
		b.WriteString("|----|-------|----------|-----------|\n")
		for _, f := range layer.Findings {
			ref := f.Reference
			if ref == "" {
				ref = "-"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", f.ID, f.Title, f.Severity, ref))
		}
		b.WriteString("\n")

		// Detailed findings
		for _, f := range layer.Findings {
			b.WriteString(fmt.Sprintf("### %s: %s\n", f.ID, f.Title))
			b.WriteString(fmt.Sprintf("**Severity:** %s  \n", f.Severity))
			if f.Reference != "" {
				b.WriteString(fmt.Sprintf("**Reference:** %s  \n", f.Reference))
			}
			if f.Evidence != "" {
				b.WriteString(fmt.Sprintf("**Evidence:** %s  \n", f.Evidence))
			}
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("**Remediation:** %s\n", f.Remediation))
			}
			b.WriteString("\n")
		}
	}

	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write markdown file: %w", err)
	}
	return nil
}
