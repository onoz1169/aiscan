package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/onoz1169/aiscan/internal/scanner"
)

// SARIF 2.1.0 types

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription map[string]string      `json:"shortDescription"`
	DefaultConfig    map[string]string      `json:"defaultConfiguration"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   map[string]string `json:"message"`
	Locations []sarifLocation   `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation map[string]string `json:"artifactLocation"`
	Region           map[string]int    `json:"region"`
}

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

func sarifLevel(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifSecuritySeverity(s scanner.Severity) float64 {
	switch s {
	case scanner.SeverityCritical:
		return 9.5
	case scanner.SeverityHigh:
		return 7.5
	case scanner.SeverityMedium:
		return 5.0
	case scanner.SeverityLow:
		return 2.0
	default:
		return 0.0
	}
}

// WriteSARIF writes the scan result as a SARIF 2.1.0 report to the given path.
func WriteSARIF(result *scanner.ScanResult, path string) error {
	rulesMap := make(map[string]sarifRule)
	var results []sarifResult

	for _, layer := range result.Layers {
		for _, f := range layer.Findings {
			if _, exists := rulesMap[f.ID]; !exists {
				rulesMap[f.ID] = sarifRule{
					ID:               f.ID,
					Name:             f.Title,
					ShortDescription: map[string]string{"text": f.Title},
					DefaultConfig:    map[string]string{"level": sarifLevel(f.Severity)},
					Properties: map[string]interface{}{
						"security-severity": fmt.Sprintf("%.1f", sarifSecuritySeverity(f.Severity)),
					},
				}
			}

			msg := f.Title
			if f.Evidence != "" {
				msg = f.Title + ": " + f.Evidence
			}

			results = append(results, sarifResult{
				RuleID:  f.ID,
				Level:   sarifLevel(f.Severity),
				Message: map[string]string{"text": msg},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysical{
							ArtifactLocation: map[string]string{"uri": result.Target},
							Region:           map[string]int{"startLine": 1},
						},
					},
				},
			})
		}
	}

	var rules []sarifRule
	for _, r := range rulesMap {
		rules = append(rules, r)
	}

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "aiscan",
						Version:        "0.1.0",
						InformationURI: "https://github.com/onoz1169/aiscan",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write sarif file: %w", err)
	}
	return nil
}
