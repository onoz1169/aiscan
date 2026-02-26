package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/onoz1169/aiscan/internal/scanner"
)

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

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
	fmt.Printf("  Duration: %s\n", formatDuration(duration))
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
	b.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", formatDuration(duration)))

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

func htmlSeverityColor(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return "#dc2626"
	case scanner.SeverityHigh:
		return "#ef4444"
	case scanner.SeverityMedium:
		return "#f59e0b"
	case scanner.SeverityLow:
		return "#06b6d4"
	default:
		return "#6b7280"
	}
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// WriteHTML writes the scan result as a self-contained HTML report to the given path.
func WriteHTML(result *scanner.ScanResult, path string) error {
	var b strings.Builder
	duration := result.EndTime.Sub(result.StartTime)
	counts := result.TotalFindings()

	totalFindings := 0
	for _, c := range counts {
		totalFindings += c
	}

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>aiscan Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 2rem 1rem; }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
  .meta { color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem; }
  .meta span { margin-right: 1.5rem; }
  .summary { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .summary-card { padding: 0.5rem 1rem; border-radius: 0.375rem; font-weight: 600; font-size: 0.875rem; background: #1e293b; }
  .sev-CRITICAL { border-left: 4px solid #dc2626; }
  .sev-HIGH { border-left: 4px solid #ef4444; }
  .sev-MEDIUM { border-left: 4px solid #f59e0b; }
  .sev-LOW { border-left: 4px solid #06b6d4; }
  .sev-INFO { border-left: 4px solid #6b7280; }
  .layer-section { margin-bottom: 2rem; }
  .layer-header { font-size: 1.1rem; font-weight: 600; color: #60a5fa; padding: 0.5rem 0; border-bottom: 1px solid #334155; margin-bottom: 0.75rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; margin-bottom: 1rem; }
  th { text-align: left; padding: 0.5rem 0.75rem; background: #1e293b; color: #94a3b8; font-weight: 600; border-bottom: 2px solid #334155; }
  td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; vertical-align: top; }
  tr:hover td { background: #1e293b; }
  .badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 700; color: #fff; }
  .finding-detail { background: #1e293b; border-radius: 0.375rem; padding: 1rem; margin-bottom: 0.75rem; }
  .finding-title { font-weight: 600; margin-bottom: 0.5rem; }
  .finding-field { margin-bottom: 0.25rem; font-size: 0.8125rem; }
  .finding-field strong { color: #94a3b8; }
  .evidence { font-family: "SF Mono", Menlo, monospace; font-size: 0.75rem; background: #0f172a; padding: 0.5rem; border-radius: 0.25rem; white-space: pre-wrap; word-break: break-all; margin-top: 0.25rem; }
  footer { text-align: center; color: #475569; font-size: 0.75rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class="container">
`)

	b.WriteString(`<h1>aiscan Security Report</h1>`)
	b.WriteString(fmt.Sprintf(`<div class="meta"><span>Target: %s</span><span>Date: %s</span><span>Duration: %s</span><span>Findings: %d</span></div>`,
		htmlEscape(result.Target),
		result.StartTime.Format("2006-01-02 15:04"),
		formatDuration(duration),
		totalFindings,
	))

	// Summary cards
	b.WriteString(`<div class="summary">`)
	for _, sev := range []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	} {
		b.WriteString(fmt.Sprintf(`<div class="summary-card sev-%s">%s: %d</div>`, sev, sev, counts[sev]))
	}
	b.WriteString(`</div>`)

	// Per-layer sections
	for _, layer := range result.Layers {
		if len(layer.Findings) == 0 {
			continue
		}
		b.WriteString(`<div class="layer-section">`)
		b.WriteString(fmt.Sprintf(`<div class="layer-header">%s</div>`, layerDisplayName(layer.Layer)))

		// Summary table
		b.WriteString(`<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Reference</th></tr></thead><tbody>`)
		for _, f := range layer.Findings {
			ref := f.Reference
			if ref == "" {
				ref = "-"
			}
			b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><span class="badge" style="background:%s">%s</span></td><td>%s</td></tr>`,
				htmlEscape(f.ID),
				htmlEscape(f.Title),
				htmlSeverityColor(f.Severity),
				f.Severity,
				htmlEscape(ref),
			))
		}
		b.WriteString(`</tbody></table>`)

		// Detailed findings
		for _, f := range layer.Findings {
			b.WriteString(`<div class="finding-detail">`)
			b.WriteString(fmt.Sprintf(`<div class="finding-title">%s: %s <span class="badge" style="background:%s">%s</span></div>`,
				htmlEscape(f.ID), htmlEscape(f.Title), htmlSeverityColor(f.Severity), f.Severity))

			if f.Description != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field">%s</div>`, htmlEscape(f.Description)))
			}
			if f.Reference != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field"><strong>Reference:</strong> %s</div>`, htmlEscape(f.Reference)))
			}
			if f.Evidence != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field"><strong>Evidence:</strong><div class="evidence">%s</div></div>`, htmlEscape(f.Evidence)))
			}
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field"><strong>Remediation:</strong> %s</div>`, htmlEscape(f.Remediation)))
			}
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(fmt.Sprintf(`<footer>Generated by aiscan v0.1.0 on %s</footer>`, result.StartTime.Format("2006-01-02 15:04:05 MST")))
	b.WriteString(`</div></body></html>`)

	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write html file: %w", err)
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
