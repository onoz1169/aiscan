package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/onoz1169/1scan/internal/scanner"
)

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// fingerprint returns a stable sha256 hex string for a finding, used as SARIF partialFingerprint.
func fingerprint(f scanner.Finding, target string) string {
	h := sha256.New()
	h.Write([]byte(f.Layer + ":" + f.ID + ":" + f.Title + ":" + target))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// ─── SARIF 2.1.0 types ───────────────────────────────────────────────────────

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
	Help             map[string]string      `json:"help,omitempty"`
	DefaultConfig    map[string]string      `json:"defaultConfiguration"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             map[string]string `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Locations           []sarifLocation   `json:"locations"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation map[string]string `json:"artifactLocation"`
	Region           map[string]int    `json:"region"`
}

// ─── Terminal colors ──────────────────────────────────────────────────────────

var (
	separator = strings.Repeat("\u2501", 50)

	colorCritical    = color.New(color.FgRed, color.Bold)
	colorHigh        = color.New(color.FgRed)
	colorMedium      = color.New(color.FgYellow)
	colorLow         = color.New(color.FgCyan)
	colorInfo        = color.New(color.FgWhite)
	colorLayerHeader = color.New(color.FgBlue, color.Bold)
	colorChain       = color.New(color.FgRed, color.Bold)
	colorMeta        = color.New(color.FgHiBlack)
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

// chainLayerLabel returns a short, capitalized layer name for attack chain display.
func chainLayerLabel(layer string) string {
	switch strings.ToLower(layer) {
	case "network":
		return "Network"
	case "webapp":
		return "WebApp"
	case "llm":
		return "LLM"
	default:
		return strings.ToUpper(layer[:1]) + layer[1:]
	}
}

// ─── Terminal output ──────────────────────────────────────────────────────────

// PrintTerminal outputs a colored security report to the terminal.
// Layout: Banner → Summary → Attack Chains → Layer Findings (Evidence+Fix)
func PrintTerminal(result *scanner.ScanResult, lang Lang) {
	lbl := getLabels(lang)
	duration := result.EndTime.Sub(result.StartTime)
	layerNames := make([]string, 0, len(result.Layers))
	for _, lr := range result.Layers {
		layerNames = append(layerNames, lr.Layer)
	}

	// ── Banner ────────────────────────────────────────────────────────────────
	fmt.Println(separator)
	fmt.Printf("  1scan  |  %s: %s\n", lbl.Target, result.Target)
	fmt.Printf("  %s: %s  |  %s: %s\n",
		lbl.Duration, formatDuration(duration),
		lbl.Layers, strings.Join(layerNames, ", "))
	fmt.Println(separator)

	// ── Summary (top, before findings) ───────────────────────────────────────
	counts := result.TotalFindings()
	fmt.Printf("\n  %s   ", lbl.Summary)
	colorCritical.Printf("CRITICAL %d  ", counts[scanner.SeverityCritical])
	colorHigh.Printf("HIGH %d  ", counts[scanner.SeverityHigh])
	colorMedium.Printf("MEDIUM %d  ", counts[scanner.SeverityMedium])
	colorLow.Printf("LOW %d  ", counts[scanner.SeverityLow])
	colorInfo.Printf("INFO %d", counts[scanner.SeverityInfo])
	fmt.Println()

	// ── Attack Chains ─────────────────────────────────────────────────────────
	if len(result.AttackChains) > 0 {
		fmt.Println()
		for _, chain := range result.AttackChains {
			colorChain.Printf("\u26a0  %s", lbl.AttackChainDetected)
			fmt.Printf("  ")
			severityColor(chain.Severity).Println(string(chain.Severity))

			for _, layerName := range chain.LayerNames {
				// Find the finding from this layer that contributed to the chain
				for _, lr := range result.Layers {
					if !strings.EqualFold(lr.Layer, layerName) {
						continue
					}
					for _, f := range lr.Findings {
						for _, fid := range chain.FindingIDs {
							if f.ID == fid {
								fmt.Printf("   %-9s: %-42s", chainLayerLabel(f.Layer), f.Title)
								severityColor(f.Severity).Printf("(%s)\n", f.Severity)
							}
						}
					}
				}
			}
			colorMeta.Printf("   %s %s\n", lbl.Arrow, chain.Description)
		}
	}

	// ── Per-layer findings ────────────────────────────────────────────────────
	for _, layer := range result.Layers {
		if len(layer.Findings) == 0 {
			continue
		}
		fmt.Println()
		colorLayerHeader.Printf("[%s]\n", layerDisplayName(layer.Layer))

		for _, f := range layer.Findings {
			sc := severityColor(f.Severity)
			fmt.Printf("  \u25cf %-46s", f.Title)
			sc.Println(string(f.Severity))

			if f.Evidence != "" {
				colorMeta.Printf("    %-11s: %s\n", lbl.Evidence, f.Evidence)
			}
			if f.Remediation != "" {
				colorMeta.Printf("    %-11s: %s\n", lbl.Fix, f.Remediation)
			}
			if f.Reference != "" {
				colorMeta.Printf("    %-11s: %s\n", lbl.Reference, f.Reference)
			}
		}
	}

	fmt.Println()
	fmt.Println(separator)
}

// ─── JSON output ──────────────────────────────────────────────────────────────

// jsonScanResult is the JSON schema for scan results, matching docs/report-design.md.
type jsonScanResult struct {
	SchemaVersion string             `json:"schema_version"`
	Scanner       jsonScanner        `json:"scanner"`
	Target        string             `json:"target"`
	StartedAt     string             `json:"started_at"`
	DurationMS    int64              `json:"duration_ms"`
	Summary       jsonSummary        `json:"summary"`
	AttackChains  []jsonAttackChain  `json:"attack_chains"`
	Layers        []jsonLayer        `json:"layers"`
}

type jsonScanner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

type jsonAttackChain struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	FindingIDs  []string `json:"finding_ids"`
	Description string   `json:"description"`
}

type jsonLayer struct {
	Layer    string        `json:"layer"`
	Findings []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Reference   string `json:"reference,omitempty"`
	OWASPRef    string `json:"owasp_llm,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// WriteJSON writes the scan result as indented JSON following the 1scan schema.
func WriteJSON(result *scanner.ScanResult, path string) error {
	counts := result.TotalFindings()
	total := 0
	for _, c := range counts {
		total += c
	}

	out := jsonScanResult{
		SchemaVersion: "1.0",
		Scanner:       jsonScanner{Name: "1scan", Version: "0.1.1"},
		Target:        result.Target,
		StartedAt:     result.StartTime.UTC().Format(time.RFC3339),
		DurationMS:    result.EndTime.Sub(result.StartTime).Milliseconds(),
		Summary: jsonSummary{
			Critical: counts[scanner.SeverityCritical],
			High:     counts[scanner.SeverityHigh],
			Medium:   counts[scanner.SeverityMedium],
			Low:      counts[scanner.SeverityLow],
			Info:     counts[scanner.SeverityInfo],
			Total:    total,
		},
	}

	for _, c := range result.AttackChains {
		out.AttackChains = append(out.AttackChains, jsonAttackChain{
			ID:          c.ID,
			Title:       c.Title,
			Severity:    strings.ToLower(string(c.Severity)),
			FindingIDs:  c.FindingIDs,
			Description: c.Description,
		})
	}

	for _, lr := range result.Layers {
		jl := jsonLayer{Layer: lr.Layer}
		for _, f := range lr.Findings {
			jl.Findings = append(jl.Findings, jsonFinding{
				ID:          f.ID,
				Title:       f.Title,
				Severity:    strings.ToLower(string(f.Severity)),
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
				Reference:   f.Reference,
				OWASPRef:    owaspRef(f.ID),
				Fingerprint: fingerprint(f, result.Target),
			})
		}
		out.Layers = append(out.Layers, jl)
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write json file: %w", err)
	}
	return nil
}

// owaspRef maps a finding ID prefix to an OWASP LLM Top 10 2025 reference.
func owaspRef(id string) string {
	switch {
	case strings.HasPrefix(id, "LLM01"):
		return "LLM01:2025"
	case strings.HasPrefix(id, "LLM02"):
		return "LLM02:2025"
	case strings.HasPrefix(id, "LLM05"):
		return "LLM05:2025"
	case strings.HasPrefix(id, "LLM06"):
		return "LLM06:2025"
	case strings.HasPrefix(id, "LLM07"):
		return "LLM07:2025"
	case strings.HasPrefix(id, "LLM09"):
		return "LLM09:2025"
	case strings.HasPrefix(id, "LLM10"):
		return "LLM10:2025"
	default:
		return ""
	}
}

// ─── Markdown output ──────────────────────────────────────────────────────────

// WriteMarkdown writes the scan result as a Markdown report to the given path.
func WriteMarkdown(result *scanner.ScanResult, path string) error {
	var b strings.Builder
	duration := result.EndTime.Sub(result.StartTime)
	counts := result.TotalFindings()

	b.WriteString("# 1scan Security Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s  \n", result.Target))
	b.WriteString(fmt.Sprintf("**Scan Date:** %s  \n", result.StartTime.Format("2006-01-02")))
	b.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", formatDuration(duration)))

	// Summary table
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

	// Attack chains section
	if len(result.AttackChains) > 0 {
		b.WriteString("## Attack Chains\n\n")
		for _, c := range result.AttackChains {
			b.WriteString(fmt.Sprintf("### %s: %s\n\n", c.ID, c.Title))
			b.WriteString(fmt.Sprintf("**Severity:** %s  \n", c.Severity))
			b.WriteString(fmt.Sprintf("**Scenario:** %s  \n", c.Description))
			b.WriteString(fmt.Sprintf("**Findings:** %s  \n\n", strings.Join(c.FindingIDs, ", ")))
		}
	}

	// Per-layer sections
	for _, layer := range result.Layers {
		if len(layer.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("## %s\n\n", layerDisplayName(layer.Layer)))

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

		for _, f := range layer.Findings {
			b.WriteString(fmt.Sprintf("### %s: %s\n", f.ID, f.Title))
			b.WriteString(fmt.Sprintf("**Severity:** %s  \n", f.Severity))
			if f.Reference != "" {
				b.WriteString(fmt.Sprintf("**Reference:** %s  \n", f.Reference))
			}
			if f.Evidence != "" {
				b.WriteString(fmt.Sprintf("**Evidence:** `%s`  \n", f.Evidence))
			}
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("**Remediation:** %s\n", f.Remediation))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString(fmt.Sprintf("---\n*Generated by 1scan v0.1.1 on %s*\n", result.StartTime.Format("2006-01-02 15:04:05 MST")))

	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write markdown file: %w", err)
	}
	return nil
}

// ─── HTML output ──────────────────────────────────────────────────────────────

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
<title>1scan Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 2rem 1rem; }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
  h2 { font-size: 1.2rem; font-weight: 600; margin: 1.5rem 0 0.75rem; color: #93c5fd; }
  .meta { color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem; }
  .meta span { margin-right: 1.5rem; }
  .summary { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .summary-card { padding: 0.5rem 1rem; border-radius: 0.375rem; font-weight: 600; font-size: 0.875rem; background: #1e293b; }
  .sev-CRITICAL { border-left: 4px solid #dc2626; }
  .sev-HIGH { border-left: 4px solid #ef4444; }
  .sev-MEDIUM { border-left: 4px solid #f59e0b; }
  .sev-LOW { border-left: 4px solid #06b6d4; }
  .sev-INFO { border-left: 4px solid #6b7280; }
  .chain-card { background: #1e293b; border: 1px solid #dc2626; border-radius: 0.5rem; padding: 1rem; margin-bottom: 0.75rem; }
  .chain-title { font-weight: 600; color: #fca5a5; margin-bottom: 0.375rem; }
  .chain-scenario { color: #94a3b8; font-size: 0.875rem; font-style: italic; }
  .chain-meta { font-size: 0.8125rem; color: #64748b; margin-top: 0.5rem; }
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

	b.WriteString(`<h1>1scan Security Report</h1>`)
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

	// Attack chains section
	if len(result.AttackChains) > 0 {
		b.WriteString(`<h2>⚠ Attack Chains</h2>`)
		for _, c := range result.AttackChains {
			b.WriteString(`<div class="chain-card">`)
			b.WriteString(fmt.Sprintf(`<div class="chain-title">%s <span class="badge" style="background:%s">%s</span></div>`,
				htmlEscape(c.Title), htmlSeverityColor(c.Severity), c.Severity))
			b.WriteString(fmt.Sprintf(`<div class="chain-scenario">→ %s</div>`, htmlEscape(c.Description)))
			b.WriteString(fmt.Sprintf(`<div class="chain-meta">Findings: %s | Layers: %s</div>`,
				htmlEscape(strings.Join(c.FindingIDs, ", ")),
				htmlEscape(strings.Join(c.LayerNames, " + "))))
			b.WriteString(`</div>`)
		}
	}

	// Per-layer sections
	for _, layer := range result.Layers {
		if len(layer.Findings) == 0 {
			continue
		}
		b.WriteString(`<div class="layer-section">`)
		b.WriteString(fmt.Sprintf(`<div class="layer-header">%s</div>`, layerDisplayName(layer.Layer)))

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

		for _, f := range layer.Findings {
			b.WriteString(`<div class="finding-detail">`)
			b.WriteString(fmt.Sprintf(`<div class="finding-title">%s: %s <span class="badge" style="background:%s">%s</span></div>`,
				htmlEscape(f.ID), htmlEscape(f.Title), htmlSeverityColor(f.Severity), f.Severity))

			if f.Description != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field">%s</div>`, htmlEscape(f.Description)))
			}
			if f.Evidence != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field"><strong>Evidence:</strong><div class="evidence">%s</div></div>`, htmlEscape(f.Evidence)))
			}
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field"><strong>Fix:</strong> %s</div>`, htmlEscape(f.Remediation)))
			}
			if f.Reference != "" {
				b.WriteString(fmt.Sprintf(`<div class="finding-field"><strong>Reference:</strong> %s</div>`, htmlEscape(f.Reference)))
			}
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(fmt.Sprintf(`<footer>Generated by 1scan v0.1.1 on %s — <a href="https://greentea.earth" style="color:#475569">greentea.earth</a></footer>`,
		result.StartTime.Format("2006-01-02 15:04:05 MST")))
	b.WriteString(`</div></body></html>`)

	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write html file: %w", err)
	}
	return nil
}

// ─── SARIF output ─────────────────────────────────────────────────────────────

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

// sarifHelpMarkdown builds a help.markdown string for a SARIF rule.
func sarifHelpMarkdown(f scanner.Finding) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## %s\n\n", f.Title))
	if f.Description != "" {
		b.WriteString(f.Description + "\n\n")
	}
	if f.Evidence != "" {
		b.WriteString(fmt.Sprintf("**Evidence:** `%s`\n\n", f.Evidence))
	}
	if f.Remediation != "" {
		b.WriteString(fmt.Sprintf("**Fix:** %s\n\n", f.Remediation))
	}
	if ref := owaspRef(f.ID); ref != "" {
		b.WriteString(fmt.Sprintf("**OWASP Reference:** %s\n", ref))
	} else if f.Reference != "" {
		b.WriteString(fmt.Sprintf("**Reference:** %s\n", f.Reference))
	}
	return b.String()
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
					Help: map[string]string{
						"text":     f.Remediation,
						"markdown": sarifHelpMarkdown(f),
					},
					DefaultConfig: map[string]string{"level": sarifLevel(f.Severity)},
					Properties: map[string]interface{}{
						"security-severity": fmt.Sprintf("%.1f", sarifSecuritySeverity(f.Severity)),
						"precision":        "high",
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
				PartialFingerprints: map[string]string{
					"primaryLocationLineHash": fingerprint(f, result.Target),
				},
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
						Name:           "1scan",
						Version:        "0.1.1",
						InformationURI: "https://github.com/onoz1169/1scan",
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
