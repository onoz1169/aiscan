# CLI UX Research: Security Scanner Best Practices

Research date: 2026-02-25
Tools analyzed: nuclei, trivy, grype, SARIF ecosystem

---

## 1. Progress Display

### How top tools show real-time scan progress

**Nuclei** uses a `-stats` flag that prints periodic statistics updates to stderr:
- Configurable interval (`-si`, default 5 seconds)
- Shows templates loaded, hosts scanned, requests sent, matches found
- Also supports `-stats-json` for JSONL-formatted stats (machine-readable)
- Verbose modes: `-v` for verbose, `-vv` for debug (shows loaded templates)

**Grype** displays a checklist-style progress on stderr:
```
 + Pulled image
 + Loaded image
 + Parsed image
 + Cataloged contents (247 packages, 118 file digests, 69 executables)
 + Scanned for vulnerabilities [52 vulnerability matches]
   + 3 critical, 8 high, 15 medium, 12 low, 14 negligible
   + 28 fixed, 24 not-fixed
```
Each step gets a checkmark as it completes. Severity breakdown is inline.

**Trivy** uses a simple progress bar for database updates and a spinner for scan phases. Results appear as a table after scanning completes.

### Recommendation for aiscan

Use a lightweight spinner per scan layer (network, webapp, llm), showing current phase:
```
[/] Scanning network layer... (3/3 checks)
[+] Network layer complete: 2 findings
[/] Scanning webapp layer... (7/12 checks)
```

**Go libraries for progress:**

| Library | Complexity | Best for |
|---------|-----------|----------|
| `briandowns/spinner` | Low | Simple spinners, 90+ character sets, easy start/stop API |
| `charmbracelet/bubbles` | High | Rich TUI with progress bars, spinners, interactive lists |
| `schollz/progressbar` | Medium | Progress bars with percentage and ETA |

**Recommendation:** Start with `briandowns/spinner` for simplicity. It's a single `go get`, supports color, prefix/suffix text, and 90 spinner styles. Only move to Bubble Tea if interactive TUI is needed later.

---

## 2. Color Scheme

### Industry standard severity colors

All major security tools converge on a consistent color scheme:

| Severity | Color | ANSI | Used by |
|----------|-------|------|---------|
| CRITICAL | Red + Bold | `\033[1;31m` | nuclei, trivy, grype, aiscan (current) |
| HIGH | Red | `\033[31m` | nuclei, trivy, grype, aiscan (current) |
| MEDIUM | Yellow | `\033[33m` | nuclei, trivy, grype, aiscan (current) |
| LOW | Cyan | `\033[36m` | nuclei, grype; aiscan (current) |
| INFO | White/Gray | `\033[37m` | nuclei, aiscan (current) |
| NEGLIGIBLE | Dark Gray | `\033[90m` | grype (not applicable to aiscan) |

**aiscan's current colors are already aligned with industry standards.** No changes needed here. The `fatih/color` library currently used is the right choice.

### Additional color conventions

- **Layer/section headers**: Blue + Bold (aiscan already does this)
- **Success messages**: Green
- **Error messages**: Red on stderr
- **Timestamps/metadata**: Dim/Gray
- **Target URL**: White + Bold or Underline

### `--no-color` flag

All tools support disabling color output. Nuclei uses `-nc` / `--no-color`. Grype auto-detects non-TTY and disables color. `fatih/color` supports `color.NoColor = true` and respects the `NO_COLOR` environment variable.

**Recommendation:** Add `--no-color` flag and also auto-detect non-TTY (pipe) output. The `fatih/color` library already handles the `NO_COLOR` env var.

---

## 3. Output Formats to Support

### What top tools support

| Format | nuclei | trivy | grype | Purpose |
|--------|--------|-------|-------|---------|
| Terminal/Table | Default | Default (`--format table`) | Default (`-o table`) | Human reading |
| JSON | `-j` (JSONL), `-je` (file) | `--format json` | `-o json` | Programmatic consumption |
| SARIF | `-se` (file) | `--format sarif` | `-o sarif` | GitHub Code Scanning |
| Markdown | `-me` (directory) | N/A | N/A | Reports/documentation |
| CycloneDX | N/A | `--format cyclonedx` | `-o cyclonedx` | SBOM integration |
| Template | N/A | `--format template` | `-o template` | Custom output |

### Current aiscan formats

aiscan currently supports: `terminal`, `json`, `markdown` via the `-o` flag.

### Recommended additions (priority order)

1. **SARIF** -- Required for GitHub Code Scanning integration. This is the highest-value addition. Upload with `github/codeql-action/upload-sarif@v3` in CI.
2. **JSONL** -- Streaming JSON (one JSON object per line per finding). Useful for piping to `jq` and real-time processing.
3. **Template** -- Allow users to define custom output via Go templates (future).

---

## 4. SARIF Format Details

### What is SARIF?

Static Analysis Results Interchange Format (SARIF) is a JSON-based OASIS standard (v2.1.0) for representing results from static analysis tools. It is the primary format consumed by:
- GitHub Code Scanning (Advanced Security)
- Azure DevOps
- VS Code SARIF Viewer
- Many CI/CD security pipelines

### SARIF structure for aiscan

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "aiscan",
          "version": "0.1.0",
          "informationUri": "https://github.com/onoz1169/aiscan",
          "rules": [
            {
              "id": "NET-001",
              "name": "OpenPort",
              "shortDescription": { "text": "Open port detected" },
              "defaultConfiguration": { "level": "warning" },
              "properties": {
                "security-severity": "5.0"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "NET-001",
          "level": "warning",
          "message": { "text": "Port 22 (SSH) is open" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "https://example.com" },
                "region": { "startLine": 1 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### Severity mapping to SARIF

| aiscan Severity | SARIF level | security-severity (numeric) |
|----------------|-------------|----------------------------|
| CRITICAL | error | 9.1 - 10.0 |
| HIGH | error | 7.0 - 8.9 |
| MEDIUM | warning | 4.0 - 6.9 |
| LOW | note | 0.1 - 3.9 |
| INFO | note | 0.0 |

### GitHub Actions integration example

```yaml
- name: Run aiscan
  run: aiscan scan -t ${{ env.TARGET }} -o sarif -f aiscan-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aiscan-results.sarif
    category: aiscan
```

---

## 5. Summary Table Format

### How tools present summary information

**Nuclei** output format (per finding):
```
[template-id] [protocol] [severity] target [extracted-data]
```
No summary table -- nuclei focuses on streaming individual findings.

**Trivy** table output:
```
+-----------+------------------+----------+-------------------+---------------+
| Library   | Vulnerability    | Severity | Installed Version | Fixed Version |
+-----------+------------------+----------+-------------------+---------------+
| lodash    | CVE-2021-23337   | CRITICAL | 4.17.20           | 4.17.21       |
+-----------+------------------+----------+-------------------+---------------+

Total: 12 (CRITICAL: 1, HIGH: 3, MEDIUM: 5, LOW: 3)
```

**Grype** table output:
```
NAME          INSTALLED   FIXED-IN  TYPE  VULNERABILITY   SEVERITY
libssl3       3.0.2-0     3.0.7-1   deb   CVE-2022-3602   Critical
libcrypto3    3.0.2-0     3.0.7-1   deb   CVE-2022-3786   High
```

### Recommended summary format for aiscan

Combine the best elements. After all layers complete, print:

```
==============================================
  aiscan v0.1.0 -- Security Scan Report
  Target:   https://example.com
  Duration: 4.2s
  Layers:   network, webapp, llm
==============================================

[NETWORK LAYER]
  ID        Title                                  Severity
  NET-001   SSH port open (22)                     MEDIUM
  NET-002   HTTP without redirect to HTTPS         HIGH

[WEBAPP LAYER]
  ID        Title                                  Severity
  WEB-001   Missing Content-Security-Policy        MEDIUM
  WEB-003   TLS 1.0 supported                      HIGH
  WEB-005   Server header exposes version           LOW

[LLM LAYER]
  ID        Title                                  Severity
  LLM-001   Prompt injection possible              CRITICAL
  LLM-004   No rate limiting on API                HIGH

==============================================
  SUMMARY
  CRITICAL: 1  HIGH: 3  MEDIUM: 2  LOW: 1  INFO: 0
  Total: 7 findings in 4.2s
==============================================
```

**Improvements over current output:**
- Add finding IDs in the table
- Add total count in summary line
- Add layer count metadata in header
- Use consistent column widths via `go-pretty` or `fmt.Sprintf` alignment

### go-pretty for tables

The `jedib0t/go-pretty` library offers:
- Auto-column-width with alignment
- Predefined styles (light, dark, colored, rounded)
- Color support per cell
- Output as ASCII table, Markdown, CSV, HTML
- Footer rows (ideal for summary counts)
- Sorting

This would be a significant UX improvement over manual `fmt.Printf` formatting.

---

## 6. Exit Code Conventions

### Industry standard

| Exit Code | Meaning | Used by |
|-----------|---------|---------|
| 0 | Scan completed, no findings above threshold | grype, trivy, safety, aiscan |
| 1 | Findings found above threshold severity | grype (`--fail-on`), trivy, nuclei |
| 2 | Scanner error / invalid usage | POSIX convention |
| 42 | Unexpected internal error | hawkeye (uncommon) |

### Current aiscan behavior

aiscan currently exits with code 1 if any CRITICAL or HIGH findings exist (hardcoded in `scan.go:98-102`).

### Recommended improvements

1. **Add `--fail-on` flag** (like grype): Let users set the threshold severity.
   ```
   aiscan scan -t example.com --fail-on medium   # exit 1 if MEDIUM+
   aiscan scan -t example.com --fail-on critical  # exit 1 only for CRITICAL
   aiscan scan -t example.com --fail-on none      # always exit 0
   ```

2. **Use exit code 2 for usage errors** (cobra does this by default).

3. **Document exit codes** in `--help` and README.

4. **Add `--exit-code` flag alias** for CI clarity:
   ```
   aiscan scan -t example.com --exit-code 0  # always succeed (CI report-only mode)
   ```

---

## 7. Flag Naming Conventions

### Patterns across security tools

| Convention | nuclei | trivy | grype | Recommendation |
|-----------|--------|-------|-------|----------------|
| Target | (positional) | (positional) | (positional) | Keep `-t/--target` (explicit is clearer for multi-layer tool) |
| Output format | `-o` (file), `-j` (json) | `-f/--format` | `-o/--output` | Use `--format` for format, `-o/--output` for file |
| Severity filter | `--severity` | `--severity` | `--fail-on` | Add `--severity` to filter display, `--fail-on` for exit code |
| Quiet mode | `--silent` | `--quiet` | `-q/--quiet` | Add `-q/--quiet` |
| Verbose | `-v` | N/A | `-v` (stackable) | Keep `-v/--verbose`, consider `-vv` for debug |
| No color | `-nc/--no-color` | N/A | (auto-detect) | Add `--no-color` |
| Config file | N/A | `--config` | `-c/--config` | Add `-c/--config` (future) |
| Template | `--templates` | `--template` | `-t/--template` | Reserve for future custom output |

### Current aiscan flag issues

The current `-o` flag conflates format and file destination:
- `-o terminal|json|markdown` sets format
- `-f` sets filename

**Recommended rename to align with industry:**
- `--format` or `-F` for output format (terminal, json, markdown, sarif)
- `-o` or `--output` for output file path
- This matches trivy (`--format`) and is more intuitive

### Additional flags to add

| Flag | Short | Purpose |
|------|-------|---------|
| `--format` | `-F` | Output format: terminal, json, markdown, sarif |
| `--output` | `-o` | Output file path (stdout if omitted) |
| `--fail-on` | | Exit code threshold severity |
| `--quiet` | `-q` | Suppress non-finding output |
| `--no-color` | | Disable ANSI colors |
| `--severity` | `-s` | Filter: only show findings at this level or above |
| `--config` | `-c` | Config file path (future) |

---

## 8. Go CLI Libraries Comparison

### Cobra (current choice -- recommended to keep)

aiscan already uses `spf13/cobra`. This is the right choice:
- Used by kubectl, docker, gh, hugo, helm
- Automatic help generation, shell completions (bash, zsh, fish, powershell)
- Subcommand-based (`aiscan scan`, `aiscan report`, `aiscan version`)
- Integrates with `spf13/viper` for config file support
- Massive ecosystem and community

### Kong

- Struct-based configuration (more Go-idiomatic)
- Less boilerplate than cobra for simple CLIs
- Smaller community
- **Not recommended** for aiscan -- cobra is already set up and is industry standard for security tools

### urfave/cli

- Older, simpler API
- Less feature-rich than cobra
- Not recommended for new projects

### Verdict: Stay with Cobra

Add `spf13/viper` later for config file support (YAML/TOML config).

---

## 9. Top 8 UX Improvements for aiscan

Ordered by impact and implementation effort:

### 1. Add real-time progress spinner per layer

**Impact: High | Effort: Low**

Use `briandowns/spinner` to show which layer is scanning and how many checks have run. Current output is silent unless `-v` is set.

```go
s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
s.Suffix = " Scanning network layer..."
s.Start()
// ... scan ...
s.Stop()
fmt.Println("[+] Network layer: 3 findings")
```

### 2. Add SARIF output format

**Impact: High | Effort: Medium**

Enables GitHub Code Scanning integration. This is the single most valuable feature for CI/CD adoption. Implement `report.WriteSARIF()` following the schema in section 4.

### 3. Rename output flags to match industry conventions

**Impact: Medium | Effort: Low**

Change `-o` to `--format` (output format) and `-f` to `-o/--output` (file path). This prevents confusion and matches trivy/grype conventions.

Before: `aiscan scan -t example.com -o json -f report`
After:  `aiscan scan -t example.com --format json -o report.json`

### 4. Add `--fail-on` severity threshold flag

**Impact: High | Effort: Low**

Replace the hardcoded CRITICAL/HIGH exit-code check with a configurable threshold. Essential for CI/CD pipelines where teams want different policies.

```
aiscan scan -t example.com --fail-on high    # exit 1 if HIGH or CRITICAL
aiscan scan -t example.com --fail-on none    # report-only mode
```

### 5. Use go-pretty for terminal table output

**Impact: Medium | Effort: Medium**

Replace manual `fmt.Printf` formatting with `jedib0t/go-pretty` tables. This gives:
- Consistent column alignment regardless of content length
- Box-drawing borders
- Color support per cell
- Footer rows for summary
- Can also render as Markdown (simplifies markdown output)

### 6. Add `--quiet` and `--no-color` flags

**Impact: Medium | Effort: Low**

- `--quiet` (`-q`): Show only findings and summary, no banner/progress
- `--no-color`: Disable ANSI codes (for piping, CI logs, accessibility)
- Auto-detect non-TTY and disable color/spinners automatically

### 7. Add `--severity` filter flag

**Impact: Medium | Effort: Low**

Let users filter output to only show findings at or above a given severity:
```
aiscan scan -t example.com --severity medium  # hide LOW and INFO
```

Different from `--fail-on` (which controls exit code, not display).

### 8. Add scan duration and finding count to all output formats

**Impact: Low | Effort: Low**

Currently the terminal output shows duration. Ensure JSON and markdown outputs also include:
- `scan_duration_seconds`
- `total_findings` count
- Per-severity counts in a top-level `summary` object
- `aiscan_version`

This metadata is critical for tracking scan results over time.

---

## Appendix: Library Recommendations

| Purpose | Library | Notes |
|---------|---------|-------|
| CLI framework | `spf13/cobra` | Already in use. Keep. |
| Terminal colors | `fatih/color` | Already in use. Keep. |
| Terminal tables | `jedib0t/go-pretty/v6` | Add for formatted tables |
| Progress spinner | `briandowns/spinner` | Add for scan progress |
| SARIF output | Manual JSON marshal | No Go SARIF library needed; schema is simple |
| Config files | `spf13/viper` | Add later for YAML config |
| JSON streaming | `encoding/json` | Already available in stdlib |

---

## References

- nuclei: https://github.com/projectdiscovery/nuclei
- trivy: https://github.com/aquasecurity/trivy
- grype: https://github.com/anchore/grype
- SARIF spec: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- go-pretty: https://github.com/jedib0t/go-pretty
- briandowns/spinner: https://github.com/briandowns/spinner
- charmbracelet/bubbles: https://github.com/charmbracelet/bubbles
- cobra: https://github.com/spf13/cobra
