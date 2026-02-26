# Architecture: nmap Integration for aiscan

Research on how to integrate nmap into aiscan's network scanning layer, covering Go libraries, integration patterns from RustScan/AutoRecon, XML parsing, and recommended approach.

## 1. Recommended Approach

**Hybrid: Pure-Go fast scan + optional nmap enrichment.**

Keep the current pure-Go CONNECT scanner as the primary engine. Add nmap as an optional enrichment step that runs only when nmap is installed and the user opts in (or by default when detected).

Rationale:
- aiscan's value proposition is a single-binary, zero-dependency security scanner
- nmap adds 2,500+ service probes, OS detection, and NSE scripts that are impractical to reimplement in Go
- The RustScan pattern (fast discovery then nmap deep-dive) is proven and widely adopted
- Making nmap optional preserves the single-binary advantage while unlocking deep analysis when available

Decision: **Optional dependency, not required.**

## 2. Go Library: github.com/Ullaakut/nmap/v4

The standard Go wrapper for nmap. Latest version is v4 (released Jan 2026).

### What it provides
- Builds nmap command-line arguments via idiomatic Go option functions
- Executes nmap as a subprocess via `os/exec`
- Parses XML output (`-oX -`) into typed Go structs
- Supports async scanning with progress channel
- Handles streaming output to io.Writer

### Key structs (maps directly to nmap XML)

```
Run (root result)
  Hosts []Host
    Addresses []Address
    Hostnames []Hostname
    Ports []Port
      ID       uint16
      Protocol string
      State    State      // state.State = "open"|"closed"|"filtered"
      Service  Service    // name, product, version, extraInfo, osType, CPEs
      Scripts  []Script   // id, output, tables, elements
    HostScripts []Script
    OS          OS         // OSMatch with name, accuracy, OSClass
```

### API example

```go
import nmap "github.com/Ullaakut/nmap/v4"

scanner, err := nmap.NewScanner(
    ctx,
    nmap.WithTargets("192.168.1.1"),
    nmap.WithPorts("22,80,443,3306"),
    nmap.WithServiceInfo(),           // -sV
    nmap.WithDefaultScript(),         // -sC
    nmap.WithTimingTemplate(nmap.TimingAggressive), // -T4
    nmap.WithSkipHostDiscovery(),     // -Pn (we already know host is up)
)

result, warnings, err := scanner.Run()

for _, host := range result.Hosts {
    for _, port := range host.Ports {
        if port.Status() == nmap.Open {
            fmt.Printf("Port %d: %s %s %s\n",
                port.ID,
                port.Service.Name,
                port.Service.Product,
                port.Service.Version,
            )
            for _, script := range port.Scripts {
                fmt.Printf("  Script %s: %s\n", script.ID, script.Output)
            }
        }
    }
}
```

### Requirement
nmap must be installed on the system PATH. The library calls `exec.LookPath("nmap")` internally.

## 3. How RustScan Integrates nmap

RustScan follows a two-phase architecture:

1. **Phase 1 (RustScan):** Async batch TCP connect scan across all 65,535 ports. Completes in ~3 seconds. Groups discovered open ports by IP in a HashMap.

2. **Phase 2 (nmap):** Constructs and executes nmap command with only the discovered open ports:
   ```
   nmap -vvv -p <comma-separated-ports> <target>
   ```
   Users can append flags after `--`:
   ```
   rustscan -a 192.168.1.1 -- -sV -sC -A
   ```

Key design decisions:
- One nmap invocation per IP (ports consolidated)
- `-Pn` implied (host already confirmed up)
- Configurable via `--scripts default|none|custom`
- Port list substituted into command template via `{{port}}` placeholder

This pattern is directly applicable to aiscan: our pure-Go scanner plays the role of RustScan's fast phase, and nmap provides the enrichment phase.

## 4. Dependency Detection Pattern

### How AutoRecon handles missing tools
AutoRecon (Python) uses `shutil.which()` in plugin `check()` methods to verify tool availability before execution. If a tool is missing, the plugin is skipped with a warning -- the scan continues with remaining tools. Users can pass `--ignore-plugin-checks` to override.

### Recommended pattern for aiscan (Go)

```go
package toolcheck

import (
    "fmt"
    "os/exec"
)

// NmapAvailability checks whether nmap is installed and returns its path.
func NmapAvailability() (path string, available bool) {
    path, err := exec.LookPath("nmap")
    if err != nil {
        return "", false
    }
    return path, true
}

// NmapVersion returns the installed nmap version string.
func NmapVersion(path string) (string, error) {
    out, err := exec.Command(path, "--version").Output()
    if err != nil {
        return "", err
    }
    // Parse "Nmap version 7.94 ( https://nmap.org )"
    return parseVersionFromOutput(string(out)), nil
}
```

Integration at scan time:

```go
func (s *NetworkScanner) Scan(target string, timeoutSec int) (*scanner.LayerResult, error) {
    // Phase 1: Pure-Go fast port scan (always runs)
    openPorts := s.fastScan(target, timeoutSec)

    // Phase 2: nmap enrichment (optional)
    if s.nmapEnabled {
        if path, ok := toolcheck.NmapAvailability(); ok {
            enriched := s.nmapEnrich(ctx, target, openPorts)
            mergeFindings(openPorts, enriched)
        } else {
            // Log warning, continue with pure-Go results
            log.Warn("nmap not found; skipping deep service detection")
        }
    }

    return buildFindings(openPorts), nil
}
```

## 5. Fallback Strategy

| Scenario | Behavior |
|----------|----------|
| nmap installed, `--nmap` flag (or default) | Run pure-Go scan, then nmap enrichment on open ports |
| nmap installed, `--no-nmap` flag | Run pure-Go scan only |
| nmap NOT installed, no flag | Run pure-Go scan, print info: "Install nmap for deeper service detection" |
| nmap NOT installed, `--nmap` flag | Exit with error: "nmap not found at PATH; install it or use --no-nmap" |

### CLI flags to add

```
--nmap          Enable nmap enrichment (default: auto-detect)
--no-nmap       Disable nmap even if installed
--nmap-path     Path to nmap binary (override PATH lookup)
--nmap-flags    Additional nmap flags (e.g., "--script vuln")
```

## 6. nmap Command to Run

### Default enrichment command

```bash
nmap -Pn -sV -sC -T4 -p <open-ports> --open -oX - <target>
```

Flags explained:
- `-Pn` -- skip host discovery (we already confirmed host is up)
- `-sV` -- version detection (probe open ports for service/version info)
- `-sC` -- run default NSE scripts (safe, useful checks)
- `-T4` -- aggressive timing (faster scan, appropriate since we already know ports are open)
- `-p <ports>` -- only scan ports we discovered as open
- `--open` -- only show open ports in output (reduce noise)
- `-oX -` -- XML output to stdout (parsed by Ullaakut/nmap library)

### Extended command (with vuln scanning)

```bash
nmap -Pn -sV -sC -T4 -p <open-ports> --open \
  --script "default,vuln,ssl-enum-ciphers,http-enum" \
  -oX - <target>
```

## 7. Top 5 NSE Scripts for aiscan's Use Case

| Script | Category | What it does | Why valuable |
|--------|----------|-------------|--------------|
| `ssl-enum-ciphers` | safe | Enumerates SSL/TLS protocol versions and cipher suites, grades strength | Directly maps to TLS misconfiguration findings; identifies TLS 1.0/1.1, weak ciphers, CBC mode |
| `vulners` | safe | Matches service CPE to CVE database, reports known CVEs with CVSS scores | Automated CVE correlation without maintaining our own vuln DB; outputs actionable CVE IDs |
| `http-enum` | discovery | Enumerates common web paths (/admin, /phpmyadmin, /.git, /wp-login.php, etc.) | Finds exposed admin panels, backup files, and sensitive paths that webapp layer might miss |
| `smb-vuln-ms17-010` | vuln | Checks for EternalBlue (MS17-010) vulnerability | High-impact, wormable SMB vulnerability still prevalent; critical finding for any exposed SMB |
| `ssh-auth-methods` | auth | Lists SSH authentication methods (password, publickey, etc.) | Flags password auth enabled on SSH (should be key-only); common audit finding |

### Honorable mentions
- `http-security-headers` -- checks for missing security headers (X-Frame-Options, CSP, etc.)
- `ssl-heartbleed` -- detects Heartbleed vulnerability (CVE-2014-0160)
- `ftp-anon` -- checks for anonymous FTP access
- `mysql-empty-password` -- checks for MySQL root without password
- `redis-info` -- extracts Redis configuration (auth status, version)

## 8. Mapping nmap Results to aiscan Finding{}

```go
func nmapPortToFinding(host nmap.Host, port nmap.Port, findingNum int) scanner.Finding {
    // Build evidence string
    evidence := fmt.Sprintf("Port %d/%s: %s %s %s",
        port.ID, port.Protocol,
        port.Service.Name,
        port.Service.Product,
        port.Service.Version,
    )

    // Determine severity from service + scripts
    severity := classifyPortSeverity(port)

    finding := scanner.Finding{
        ID:          fmt.Sprintf("NET-%03d", findingNum),
        Layer:       "network",
        Title:       fmt.Sprintf("Open port: %d (%s %s)", port.ID, port.Service.Product, port.Service.Version),
        Description: fmt.Sprintf("Service %s detected via nmap version detection.", port.Service.Name),
        Severity:    severity,
        Reference:   buildReference(port),  // CPE -> CVE lookup from vulners script
        Evidence:    evidence,
        Remediation: buildRemediation(port),
    }

    // Append NSE script outputs to evidence
    for _, script := range port.Scripts {
        finding.Evidence += fmt.Sprintf("\n  [NSE %s]: %s", script.ID, script.Output)
    }

    return finding
}

func classifyPortSeverity(port nmap.Port) scanner.Severity {
    // Check if any vuln script reported findings
    for _, script := range port.Scripts {
        if strings.Contains(script.ID, "vuln") && strings.Contains(script.Output, "VULNERABLE") {
            return scanner.SeverityCritical
        }
    }
    // Fall back to risky port map
    if rp, ok := riskyPorts[int(port.ID)]; ok {
        return rp.Severity
    }
    return scanner.SeverityInfo
}
```

## 9. Implementation Sketch

### File structure

```
internal/
  scanner/
    network/
      network.go           # existing pure-Go scanner
      nmap.go              # NEW: nmap integration
      nmap_test.go         # NEW: tests with mock XML
  toolcheck/
    toolcheck.go           # NEW: binary detection utilities
```

### nmap.go pseudocode

```go
package network

import (
    "context"
    "fmt"
    "strings"
    "time"

    nmap "github.com/Ullaakut/nmap/v4"
    "github.com/onoz1169/aiscan/internal/scanner"
)

type NmapEnricher struct {
    BinaryPath string
    ExtraFlags []string
    Timeout    time.Duration
}

func NewNmapEnricher(binaryPath string, timeout time.Duration) *NmapEnricher {
    return &NmapEnricher{
        BinaryPath: binaryPath,
        Timeout:    timeout,
    }
}

// Enrich runs nmap against the target for the given open ports
// and returns enriched findings with service versions and NSE script output.
func (n *NmapEnricher) Enrich(ctx context.Context, target string, openPorts []int) ([]scanner.Finding, error) {
    // Build port string: "22,80,443,3306"
    portStrs := make([]string, len(openPorts))
    for i, p := range openPorts {
        portStrs[i] = fmt.Sprintf("%d", p)
    }
    portArg := strings.Join(portStrs, ",")

    // Configure nmap scanner
    opts := []nmap.Option{
        nmap.WithTargets(target),
        nmap.WithPorts(portArg),
        nmap.WithServiceInfo(),           // -sV
        nmap.WithDefaultScript(),         // -sC
        nmap.WithTimingTemplate(nmap.TimingAggressive), // -T4
        nmap.WithSkipHostDiscovery(),     // -Pn
        nmap.WithOpenOnly(),              // --open
    }

    if n.BinaryPath != "" {
        opts = append(opts, nmap.WithBinaryPath(n.BinaryPath))
    }

    scanner, err := nmap.NewScanner(ctx, opts...)
    if err != nil {
        return nil, fmt.Errorf("nmap scanner init: %w", err)
    }

    result, warnings, err := scanner.Run()
    if err != nil {
        return nil, fmt.Errorf("nmap scan: %w", err)
    }

    // Log warnings (non-fatal)
    for _, w := range warnings {
        fmt.Fprintf(os.Stderr, "  [nmap warning] %s\n", w)
    }

    // Convert nmap results to aiscan findings
    var findings []scanner.Finding
    findingNum := 1

    for _, host := range result.Hosts {
        for _, port := range host.Ports {
            if port.Status() != nmap.Open {
                continue
            }
            findings = append(findings, nmapPortToFinding(host, port, findingNum))
            findingNum++
        }
    }

    return findings, nil
}
```

### Integration into NetworkScanner.Scan()

```go
func (s *NetworkScanner) Scan(target string, timeoutSec int) (*scanner.LayerResult, error) {
    host := extractHost(target)
    start := time.Now()

    // Phase 1: Pure-Go fast port discovery (existing code)
    openPorts, pureGoFindings := s.fastPortScan(host, timeoutSec)

    // Phase 2: nmap enrichment (if available and enabled)
    if s.nmapEnabled && len(openPorts) > 0 {
        nmapPath, available := toolcheck.NmapAvailability()
        if available {
            enricher := NewNmapEnricher(nmapPath, time.Duration(timeoutSec)*time.Second*3)
            ctx, cancel := context.WithTimeout(context.Background(), enricher.Timeout)
            defer cancel()

            nmapFindings, err := enricher.Enrich(ctx, host, openPorts)
            if err != nil {
                // Non-fatal: log and fall back to pure-Go findings
                scanErrors = append(scanErrors, fmt.Sprintf("nmap enrichment failed: %v", err))
            } else {
                // Merge: nmap findings replace pure-Go findings for the same ports
                pureGoFindings = mergeFindings(pureGoFindings, nmapFindings)
            }
        } else {
            // Info message on first scan only
            fmt.Fprintf(os.Stderr, "  [i] nmap not installed; using built-in detection only\n")
            fmt.Fprintf(os.Stderr, "      Install nmap for deeper service/version detection\n")
        }
    }

    return &scanner.LayerResult{
        Layer:    "network",
        Target:   host,
        Duration: time.Since(start),
        Findings: pureGoFindings,
    }, nil
}
```

## 10. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Command injection via target string | Ullaakut/nmap uses `exec.Command` with separate args (no shell expansion). Target is validated before passing. |
| nmap requires root for SYN scan | We use `-sV` (version detection on already-open ports), not SYN scan. No root needed for our use case. |
| nmap output parsing | XML parsed by well-tested library with Go's encoding/xml. No eval or shell parsing. |
| Malicious nmap binary | `exec.LookPath` follows PATH. Users can override with `--nmap-path`. Document that users should verify nmap installation. |
| nmap scan takes too long | Context timeout wraps the nmap subprocess. Kill process on cancellation. |
| Large XML output | Stream parsing via Ullaakut/nmap library handles this. Bounded by number of open ports (which we control). |

## 11. Tradeoffs Summary

| Factor | Pure-Go Only | With nmap Integration |
|--------|-------------|----------------------|
| Dependencies | Zero (single binary) | Optional nmap install |
| Service detection | 13 fingerprints | 2,500+ service probes |
| Version detection | Basic banner match | Product + version + CPE |
| Vuln detection | Port-based risk only | NSE scripts + CVE matching |
| OS detection | None | nmap OS fingerprinting |
| Scan speed | Fast (~5s for 100 ports) | +30-60s for nmap enrichment |
| Distribution | Single binary, any platform | Binary + "install nmap" instructions |
| CI/CD usage | Works anywhere | May need nmap in Docker image |

The hybrid approach gives users the best of both worlds: instant results from pure-Go scanning, with optional deep analysis when nmap is available.

## Sources

- Ullaakut/nmap Go library: https://github.com/Ullaakut/nmap
- Ullaakut/nmap Go docs (v2): https://pkg.go.dev/github.com/Ullaakut/nmap/v2
- RustScan nmap integration: https://deepwiki.com/bee-san/RustScan/4.2-nmap-integration
- RustScan repository: https://github.com/bee-san/RustScan
- AutoRecon repository: https://github.com/Tib3rius/AutoRecon
- nmap XML output format: https://nmap.org/book/output-formats-xml-output.html
- nmap NSE usage: https://nmap.org/book/nse-usage.html
- nmap NSE script index: https://nmap.org/nsedoc/scripts/
- vulners NSE script: https://nmap.org/nsedoc/scripts/vulners.html
- Go exec.LookPath: https://pkg.go.dev/os/exec#LookPath
