package network

import (
	"context"
	"fmt"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
	"github.com/onoz1169/aiscan/internal/cve"
	"github.com/onoz1169/aiscan/internal/scanner"
)

// nmapEnricher runs nmap service/version detection on already-discovered open ports.
type nmapEnricher struct {
	binaryPath string
	extraFlags string
	timeout    time.Duration
	cveClient  *cve.Client // nil = CVE lookup disabled
}

func newNmapEnricher(binaryPath, extraFlags string, timeout time.Duration, cveClient *cve.Client) *nmapEnricher {
	return &nmapEnricher{
		binaryPath: binaryPath,
		extraFlags: extraFlags,
		timeout:    timeout,
		cveClient:  cveClient,
	}
}

// Enrich runs nmap against the given host and open ports, returning additional findings.
func (e *nmapEnricher) Enrich(ctx context.Context, host string, openPorts []int) ([]scanner.Finding, error) {
	portStrs := make([]string, len(openPorts))
	for i, p := range openPorts {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	portList := strings.Join(portStrs, ",")

	opts := []nmap.Option{
		nmap.WithTargets(host),
		nmap.WithPorts(portList),
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithSkipHostDiscovery(),
	}
	if e.binaryPath != "" {
		opts = append(opts, nmap.WithBinaryPath(e.binaryPath))
	}
	if e.extraFlags != "" {
		opts = append(opts, nmap.WithCustomArguments(strings.Fields(e.extraFlags)...))
	}

	s, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("nmap scanner init: %w", err)
	}

	result, _, err := s.Run()
	if err != nil {
		return nil, fmt.Errorf("nmap run: %w", err)
	}

	var findings []scanner.Finding
	for _, h := range result.Hosts {
		for _, p := range h.Ports {
			evidence := fmt.Sprintf("Port %d/%s: %s %s %s",
				p.ID, p.Protocol,
				p.Service.Name, p.Service.Product, p.Service.Version)

			sev := scanner.SeverityInfo
			title := fmt.Sprintf("Nmap: %s on port %d", p.Service.Name, p.ID)
			description := fmt.Sprintf("Nmap detected %s %s %s on port %d/%s.", p.Service.Name, p.Service.Product, p.Service.Version, p.ID, p.Protocol)
			remediation := "Review service versions for known vulnerabilities. Update outdated software."
			ref := "nmap-sV"

			if rp, ok := riskyPorts[int(p.ID)]; ok {
				sev = rp.Severity
				title = rp.Title + " [nmap-verified]"
				description = rp.Description
				remediation = rp.Remediation
				ref = rp.Reference
			}

			// Append NSE script outputs
			for _, script := range p.Scripts {
				evidence += fmt.Sprintf("\n  [%s] %s", script.ID, script.Output)
				if strings.Contains(script.Output, "VULNERABLE") {
					sev = scanner.SeverityCritical
				}
			}

			findings = append(findings, scanner.Finding{
				ID:          fmt.Sprintf("NET-NMP-%d", p.ID),
				Layer:       "network",
				Title:       title,
				Description: description,
				Severity:    sev,
				Reference:   ref,
				Evidence:    evidence,
				Remediation: remediation,
			})

			// CVE lookup: only when version info is available
			if e.cveClient != nil && p.Service.Product != "" && p.Service.Version != "" {
				cveResults, err := e.cveClient.Lookup(p.Service.Product, p.Service.Version, 3, 4.0)
				if err == nil {
					for _, c := range cveResults {
						cveSev := cveSeverity(c.Score)
						findings = append(findings, scanner.Finding{
							ID:          fmt.Sprintf("NET-CVE-%s", c.ID),
							Layer:       "network",
							Title:       fmt.Sprintf("%s in %s %s", c.ID, p.Service.Product, p.Service.Version),
							Description: truncateDesc(c.Description, 300),
							Severity:    cveSev,
							Reference:   c.URL,
							Evidence:    fmt.Sprintf("CVSS %.1f (%s) — detected on port %d/%s", c.Score, c.Severity, p.ID, p.Protocol),
							Remediation: fmt.Sprintf("Update %s to a patched version. See %s", p.Service.Product, c.URL),
						})
					}
				}
			}
		}
	}

	return findings, nil
}

func cveSeverity(score float64) scanner.Severity {
	switch {
	case score >= 9.0:
		return scanner.SeverityCritical
	case score >= 7.0:
		return scanner.SeverityHigh
	case score >= 4.0:
		return scanner.SeverityMedium
	default:
		return scanner.SeverityLow
	}
}

func truncateDesc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
