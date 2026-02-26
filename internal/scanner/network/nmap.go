package network

import (
	"context"
	"fmt"
	"strings"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
	"github.com/onoz1169/aiscan/internal/scanner"
)

// nmapEnricher runs nmap service/version detection on already-discovered open ports.
type nmapEnricher struct {
	binaryPath string
	extraFlags string
	timeout    time.Duration
}

func newNmapEnricher(binaryPath, extraFlags string, timeout time.Duration) *nmapEnricher {
	return &nmapEnricher{
		binaryPath: binaryPath,
		extraFlags: extraFlags,
		timeout:    timeout,
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
		}
	}

	return findings, nil
}
