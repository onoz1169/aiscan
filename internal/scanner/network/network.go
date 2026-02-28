// Package network implements network-layer port scanning with optional enrichment.
// TCP scanning covers top-100 ports with banner grabbing and service fingerprinting.
// Optional enrichments: nmap (service/version), Shodan InternetDB, AbuseIPDB, UDP probes.
package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/onoz1169/1scan/internal/abuseipdb"
	"github.com/onoz1169/1scan/internal/cve"
	"github.com/onoz1169/1scan/internal/scanner"
	"github.com/onoz1169/1scan/internal/toolcheck"
)

// NmapOptions controls optional nmap enrichment during network scans.
type NmapOptions struct {
	Disabled   bool        // if true, skip nmap even if installed
	Path       string      // override PATH lookup (empty = auto)
	ExtraFlags string      // additional nmap flags
	CVEClient  *cve.Client // nil = CVE lookup disabled
}

// NetworkEnrichmentOptions controls optional external API enrichments.
type NetworkEnrichmentOptions struct {
	ShodanEnabled bool              // default true; queries Shodan InternetDB (no key)
	AbuseIPDB     *abuseipdb.Client // nil = skip AbuseIPDB
}

// NetworkScanner implements the Scanner interface for network-layer port scanning.
type NetworkScanner struct {
	nmapOpts   NmapOptions
	enrichOpts NetworkEnrichmentOptions
	authOpts   scanner.AuthOptions
}

func New() *NetworkScanner {
	return &NetworkScanner{enrichOpts: NetworkEnrichmentOptions{ShodanEnabled: true}}
}

func NewWithOptions(nmapOpts NmapOptions, enrichOpts NetworkEnrichmentOptions) *NetworkScanner {
	return &NetworkScanner{nmapOpts: nmapOpts, enrichOpts: enrichOpts}
}

// NewWithAuth creates a NetworkScanner with authentication options for HTTP header probing.
func NewWithAuth(nmapOpts NmapOptions, enrichOpts NetworkEnrichmentOptions, authOpts scanner.AuthOptions) *NetworkScanner {
	return &NetworkScanner{nmapOpts: nmapOpts, enrichOpts: enrichOpts, authOpts: authOpts}
}

func (s *NetworkScanner) Name() string {
	return "network"
}

func (s *NetworkScanner) Scan(target string, timeoutSec int) (*scanner.LayerResult, error) {
	host := extractHost(target)
	if host == "" {
		return nil, fmt.Errorf("could not extract hostname from target: %s", target)
	}

	start := time.Now()
	// Ports are scanned concurrently, so perPortTimeout is an independent per-connection limit.
	// Cap at 3s to keep individual connections from blocking the scan indefinitely.
	perPortTimeout := time.Duration(timeoutSec) * time.Second
	if perPortTimeout > 3*time.Second {
		perPortTimeout = 3 * time.Second
	}

	type scanResult struct {
		port    portInfo
		open    bool
		banner  string
		headers map[string]string
		scanErr string
	}

	results := make([]scanResult, len(defaultPorts))
	var wg sync.WaitGroup

	// Limit concurrency to avoid resource exhaustion with 100+ ports
	sem := make(chan struct{}, 50)

	for i, p := range defaultPorts {
		wg.Add(1)
		go func(idx int, pi portInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", host, pi.Port)
			conn, err := net.DialTimeout("tcp", addr, perPortTimeout)
			if err != nil {
				results[idx] = scanResult{port: pi, open: false}
				return
			}
			defer conn.Close()

			banner := grabBanner(conn, perPortTimeout)

			// Fetch HTTP headers for HTTP ports or if banner looks like HTTP
			var headers map[string]string
			if httpPorts[pi.Port] || strings.HasPrefix(banner, "HTTP/") {
				headers = fetchHTTPHeaders(host, pi.Port, perPortTimeout)
			}

			results[idx] = scanResult{port: pi, open: true, banner: banner, headers: headers}
		}(i, p)
	}
	wg.Wait()

	var findings []scanner.Finding
	var scanErrors []string
	var openPorts []int
	findingNum := 1

	for _, r := range results {
		if !r.open {
			continue
		}

		openPorts = append(openPorts, r.port.Port)

		// Identify service from banner fingerprinting
		detectedService := identifyService(r.banner)
		serviceName := r.port.Service
		if detectedService != "" {
			serviceName = detectedService
		}

		evidence := fmt.Sprintf("Port %d/%s is open on %s", r.port.Port, serviceName, host)
		if r.banner != "" {
			evidence += fmt.Sprintf("; Banner: %s", sanitizeBanner(r.banner))
		}

		// INFO finding for every open port
		findings = append(findings, scanner.Finding{
			ID:          fmt.Sprintf("NET-%03d", findingNum),
			Layer:       "network",
			Title:       fmt.Sprintf("Open port: %d (%s)", r.port.Port, serviceName),
			Description: fmt.Sprintf("Port %d (%s) is open and accepting TCP connections.", r.port.Port, serviceName),
			Severity:    scanner.SeverityInfo,
			Reference:   "CWE-200",
			Evidence:    evidence,
			Remediation: "Review whether this port needs to be publicly accessible. Close unnecessary ports.",
		})
		findingNum++

		// Risk finding for known risky services
		if rp, ok := riskyPorts[r.port.Port]; ok {
			findings = append(findings, scanner.Finding{
				ID:          fmt.Sprintf("NET-%03d", findingNum),
				Layer:       "network",
				Title:       rp.Title,
				Description: rp.Description,
				Severity:    rp.Severity,
				Reference:   rp.Reference,
				Evidence:    evidence,
				Remediation: rp.Remediation,
			})
			findingNum++
		}

		// Banner-detected VNC on non-5900 port
		if detectedService == "VNC" && r.port.Port != 5900 {
			findings = append(findings, scanner.Finding{
				ID:          fmt.Sprintf("NET-%03d", findingNum),
				Layer:       "network",
				Title:       fmt.Sprintf("VNC service detected on port %d", r.port.Port),
				Description: "VNC provides remote desktop access and often lacks strong authentication. Exposed VNC can allow full system control.",
				Severity:    scanner.SeverityHigh,
				Reference:   "CWE-306",
				Evidence:    evidence,
				Remediation: "Disable VNC or restrict access via VPN. Use strong passwords and enable encryption.",
			})
			findingNum++
		}

		// Service-port mismatch detection
		if mismatchFinding := checkServiceMismatch(r.port.Port, r.banner, host, evidence, findingNum); mismatchFinding != nil {
			findings = append(findings, *mismatchFinding)
			findingNum++
		}

		// HTTP header info finding
		if len(r.headers) > 0 {
			headerInfo := buildHTTPHeaderEvidence(r.port.Port, r.headers)
			findings = append(findings, scanner.Finding{
				ID:          fmt.Sprintf("NET-%03d", findingNum),
				Layer:       "network",
				Title:       fmt.Sprintf("HTTP service on port %d", r.port.Port),
				Description: fmt.Sprintf("HTTP service detected on port %d with identifiable server headers.", r.port.Port),
				Severity:    scanner.SeverityInfo,
				Reference:   "CWE-200",
				Evidence:    headerInfo,
				Remediation: "Remove or obfuscate server version headers (Server, X-Powered-By) to reduce information leakage.",
			})
			findingNum++
		}

		if r.scanErr != "" {
			scanErrors = append(scanErrors, r.scanErr)
		}
	}

	// nmap enrichment phase
	if !s.nmapOpts.Disabled && len(openPorts) > 0 {
		nmapPath, ok := toolcheck.Available("nmap")
		if s.nmapOpts.Path != "" {
			nmapPath = s.nmapOpts.Path
			ok = true
		}
		if ok {
			nmapTimeout := time.Duration(timeoutSec) * 3 * time.Second
			if nmapTimeout < 60*time.Second {
				nmapTimeout = 60 * time.Second
			}
			enricher := newNmapEnricher(nmapPath, s.nmapOpts.ExtraFlags, nmapTimeout, s.nmapOpts.CVEClient)
			ctx, cancel := context.WithTimeout(context.Background(), enricher.timeout)
			defer cancel()
			nmapFindings, err := enricher.Enrich(ctx, host, openPorts)
			if err != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("nmap enrichment: %v", err))
			} else {
				findings = append(findings, nmapFindings...)
			}
		} else {
			fmt.Fprintf(os.Stderr, "  [i] nmap not found; install it for deeper service/version detection\n")
		}
	}

	// Shodan InternetDB enrichment (no key, external perspective)
	if s.enrichOpts.ShodanEnabled {
		ip := resolveIP(host)
		if ip != "" {
			shodanFindings, shodanErrs := enrichShodan(ip, findingNum)
			findings = append(findings, shodanFindings...)
			findingNum += len(shodanFindings)
			scanErrors = append(scanErrors, shodanErrs...)
		}
	}

	// AbuseIPDB enrichment (optional, requires API key)
	if s.enrichOpts.AbuseIPDB != nil {
		ip := resolveIP(host)
		if ip != "" {
			abuseFindings, abuseErrs := enrichAbuseIPDB(s.enrichOpts.AbuseIPDB, ip, findingNum)
			findings = append(findings, abuseFindings...)
			findingNum += len(abuseFindings)
			scanErrors = append(scanErrors, abuseErrs...)
		}
	}

	// UDP scan phase: probe well-known UDP services
	udpFindings, udpErrors := scanUDP(host, perPortTimeout, findingNum)
	findings = append(findings, udpFindings...)
	scanErrors = append(scanErrors, udpErrors...)

	return &scanner.LayerResult{
		Layer:    "network",
		Target:   host,
		Duration: time.Since(start),
		Findings: findings,
		Errors:   scanErrors,
	}, nil
}
