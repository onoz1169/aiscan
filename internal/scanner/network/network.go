package network

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/onoz1169/aiscan/internal/scanner"
)

type portInfo struct {
	Port    int
	Service string
}

var defaultPorts = []portInfo{
	{21, "FTP"},
	{22, "SSH"},
	{23, "Telnet"},
	{25, "SMTP"},
	{53, "DNS"},
	{80, "HTTP"},
	{110, "POP3"},
	{143, "IMAP"},
	{443, "HTTPS"},
	{445, "SMB"},
	{3306, "MySQL"},
	{3389, "RDP"},
	{5432, "PostgreSQL"},
	{6379, "Redis"},
	{8080, "HTTP-alt"},
	{8443, "HTTPS-alt"},
	{27017, "MongoDB"},
}

// riskyPort defines severity and metadata for ports that pose security risks.
type riskyPort struct {
	Severity    scanner.Severity
	Title       string
	Description string
	Reference   string
	Remediation string
}

var riskyPorts = map[int]riskyPort{
	23: {
		Severity:    scanner.SeverityCritical,
		Title:       "Telnet service exposed",
		Description: "Telnet transmits all data including credentials in plaintext. Any network observer can intercept traffic.",
		Reference:   "CWE-319",
		Remediation: "Disable Telnet and use SSH for remote administration.",
	},
	21: {
		Severity:    scanner.SeverityHigh,
		Title:       "FTP service exposed",
		Description: "FTP transmits credentials in plaintext and is frequently misconfigured to allow anonymous access.",
		Reference:   "CWE-319",
		Remediation: "Replace FTP with SFTP or SCP. If FTP is required, enforce TLS (FTPS) and disable anonymous login.",
	},
	445: {
		Severity:    scanner.SeverityHigh,
		Title:       "SMB service exposed",
		Description: "SMB is a common attack vector for ransomware (WannaCry, NotPetya) and lateral movement.",
		Reference:   "CWE-284",
		Remediation: "Block SMB at the perimeter firewall. If internal access is needed, restrict to specific IPs and enforce SMBv3.",
	},
	6379: {
		Severity:    scanner.SeverityHigh,
		Title:       "Redis service exposed",
		Description: "Redis often runs without authentication. Exposed Redis instances can lead to remote code execution.",
		Reference:   "CWE-306",
		Remediation: "Bind Redis to localhost or private interfaces. Enable AUTH and use TLS. Never expose to the internet.",
	},
	27017: {
		Severity:    scanner.SeverityHigh,
		Title:       "MongoDB service exposed",
		Description: "MongoDB instances without authentication expose all databases to unauthenticated access.",
		Reference:   "CWE-306",
		Remediation: "Enable MongoDB authentication, bind to localhost, and use TLS for connections.",
	},
	3389: {
		Severity:    scanner.SeverityMedium,
		Title:       "RDP service exposed",
		Description: "Exposed RDP is a primary target for brute-force attacks and known vulnerabilities (BlueKeep).",
		Reference:   "CWE-284",
		Remediation: "Use a VPN or gateway for RDP access. Enable NLA and enforce strong credentials.",
	},
	3306: {
		Severity:    scanner.SeverityMedium,
		Title:       "MySQL service exposed",
		Description: "Publicly accessible MySQL can be targeted by brute-force attacks and SQL injection from external sources.",
		Reference:   "CWE-284",
		Remediation: "Bind MySQL to localhost or private interfaces. Use firewall rules to restrict access.",
	},
}

// NetworkScanner implements the Scanner interface for network-layer port scanning.
type NetworkScanner struct{}

func New() *NetworkScanner {
	return &NetworkScanner{}
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
	timeout := time.Duration(timeoutSec) * time.Second
	perPortTimeout := timeout / time.Duration(len(defaultPorts))
	if perPortTimeout < 500*time.Millisecond {
		perPortTimeout = 500 * time.Millisecond
	}
	if perPortTimeout > 3*time.Second {
		perPortTimeout = 3 * time.Second
	}

	type scanResult struct {
		port    portInfo
		open    bool
		banner  string
		scanErr string
	}

	results := make([]scanResult, len(defaultPorts))
	var wg sync.WaitGroup

	for i, p := range defaultPorts {
		wg.Add(1)
		go func(idx int, pi portInfo) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", host, pi.Port)
			conn, err := net.DialTimeout("tcp", addr, perPortTimeout)
			if err != nil {
				results[idx] = scanResult{port: pi, open: false}
				return
			}
			defer conn.Close()

			banner := grabBanner(conn, perPortTimeout)
			results[idx] = scanResult{port: pi, open: true, banner: banner}
		}(i, p)
	}
	wg.Wait()

	var findings []scanner.Finding
	var scanErrors []string
	findingNum := 1

	for _, r := range results {
		if !r.open {
			continue
		}

		evidence := fmt.Sprintf("Port %d/%s is open on %s", r.port.Port, r.port.Service, host)
		if r.banner != "" {
			evidence += fmt.Sprintf("; Banner: %s", sanitizeBanner(r.banner))
		}

		// INFO finding for every open port
		findings = append(findings, scanner.Finding{
			ID:          fmt.Sprintf("NET-%03d", findingNum),
			Layer:       "network",
			Title:       fmt.Sprintf("Open port: %d (%s)", r.port.Port, r.port.Service),
			Description: fmt.Sprintf("Port %d (%s) is open and accepting TCP connections.", r.port.Port, r.port.Service),
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

		if r.scanErr != "" {
			scanErrors = append(scanErrors, r.scanErr)
		}
	}

	return &scanner.LayerResult{
		Layer:    "network",
		Target:   host,
		Duration: time.Since(start),
		Findings: findings,
		Errors:   scanErrors,
	}, nil
}

// extractHost parses the target to extract a hostname suitable for TCP dialing.
func extractHost(target string) string {
	// Handle URLs like https://example.com/path
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}

	// Strip any port suffix and path
	host := target
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Remove port if present (but keep IPv6 brackets intact)
	if !strings.Contains(host, "[") {
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
	}

	return strings.TrimSpace(host)
}

// grabBanner attempts to read up to 256 bytes from the connection within the deadline.
func grabBanner(conn net.Conn, timeout time.Duration) string {
	deadline := timeout / 2
	if deadline < 500*time.Millisecond {
		deadline = 500 * time.Millisecond
	}
	conn.SetReadDeadline(time.Now().Add(deadline))

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

// sanitizeBanner cleans banner text for safe display: removes control characters and truncates.
func sanitizeBanner(banner string) string {
	var b strings.Builder
	for _, r := range banner {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteRune('.')
		}
	}
	s := b.String()
	if len(s) > 128 {
		s = s[:128] + "..."
	}
	return s
}
