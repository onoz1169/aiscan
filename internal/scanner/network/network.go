package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/onoz1169/aiscan/internal/scanner"
	"github.com/onoz1169/aiscan/internal/toolcheck"
)

type portInfo struct {
	Port    int
	Service string
}

// TCP top 100 from nmap's nmap-services frequency data
var defaultPorts = []portInfo{
	{7, "Echo"},
	{9, "Discard"},
	{13, "Daytime"},
	{21, "FTP"},
	{22, "SSH"},
	{23, "Telnet"},
	{25, "SMTP"},
	{26, "SMTP-alt"},
	{37, "Time"},
	{53, "DNS"},
	{79, "Finger"},
	{80, "HTTP"},
	{81, "HTTP-alt"},
	{88, "Kerberos"},
	{106, "POPPASSD"},
	{110, "POP3"},
	{111, "RPCbind"},
	{113, "Ident"},
	{119, "NNTP"},
	{135, "MSRPC"},
	{139, "NetBIOS"},
	{143, "IMAP"},
	{144, "NeWS"},
	{179, "BGP"},
	{199, "SMUX"},
	{443, "HTTPS"},
	{444, "SNPP"},
	{445, "SMB"},
	{465, "SMTPS"},
	{513, "rlogin"},
	{514, "rsh"},
	{515, "LPD"},
	{543, "klogin"},
	{544, "kshell"},
	{548, "AFP"},
	{554, "RTSP"},
	{587, "Submission"},
	{631, "IPP"},
	{646, "LDP"},
	{873, "rsync"},
	{990, "FTPS"},
	{993, "IMAPS"},
	{995, "POP3S"},
	{1025, "NFS-or-IIS"},
	{1026, "LSA-or-nterm"},
	{1027, "IIS"},
	{1028, "unknown"},
	{1029, "ms-lsa"},
	{1110, "nfsd-status"},
	{1433, "MSSQL"},
	{1720, "H.323"},
	{1723, "PPTP"},
	{1755, "MMS"},
	{1900, "SSDP"},
	{2000, "Cisco-SCCP"},
	{2001, "DC"},
	{2049, "NFS"},
	{2121, "FTP-alt"},
	{2717, "PN-requester"},
	{3000, "HTTP-dev"},
	{3128, "HTTP-proxy"},
	{3306, "MySQL"},
	{3389, "RDP"},
	{3986, "MAPPER"},
	{4899, "Radmin"},
	{5000, "UPnP"},
	{5009, "AirPort"},
	{5051, "ITA-agent"},
	{5060, "SIP"},
	{5101, "Talarian"},
	{5190, "AIM/ICQ"},
	{5357, "WSDAPI"},
	{5432, "PostgreSQL"},
	{5631, "pcAnywhere"},
	{5666, "NRPE"},
	{5672, "RabbitMQ"},
	{5800, "VNC-HTTP"},
	{5900, "VNC"},
	{6000, "X11"},
	{6001, "X11-1"},
	{6112, "dtspc"},
	{6379, "Redis"},
	{6513, "NETCONF"},
	{6543, "unknown"},
	{6646, "unknown"},
	{6789, "IBM-DB2"},
	{7000, "AFS"},
	{7070, "RealServer"},
	{7937, "NSClient"},
	{7938, "Lgtomapper"},
	{8000, "HTTP-alt"},
	{8008, "HTTP-alt"},
	{8009, "AJP"},
	{8080, "HTTP-proxy"},
	{8081, "HTTP-alt"},
	{8443, "HTTPS-alt"},
	{8888, "HTTP-alt"},
	{9100, "JetDirect"},
	{9200, "Elasticsearch"},
	{9999, "Aastra"},
	{10000, "Webmin"},
	{32768, "FileMaker"},
	{49152, "Dynamic"},
	{49153, "Dynamic"},
	{49154, "Dynamic"},
}

// serviceFingerprint maps banner patterns to service names.
type serviceFingerprint struct {
	pattern string
	service string
}

var serviceFingerprints = []serviceFingerprint{
	{"SSH-", "SSH"},
	{"220 ", "FTP/SMTP"},
	{"220-", "FTP/SMTP"},
	{"HTTP/", "HTTP"},
	{"* OK", "IMAP"},
	{"+OK", "POP3"},
	{"redis_version", "Redis"},
	{"mongo", "MongoDB"},
	{"MySQL", "MySQL"},
	{"PostgreSQL", "PostgreSQL"},
	{"SMB", "SMB"},
	{"RFB ", "VNC"},
	{"AMQP", "RabbitMQ"},
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
	5900: {
		Severity:    scanner.SeverityHigh,
		Title:       "VNC service exposed",
		Description: "VNC provides remote desktop access and often lacks strong authentication. Exposed VNC can allow full system control.",
		Reference:   "CWE-306",
		Remediation: "Disable VNC or restrict access via VPN. Use strong passwords and enable encryption.",
	},
	9200: {
		Severity:    scanner.SeverityCritical,
		Title:       "Elasticsearch service exposed",
		Description: "Elasticsearch is often completely unauthenticated by default. Exposed instances can leak all indexed data and allow arbitrary writes.",
		Reference:   "CWE-306",
		Remediation: "Enable Elasticsearch security features (X-Pack). Bind to localhost or use a reverse proxy with authentication.",
	},
	5672: {
		Severity:    scanner.SeverityHigh,
		Title:       "RabbitMQ service exposed",
		Description: "RabbitMQ message broker is often exposed without authentication, allowing message interception and injection.",
		Reference:   "CWE-306",
		Remediation: "Enable RabbitMQ authentication, change default credentials, and restrict access to trusted networks.",
	},
	2049: {
		Severity:    scanner.SeverityHigh,
		Title:       "NFS service exposed",
		Description: "NFS shares can expose filesystem contents to unauthenticated users if exports are misconfigured.",
		Reference:   "CWE-284",
		Remediation: "Restrict NFS exports to specific IPs. Use NFSv4 with Kerberos authentication. Never expose NFS to the internet.",
	},
	873: {
		Severity:    scanner.SeverityHigh,
		Title:       "rsync service exposed",
		Description: "rsync often allows unauthenticated file access, potentially exposing sensitive data or allowing file modification.",
		Reference:   "CWE-306",
		Remediation: "Require authentication for rsync. Restrict access via firewall rules and use rsync over SSH.",
	},
}

// expectedServiceOnPort maps ports to expected banner content for mismatch detection.
var expectedServiceOnPort = map[int]struct {
	bannerHint string
	mismatch   string
	severity   scanner.Severity
}{
	22:   {"SSH", "Unusual service on SSH port", scanner.SeverityMedium},
	80:   {"HTTP", "Unexpected service on HTTP port", scanner.SeverityLow},
	8080: {"HTTP", "Unexpected service on HTTP-proxy port", scanner.SeverityLow},
	443:  {"", "Plaintext service on expected HTTPS port", scanner.SeverityHigh},
	8443: {"", "Plaintext service on expected HTTPS-alt port", scanner.SeverityHigh},
}

// httpPorts are ports that commonly serve HTTP and should be probed for headers.
var httpPorts = map[int]bool{
	80: true, 81: true, 443: true, 3000: true, 3128: true,
	5000: true, 7070: true, 8000: true, 8008: true, 8009: true,
	8080: true, 8081: true, 8443: true, 8888: true, 9200: true,
	10000: true,
}

// NmapOptions controls optional nmap enrichment during network scans.
type NmapOptions struct {
	Disabled   bool   // if true, skip nmap even if installed
	Path       string // override PATH lookup (empty = auto)
	ExtraFlags string // additional nmap flags
}

// NetworkScanner implements the Scanner interface for network-layer port scanning.
type NetworkScanner struct {
	nmapOpts NmapOptions
}

func New() *NetworkScanner {
	return &NetworkScanner{}
}

func NewWithOptions(nmapOpts NmapOptions) *NetworkScanner {
	return &NetworkScanner{nmapOpts: nmapOpts}
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
			enricher := newNmapEnricher(nmapPath, s.nmapOpts.ExtraFlags, nmapTimeout)
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

	return &scanner.LayerResult{
		Layer:    "network",
		Target:   host,
		Duration: time.Since(start),
		Findings: findings,
		Errors:   scanErrors,
	}, nil
}

// identifyService matches banner content against known service fingerprints.
func identifyService(banner string) string {
	if banner == "" {
		return ""
	}
	for _, fp := range serviceFingerprints {
		if strings.Contains(banner, fp.pattern) {
			return fp.service
		}
	}
	return ""
}

// checkServiceMismatch detects when a service running on a port doesn't match expectations.
func checkServiceMismatch(port int, banner, host, evidence string, findingNum int) *scanner.Finding {
	expected, ok := expectedServiceOnPort[port]
	if !ok {
		return nil
	}

	// Special handling for HTTPS ports (443, 8443): flag if no TLS detected
	if port == 443 || port == 8443 {
		if banner != "" && !isTLSPort(host, port) {
			return &scanner.Finding{
				ID:          fmt.Sprintf("NET-%03d", findingNum),
				Layer:       "network",
				Title:       expected.mismatch,
				Description: fmt.Sprintf("Port %d is expected to serve HTTPS but appears to respond with plaintext. This could expose sensitive data in transit.", port),
				Severity:    expected.severity,
				Reference:   "CWE-319",
				Evidence:    evidence,
				Remediation: "Configure TLS on this port or move the service to a non-HTTPS port to avoid confusion.",
			}
		}
		return nil
	}

	// For other ports: check if banner matches expected service
	if banner != "" && expected.bannerHint != "" && !strings.Contains(banner, expected.bannerHint) {
		return &scanner.Finding{
			ID:          fmt.Sprintf("NET-%03d", findingNum),
			Layer:       "network",
			Title:       expected.mismatch,
			Description: fmt.Sprintf("Port %d is expected to serve %s but the banner does not match. A different service may be running on this port.", port, expected.bannerHint),
			Severity:    expected.severity,
			Reference:   "CWE-200",
			Evidence:    evidence,
			Remediation: "Verify the service running on this port is intentional. Move non-standard services to appropriate ports.",
		}
	}

	return nil
}

// isTLSPort attempts a TLS handshake to determine if a port speaks TLS.
func isTLSPort(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// fetchHTTPHeaders performs a simple GET request and returns response headers.
func fetchHTTPHeaders(host string, port int, timeout time.Duration) map[string]string {
	scheme := "http"
	if port == 443 || port == 8443 || port == 990 {
		scheme = "https"
	}

	targetURL := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	headers := make(map[string]string)
	for _, key := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if val := resp.Header.Get(key); val != "" {
			headers[key] = val
		}
	}
	return headers
}

// buildHTTPHeaderEvidence formats HTTP headers into an evidence string.
func buildHTTPHeaderEvidence(port int, headers map[string]string) string {
	parts := []string{fmt.Sprintf("HTTP service on port %d:", port)}
	for key, val := range headers {
		parts = append(parts, fmt.Sprintf("%s=%s", key, val))
	}
	return strings.Join(parts, " ")
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
