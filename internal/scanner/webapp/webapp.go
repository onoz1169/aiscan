package webapp

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/onoz1169/1scan/internal/scanner"
	"github.com/onoz1169/1scan/internal/toolcheck"
	"github.com/onoz1169/1scan/internal/virustotal"
)

// NucleiOptions controls optional nuclei subprocess enrichment.
type NucleiOptions struct {
	Disabled  bool   // if true, skip nuclei even if installed
	Templates string // comma-separated template categories (default: "cves,misconfiguration,exposed-panels")
}

// WebAppScanner checks web application security (OWASP Top 10 2021).
type WebAppScanner struct {
	nucleiOpts NucleiOptions
	vtClient   *virustotal.Client // nil = VT check disabled
}

func New() *WebAppScanner {
	return &WebAppScanner{}
}

func NewWithOptions(opts NucleiOptions) *WebAppScanner {
	return &WebAppScanner{nucleiOpts: opts}
}

// NewWithVT creates a WebAppScanner with nuclei and VirusTotal options.
func NewWithVT(nucleiOpts NucleiOptions, vtClient *virustotal.Client) *WebAppScanner {
	return &WebAppScanner{nucleiOpts: nucleiOpts, vtClient: vtClient}
}

func (s *WebAppScanner) Name() string {
	return "webapp"
}

func (s *WebAppScanner) Scan(target string, timeoutSec int) (*scanner.LayerResult, error) {
	start := time.Now()

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	result := &scanner.LayerResult{
		Layer:  "webapp",
		Target: target,
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Run all checks
	s.checkTLS(parsed, timeoutSec, result)
	s.checkHTTPResponse(client, target, result)
	s.checkTRACE(client, target, result)
	s.checkCORS(client, target, result)
	s.checkHTTPSRedirect(client, target, result)
	s.checkDirectoryListing(client, target, result)
	s.checkInterestingPaths(client, target, result)

	// VirusTotal URL reputation check (optional, requires API key)
	if s.vtClient != nil {
		s.checkVirusTotal(target, result)
	}

	// nuclei enrichment (optional, if installed)
	if !s.nucleiOpts.Disabled {
		nucleiPath, ok := toolcheck.Available("nuclei")
		if ok {
			templates := s.nucleiOpts.Templates
			if templates == "" {
				templates = "cves,misconfiguration,exposed-panels"
			}
			enricher := newNucleiEnricher(nucleiPath, templates, time.Duration(timeoutSec)*time.Second*5)
			nucleiFindings, err := enricher.Enrich(target)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("nuclei: %v", err))
			} else {
				result.Findings = append(result.Findings, nucleiFindings...)
			}
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// checkTLS inspects TLS version and certificate validity.
func (s *WebAppScanner) checkTLS(parsed *url.URL, timeoutSec int, result *scanner.LayerResult) {
	if parsed.Scheme != "https" {
		return
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	addr := host + ":" + port

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("TLS connection failed: %v", err))
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Check TLS version
	switch state.Version {
	case tls.VersionTLS10:
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-008",
			Layer:       "webapp",
			Title:       "TLS 1.0 in use",
			Description: "Server supports TLS 1.0 which has known vulnerabilities.",
			Severity:    scanner.SeverityHigh,
			Reference:   "OWASP A02:2021 - Cryptographic Failures",
			Evidence:    "Negotiated TLS version: 1.0",
			Remediation: "Disable TLS 1.0 and configure the server to use TLS 1.2 or higher.",
		})
	case tls.VersionTLS11:
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-009",
			Layer:       "webapp",
			Title:       "TLS 1.1 in use",
			Description: "Server supports TLS 1.1 which is deprecated.",
			Severity:    scanner.SeverityHigh,
			Reference:   "OWASP A02:2021 - Cryptographic Failures",
			Evidence:    "Negotiated TLS version: 1.1",
			Remediation: "Disable TLS 1.1 and configure the server to use TLS 1.2 or higher.",
		})
	case tls.VersionTLS12:
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-010",
			Layer:       "webapp",
			Title:       "TLS 1.2 in use",
			Description: "Server uses TLS 1.2. Consider upgrading to TLS 1.3 for improved security.",
			Severity:    scanner.SeverityLow,
			Reference:   "OWASP A02:2021 - Cryptographic Failures",
			Evidence:    "Negotiated TLS version: 1.2",
			Remediation: "Enable TLS 1.3 support on the server.",
		})
	case tls.VersionTLS13:
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-011",
			Layer:       "webapp",
			Title:       "TLS 1.3 in use",
			Description: "Server uses TLS 1.3, the latest version.",
			Severity:    scanner.SeverityInfo,
			Reference:   "OWASP A02:2021 - Cryptographic Failures",
			Evidence:    "Negotiated TLS version: 1.3",
			Remediation: "No action required.",
		})
	}

	// Check certificates
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		if time.Now().After(cert.NotAfter) {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-012",
				Layer:       "webapp",
				Title:       "Expired TLS certificate",
				Description: "The server TLS certificate has expired.",
				Severity:    scanner.SeverityCritical,
				Reference:   "OWASP A02:2021 - Cryptographic Failures",
				Evidence:    fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
				Remediation: "Renew the TLS certificate immediately.",
			})
		}

		if cert.IsCA || cert.Issuer.CommonName == cert.Subject.CommonName {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-013",
				Layer:       "webapp",
				Title:       "Self-signed TLS certificate",
				Description: "The server uses a self-signed certificate which is not trusted by browsers.",
				Severity:    scanner.SeverityMedium,
				Reference:   "OWASP A02:2021 - Cryptographic Failures",
				Evidence:    fmt.Sprintf("Issuer and Subject match: %s", cert.Subject.CommonName),
				Remediation: "Obtain a certificate from a trusted Certificate Authority.",
			})
		}
	}
}

// checkHTTPResponse fetches the target and inspects headers, cookies, and body.
func (s *WebAppScanner) checkHTTPResponse(client *http.Client, target string, result *scanner.LayerResult) {
	resp, err := client.Get(target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("HTTP GET failed: %v", err))
		return
	}
	defer resp.Body.Close()

	isHTTPS := strings.HasPrefix(target, "https://")

	s.checkSecurityHeaders(resp, isHTTPS, result)
	s.checkInfoDisclosureHeaders(resp, result)
	s.checkCookies(resp, result)
	s.checkResponseBody(resp, result)
}

type headerCheck struct {
	id          string
	header      string
	httpsOnly   bool
	title       string
	description string
	severity    scanner.Severity
	remediation string
}

var securityHeaderChecks = []headerCheck{
	{
		id: "WEB-001", header: "Content-Security-Policy",
		title:       "Missing Content-Security-Policy header",
		description: "The Content-Security-Policy header is not set, increasing risk of XSS attacks.",
		severity:    scanner.SeverityMedium,
		remediation: "Set a Content-Security-Policy header with a restrictive policy.",
	},
	{
		id: "WEB-002", header: "Strict-Transport-Security", httpsOnly: true,
		title:       "Missing Strict-Transport-Security header",
		description: "HSTS header is not set. Browsers may allow downgrade to HTTP.",
		severity:    scanner.SeverityHigh,
		remediation: "Set Strict-Transport-Security header with max-age of at least 31536000.",
	},
	{
		id: "WEB-003", header: "X-Frame-Options",
		title:       "Missing X-Frame-Options header",
		description: "Page can be embedded in iframes, enabling clickjacking attacks.",
		severity:    scanner.SeverityMedium,
		remediation: "Set X-Frame-Options to DENY or SAMEORIGIN.",
	},
	{
		id: "WEB-004", header: "X-Content-Type-Options",
		title:       "Missing X-Content-Type-Options header",
		description: "Browser may MIME-sniff the response, leading to security issues.",
		severity:    scanner.SeverityLow,
		remediation: "Set X-Content-Type-Options to nosniff.",
	},
	{
		id: "WEB-005", header: "Referrer-Policy",
		title:       "Missing Referrer-Policy header",
		description: "Referrer information may leak to third-party sites.",
		severity:    scanner.SeverityLow,
		remediation: "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
	},
	{
		id: "WEB-006", header: "Permissions-Policy",
		title:       "Missing Permissions-Policy header",
		description: "Browser features are not restricted via Permissions-Policy.",
		severity:    scanner.SeverityInfo,
		remediation: "Set a Permissions-Policy header to restrict browser features.",
	},
}

var versionPattern = regexp.MustCompile(`\d+\.\d+`)

// checkSecurityHeaders checks for missing security headers (A05:2021).
func (s *WebAppScanner) checkSecurityHeaders(resp *http.Response, isHTTPS bool, result *scanner.LayerResult) {
	const ref = "OWASP A05:2021 - Security Misconfiguration"

	for _, chk := range securityHeaderChecks {
		if chk.httpsOnly && !isHTTPS {
			continue
		}
		val := resp.Header.Get(chk.header)
		if val != "" {
			if chk.header == "Content-Security-Policy" {
				s.analyzeCSPQuality(val, result)
			}
			continue
		}
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          chk.id,
			Layer:       "webapp",
			Title:       chk.title,
			Description: chk.description,
			Severity:    chk.severity,
			Reference:   ref,
			Evidence:    chk.header + " header not found in response.",
			Remediation: chk.remediation,
		})
	}

	if server := resp.Header.Get("Server"); server != "" && versionPattern.MatchString(server) {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-007",
			Layer:       "webapp",
			Title:       "Server header reveals version information",
			Description: "The Server header discloses software version, aiding attackers in fingerprinting.",
			Severity:    scanner.SeverityLow,
			Reference:   ref,
			Evidence:    fmt.Sprintf("Server: %s", server),
			Remediation: "Remove or obscure version information from the Server header.",
		})
	}
}

// checkInfoDisclosureHeaders checks for information leakage headers.
func (s *WebAppScanner) checkInfoDisclosureHeaders(resp *http.Response, result *scanner.LayerResult) {
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-014",
			Layer:       "webapp",
			Title:       "X-Powered-By header present",
			Description: "The X-Powered-By header reveals technology stack information.",
			Severity:    scanner.SeverityLow,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    fmt.Sprintf("X-Powered-By: %s", xpb),
			Remediation: "Remove the X-Powered-By header from server responses.",
		})
	}
}

// checkCookies inspects Set-Cookie headers for missing security attributes (A02:2021).
func (s *WebAppScanner) checkCookies(resp *http.Response, result *scanner.LayerResult) {
	for _, cookie := range resp.Cookies() {
		name := cookie.Name

		if !cookie.Secure {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-015",
				Layer:       "webapp",
				Title:       fmt.Sprintf("Cookie '%s' without Secure flag", name),
				Description: "Cookie may be sent over unencrypted HTTP connections.",
				Severity:    scanner.SeverityMedium,
				Reference:   "OWASP A02:2021 - Cryptographic Failures",
				Evidence:    fmt.Sprintf("Cookie '%s' is missing the Secure attribute.", name),
				Remediation: "Set the Secure flag on all cookies.",
			})
		}

		if !cookie.HttpOnly {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-016",
				Layer:       "webapp",
				Title:       fmt.Sprintf("Cookie '%s' without HttpOnly flag", name),
				Description: "Cookie is accessible via JavaScript, increasing XSS risk.",
				Severity:    scanner.SeverityMedium,
				Reference:   "OWASP A02:2021 - Cryptographic Failures",
				Evidence:    fmt.Sprintf("Cookie '%s' is missing the HttpOnly attribute.", name),
				Remediation: "Set the HttpOnly flag on cookies that do not need JavaScript access.",
			})
		}

		if cookie.SameSite == http.SameSiteDefaultMode {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-017",
				Layer:       "webapp",
				Title:       fmt.Sprintf("Cookie '%s' without SameSite attribute", name),
				Description: "Cookie lacks SameSite attribute, which may enable CSRF attacks.",
				Severity:    scanner.SeverityLow,
				Reference:   "OWASP A02:2021 - Cryptographic Failures",
				Evidence:    fmt.Sprintf("Cookie '%s' is missing the SameSite attribute.", name),
				Remediation: "Set SameSite=Lax or SameSite=Strict on cookies.",
			})
		}
	}
}

// checkResponseBody reads part of the response body and checks for stack trace patterns.
func (s *WebAppScanner) checkResponseBody(resp *http.Response, result *scanner.LayerResult) {
	buf := make([]byte, 64*1024) // read up to 64KB
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	stackTracePatterns := []string{
		"Traceback (most recent call last)",
		"at java.",
		"at sun.",
		"Exception in thread",
		"panic:",
		"goroutine ",
		"Microsoft.AspNetCore",
		"System.NullReferenceException",
		"Fatal error:",
		"Stack trace:",
	}

	for _, pattern := range stackTracePatterns {
		if strings.Contains(body, pattern) {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-018",
				Layer:       "webapp",
				Title:       "Stack trace detected in response body",
				Description: "Response body contains stack trace information that may reveal internal details.",
				Severity:    scanner.SeverityHigh,
				Reference:   "OWASP A05:2021 - Security Misconfiguration",
				Evidence:    fmt.Sprintf("Pattern found: %s", pattern),
				Remediation: "Disable detailed error messages in production. Use custom error pages.",
			})
			break // one finding is enough
		}
	}
}

// checkTRACE tests whether the TRACE method is enabled.
func (s *WebAppScanner) checkTRACE(client *http.Client, target string, result *scanner.LayerResult) {
	req, err := http.NewRequest(http.MethodTrace, target, nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-019",
			Layer:       "webapp",
			Title:       "TRACE method enabled",
			Description: "HTTP TRACE method is enabled, which can be used in cross-site tracing attacks.",
			Severity:    scanner.SeverityMedium,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "TRACE request returned HTTP 200 OK.",
			Remediation: "Disable the TRACE HTTP method on the web server.",
		})
	}
}

// checkVirusTotal checks the target URL's reputation via VirusTotal.
func (s *WebAppScanner) checkVirusTotal(target string, result *scanner.LayerResult) {
	report, err := s.vtClient.CheckURL(target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("virustotal: %v", err))
		return
	}
	if report == nil {
		return // URL not yet in VT database
	}

	stats := report.Stats
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
	if stats.Malicious == 0 && stats.Suspicious == 0 {
		return // clean
	}

	sev := scanner.SeverityMedium
	if stats.Malicious >= 5 {
		sev = scanner.SeverityCritical
	} else if stats.Malicious >= 2 {
		sev = scanner.SeverityHigh
	}

	evidence := fmt.Sprintf("VirusTotal: %d/%d engines flagged | malicious=%d suspicious=%d harmless=%d | reputation=%d",
		stats.Malicious+stats.Suspicious, total, stats.Malicious, stats.Suspicious, stats.Harmless, report.Reputation)

	result.Findings = append(result.Findings, scanner.Finding{
		ID:          "WEB-VT-001",
		Layer:       "webapp",
		Title:       fmt.Sprintf("VirusTotal: URL flagged by %d security engines", stats.Malicious+stats.Suspicious),
		Description: fmt.Sprintf("VirusTotal reports this URL as malicious or suspicious by %d out of %d security engines.", stats.Malicious+stats.Suspicious, total),
		Severity:    sev,
		Reference:   "https://www.virustotal.com/gui/url/" + target,
		Evidence:    evidence,
		Remediation: "Investigate whether the URL hosts malware or phishing content. Review server content and request VT re-analysis after remediation.",
	})
}

