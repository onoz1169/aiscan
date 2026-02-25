package webapp

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/onoz1169/aiscan/internal/scanner"
)

// WebAppScanner checks web application security (OWASP Top 10 2021).
type WebAppScanner struct{}

func New() *WebAppScanner {
	return &WebAppScanner{}
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

// checkSecurityHeaders checks for missing security headers (A05:2021).
func (s *WebAppScanner) checkSecurityHeaders(resp *http.Response, isHTTPS bool, result *scanner.LayerResult) {
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-001",
			Layer:       "webapp",
			Title:       "Missing Content-Security-Policy header",
			Description: "The Content-Security-Policy header is not set, increasing risk of XSS attacks.",
			Severity:    scanner.SeverityMedium,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "Content-Security-Policy header not found in response.",
			Remediation: "Set a Content-Security-Policy header with a restrictive policy.",
		})
	} else {
		s.analyzeCSPQuality(csp, result)
	}

	if isHTTPS && resp.Header.Get("Strict-Transport-Security") == "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-002",
			Layer:       "webapp",
			Title:       "Missing Strict-Transport-Security header",
			Description: "HSTS header is not set. Browsers may allow downgrade to HTTP.",
			Severity:    scanner.SeverityHigh,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "Strict-Transport-Security header not found in HTTPS response.",
			Remediation: "Set Strict-Transport-Security header with max-age of at least 31536000.",
		})
	}

	if resp.Header.Get("X-Frame-Options") == "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-003",
			Layer:       "webapp",
			Title:       "Missing X-Frame-Options header",
			Description: "Page can be embedded in iframes, enabling clickjacking attacks.",
			Severity:    scanner.SeverityMedium,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "X-Frame-Options header not found in response.",
			Remediation: "Set X-Frame-Options to DENY or SAMEORIGIN.",
		})
	}

	if resp.Header.Get("X-Content-Type-Options") == "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-004",
			Layer:       "webapp",
			Title:       "Missing X-Content-Type-Options header",
			Description: "Browser may MIME-sniff the response, leading to security issues.",
			Severity:    scanner.SeverityLow,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "X-Content-Type-Options header not found in response.",
			Remediation: "Set X-Content-Type-Options to nosniff.",
		})
	}

	if resp.Header.Get("Referrer-Policy") == "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-005",
			Layer:       "webapp",
			Title:       "Missing Referrer-Policy header",
			Description: "Referrer information may leak to third-party sites.",
			Severity:    scanner.SeverityLow,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "Referrer-Policy header not found in response.",
			Remediation: "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
		})
	}

	if resp.Header.Get("Permissions-Policy") == "" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-006",
			Layer:       "webapp",
			Title:       "Missing Permissions-Policy header",
			Description: "Browser features are not restricted via Permissions-Policy.",
			Severity:    scanner.SeverityInfo,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "Permissions-Policy header not found in response.",
			Remediation: "Set a Permissions-Policy header to restrict browser features.",
		})
	}

	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" && containsVersion(serverHeader) {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-007",
			Layer:       "webapp",
			Title:       "Server header reveals version information",
			Description: "The Server header discloses software version, aiding attackers in fingerprinting.",
			Severity:    scanner.SeverityLow,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    fmt.Sprintf("Server: %s", serverHeader),
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

// containsVersion checks if a header value contains a version-like pattern (e.g. "1.2.3" or "/1.2").
func containsVersion(value string) bool {
	// Look for patterns like X.Y, X.Y.Z, or /X.Y
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			// found a digit, check if followed by .digit pattern
			for j := i + 1; j < len(value); j++ {
				if value[j] == '.' {
					if j+1 < len(value) && value[j+1] >= '0' && value[j+1] <= '9' {
						return true
					}
				} else if value[j] < '0' || value[j] > '9' {
					break
				}
			}
		}
	}
	return false
}
