package webapp

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/onoz1169/aiscan/internal/scanner"
)

// checkCORS sends a request with a forged Origin header and inspects CORS response headers (A05:2021).
func (s *WebAppScanner) checkCORS(client *http.Client, target string, result *scanner.LayerResult) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", "https://evil.attacker.com")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "" {
		return
	}

	if acao == "https://evil.attacker.com" {
		if acac == "true" {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-020",
				Layer:       "webapp",
				Title:       "CORS reflects arbitrary origin with credentials",
				Description: "The server reflects an arbitrary Origin in Access-Control-Allow-Origin and allows credentials, enabling full authentication bypass from any domain.",
				Severity:    scanner.SeverityCritical,
				Reference:   "OWASP A05:2021 - Security Misconfiguration",
				Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true", acao),
				Remediation: "Implement a strict Origin allowlist. Never reflect arbitrary origins when credentials are allowed.",
			})
			return
		}
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-021",
			Layer:       "webapp",
			Title:       "CORS reflects arbitrary origin",
			Description: "The server reflects an arbitrary Origin in Access-Control-Allow-Origin, allowing cross-origin reads from any domain.",
			Severity:    scanner.SeverityHigh,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
			Remediation: "Implement a strict Origin allowlist instead of reflecting the request Origin.",
		})
		return
	}

	if acao == "*" && acac == "true" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-022",
			Layer:       "webapp",
			Title:       "Wildcard CORS with credentials",
			Description: "Access-Control-Allow-Origin is set to * with credentials enabled. Browsers block this combination but it indicates misconfiguration.",
			Severity:    scanner.SeverityCritical,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
			Remediation: "Never combine wildcard CORS with credentials. Use a specific Origin allowlist.",
		})
		return
	}

	if acao == "*" {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-023",
			Layer:       "webapp",
			Title:       "Wildcard CORS allows cross-origin reads",
			Description: "Access-Control-Allow-Origin is set to *, allowing any domain to read responses.",
			Severity:    scanner.SeverityMedium,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    "Access-Control-Allow-Origin: *",
			Remediation: "Restrict CORS to specific trusted origins unless the resource is intentionally public.",
		})
	}
}

var wildcardSrcRegex = regexp.MustCompile(`(script-src|default-src)[^;]*\*`)

// analyzeCSPQuality inspects the Content-Security-Policy value for common weaknesses (A05:2021).
func (s *WebAppScanner) analyzeCSPQuality(csp string, result *scanner.LayerResult) {
	if csp == "" {
		return
	}

	lower := strings.ToLower(csp)

	if strings.Contains(lower, "'unsafe-inline'") {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-024",
			Layer:       "webapp",
			Title:       "CSP contains 'unsafe-inline'",
			Description: "The Content-Security-Policy allows inline scripts, effectively bypassing XSS protections.",
			Severity:    scanner.SeverityHigh,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    fmt.Sprintf("CSP: %s", truncate(csp, 200)),
			Remediation: "Remove 'unsafe-inline' from CSP. Use nonces or hashes for inline scripts.",
		})
	}

	if strings.Contains(lower, "'unsafe-eval'") {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-025",
			Layer:       "webapp",
			Title:       "CSP contains 'unsafe-eval'",
			Description: "The Content-Security-Policy allows eval(), enabling dynamic code execution and potential XSS.",
			Severity:    scanner.SeverityHigh,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    fmt.Sprintf("CSP: %s", truncate(csp, 200)),
			Remediation: "Remove 'unsafe-eval' from CSP. Refactor code to avoid eval() and similar functions.",
		})
	}

	if wildcardSrcRegex.MatchString(lower) {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-026",
			Layer:       "webapp",
			Title:       "CSP uses wildcard source",
			Description: "The Content-Security-Policy uses a wildcard (*) in script-src or default-src, bypassing origin restrictions.",
			Severity:    scanner.SeverityMedium,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    fmt.Sprintf("CSP: %s", truncate(csp, 200)),
			Remediation: "Replace wildcard sources with specific trusted origins.",
		})
	}

	if !strings.Contains(lower, "object-src") && !strings.Contains(lower, "default-src") {
		result.Findings = append(result.Findings, scanner.Finding{
			ID:          "WEB-027",
			Layer:       "webapp",
			Title:       "CSP missing object-src restriction",
			Description: "The Content-Security-Policy does not restrict object-src, leaving plugin content unrestricted.",
			Severity:    scanner.SeverityLow,
			Reference:   "OWASP A05:2021 - Security Misconfiguration",
			Evidence:    fmt.Sprintf("CSP: %s", truncate(csp, 200)),
			Remediation: "Add object-src 'none' to the Content-Security-Policy.",
		})
	}
}

type interestingPath struct {
	path     string
	severity scanner.Severity
	title    string
}

var interestingPaths = []interestingPath{
	{"/.git/HEAD", scanner.SeverityHigh, "Git repository exposed"},
	{"/.git/config", scanner.SeverityHigh, "Git config exposed"},
	{"/.env", scanner.SeverityCritical, ".env file exposed - may contain secrets"},
	{"/.env.local", scanner.SeverityCritical, ".env.local exposed"},
	{"/.env.production", scanner.SeverityCritical, ".env.production exposed"},
	{"/backup.zip", scanner.SeverityHigh, "Backup archive accessible"},
	{"/backup.tar.gz", scanner.SeverityHigh, "Backup archive accessible"},
	{"/admin", scanner.SeverityMedium, "Admin panel accessible"},
	{"/admin/", scanner.SeverityMedium, "Admin panel accessible"},
	{"/phpinfo.php", scanner.SeverityHigh, "PHP info page exposed"},
	{"/server-status", scanner.SeverityMedium, "Apache server-status exposed"},
	{"/api/docs", scanner.SeverityInfo, "API documentation publicly accessible"},
	{"/swagger.json", scanner.SeverityMedium, "Swagger API spec exposed"},
	{"/swagger-ui.html", scanner.SeverityMedium, "Swagger UI exposed"},
	{"/v1/api-docs", scanner.SeverityMedium, "API docs exposed"},
	{"/actuator", scanner.SeverityHigh, "Spring Boot Actuator exposed"},
	{"/actuator/env", scanner.SeverityCritical, "Spring Boot env actuator - may leak secrets"},
	{"/debug", scanner.SeverityHigh, "Debug endpoint accessible"},
	{"/config.json", scanner.SeverityHigh, "Config file exposed"},
	{"/.DS_Store", scanner.SeverityLow, ".DS_Store exposes directory structure"},
	{"/robots.txt", scanner.SeverityInfo, "robots.txt exists - check for hidden paths"},
	{"/sitemap.xml", scanner.SeverityInfo, "Sitemap accessible"},
	{"/crossdomain.xml", scanner.SeverityMedium, "Flash crossdomain policy exists"},
	{"/wp-admin/", scanner.SeverityMedium, "WordPress admin panel detected"},
	{"/wp-login.php", scanner.SeverityMedium, "WordPress login page detected"},
}

// checkInterestingPaths probes for sensitive files and endpoints (A05:2021, A01:2021).
func (s *WebAppScanner) checkInterestingPaths(client *http.Client, target string, result *scanner.LayerResult) {
	parsed, err := url.Parse(target)
	if err != nil {
		return
	}
	base := parsed.Scheme + "://" + parsed.Host

	// Use a non-redirect client so we can detect 200 vs redirect
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // max 10 concurrent requests

	for _, p := range interestingPaths {
		wg.Add(1)
		go func(p interestingPath) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			reqURL := base + p.path
			resp, err := noRedirectClient.Get(reqURL)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			if resp.StatusCode == http.StatusOK {
				finding := scanner.Finding{
					ID:          "WEB-028",
					Layer:       "webapp",
					Title:       p.title,
					Description: fmt.Sprintf("The path %s returned HTTP 200, indicating the resource is accessible.", p.path),
					Severity:    p.severity,
					Reference:   "OWASP A05:2021 - Security Misconfiguration",
					Evidence:    fmt.Sprintf("GET %s returned HTTP %d", p.path, resp.StatusCode),
					Remediation: "Remove or restrict access to this resource. Use authentication or firewall rules.",
				}
				mu.Lock()
				result.Findings = append(result.Findings, finding)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
}

// checkHTTPSRedirect verifies that HTTP traffic is redirected to HTTPS (A02:2021).
func (s *WebAppScanner) checkHTTPSRedirect(client *http.Client, target string, result *scanner.LayerResult) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" {
		return
	}

	httpTarget := "http://" + parsed.Host + parsed.RequestURI()

	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := noRedirectClient.Get(httpTarget)
	if err != nil {
		// Connection refused on port 80 is fine - no HTTP exposure
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
		location := resp.Header.Get("Location")
		if strings.HasPrefix(location, "https://") {
			// Redirects to HTTPS - good
			return
		}
	}

	result.Findings = append(result.Findings, scanner.Finding{
		ID:          "WEB-029",
		Layer:       "webapp",
		Title:       "HTTP does not redirect to HTTPS",
		Description: "The HTTP version of the site does not redirect to HTTPS, allowing cleartext traffic.",
		Severity:    scanner.SeverityMedium,
		Reference:   "OWASP A02:2021 - Cryptographic Failures",
		Evidence:    fmt.Sprintf("GET %s returned HTTP %d without HTTPS redirect", httpTarget, resp.StatusCode),
		Remediation: "Configure a 301 redirect from HTTP to HTTPS for all paths.",
	})
}

// checkDirectoryListing inspects the response body for directory listing indicators.
func (s *WebAppScanner) checkDirectoryListing(client *http.Client, target string, result *scanner.LayerResult) {
	resp, err := client.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	dirPatterns := []string{
		"Index of /",
		"Directory listing",
		"<title>Index of",
		"Parent Directory",
	}

	for _, pattern := range dirPatterns {
		if strings.Contains(body, pattern) {
			result.Findings = append(result.Findings, scanner.Finding{
				ID:          "WEB-030",
				Layer:       "webapp",
				Title:       "Directory listing enabled",
				Description: "The web server exposes directory contents, which may reveal sensitive files.",
				Severity:    scanner.SeverityHigh,
				Reference:   "OWASP A05:2021 - Security Misconfiguration",
				Evidence:    fmt.Sprintf("Response body contains: %s", pattern),
				Remediation: "Disable directory listing in the web server configuration.",
			})
			return
		}
	}
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
