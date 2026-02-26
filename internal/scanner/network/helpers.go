package network

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/onoz1169/1scan/internal/scanner"
)

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
