# Web Application Scanner Research Report

Research date: 2025-02-25
Tools surveyed: nikto, nuclei (web templates), OWASP ZAP, testssl.sh, securityheaders.com approach
Current implementation: `/internal/scanner/webapp/webapp.go`

---

## 1. OWASP Top 10 2021 -- Concrete HTTP Checks Mapping

### A01: Broken Access Control

| Check | Method | Severity |
|-------|--------|----------|
| CORS misconfiguration (`Access-Control-Allow-Origin: *`) | Passive header inspection | High |
| Directory listing enabled | GET common paths, check for index-of patterns | Medium |
| robots.txt / sitemap.xml information disclosure | GET `/robots.txt`, `/sitemap.xml` | Info |
| Accessible admin panels | GET `/admin`, `/administrator`, `/wp-admin`, `/cpanel` | High |
| HTTP method enumeration (PUT, DELETE allowed) | OPTIONS request, then test PUT/DELETE | Medium |
| TRACE method enabled | TRACE request (already implemented: WEB-019) | Medium |
| Missing CSRF tokens in forms | Parse HTML forms for hidden token fields | Medium |
| Session ID in URL rewrite | Inspect URLs for `JSESSIONID`, `PHPSESSID` patterns | Medium |

### A02: Cryptographic Failures

| Check | Method | Severity |
|-------|--------|----------|
| TLS version (1.0/1.1 deprecated) | TLS handshake (already implemented: WEB-008/009) | High |
| Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT) | Enumerate offered ciphers via handshake | High |
| Missing forward secrecy (no ECDHE/DHE) | Check negotiated cipher key exchange | Medium |
| Expired/self-signed certificate | Certificate inspection (already implemented: WEB-012/013) | Critical/Medium |
| Certificate chain incomplete | Verify chain to trusted root | Medium |
| Short RSA key (<2048 bits) | Check certificate public key length | High |
| Weak signature algorithm (SHA-1, MD5) | Check certificate signature algorithm | High |
| Missing OCSP stapling | Check TLS extensions in handshake | Low |
| HSTS not set on HTTPS | Header check (already implemented: WEB-002) | High |
| Cookie without Secure flag over HTTPS | Cookie inspection (already implemented: WEB-015) | Medium |
| Mixed content (HTTP resources on HTTPS page) | Parse HTML for `http://` src/href on HTTPS pages | Medium |

### A03: Injection

| Check | Method | Severity |
|-------|--------|----------|
| Reflected input in response (basic XSS probe) | Inject canary in query params, check reflection | High |
| CSP header missing or weak | Header inspection (already implemented: WEB-001) | Medium |
| X-Content-Type-Options missing | Header inspection (already implemented: WEB-004) | Low |

Note: Full injection testing requires active scanning beyond aiscan's passive/light-active scope. CSP is the primary HTTP-level mitigation.

### A04: Insecure Design

Not directly testable via HTTP checks. Primarily a design-level concern.

### A05: Security Misconfiguration

| Check | Method | Severity |
|-------|--------|----------|
| Missing security headers (full set, see Section 2) | Passive header inspection | Varies |
| Server version disclosure | Server header with version pattern (already: WEB-007) | Low |
| X-Powered-By disclosure | Header check (already implemented: WEB-014) | Low |
| X-AspNet-Version / X-AspNetMvc-Version disclosure | Header check | Low |
| X-Generator / X-CMS header disclosure | Header check | Low |
| Default error pages (stack traces) | Response body check (already: WEB-018) | High |
| Directory listing enabled | GET known paths, check for auto-index signatures | Medium |
| Exposed `.env`, `.git/HEAD`, `.DS_Store` files | GET sensitive file paths, check for 200 | Critical |
| Exposed backup files (`.bak`, `.old`, `.sql`) | GET common backup paths | High |
| Debug endpoints (`/debug`, `/phpinfo.php`, `/server-status`) | GET known debug paths | High |
| Unnecessary HTTP methods (OPTIONS check) | Send OPTIONS, parse Allow header | Low |
| TRACE method enabled | TRACE request (already implemented: WEB-019) | Medium |

### A06: Vulnerable and Outdated Components

| Check | Method | Severity |
|-------|--------|----------|
| Server header version fingerprint | Parse Server header for known CVEs | Medium |
| X-Powered-By version fingerprint | Parse for framework + version | Medium |
| Known vulnerable JS libraries (e.g., jQuery < 3.5.0) | Parse HTML/JS for library versions | Medium |
| WordPress/CMS version detection | Parse generator meta tag, known paths | Medium |

### A07: Identification and Authentication Failures

| Check | Method | Severity |
|-------|--------|----------|
| Basic auth over HTTP (not HTTPS) | Check WWW-Authenticate header on HTTP | Critical |
| Session cookie without HttpOnly | Cookie inspection (already: WEB-016) | Medium |
| Session cookie without SameSite | Cookie inspection (already: WEB-017) | Low |
| Cookie without `__Host-` or `__Secure-` prefix | Cookie name inspection | Info |
| Login page over HTTP | Check form action URLs | High |

### A08: Software and Data Integrity Failures

| Check | Method | Severity |
|-------|--------|----------|
| Missing Subresource Integrity (SRI) on external scripts | Parse HTML for `<script src>` without `integrity` | Medium |
| Content served from known compromised CDNs | Check script src domains against blocklist | High |

### A09: Security Logging and Monitoring Failures

Not directly testable via HTTP checks. Operational concern.

### A10: Server-Side Request Forgery (SSRF)

Not testable via passive scanning. Requires active exploitation attempts.

---

## 2. Security Headers -- Full List with Severity Ratings

### Headers to ADD (check for presence)

| Header | Recommended Value | Severity | Attack Prevented | Our Status |
|--------|-------------------|----------|------------------|------------|
| **Strict-Transport-Security** | `max-age=31536000; includeSubDomains` | HIGH | Protocol downgrade, cookie hijacking | Implemented (WEB-002) |
| **Content-Security-Policy** | `default-src 'self'; ...` | HIGH | XSS, injection, clickjacking | Implemented (WEB-001) but no value analysis |
| **X-Frame-Options** | `DENY` or `SAMEORIGIN` | MEDIUM | Clickjacking | Implemented (WEB-003) |
| **X-Content-Type-Options** | `nosniff` | LOW | MIME sniffing | Implemented (WEB-004) |
| **Referrer-Policy** | `strict-origin-when-cross-origin` or `no-referrer` | LOW | Referrer information leakage | Implemented (WEB-005) |
| **Permissions-Policy** | `geolocation=(), camera=(), microphone=()` | INFO | Unauthorized feature access | Implemented (WEB-006) |
| **Cross-Origin-Opener-Policy** | `same-origin` | MEDIUM | XS-Leaks, Spectre | **MISSING** |
| **Cross-Origin-Embedder-Policy** | `require-corp` | MEDIUM | Spectre side-channel | **MISSING** |
| **Cross-Origin-Resource-Policy** | `same-origin` | MEDIUM | Spectre, XSSI | **MISSING** |
| **X-Permitted-Cross-Domain-Policies** | `none` | LOW | Flash/PDF cross-domain access | **MISSING** |
| **Cache-Control** | `no-store, max-age=0` (sensitive pages) | MEDIUM | Sensitive data cached | **MISSING** |
| **Clear-Site-Data** | `"cache","cookies","storage"` (logout pages) | LOW | Data exposure after logout | **MISSING** (niche) |
| **X-DNS-Prefetch-Control** | `off` | LOW | DNS prefetch data exfiltration | **MISSING** |

### Headers to REMOVE (check for information disclosure)

| Header | Severity | Our Status |
|--------|----------|------------|
| **Server** (with version) | LOW | Implemented (WEB-007) |
| **X-Powered-By** | LOW | Implemented (WEB-014) |
| **X-AspNet-Version** | LOW | **MISSING** |
| **X-AspNetMvc-Version** | LOW | **MISSING** |
| **X-Generator** | LOW | **MISSING** |
| **X-Debug-Token** | MEDIUM | **MISSING** |
| **X-SourceMap** / **SourceMap** | LOW | **MISSING** |
| **X-Backend-Server** | MEDIUM | **MISSING** |
| **X-ChromeLogger-Data** | MEDIUM | **MISSING** |

### Deprecated Headers (warn if present with wrong value)

| Header | Action | Reason |
|--------|--------|--------|
| **X-XSS-Protection** | Warn if set to `1; mode=block` | Can create XSS in older IE; should be `0` or absent; use CSP |
| **Expect-CT** | Info only | Deprecated; browsers enforce CT by default |
| **Public-Key-Pins** | Warn if present | Deprecated; risk of browser lockout |

### CSP Value Analysis (not just presence)

Beyond checking if CSP exists, high-value checks include:

| CSP Issue | Severity | Detection |
|-----------|----------|-----------|
| `unsafe-inline` in script-src | HIGH | Regex match in CSP value |
| `unsafe-eval` in script-src | HIGH | Regex match |
| `*` wildcard in src directives | MEDIUM | Regex match |
| `data:` in script-src | MEDIUM | Regex match |
| `http:` scheme in src directives | MEDIUM | Regex match |
| Missing `default-src` | MEDIUM | Absence check |
| Missing `frame-ancestors` (when no X-Frame-Options) | MEDIUM | Absence check |

Source: OWASP HTTP Headers Cheat Sheet, OWASP Secure Headers Project, nuclei `http-missing-security-headers.yaml`, ZAP passive rule 10038/10055.

---

## 3. TLS Checks That Matter (Beyond Version)

Our current implementation checks only TLS version and certificate expiry/self-signed status. testssl.sh and SSL Labs demonstrate the following comprehensive approach:

### Protocol Checks

| Check | Severity | Our Status |
|-------|----------|------------|
| SSLv2 support | CRITICAL | Not checked (Go's TLS lib won't negotiate SSLv2, but should attempt) |
| SSLv3 support | CRITICAL | Not checked |
| TLS 1.0 support | HIGH | Implemented (WEB-008) |
| TLS 1.1 support | HIGH | Implemented (WEB-009) |
| TLS 1.2 support | INFO | Implemented (WEB-010) |
| TLS 1.3 support | INFO | Implemented (WEB-011) |

Current gap: We only check the *negotiated* version, not which versions the server *supports*. A server might negotiate TLS 1.3 with us but still accept TLS 1.0 from other clients. To fully test, we should attempt connections at each protocol version.

### Cipher Suite Checks

| Check | Severity | testssl.sh Equivalent |
|-------|----------|-----------------------|
| NULL encryption ciphers | CRITICAL | `-e` cipher enumeration |
| EXPORT ciphers (40/56-bit) | CRITICAL | FREAK/Logjam test |
| DES / 3DES ciphers | HIGH | SWEET32 check |
| RC4 ciphers | HIGH | Dedicated RC4 check |
| CBC ciphers with TLS 1.0 | MEDIUM | BEAST check |
| No forward secrecy (missing ECDHE/DHE) | MEDIUM | `-f` forward secrecy test |
| Weak DH parameters (<2048 bits) | HIGH | Logjam check |
| Server cipher preference (server vs client order) | LOW | `-o` ordering check |

### Certificate Checks

| Check | Severity | Our Status |
|-------|----------|------------|
| Expired certificate | CRITICAL | Implemented (WEB-012) |
| Self-signed certificate | MEDIUM | Implemented (WEB-013) |
| Weak RSA key (<2048 bits) | HIGH | **MISSING** |
| Weak signature algorithm (SHA-1, MD5) | HIGH | **MISSING** |
| Certificate chain incomplete | MEDIUM | **MISSING** |
| SAN mismatch (hostname not in SAN) | HIGH | **MISSING** |
| Certificate expiring soon (<30 days) | MEDIUM | **MISSING** |
| Wildcard certificate usage | INFO | **MISSING** |
| OCSP stapling not enabled | LOW | **MISSING** |
| Certificate Transparency SCTs | INFO | **MISSING** |

### Known Vulnerability Checks (testssl.sh coverage)

| Vulnerability | Description | Severity | Feasibility for Go |
|---------------|-------------|----------|-------------------|
| Heartbleed | OpenSSL memory leak | CRITICAL | Requires raw TLS handshake |
| POODLE | SSLv3 CBC padding oracle | HIGH | Check SSLv3 support |
| BEAST | CBC in TLS 1.0 | MEDIUM | Check TLS 1.0 + CBC ciphers |
| SWEET32 | 64-bit block cipher birthday attack | MEDIUM | Check 3DES usage |
| FREAK | Export RSA key factoring | HIGH | Check export ciphers |
| Logjam | Weak DH export | HIGH | Check DH params |
| ROBOT | Bleichenbacher oracle | HIGH | Complex; skip for v1 |
| DROWN | SSLv2 cross-protocol attack | HIGH | Check SSLv2 support |
| CRIME | TLS compression leak | MEDIUM | Check compression |
| BREACH | HTTP compression leak | MEDIUM | Check Content-Encoding |

Recommendation: For aiscan v1, focus on protocol version enumeration, key size, signature algorithm, cipher strength categories, and forward secrecy. Leave complex oracle attacks (ROBOT, Heartbleed raw) for later versions.

---

## 4. Cookie Checks -- Comprehensive List

### Attributes to Check

| Attribute | Check | Severity | Our Status |
|-----------|-------|----------|------------|
| `Secure` | Must be set for HTTPS cookies | MEDIUM | Implemented (WEB-015) |
| `HttpOnly` | Should be set for session cookies | MEDIUM | Implemented (WEB-016) |
| `SameSite` | Should be `Lax` or `Strict` | LOW | Implemented (WEB-017) |
| `Path` | Should be restrictive (not `/`) | LOW | **MISSING** |
| `Domain` | Should not be overly broad | LOW | **MISSING** |
| `Max-Age` / `Expires` | Session cookies should not be persistent | LOW | **MISSING** |
| `__Host-` prefix | Best practice for host-locked cookies | INFO | **MISSING** |
| `__Secure-` prefix | Requires Secure flag | INFO | **MISSING** |

### Additional Cookie Checks (from ZAP)

| Check | Description | Severity |
|-------|-------------|----------|
| Loosely scoped cookie | Domain attribute set too broadly (e.g., `.example.com` on subdomain) | LOW |
| Cookie poisoning | Cookie value influenced by user-controlled input | MEDIUM |
| Session ID in URL | Session token in query string instead of cookie | MEDIUM |
| Persistent session cookie | Session cookie with explicit Max-Age/Expires | LOW |
| Cookie size excessive | Cookie > 4KB (performance + potential abuse) | INFO |

---

## 5. What Our Current Implementation Is Missing

### Gap Analysis Summary

| Category | Current Checks | Missing High-Value Checks | Priority |
|----------|---------------|---------------------------|----------|
| **Security Headers** | 7 headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server version) | COOP, COEP, CORP, Cache-Control, CSP value analysis, info-disclosure headers (X-AspNet-Version, X-Debug-Token, X-Backend-Server) | HIGH |
| **TLS** | Version check (negotiated only), cert expiry, self-signed | Multi-version probing, cipher strength, key size, sig algorithm, forward secrecy, cert chain, SAN match, expiry-soon | HIGH |
| **Cookies** | Secure, HttpOnly, SameSite | Path scope, Domain scope, prefix checks, persistence | LOW |
| **Sensitive Files** | None | `.env`, `.git/HEAD`, `robots.txt`, backup files, debug endpoints | HIGH |
| **CORS** | None | `Access-Control-Allow-Origin: *` check | MEDIUM |
| **HTTP Methods** | TRACE only | OPTIONS enumeration, PUT/DELETE check | MEDIUM |
| **Content Checks** | Stack traces only | Mixed content, SRI missing, form action over HTTP, sensitive data patterns (emails, IPs, PII) | MEDIUM |
| **Redirect Checks** | Follows up to 10 redirects | HTTP-to-HTTPS redirect check, open redirect detection | MEDIUM |
| **CSP Analysis** | Presence only | Unsafe-inline, unsafe-eval, wildcard, data: scheme analysis | HIGH |

### Architectural Gaps

1. **Single request model**: We send one GET request and one TRACE request. nikto sends hundreds of probes; nuclei sends targeted requests per template. We need at minimum a small set of targeted probes beyond the main page.

2. **No multi-protocol TLS probing**: We connect once and check the negotiated version. We should attempt connections at TLS 1.0, 1.1, 1.2, 1.3 individually to see what the server accepts.

3. **No path probing**: We only check the root URL. High-value sensitive file checks (`.env`, `.git/HEAD`) require additional GET requests to specific paths.

4. **No HTTP-to-HTTPS redirect check**: We default to `https://` but never test whether `http://` redirects properly.

5. **No response body analysis beyond stack traces**: Missing mixed content detection, PII patterns, JS library version extraction.

---

## 6. Top 10 Improvements to Implement (Prioritized by Impact)

### Priority 1 -- Critical / Easy Wins

**1. Sensitive file exposure checks**
- Probe: `/.env`, `/.git/HEAD`, `/.git/config`, `/.DS_Store`, `/wp-config.php.bak`, `/.htaccess`, `/server-status`, `/phpinfo.php`, `/web.config`
- Why: Immediate critical findings. These are among the highest-signal checks in nikto and nuclei.
- Effort: Low (additional GET requests, check for 200 + content patterns)
- OWASP: A05 Security Misconfiguration
- Source: nikto file database, nuclei `http/exposures/` templates

**2. CSP value analysis**
- Check for `unsafe-inline`, `unsafe-eval`, `*` wildcard, `data:` in script-src, missing `default-src`
- Why: A present but weak CSP gives false sense of security. ZAP rule 10055 does this.
- Effort: Low (regex on existing header value)
- OWASP: A03 Injection (XSS mitigation)

**3. TLS cipher strength check**
- Attempt connections with different cipher suites to detect NULL, EXPORT, DES, RC4
- Why: TLS version alone is insufficient. A TLS 1.2 server with RC4 is still vulnerable.
- Effort: Medium (multiple TLS connections with restricted cipher configs)
- OWASP: A02 Cryptographic Failures
- Source: testssl.sh cipher categories

### Priority 2 -- High Value

**4. Certificate key size and signature algorithm**
- Check RSA key >= 2048 bits, ECDSA >= 256 bits, no SHA-1/MD5 signatures
- Why: Weak keys are exploitable; weak signatures are forgeable. Already have cert access.
- Effort: Low (add fields to existing cert inspection)
- OWASP: A02 Cryptographic Failures

**5. Cross-Origin headers (COOP, COEP, CORP, CORS)**
- Check for COOP/COEP/CORP presence, check for overly permissive CORS (`Access-Control-Allow-Origin: *`)
- Why: Modern browsers rely on these for Spectre/XS-Leak protection. nuclei checks all of them.
- Effort: Low (header presence/value checks)
- OWASP: A01 Broken Access Control, A05 Security Misconfiguration

**6. Additional info-disclosure headers**
- Check for: `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Debug-Token`, `X-Backend-Server`, `X-ChromeLogger-Data`, `SourceMap`
- Why: ZAP has dedicated passive rules for each of these (rules 10061, 10039, 10052, 10056).
- Effort: Low (header presence checks)
- OWASP: A05 Security Misconfiguration

### Priority 3 -- Medium Value

**7. HTTP-to-HTTPS redirect check**
- Send GET to `http://` variant, verify 301/302 to `https://`
- Why: HSTS only works after first HTTPS visit. Redirect is the first line of defense.
- Effort: Low (one additional request)
- OWASP: A02 Cryptographic Failures

**8. HTTP method enumeration**
- Send OPTIONS request, parse `Allow` header; optionally test PUT/DELETE
- Why: Overly permissive methods can enable data modification. nikto and ZAP both check this.
- Effort: Low (OPTIONS request + parsing)
- OWASP: A01 Broken Access Control

**9. Mixed content and SRI checks**
- Parse HTML for `http://` resources on HTTPS pages (mixed content)
- Check external `<script>` tags for missing `integrity` attribute (SRI)
- Why: Mixed content downgrades security; missing SRI enables supply chain attacks. ZAP rules 10040, 90003.
- Effort: Medium (HTML parsing)
- OWASP: A02 Cryptographic Failures, A08 Software and Data Integrity Failures

**10. Multi-version TLS probing**
- Attempt TLS connections at each version (1.0, 1.1, 1.2, 1.3) separately
- Why: Current implementation only checks negotiated version. Server may accept deprecated versions from other clients.
- Effort: Medium (4 separate TLS connections with restricted configs)
- OWASP: A02 Cryptographic Failures
- Source: testssl.sh `-p` protocol check

---

## Appendix A: Tool-Specific Insights

### nikto

- **Database-driven**: 6,400+ checks from CSV/text databases of known bad paths, default files, and version signatures
- **Tuning categories**: 0=Upload, 1=Interesting files, 2=Misconfig/Default, 3=Info Disclosure, 4=XSS, 5=File Retrieval (webroot), 6=DoS, 7=File Retrieval (server), 8=RCE, 9=SQLi, a=Auth Bypass, b=Software ID, c=Remote Include
- **Highest signal checks**: Missing security headers, default file detection, server version fingerprinting, dangerous HTTP methods
- **Output formats**: CSV, HTML, NBE (Nessus), SQL, TXT, XML, JSON
- **Key lesson for aiscan**: Even a small set of targeted path probes (top 20 sensitive files) provides enormous value vs. checking only the root URL

### nuclei (web templates)

- **Template structure**: YAML-based with `id`, `info` (name, author, severity, tags), `http` (method, path, matchers, extractors)
- **Repository**: 11,344 templates across 848 directories, 300+ contributors
- **Key web templates**: `http-missing-security-headers.yaml` checks 12 headers in one request
- **Matcher approach**: DSL-based regex matching on response headers/body with condition logic (AND/OR)
- **Key lesson for aiscan**: Structure findings by template ID for consistent reporting. Use matchers-condition logic to reduce false positives.

### OWASP ZAP Passive Scan Rules

- **50+ passive rules** running on every proxied response
- **Header rules**: Anti-clickjacking (10020), CSP not set (10038), CSP analysis (10055), HSTS (10035), X-Content-Type-Options (10021), Server header (10036), X-Powered-By (10037)
- **Cookie rules**: HttpOnly (10010), Secure flag (10011), SameSite (10054), Loosely scoped (90033), Cookie poisoning (10029)
- **Content rules**: Application errors (90022), Information disclosure in URL (10024), debug errors (10023), suspicious comments (10027), PII disclosure (10062), hash disclosure (10097)
- **Key lesson for aiscan**: ZAP's passive rules are the gold standard for header/cookie checks. Match their coverage for header and cookie analysis.

### testssl.sh

- **Comprehensive TLS testing**: Protocol versions, 370 cipher suites, forward secrecy, 15+ vulnerability checks, certificate chain validation, client simulation
- **Implementation**: Pure bash using `/dev/tcp` sockets -- does not depend on OpenSSL client capabilities
- **Key checks**: Protocol support enumeration, cipher strength categorization (NULL/EXPORT/LOW/MEDIUM/HIGH), forward secrecy, OCSP stapling, certificate transparency, known vulnerabilities (Heartbleed, POODLE, BEAST, SWEET32, FREAK, Logjam, DROWN, ROBOT)
- **Key lesson for aiscan**: For Go implementation, use `crypto/tls` with restricted configs per-check. Enumerate protocol support by attempting connections at each version. Categorize ciphers by strength.

### securityheaders.com Approach

- **Grading**: A+ to F based on presence of security headers
- **Scored headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Informational headers**: Server, X-Powered-By (penalize for presence)
- **Key lesson for aiscan**: Simple presence/absence scoring is valuable for quick assessment. Consider adding a per-layer score.

---

## Appendix B: Finding ID Allocation Plan

Current implementation uses WEB-001 through WEB-019. Proposed allocation for new checks:

| Range | Category |
|-------|----------|
| WEB-020 -- WEB-029 | Cross-Origin headers (COOP, COEP, CORP, CORS) |
| WEB-030 -- WEB-039 | Additional info-disclosure headers |
| WEB-040 -- WEB-049 | CSP value analysis |
| WEB-050 -- WEB-069 | Sensitive file exposure |
| WEB-070 -- WEB-079 | TLS cipher and certificate deep checks |
| WEB-080 -- WEB-089 | HTTP method checks |
| WEB-090 -- WEB-099 | Content analysis (mixed content, SRI, PII) |
| WEB-100 -- WEB-109 | Cookie advanced checks |
| WEB-110 -- WEB-119 | Redirect and transport checks |

---

## References

- OWASP Top 10 2021: https://owasp.org/Top10/2021/
- OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- ZAP Passive Scan Rules: https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/
- testssl.sh: https://github.com/testssl/testssl.sh
- nuclei-templates: https://github.com/projectdiscovery/nuclei-templates
- nuclei missing headers template: https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/http-missing-security-headers.yaml
- nikto: https://github.com/sullo/nikto
- SSL/TLS Deployment Best Practices: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
- OWASP Testing Guide - Weak TLS: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection
