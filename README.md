# 1scan

**All-in-one security scanner: Network × Web App × LLM — one command, one report.**

```
1scan scan -t https://api.example.com
```

---

## Why all-in-one?

Modern AI-powered applications have three distinct attack surfaces that today's tools treat as separate problems:

| Attack surface | Typical tools | Problem |
|---------------|--------------|---------|
| Network (open ports, exposed services) | nmap, masscan | Standalone. No correlation with web/LLM results. |
| Web App (OWASP Top 10: headers, TLS, CORS) | nikto, ZAP, nuclei | Requires setup, config, separate reports. |
| LLM endpoints (OWASP LLM Top 10: prompt injection, data leakage) | garak, promptfoo | Python-only, no network/web context. |

**No single OSS tool covers all three.** Security teams run three separate scanners, get three separate reports, and miss the picture: a misconfigured CORS policy on the same server running an unprotected LLM endpoint is a critical chain, not two independent findings.

1scan runs all three layers in one command and produces one unified report.

```
1scan scan -t https://api.example.com

  [/] Scanning network layer...   [+] network: 4 findings
  [/] Scanning webapp layer...    [+] webapp: 7 findings
  [/] Scanning llm layer...       [+] llm: 2 findings

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    1scan — Security Scan Report
    Target: https://api.example.com
    Duration: 8.4s
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [NETWORK LAYER]
    ● Elasticsearch (9200) exposed — unauthenticated   CRITICAL
    ● Redis (6379) exposed                             HIGH

  [WEBAPP LAYER]
    ● Missing HSTS header                              HIGH
    ● CORS reflects arbitrary origin with credentials  CRITICAL

  [LLM LAYER]
    ● Prompt Injection (role-manipulation) detected    HIGH
    ● System Prompt Leakage                            HIGH

  SUMMARY
  CRITICAL: 2  HIGH: 4  MEDIUM: 1  LOW: 0  INFO: 2
```

---

## Installation

**From source (requires Go 1.21+):**

```bash
git clone https://github.com/onoz1169/1scan
cd 1scan
go build -o 1scan .
./1scan --version
```

**Go install:**

```bash
go install github.com/onoz1169/1scan@latest
```

---

## Usage

### Basic scan (all three layers)

```bash
1scan scan -t https://example.com
```

### Specific layers only

```bash
# Network only
1scan scan -t example.com -l network

# Web app + LLM (skip network)
1scan scan -t https://api.example.com -l webapp,llm

# LLM endpoint only (Ollama, OpenAI-compatible, Anthropic, HF TGI)
1scan scan -t http://localhost:11434 -l llm
```

### Output formats

```bash
# JSON report
1scan scan -t https://example.com -F json -o report.json

# Markdown report
1scan scan -t https://example.com -F markdown -o report.md

# SARIF (for GitHub Code Scanning)
1scan scan -t https://example.com -F sarif -o results.sarif

# HTML report (self-contained, shareable)
1scan scan -t https://example.com -F html -o report.html
```

### CI/CD usage

```bash
# Fail build if any HIGH or CRITICAL finding (default)
1scan scan -t https://staging.example.com --fail-on high

# Fail only on CRITICAL
1scan scan -t https://staging.example.com --fail-on critical

# Report mode: never fail, just output
1scan scan -t https://staging.example.com --fail-on none -F sarif -o results.sarif
```

### GitHub Actions

```yaml
- name: Run 1scan
  run: |
    go install github.com/onoz1169/1scan@latest
    1scan scan -t ${{ env.TARGET_URL }} -F sarif -o 1scan-results.sarif --fail-on none

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 1scan-results.sarif
    category: 1scan
```

---

## What each layer checks

### Layer 1: Network

Scans the top 100 most common TCP ports (based on nmap frequency data) and flags risky exposures.

| Check | Severity |
|-------|----------|
| Elasticsearch (9200) exposed without auth | CRITICAL |
| Telnet (23) open — plaintext credentials | CRITICAL |
| .env / actuator endpoints responding 200 | CRITICAL |
| FTP (21), SMB (445), Redis (6379), MongoDB (27017) exposed | HIGH |
| VNC (5900), NFS (2049), rsync (873), RabbitMQ (5672) exposed | HIGH |
| RDP (3389), MySQL (3306) publicly reachable | MEDIUM |
| HTTPS port (443/8443) serving plaintext | HIGH |
| Service-port mismatch (e.g., SSH on port 80) | MEDIUM |
| HTTP server headers revealing software version | INFO |

### Layer 2: Web App (OWASP Top 10 2021)

| Check | OWASP | Severity |
|-------|-------|----------|
| CORS reflects arbitrary origin + credentials | A05 | CRITICAL |
| Wildcard CORS with credentials | A05 | CRITICAL |
| Missing HSTS on HTTPS | A05 | HIGH |
| CSP `unsafe-inline` or `unsafe-eval` | A05 | HIGH |
| Missing X-Frame-Options (clickjacking) | A05 | MEDIUM |
| TRACE method enabled | A05 | MEDIUM |
| HTTP does not redirect to HTTPS | A02 | MEDIUM |
| Expired or self-signed TLS certificate | A02 | CRITICAL / MEDIUM |
| TLS 1.0 or 1.1 in use | A02 | HIGH |
| Cookie without Secure / HttpOnly / SameSite | A02 | MEDIUM / LOW |
| Stack trace in response body | A05 | HIGH |
| Directory listing enabled | A05 | HIGH |
| `.git/`, `.env`, `/actuator/env`, `/swagger.json` accessible | A05/A01 | CRITICAL–INFO |
| Server / X-Powered-By version disclosure | A05 | LOW |

**Sensitive path discovery (25 paths, parallel):**
`.git/HEAD`, `.git/config`, `.env`, `.env.local`, `.env.production`, `backup.zip`,
`backup.tar.gz`, `admin/`, `phpinfo.php`, `server-status`, `api/docs`, `swagger.json`,
`swagger-ui.html`, `actuator`, `actuator/env`, `debug`, `config.json`, `.DS_Store`,
`wp-admin/`, `wp-login.php`, and more.

### Layer 3: LLM (OWASP LLM Top 10 2025)

Detects LLM API endpoints automatically (OpenAI-compatible, Ollama, Anthropic, HF TGI) then runs 30+ probes.

| OWASP ID | Check | Severity |
|----------|-------|----------|
| LLM01 | Prompt Injection — instruction override, DAN/role manipulation, base64/ROT13 encoding bypass, delimiter manipulation, token injection | HIGH |
| LLM02 | Sensitive Information Disclosure — credentials, API keys, env vars, DB connection strings | CRITICAL |
| LLM05 | Improper Output Handling — XSS, SQL injection, shell commands, SSTI in LLM output | HIGH |
| LLM06 | Excessive Agency — tool/function disclosure, capability enumeration | MEDIUM |
| LLM07 | System Prompt Leakage — extraction probes, instruction pattern detection | HIGH |
| LLM09 | Overreliance — model claims infallibility | MEDIUM |
| LLM10 | Unbounded Consumption — no rate limiting on rapid-fire requests, large context accepted without restriction | HIGH / MEDIUM |

**Endpoint auto-detection:**
- OpenAI-compatible (`/v1/chat/completions`) — with model auto-discovery via `/v1/models`
- Ollama (`/api/chat`) — with model auto-discovery via `/api/tags`
- Anthropic (`/v1/messages`)
- Hugging Face TGI (`/generate`)
- Generic JSON POST endpoints

**Response analysis:**
Multi-signal heuristics for each probe: compliance phrase detection, instruction-pattern matching, response length anomaly, credential regex patterns. Confidence scoring: HIGH / MEDIUM / LOW.

---

## All flags

```
1scan scan [flags]

  -t, --target string     Target URL or hostname (required)
  -l, --layers strings    Layers to run: network, webapp, llm (default: all three)
  -F, --format string     Output format: terminal, json, markdown, sarif, html (default: terminal)
  -o, --output string     Output file path (auto-named if empty)
      --fail-on string    Exit 1 if findings at or above: critical, high, medium, low, none (default: high)
  -s, --severity string   Only display findings at or above: critical, high, medium, low, info
  -q, --quiet             Suppress banner and progress output (stdout only)
      --no-color          Disable ANSI colors
      --timeout int       Timeout per scan in seconds (default: 10)
  -v, --verbose           Verbose output
      --cve-lookup        Enrich nmap findings with NVD CVE data
      --nvd-api-key string NVD API key for CVE lookups (or set NVD_API_KEY env var)
      --config string     Path to YAML config file (CLI flags override config)
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no findings above `--fail-on` threshold |
| 1 | Findings found at or above `--fail-on` severity |
| 2 | Usage error (invalid flags) |

---

## Philosophy

1scan is built on a simple belief: **security knowledge should not require a security team.**

Most developers don't know to run a port scanner, a web scanner, and an LLM red-teaming framework separately — and stitch the results together manually. 1scan is the tool that does all of it in one command, designed to be run by anyone who can type a URL.

The tool is also a response to the AI ecosystem's security blind spot. As LLM APIs become infrastructure — embedded in APIs, CI pipelines, and internal tools — the attack surface grows invisibly. 1scan treats LLM endpoints as first-class infrastructure to be scanned, not as a special case.

Built by a security engineer who spent years breaking into systems, and now builds tools designed to survive it.

---

## Roadmap

- [x] HTML report output
- [x] Intelligence layer: CVE feed ingestion for latest vulnerability probes
- [x] UDP scanning (DNS, SNMP, NTP, TFTP)
- [x] Rate limiting / LLM10 unbounded consumption probes
- [x] `--config` file support for custom targets and payload sets
- [ ] aiwatch: companion defensive monitoring tool

---

## License

MIT
