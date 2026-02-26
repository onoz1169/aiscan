# aiscan Architecture: Standing on Giants

**Decision document for integrating existing OSS tools into aiscan.**

Date: 2026-02-26

---

## Executive Summary

aiscan's current implementation builds everything from scratch in pure Go. The right approach is:

- **Keep pure Go as the primary engine** (zero-dependency single binary, works everywhere)
- **Add optional external tools as enrichment** (nmap, nuclei) when installed
- **Embed curated payloads** from garak/promptfoo as Go-native data (no Python required)

This preserves the "one command, zero setup" value proposition while unlocking deep analysis for users who have the tools installed.

---

## Layer-by-Layer Architecture

### Layer 1: Network

**Current**: Pure-Go TCP connect scan, 100 ports, 13 service fingerprints.
**Gap**: nmap has 2,500+ service probes, OS detection, NSE vulnerability scripts.

**Architecture: Two-phase hybrid**

```
Phase 1 (always): Pure-Go concurrent TCP connect scan
  → Fast, ~3–5s, finds open ports
  → Uses existing riskyPorts severity map

Phase 2 (optional): nmap enrichment on discovered open ports
  → Runs only if nmap is installed (auto-detected via exec.LookPath)
  → One nmap invocation: nmap -Pn -sV -sC -T4 -p <open-ports> -oX - <target>
  → NSE scripts: ssl-enum-ciphers, vulners, http-enum, smb-vuln-ms17-010, ssh-auth-methods
  → Adds: exact service version, CPE, CVE matches, OS detection
```

**Go library**: `github.com/Ullaakut/nmap/v4` (latest: Jan 2026)
- Wraps nmap subprocess with typed Go structs (Host, Port, Service, Script)
- Parses XML output via Go's encoding/xml
- Minimal dependencies (wraps subprocess, no heavy deps)

**Pure-Go fallback upgrade**: Consider replacing current TCP connect scanner with `github.com/projectdiscovery/naabu` — a production-grade pure-Go port scanner from projectdiscovery. Better concurrency, retries, and SYN scan support vs our current implementation. (Optional: current scanner works fine for top-100 ports use case.)

**nmap file import**: Support `--nmap-xml <file>` to import pre-existing nmap XML output (Metasploit pattern). Useful for environments where nmap must be run separately with elevated privileges.

**New files**:
```
internal/scanner/network/nmap.go       # NmapEnricher struct + Enrich()
internal/toolcheck/toolcheck.go        # exec.LookPath detection utilities
```

**CLI flags to add**:
```
--nmap          Enable nmap enrichment (default: auto when installed)
--no-nmap       Disable nmap even if installed
--nmap-path     Path to nmap binary (override PATH)
--nmap-flags    Additional nmap flags (e.g., "--script vuln")
```

**UX behavior**:

| Condition | Behavior |
|-----------|----------|
| nmap installed, no flags | Auto-enrich, no message |
| nmap installed, `--no-nmap` | Pure-Go only, no message |
| nmap NOT installed | Pure-Go only, info: "Install nmap for deeper service detection" |
| nmap NOT installed, `--nmap` | Error: "nmap not found; install it or remove --nmap flag" |

---

### Layer 2: WebApp

**Current**: Pure-Go OWASP Top 10 checks (headers, TLS, CORS, cookies, 25 sensitive paths).
**Gap**: nuclei has 10,000+ community templates; new CVE templates added daily.

**Architecture: Pure Go baseline + optional nuclei subprocess**

```
Always runs (pure Go):
  → Security headers (CSP, HSTS, X-Frame-Options, etc.)
  → TLS version + certificate checks
  → CORS misconfiguration
  → Cookie security flags
  → Stack trace detection
  → Sensitive path discovery (25 curated paths)
  → TRACE method check
  → HTTP→HTTPS redirect check

Optional (nuclei subprocess if installed):
  → nuclei -target <url> -severity medium,high,critical -j
  → Parse JSONL output, map to Finding{}
  → Adds: CVE-specific checks, WAF bypass, CMS vulnerabilities
```

**nuclei SDK decision: DO NOT use the Go library directly.**

The `github.com/projectdiscovery/nuclei/v3/lib` SDK has:
- 111 direct dependencies + 300+ transitive dependencies
- Includes Azure SDK, AWS SDK, Docker client, MongoDB driver
- Binary size impact: +50–100MB
- Frequent breaking changes, no stable releases

Shell-out to nuclei subprocess is the right approach. Lightweight integration, no binary bloat.

**nuclei output parsing**: nuclei outputs JSONL with fields `templateID`, `info.severity`, `matched-at`, `matcher-name`. Map to `Finding{ID: templateID, Title: info.name, Severity: ...}`.

**nikto**: Not recommended. Perl-based, unreliable JSON output (malformed edge cases), poor Go integration story. nuclei covers the same ground with better tooling.

**New files**:
```
internal/scanner/webapp/nuclei.go      # NucleiEnricher struct + Enrich()
```

**CLI flags to add**:
```
--nuclei           Enable nuclei scan (default: auto when installed)
--no-nuclei        Disable nuclei
--nuclei-templates Comma-separated template categories (default: "cves,misconfiguration")
```

---

### Layer 3: LLM

**Current**: ~30 hardcoded probes in Go, 6 OWASP LLM Top 10 categories.
**Gap**: garak has 1,000+ probes; promptfoo has extensive redteam templates.

**Architecture: Embedded payload library (no Python required)**

Shell-out to garak/promptfoo is NOT recommended:
- garak requires Python 3.11+, multiple model APIs configured
- promptfoo requires Node.js
- Both are heavy, opinionated frameworks designed for different use cases
- Our value: LLM testing as part of network+web context, not standalone

**Right approach: Embed curated garak/promptfoo payloads as Go-native YAML/JSON.**

garak's probe files are MIT-licensed Python with string payloads. Extract the payloads, embed as YAML in the Go binary.

**Payload expansion plan** (from garak + research-llm.md):

garak's payload files are **pure JSON, static, trivially embeddable**:
- `garak/data/payloads/` — 17 JSON files (harmful_behaviors, sql_injection, encoded, xss, etc.)
- `garak/data/dan/` — 14 JSON files (DAN 6.0–11.0, STAN, DUDE, AntiDAN, etc.)

Format:
```json
{
  "garak_payload_name": "category_name",
  "payload_types": ["text"],
  "payloads": ["string1", "string2", ...],
  "lang": "en"
}
```

promptfoo payloads are **NOT static** — they are LLM-generated at runtime via cloud API. Do NOT extract from promptfoo. However, promptfoo's encoding strategy algorithms (base64, ROT13, leetspeak, homoglyph) are worth reimplementing in Go — trivial functions.

```
internal/scanner/llm/payloads/
  embed.go                   # //go:embed payloads/*.json
  payloads/
    prompt_injection.json    # LLM01: from garak + research (50+ payloads)
    jailbreak_dan.json       # LLM01: from garak/data/dan/ (DAN variants)
    harmful_behaviors.json   # LLM01: from garak/data/payloads/
    encoding_bypass.json     # LLM01: base64, ROT13, leetspeak (reimplemented from promptfoo)
    system_prompt_leak.json  # LLM07: extraction probes
    data_exfiltration.json   # LLM02: credential/PII patterns
    output_handling.json     # LLM05: XSS, SQLi, shell injection
```

Use Go `//go:embed` via `embed.FS`. Zero runtime dependencies.

**Top 10 most effective payload categories** (by Attack Success Rate, from arxiv research):
1. Roleplay/Persona Hijack (DAN) — 89.6% ASR
2. Logic Trap — 81.4%
3. Encoding Bypass (base64, ROT13) — 76.2%
4. Multi-Turn Grooming — 68.7%
5. System Prompt Extraction — ~65%
6. Indirect Injection (RAG) — ~60%
7. Token Smuggling / Adversarial Suffixes — ~55%
8. Instruction Override — ~50%
9. Output Format Manipulation — ~45%
10. Multimodal Injection — ~40%

**garak license**: Apache 2.0 — compatible with MIT aiscan. Add `THIRD_PARTY_LICENSES` file crediting NVIDIA/garak.
**promptfoo license**: MIT — fully compatible.

**Response analysis improvement**: Upgrade from keyword matching to regex + confidence scoring system (already partially done in llm.go `analyzeResponse()`).

**New/modified files**:
```
internal/scanner/llm/payloads/          # Embedded YAML payload library
internal/scanner/llm/llm.go             # Load payloads via go:embed
```

---

## Orchestration Pattern

**Single toolcheck package** handles all external tool detection:

```go
// internal/toolcheck/toolcheck.go

type Tool struct {
    Name    string
    MinVer  string
    Install string // install hint
}

var knownTools = map[string]Tool{
    "nmap":   {Name: "nmap", Install: "brew install nmap / apt install nmap"},
    "nuclei": {Name: "nuclei", Install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
}

func Available(name string) (path string, ok bool)
func Version(path string) string
func PrintAvailability(tools []string)  // for --version or --tools flag
```

**New flag**: `--show-tools` prints which optional tools are detected:

```
aiscan --show-tools

  Optional tools:
    [✓] nmap 7.94          (/usr/bin/nmap)
    [✗] nuclei             (not installed — run: go install github.com/projectdiscovery/nuclei/v3/...)
```

---

## Implementation Priority

| Priority | Change | Effort | Impact |
|----------|--------|--------|--------|
| 1 | nmap integration (network layer) | Medium | HIGH — 2,500 probes vs 13 |
| 2 | LLM payload YAML embedding | Low | MEDIUM — 30 → 100+ probes |
| 3 | nuclei integration (webapp layer) | Medium | MEDIUM — CVE template coverage |
| 4 | `--show-tools` flag | Low | LOW — UX improvement |

---

## Single Binary Distribution

aiscan remains a single Go binary with zero required dependencies.

```
go install github.com/onoz1169/aiscan@latest
aiscan scan -t https://example.com    # works immediately, pure-Go mode
```

Optional tool install instructions appear only when:
1. User explicitly adds `--nmap` / `--nuclei` flag without tool installed
2. `--show-tools` flag is used
3. Scan completes and optional tools were not available (one-line info message at report footer)

---

## Go Module Changes

Add one new dependency:

```
github.com/Ullaakut/nmap/v4     # nmap integration (lightweight subprocess wrapper)
```

nuclei is subprocess only (no Go import). garak payloads are YAML data (no import). Total new binary size increase: ~minimal (Ullaakut/nmap is a thin wrapper).

---

## What We Do NOT Do

- **Do NOT import nuclei/v3/lib** — 300+ transitive deps, 50-100MB binary bloat, unstable API
- **Do NOT shell out to garak** — requires Python 3.11+, too heavy for Go CLI integration
- **Do NOT shell out to nikto** — Perl-based, unreliable JSON, nuclei covers the same space
- **Do NOT make nmap required** — breaks single-binary value proposition and CI/CD environments
- **Do NOT add masscan** — our pure-Go scanner already covers the use case adequately

---

## Sources

- arch-nmap.md (agent-nmap research, 2026-02-26)
- agent-web-arch findings: nuclei SDK analysis, nikto JSON reliability
- research-llm.md: OWASP LLM Top 10 2025, payload library (A-F categories)
- garak license: https://github.com/leondz/garak (Apache 2.0)
- nuclei SDK deps: https://github.com/projectdiscovery/nuclei
- Ullaakut/nmap: https://github.com/Ullaakut/nmap
