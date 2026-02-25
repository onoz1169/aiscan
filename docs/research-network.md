# Network Scanner Research Report

Research on OSS network security scanners to inform aiscan's network layer improvements.

## 1. Tools Analyzed

### naabu (projectdiscovery/naabu)
- Go port scanner, 8K+ stars
- Supports SYN scan (raw sockets, half-open), CONNECT scan (full TCP handshake), and UDP scan
- SYN scan: sends TCP SYN, reads SYN-ACK without completing handshake. Requires root/libpcap. Default 1000 PPS rate limit.
- CONNECT scan: standard `net.Dial`, no privileges needed. Default 1500 PPS. Fallback when SYN unavailable.
- Concurrency: sized wait group with configurable worker count (default 25 via `-c` flag)
- Rate limiting: packets-per-second control via `-rate` flag
- Retries: configurable (default 3) via `-retries` flag
- Timeouts: 1s for SYN, 3s for CONNECT, adjustable via `-timeout`
- Warm-up time (2s default) between scan phases
- Stream mode (`-stream`) disables features for maximum speed

### RustScan
- Rust port scanner, scans all 65535 ports in ~3 seconds
- Uses async I/O (tokio runtime) with `FuturesUnordered` for concurrent task management
- Batch scanning: default 4500 ports per batch, auto-adjusted based on system ulimit
- Adaptive learning: auto-detects system file descriptor limits and adjusts batch size
- Pipeline architecture: fast port discovery -> feed open ports to nmap for deep analysis
- Key insight: separate "fast scan" from "deep analysis" into two distinct phases

### nmap
- Gold standard for network scanning
- Service detection via nmap-service-probes database (~6500 patterns for 650+ protocols)
- Version detection technique:
  1. NULL probe: connect, send nothing, wait ~5s for banner (FTP, SSH, SMTP, Telnet, POP3, IMAP self-identify)
  2. Targeted probes: send protocol-specific data, match response against regex signatures
  3. Soft matches: narrow future probes to related service family
  4. Fallback: re-check NULL probe signatures if specific probes fail
- Probe rarity ratings (1-9), default intensity 7
- NSE (Nmap Scripting Engine): Lua scripts in categories (default, safe, auth, brute, vuln, discovery, version)
- Top port selection based on empirical frequency data from large-scale internet scans

### nuclei (network templates)
- YAML-based vulnerability detection templates
- ~257 network protocol templates for TCP/UDP services
- Template structure: id, info (name/severity/tags), network inputs (hex or plaintext), host/port, read-size, matchers, extractors
- Matchers: word, regex, binary (hex), DSL (complex logic), combinable with AND/OR
- Extractors: pull version numbers, service identifiers from responses
- Example: MongoDB detection sends hex-encoded isMaster command, matches on "logicalSessionTimeout"
- Example: Memcached detection sends plaintext "stats\r\nquit\r\n", matches on "STAT "

## 2. Key Techniques to Adopt

### 2.1 Two-Phase Scanning (from RustScan)
Separate port discovery from service analysis:
- Phase 1: Fast connect scan across all target ports (high concurrency)
- Phase 2: Banner grab and service fingerprint only on open ports

This avoids wasting time on banner grabs for closed ports.

### 2.2 Active Service Probing (from nmap)
Current aiscan only does passive banner grab (read after connect). Should add:
- NULL probe: wait for voluntary banner (already implemented, but limited)
- Protocol-specific probes: send trigger data to elicit responses
  - HTTP: `GET / HTTP/1.0\r\n\r\n`
  - SSH: wait for banner (passive)
  - FTP: wait for 220 banner (passive)
  - SMTP: wait for 220 banner, then `EHLO test\r\n`
  - MySQL: wait for server greeting packet
  - Redis: `PING\r\n` -> expect `+PONG`
  - MongoDB: isMaster command (binary)

### 2.3 Service Fingerprint Matching (from nmap)
Build a probe-response signature database:
```go
type ServiceProbe struct {
    Name     string         // e.g., "SSH"
    Port     int            // default port
    Probe    []byte         // data to send (nil = NULL probe / passive)
    Timeout  time.Duration
    Matchers []SignatureMatcher
}

type SignatureMatcher struct {
    Pattern *regexp.Regexp  // regex to match response
    Service string          // identified service name
    Version string          // version extraction group
}
```

### 2.4 Concurrency Control (from naabu)
Replace simple `sync.WaitGroup` with:
- Sized semaphore limiting concurrent goroutines
- Rate limiter (tokens per second) to avoid overwhelming target
- Configurable retry count per port

### 2.5 Configurable Timeouts (from naabu)
Current per-port timeout is derived from total timeout. Should instead use:
- Per-port connect timeout (default 3s for connect scan)
- Per-port read timeout for banner grab (default 2s)
- Total scan timeout as hard ceiling

## 3. Port List Best Practices

### Current aiscan: 17 ports
Missing many commonly-open and security-relevant ports.

### Recommended: Top 50 Security-Relevant Ports
Based on nmap frequency data and security relevance:

```
# Remote Access & Shell
22    SSH
23    Telnet
3389  RDP
5900  VNC
5985  WinRM-HTTP
5986  WinRM-HTTPS

# Web
80    HTTP
443   HTTPS
8080  HTTP-alt
8443  HTTPS-alt
8000  HTTP-alt
8888  HTTP-alt
9090  HTTP-proxy/management

# Email
25    SMTP
465   SMTPS
587   SMTP-submission
110   POP3
995   POP3S
143   IMAP
993   IMAPS

# File Transfer
21    FTP
69    TFTP (UDP)
445   SMB
139   NetBIOS
2049  NFS

# DNS
53    DNS

# Databases
3306  MySQL
5432  PostgreSQL
1433  MSSQL
1521  Oracle
6379  Redis
27017 MongoDB
9200  Elasticsearch
5984  CouchDB
11211 Memcached

# Message Queues & Caches
5672  RabbitMQ
6380  Redis-alt
9092  Kafka

# DevOps & Management
2375  Docker API (unencrypted)
2376  Docker API (TLS)
5601  Kibana
8500  Consul
8200  Vault
9100  Node Exporter
10250 Kubelet API
6443  Kubernetes API

# LDAP
389   LDAP
636   LDAPS

# Other Risky
161   SNMP (UDP)
111   RPCbind
502   Modbus
1883  MQTT
```

This covers ~50 ports. For a security scanner, these are higher value than nmap's top-100 which includes many legacy/rare services.

## 4. Service Fingerprinting: How to Identify Service from Banner

### Passive Signatures (banner patterns)
Services that self-identify on connect:

| Service | Banner Pattern | Example |
|---------|---------------|---------|
| SSH | `^SSH-` | `SSH-2.0-OpenSSH_8.9p1` |
| FTP | `^220[ -]` | `220 ProFTPD Server` |
| SMTP | `^220[ -].*SMTP\|ESMTP` | `220 mail.example.com ESMTP` |
| POP3 | `^\+OK` | `+OK Dovecot ready` |
| IMAP | `^\* OK` | `* OK [CAPABILITY IMAP4rev1]` |
| MySQL | `\x00.*mysql\|MariaDB` | binary greeting with version |
| Redis | `^-ERR\|-DENIED\|$` (after PING: `+PONG`) | `-ERR unknown command` |
| MongoDB | `logicalSessionTimeout` | binary response to isMaster |
| HTTP | `^HTTP/` (after GET probe) | `HTTP/1.1 200 OK` |
| RDP | binary: `\x03\x00` (after RDP negotiation) | RDP negotiation response |
| Telnet | `^\xff[\xfb-\xfe]` (IAC negotiation bytes) | Telnet option negotiation |

### Active Probes (send data, read response)
For services that don't self-identify:

| Service | Probe | Expected Response |
|---------|-------|-------------------|
| HTTP | `GET / HTTP/1.0\r\nHost: target\r\n\r\n` | `HTTP/1.x ...` |
| Redis | `PING\r\n` | `+PONG\r\n` |
| Memcached | `stats\r\nquit\r\n` | `STAT ...` |
| Elasticsearch | `GET / HTTP/1.0\r\n\r\n` | JSON with `"cluster_name"` |
| Docker API | `GET /version HTTP/1.0\r\n\r\n` | JSON with `"ApiVersion"` |
| MQTT | binary connect packet | CONNACK response |

### Implementation Approach
```go
func identifyService(port int, banner string) string {
    // 1. Check passive signatures against banner
    for _, sig := range passiveSignatures {
        if sig.Pattern.MatchString(banner) {
            return sig.Service
        }
    }
    // 2. Fall back to port-based guess
    if svc, ok := portServiceMap[port]; ok {
        return svc + " (unconfirmed)"
    }
    return "unknown"
}
```

## 5. What Our Current Implementation Is Missing

| Gap | Current State | What OSS Tools Do |
|-----|--------------|-------------------|
| Port coverage | 17 hardcoded ports | nmap: 1000 by default; naabu: configurable top-N or all 65535 |
| Scan technique | CONNECT only | naabu: SYN + CONNECT + UDP; rustscan: async batch connect |
| Service identification | Port-number guess only | nmap: 6500+ regex signatures; nuclei: protocol-specific probes |
| Banner analysis | Passive read, no probing | nmap: NULL probe + active probes; nuclei: hex/text protocol requests |
| Concurrency control | WaitGroup (all at once) | naabu: sized semaphore + rate limiter; rustscan: batch with ulimit-aware sizing |
| Retry logic | None | naabu: 3 retries default |
| Version extraction | None | nmap: regex capture groups from banners |
| Configuration | No user control | All tools: timeout, ports, concurrency, rate configurable via flags |
| UDP scanning | None | naabu: UDP scan support |
| Output detail | Basic open/closed | nmap: service name, version, OS; nuclei: structured findings with CVE refs |
| TLS inspection | None | nmap/nuclei: TLS version, cipher suites, certificate info |

## 6. Top 5 Improvements to Implement (Prioritized)

### Priority 1: Expand Port List and Make It Configurable
- Expand default to ~50 security-relevant ports (see Section 3)
- Add `--ports` flag for custom port specification (e.g., `--ports 80,443,8080` or `--ports 1-1024`)
- Add `--top-ports N` for common presets (top-20, top-50, top-100)
- Effort: Low. Impact: High. Currently missing 70%+ of security-relevant ports.

### Priority 2: Active Service Probing and Fingerprinting
- Implement probe-response engine with signature database
- Start with 10-15 most common services (SSH, HTTP, FTP, SMTP, MySQL, PostgreSQL, Redis, MongoDB, SMTP, RDP, Elasticsearch)
- Use nmap's NULL-probe-first approach: wait for banner, then send probe if no match
- Report actual service name + version instead of port-number guess
- Effort: Medium. Impact: High. This is the difference between "port 8080 is open" and "Apache Tomcat 9.0.65 on port 8080."

### Priority 3: Concurrency and Rate Control
- Replace bare WaitGroup with semaphore-based concurrency (e.g., `golang.org/x/sync/semaphore` or channel-based)
- Add rate limiter to prevent overwhelming target or triggering IDS
- Implement configurable retry (default 2-3 attempts per port)
- Add per-port timeout independent of total scan timeout
- Effort: Medium. Impact: Medium. Improves reliability and prevents false negatives from dropped connections.

### Priority 4: TLS Inspection
- For ports that respond, attempt TLS handshake to detect:
  - TLS version (flag TLS 1.0/1.1 as insecure)
  - Certificate validity (expiry, self-signed, wrong hostname)
  - Cipher suite strength (flag weak ciphers)
- Use Go's `crypto/tls` with custom `tls.Config` to extract handshake details
- This is a major finding category -- expired certs and weak TLS are common audit findings
- Effort: Medium. Impact: High.

### Priority 5: Add Risky Service Detections
- Expand riskyPorts map with more dangerous exposed services:
  - Docker API (2375): unauthenticated = full host compromise
  - Kubernetes API (6443/10250): exposed = cluster compromise
  - Elasticsearch (9200): often no auth, data exfil risk
  - Memcached (11211): amplification attacks, data exposure
  - MQTT (1883): IoT command injection
  - VNC (5900): often weak/no auth
  - SNMP (161): community string exposure
- Each with severity, CWE reference, and remediation
- Effort: Low. Impact: Medium. Purely additive to existing riskyPorts pattern.

## 7. Reference Architecture

```
Target
  |
  v
[Port Discovery] -- concurrent CONNECT scan, ~50 ports, rate-limited
  |
  v
[Open Ports List]
  |
  v
[Service Identification] -- NULL probe (passive) -> active probe -> regex match
  |
  v
[TLS Inspection] -- for TLS-capable ports
  |
  v
[Risk Assessment] -- map service+version to known risks
  |
  v
[Findings Report] -- structured findings with severity, evidence, remediation
```

## Sources

- naabu: https://github.com/projectdiscovery/naabu
- naabu scan types: https://deepwiki.com/projectdiscovery/naabu/6.1-scan-types
- RustScan: https://github.com/bee-san/RustScan
- RustScan architecture: https://deepwiki.com/bee-san/RustScan/1-overview
- nmap service detection: https://nmap.org/book/man-version-detection.html
- nmap version scan technique: https://nmap.org/book/vscan-technique.html
- nmap port selection: https://nmap.org/book/performance-port-selection.html
- nmap NSE scripts: https://nmap.org/nsedoc/scripts/
- nuclei templates: https://github.com/projectdiscovery/nuclei-templates
- nuclei network templates guide: https://projectdiscovery.io/blog/writing-network-templates-with-nuclei
- nuclei template structure: https://deepwiki.com/projectdiscovery/nuclei-templates/2.1-template-structure
