package network

import (
	"fmt"
	"net"
	"time"

	"github.com/onoz1169/1scan/internal/scanner"
)

// udpProbe defines a UDP service probe.
type udpProbe struct {
	port      int
	service   string
	payload   []byte // bytes to send
	checkResp func(resp []byte) bool
	severity  scanner.Severity
	title     string
	desc      string
	ref       string
	remediation string
}

var udpProbes = []udpProbe{
	{
		port:    53,
		service: "DNS",
		// Minimal DNS query for "version.bind" TXT CH
		payload: []byte{
			0x00, 0x01, // transaction ID
			0x00, 0x00, // flags: standard query
			0x00, 0x01, // QDCOUNT=1
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT, ARCOUNT = 0
			// QNAME: version.bind
			0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
			0x04, 'b', 'i', 'n', 'd',
			0x00,       // end of QNAME
			0x00, 0x10, // QTYPE = TXT
			0x00, 0x03, // QCLASS = CH (Chaos)
		},
		checkResp:   func(r []byte) bool { return len(r) >= 12 },
		severity:    scanner.SeverityMedium,
		title:       "DNS service exposed",
		desc:        "A DNS server is responding on UDP port 53. Misconfigured DNS can enable zone transfers, cache poisoning, or serve as an amplification vector in DDoS attacks.",
		ref:         "CWE-284",
		remediation: "Restrict DNS to authoritative zones only. Disable recursion if not needed. Implement rate limiting and DNSSEC.",
	},
	{
		port:    161,
		service: "SNMP",
		// SNMP v1 GetRequest with community "public"
		payload: []byte{
			0x30, 0x26, // SEQUENCE (38 bytes)
			0x02, 0x01, 0x00, // INTEGER version=0 (SNMPv1)
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING "public"
			0xa0, 0x19, // GetRequest-PDU
			0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
			0x02, 0x01, 0x00, // error-status
			0x02, 0x01, 0x00, // error-index
			0x30, 0x0b, // VarBindList
			0x30, 0x09, // VarBind
			0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1
			0x05, 0x00, // NULL
		},
		checkResp:   func(r []byte) bool { return len(r) >= 10 && r[0] == 0x30 },
		severity:    scanner.SeverityHigh,
		title:       "SNMP service exposed with default community string",
		desc:        "SNMP is responding with the default 'public' community string. SNMPv1/v2 community strings are transmitted in plaintext and are widely exploited for device enumeration and configuration extraction.",
		ref:         "CWE-284",
		remediation: "Upgrade to SNMPv3 with authentication and encryption. Change default community strings. Restrict SNMP access to management networks.",
	},
	{
		port:    123,
		service: "NTP",
		// NTP client request (mode 3)
		payload: func() []byte {
			b := make([]byte, 48)
			b[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
			return b
		}(),
		checkResp:   func(r []byte) bool { return len(r) >= 48 && (r[0]>>3)&0x7 == 4 },
		severity:    scanner.SeverityMedium,
		title:       "NTP service exposed",
		desc:        "An NTP server is accessible. Unprotected NTP can be abused for monlist amplification attacks (DDoS) or time manipulation.",
		ref:         "CWE-284",
		remediation: "Restrict NTP access to trusted hosts. Disable monlist (noquery). Upgrade to NTPsec.",
	},
	{
		port:    69,
		service: "TFTP",
		// TFTP RRQ for 'test' in octet mode
		payload: []byte{
			0x00, 0x01, // opcode RRQ
			't', 'e', 's', 't', 0x00, // filename
			'o', 'c', 't', 'e', 't', 0x00, // mode
		},
		checkResp:   func(r []byte) bool { return len(r) >= 4 },
		severity:    scanner.SeverityHigh,
		title:       "TFTP service exposed",
		desc:        "TFTP (Trivial File Transfer Protocol) is accessible. TFTP has no authentication and can allow unauthenticated file read/write on the server.",
		ref:         "CWE-306",
		remediation: "Disable TFTP unless absolutely required. If needed, restrict access to specific IP ranges and monitor for unusual file requests.",
	},
}

// scanUDP probes well-known UDP services and returns findings.
func scanUDP(host string, timeout time.Duration, startIdx int) ([]scanner.Finding, []string) {
	var findings []scanner.Finding
	var errors []string
	findingNum := startIdx

	udpTimeout := timeout
	if udpTimeout < time.Second {
		udpTimeout = time.Second
	}

	for _, probe := range udpProbes {
		addr := fmt.Sprintf("%s:%d", host, probe.port)
		conn, err := net.DialTimeout("udp", addr, udpTimeout)
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(udpTimeout))
		if _, werr := conn.Write(probe.payload); werr != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 512)
		n, rerr := conn.Read(buf)
		conn.Close()

		if rerr != nil || n == 0 {
			continue // no response = likely filtered or closed
		}

		if probe.checkResp(buf[:n]) {
			findings = append(findings, scanner.Finding{
				ID:          fmt.Sprintf("NET-%03d", findingNum),
				Layer:       "network",
				Title:       probe.title,
				Description: probe.desc,
				Severity:    probe.severity,
				Reference:   probe.ref,
				Evidence:    fmt.Sprintf("UDP port %d/%s responded (%d bytes)", probe.port, probe.service, n),
				Remediation: probe.remediation,
			})
			findingNum++
		}
	}

	return findings, errors
}
