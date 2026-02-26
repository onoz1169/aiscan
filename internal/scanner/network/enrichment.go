package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/onoz1169/1scan/internal/abuseipdb"
	"github.com/onoz1169/1scan/internal/scanner"
	"github.com/onoz1169/1scan/internal/shodan"
)

// resolveIP resolves a hostname to its first IP address.
// Returns the input unchanged if it is already a valid IP.
func resolveIP(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

// enrichShodan queries Shodan InternetDB for external perspective data on the given IP.
func enrichShodan(ip string, startIdx int) ([]scanner.Finding, []string) {
	result, err := shodan.QueryInternetDB(ip)
	if err != nil {
		return nil, []string{fmt.Sprintf("shodan internetdb: %v", err)}
	}
	if result == nil {
		return nil, nil // IP not in Shodan database
	}

	var findings []scanner.Finding
	findingNum := startIdx

	if len(result.Vulns) > 0 {
		cveList := strings.Join(result.Vulns, ", ")
		findings = append(findings, scanner.Finding{
			ID:          fmt.Sprintf("NET-%03d", findingNum),
			Layer:       "network",
			Title:       fmt.Sprintf("Shodan: %d known CVE(s) associated with %s", len(result.Vulns), ip),
			Description: fmt.Sprintf("Shodan InternetDB reports CVEs associated with this IP: %s", cveList),
			Severity:    scanner.SeverityHigh,
			Reference:   "https://internetdb.shodan.io/" + ip,
			Evidence:    fmt.Sprintf("IP: %s | CVEs: %s | CPEs: %s", ip, cveList, strings.Join(result.CPEs, ", ")),
			Remediation: "Review and patch the reported CVEs. Update software to the latest versions.",
		})
		findingNum++
	}

	if len(result.Ports) > 0 {
		portStrs := make([]string, len(result.Ports))
		for i, p := range result.Ports {
			portStrs[i] = fmt.Sprintf("%d", p)
		}
		evidence := fmt.Sprintf("External ports: %s", strings.Join(portStrs, ", "))
		if len(result.Hostnames) > 0 {
			evidence += fmt.Sprintf(" | Hostnames: %s", strings.Join(result.Hostnames, ", "))
		}
		if len(result.Tags) > 0 {
			evidence += fmt.Sprintf(" | Tags: %s", strings.Join(result.Tags, ", "))
		}
		findings = append(findings, scanner.Finding{
			ID:          fmt.Sprintf("NET-%03d", findingNum),
			Layer:       "network",
			Title:       fmt.Sprintf("Shodan: %d port(s) externally visible on %s", len(result.Ports), ip),
			Description: fmt.Sprintf("Shodan reports the following ports as externally visible: %s. This is the attacker's view of the target.", strings.Join(portStrs, ", ")),
			Severity:    scanner.SeverityInfo,
			Reference:   "https://internetdb.shodan.io/" + ip,
			Evidence:    evidence,
			Remediation: "Close unnecessary ports and restrict access via firewall rules.",
		})
	}

	return findings, nil
}

// enrichAbuseIPDB queries AbuseIPDB for IP reputation data.
func enrichAbuseIPDB(client *abuseipdb.Client, ip string, startIdx int) ([]scanner.Finding, []string) {
	check, err := client.Check(ip, 90)
	if err != nil {
		return nil, []string{fmt.Sprintf("abuseipdb: %v", err)}
	}
	if check == nil || (check.AbuseConfidenceScore == 0 && check.TotalReports == 0) {
		return nil, nil // clean IP
	}

	sev := scanner.SeverityLow
	switch {
	case check.AbuseConfidenceScore >= 75:
		sev = scanner.SeverityCritical
	case check.AbuseConfidenceScore >= 50:
		sev = scanner.SeverityHigh
	case check.AbuseConfidenceScore >= 25:
		sev = scanner.SeverityMedium
	}

	evidence := fmt.Sprintf("IP: %s | Confidence: %d%% | Reports: %d from %d users | ISP: %s | Country: %s",
		ip, check.AbuseConfidenceScore, check.TotalReports, check.NumDistinctUsers, check.ISP, check.CountryCode)
	if check.LastReportedAt != "" {
		evidence += fmt.Sprintf(" | Last reported: %s", check.LastReportedAt)
	}

	findings := []scanner.Finding{{
		ID:          fmt.Sprintf("NET-%03d", startIdx),
		Layer:       "network",
		Title:       fmt.Sprintf("AbuseIPDB: %s has %d%% abuse confidence score", ip, check.AbuseConfidenceScore),
		Description: fmt.Sprintf("AbuseIPDB reports this IP with an abuse confidence score of %d%% based on %d reports from %d distinct users in the last 90 days.", check.AbuseConfidenceScore, check.TotalReports, check.NumDistinctUsers),
		Severity:    sev,
		Reference:   "https://www.abuseipdb.com/check/" + ip,
		Evidence:    evidence,
		Remediation: "Consider blocking or rate-limiting traffic from this IP. Review firewall and access logs.",
	}}
	return findings, nil
}
