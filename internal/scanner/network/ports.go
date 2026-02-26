package network

import "github.com/onoz1169/1scan/internal/scanner"

type portInfo struct {
	Port    int
	Service string
}

// TCP top 100 from nmap's nmap-services frequency data
var defaultPorts = []portInfo{
	{7, "Echo"},
	{9, "Discard"},
	{13, "Daytime"},
	{21, "FTP"},
	{22, "SSH"},
	{23, "Telnet"},
	{25, "SMTP"},
	{26, "SMTP-alt"},
	{37, "Time"},
	{53, "DNS"},
	{79, "Finger"},
	{80, "HTTP"},
	{81, "HTTP-alt"},
	{88, "Kerberos"},
	{106, "POPPASSD"},
	{110, "POP3"},
	{111, "RPCbind"},
	{113, "Ident"},
	{119, "NNTP"},
	{135, "MSRPC"},
	{139, "NetBIOS"},
	{143, "IMAP"},
	{144, "NeWS"},
	{179, "BGP"},
	{199, "SMUX"},
	{443, "HTTPS"},
	{444, "SNPP"},
	{445, "SMB"},
	{465, "SMTPS"},
	{513, "rlogin"},
	{514, "rsh"},
	{515, "LPD"},
	{543, "klogin"},
	{544, "kshell"},
	{548, "AFP"},
	{554, "RTSP"},
	{587, "Submission"},
	{631, "IPP"},
	{646, "LDP"},
	{873, "rsync"},
	{990, "FTPS"},
	{993, "IMAPS"},
	{995, "POP3S"},
	{1025, "NFS-or-IIS"},
	{1026, "LSA-or-nterm"},
	{1027, "IIS"},
	{1028, "unknown"},
	{1029, "ms-lsa"},
	{1110, "nfsd-status"},
	{1433, "MSSQL"},
	{1720, "H.323"},
	{1723, "PPTP"},
	{1755, "MMS"},
	{1900, "SSDP"},
	{2000, "Cisco-SCCP"},
	{2001, "DC"},
	{2049, "NFS"},
	{2121, "FTP-alt"},
	{2717, "PN-requester"},
	{3000, "HTTP-dev"},
	{3128, "HTTP-proxy"},
	{3306, "MySQL"},
	{3389, "RDP"},
	{3986, "MAPPER"},
	{4899, "Radmin"},
	{5000, "UPnP"},
	{5009, "AirPort"},
	{5051, "ITA-agent"},
	{5060, "SIP"},
	{5101, "Talarian"},
	{5190, "AIM/ICQ"},
	{5357, "WSDAPI"},
	{5432, "PostgreSQL"},
	{5631, "pcAnywhere"},
	{5666, "NRPE"},
	{5672, "RabbitMQ"},
	{5800, "VNC-HTTP"},
	{5900, "VNC"},
	{6000, "X11"},
	{6001, "X11-1"},
	{6112, "dtspc"},
	{6379, "Redis"},
	{6513, "NETCONF"},
	{6543, "unknown"},
	{6646, "unknown"},
	{6789, "IBM-DB2"},
	{7000, "AFS"},
	{7070, "RealServer"},
	{7937, "NSClient"},
	{7938, "Lgtomapper"},
	{8000, "HTTP-alt"},
	{8008, "HTTP-alt"},
	{8009, "AJP"},
	{8080, "HTTP-proxy"},
	{8081, "HTTP-alt"},
	{8443, "HTTPS-alt"},
	{8888, "HTTP-alt"},
	{9100, "JetDirect"},
	{9200, "Elasticsearch"},
	{9999, "Aastra"},
	{10000, "Webmin"},
	{32768, "FileMaker"},
	{49152, "Dynamic"},
	{49153, "Dynamic"},
	{49154, "Dynamic"},
}

// serviceFingerprint maps banner patterns to service names.
type serviceFingerprint struct {
	pattern string
	service string
}

var serviceFingerprints = []serviceFingerprint{
	{"SSH-", "SSH"},
	{"220 ", "FTP/SMTP"},
	{"220-", "FTP/SMTP"},
	{"HTTP/", "HTTP"},
	{"* OK", "IMAP"},
	{"+OK", "POP3"},
	{"redis_version", "Redis"},
	{"mongo", "MongoDB"},
	{"MySQL", "MySQL"},
	{"PostgreSQL", "PostgreSQL"},
	{"SMB", "SMB"},
	{"RFB ", "VNC"},
	{"AMQP", "RabbitMQ"},
}

// riskyPort defines severity and metadata for ports that pose security risks.
type riskyPort struct {
	Severity    scanner.Severity
	Title       string
	Description string
	Reference   string
	Remediation string
}

var riskyPorts = map[int]riskyPort{
	23: {
		Severity:    scanner.SeverityCritical,
		Title:       "Telnet service exposed",
		Description: "Telnet transmits all data including credentials in plaintext. Any network observer can intercept traffic.",
		Reference:   "CWE-319",
		Remediation: "Disable Telnet and use SSH for remote administration.",
	},
	21: {
		Severity:    scanner.SeverityHigh,
		Title:       "FTP service exposed",
		Description: "FTP transmits credentials in plaintext and is frequently misconfigured to allow anonymous access.",
		Reference:   "CWE-319",
		Remediation: "Replace FTP with SFTP or SCP. If FTP is required, enforce TLS (FTPS) and disable anonymous login.",
	},
	445: {
		Severity:    scanner.SeverityHigh,
		Title:       "SMB service exposed",
		Description: "SMB is a common attack vector for ransomware (WannaCry, NotPetya) and lateral movement.",
		Reference:   "CWE-284",
		Remediation: "Block SMB at the perimeter firewall. If internal access is needed, restrict to specific IPs and enforce SMBv3.",
	},
	6379: {
		Severity:    scanner.SeverityHigh,
		Title:       "Redis service exposed",
		Description: "Redis often runs without authentication. Exposed Redis instances can lead to remote code execution.",
		Reference:   "CWE-306",
		Remediation: "Bind Redis to localhost or private interfaces. Enable AUTH and use TLS. Never expose to the internet.",
	},
	27017: {
		Severity:    scanner.SeverityHigh,
		Title:       "MongoDB service exposed",
		Description: "MongoDB instances without authentication expose all databases to unauthenticated access.",
		Reference:   "CWE-306",
		Remediation: "Enable MongoDB authentication, bind to localhost, and use TLS for connections.",
	},
	3389: {
		Severity:    scanner.SeverityMedium,
		Title:       "RDP service exposed",
		Description: "Exposed RDP is a primary target for brute-force attacks and known vulnerabilities (BlueKeep).",
		Reference:   "CWE-284",
		Remediation: "Use a VPN or gateway for RDP access. Enable NLA and enforce strong credentials.",
	},
	3306: {
		Severity:    scanner.SeverityMedium,
		Title:       "MySQL service exposed",
		Description: "Publicly accessible MySQL can be targeted by brute-force attacks and SQL injection from external sources.",
		Reference:   "CWE-284",
		Remediation: "Bind MySQL to localhost or private interfaces. Use firewall rules to restrict access.",
	},
	5900: {
		Severity:    scanner.SeverityHigh,
		Title:       "VNC service exposed",
		Description: "VNC provides remote desktop access and often lacks strong authentication. Exposed VNC can allow full system control.",
		Reference:   "CWE-306",
		Remediation: "Disable VNC or restrict access via VPN. Use strong passwords and enable encryption.",
	},
	9200: {
		Severity:    scanner.SeverityCritical,
		Title:       "Elasticsearch service exposed",
		Description: "Elasticsearch is often completely unauthenticated by default. Exposed instances can leak all indexed data and allow arbitrary writes.",
		Reference:   "CWE-306",
		Remediation: "Enable Elasticsearch security features (X-Pack). Bind to localhost or use a reverse proxy with authentication.",
	},
	5672: {
		Severity:    scanner.SeverityHigh,
		Title:       "RabbitMQ service exposed",
		Description: "RabbitMQ message broker is often exposed without authentication, allowing message interception and injection.",
		Reference:   "CWE-306",
		Remediation: "Enable RabbitMQ authentication, change default credentials, and restrict access to trusted networks.",
	},
	2049: {
		Severity:    scanner.SeverityHigh,
		Title:       "NFS service exposed",
		Description: "NFS shares can expose filesystem contents to unauthenticated users if exports are misconfigured.",
		Reference:   "CWE-284",
		Remediation: "Restrict NFS exports to specific IPs. Use NFSv4 with Kerberos authentication. Never expose NFS to the internet.",
	},
	873: {
		Severity:    scanner.SeverityHigh,
		Title:       "rsync service exposed",
		Description: "rsync often allows unauthenticated file access, potentially exposing sensitive data or allowing file modification.",
		Reference:   "CWE-306",
		Remediation: "Require authentication for rsync. Restrict access via firewall rules and use rsync over SSH.",
	},
}

// expectedServiceOnPort maps ports to expected banner content for mismatch detection.
var expectedServiceOnPort = map[int]struct {
	bannerHint string
	mismatch   string
	severity   scanner.Severity
}{
	22:   {"SSH", "Unusual service on SSH port", scanner.SeverityMedium},
	80:   {"HTTP", "Unexpected service on HTTP port", scanner.SeverityLow},
	8080: {"HTTP", "Unexpected service on HTTP-proxy port", scanner.SeverityLow},
	443:  {"", "Plaintext service on expected HTTPS port", scanner.SeverityHigh},
	8443: {"", "Plaintext service on expected HTTPS-alt port", scanner.SeverityHigh},
}

// httpPorts are ports that commonly serve HTTP and should be probed for headers.
var httpPorts = map[int]bool{
	80: true, 81: true, 443: true, 3000: true, 3128: true,
	5000: true, 7070: true, 8000: true, 8008: true, 8009: true,
	8080: true, 8081: true, 8443: true, 8888: true, 9200: true,
	10000: true,
}
