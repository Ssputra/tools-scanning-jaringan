package scanner

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortResult represents the scan result of a single port.
type PortResult struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`  // "open", "closed", "filtered"
	Service string `json:"service"` // Service name from wellKnownPorts
}

const (
	workerCount   = 200              // Goroutine pool — safe for Windows socket limits
	dialTimeout   = 500 * time.Millisecond // Strict timeout per port
	bannerTimeout = 300 * time.Millisecond // Banner grab timeout
)

// topPorts: Nmap-style Top 1000 most common ports.
// Scanned FIRST so user sees results within seconds.
var topPorts = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 100, 106, 110,
	111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
	465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 873, 990, 993,
	995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
	2000, 2001, 2049, 2121, 2717, 3000, 3001, 3128, 3268, 3306, 3389, 3986,
	4899, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101, 5190, 5357, 5432,
	5555, 5631, 5666, 5800, 5900, 5901, 5985, 6000, 6001, 6379, 6646, 7000,
	7001, 7070, 7100, 7443, 7938, 8000, 8001, 8002, 8008, 8009, 8010, 8080,
	8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8443, 8888,
	9000, 9001, 9090, 9091, 9200, 9443, 9999, 10000, 10443, 11211, 27017,
	27018, 28017, 50000, 50070, 61616,
}

// wellKnownPorts maps port numbers to service names (Nmap-style).
var wellKnownPorts = map[int]string{
	// Core Internet Services
	20:    "FTP-Data",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	67:    "DHCP",
	68:    "DHCP",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	993:   "IMAPS",
	995:   "POP3S",
	// Mail & Messaging
	465:   "SMTPS",
	587:   "SMTP-Submission",
	873:   "Rsync",
	1110:  "LDAP",
	1433:  "MSSQL",
	1434:  "MSSQL-Monitor",
	1723:  "PPTP",
	1900:  "UPnP",
	// Remote Access & Management
	135:   "MSRPC",
	139:   "NetBIOS",
	389:   "LDAP",
	445:   "SMB",
	464:   "Kerberos",
	513:   "RLogin",
	514:   "Syslog",
	515:   "LPD/Printer",
	554:   "RTSP",
	631:   "CUPS",
	636:   "LDAPS",
	2049:  "NFS",
	3389:  "RDP",
	5900:  "VNC",
	5901:  "VNC-1",
	5985:  "WinRM",
	// Databases
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
	27018: "MongoDB",
	28017: "MongoDB-Web",
	// Web Servers & Proxies
	8000:  "HTTP-Alt",
	8001:  "HTTP-Alt",
	8008:  "HTTP",
	8009:  "AJP",
	8080:  "HTTP-Proxy",
	8081:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9000:  "HTTP-Alt",
	9090:  "Web-Console",
	9443:  "HTTPS-Alt",
	// Industrial & IoT
	102:   "S7comm",
	502:   "Modbus",
	44818: "EtherNet/IP",
	47808: "BACnet",
	// Misc Services
	7:     "Echo",
	9:     "Discard",
	13:    "Daytime",
	37:    "Time",
	79:    "Finger",
	111:   "RPCBind",
	113:   "Ident",
	119:   "NNTP",
	179:   "BGP",
	255:   "Reserved",
	427:   "SLP",
	444:   "SneakSnake",
	543:   "Klogin",
	544:   "Kshell",
	548:   "AFP",
	1025:  "NFS-IE",
	1026:  "WinRPC",
	1027:  "MSRPC",
	1028:  "MSRPC",
	1029:  "MSRPC",
	1755:  "MMS",
	2000:  "Cisco-SCCP",
	2001:  "Cisco-Tele",
	2121:  "CCProxy",
	2717:  "MMS",
	3000:  "Dev-Server",
	3001:  "Dev-Server",
	3128:  "Squid-Proxy",
	3268:  "LDAP-GC",
	3986:  "SNMP",
	4899:  "Radmin",
	5000:  "UPnP",
	5001:  "Dev-Server",
	5003:  "FileMaker",
	5009:  "AirTunes",
	5050:  "MMS",
	5060:  "SIP",
	5101:  "Padl-Studio",
	5357:  "WSDAPI",
	5555:  "ADB",
	5631:  "PCAnywhere",
	5666:  "NRPE",
	5800:  "VNC-Web",
	6000:  "X11",
	6001:  "X11",
	6646:  "MMS",
	7000:  "Asterisk",
	7001:  "WebLogic",
	7070:  "RealServer",
	7100:  "XFS",
	7443:  "HTTPS-Alt",
	7938:  "MMS",
	8002:  "Cisco-Tele",
	8010:  "XMPP",
	8082:  "HTTP-Alt",
	8083:  "HTTP-Alt",
	8084:  "HTTPS-Alt",
	8085:  "HTTP-Alt",
	8086:  "HTTP-Alt",
	8087:  "HTTP-Alt",
	8088:  "HTTP-Alt",
	8089:  "HTTPS-Alt",
	8090:  "HTTP-Alt",
	9001:  "HTTP-Alt",
	9091:  "Transmission",
	9999:  "HTTP-Alt",
	10000: "Webmin",
	10443: "HTTPS-Alt",
	50000: "SAP",
	50070: "HDFS",
	61616: "ActiveMQ",
}

// serviceHints maps common banner keywords to service names.
var serviceHints = map[string]string{
	"SSH":          "SSH",
	"OpenSSH":      "SSH",
	"dropbear":     "SSH",
	"HTTP":         "HTTP",
	"Apache":       "Apache",
	"nginx":        "Nginx",
	"IIS":          "IIS",
	"Microsoft-IIS": "IIS",
	"Caddy":        "Caddy",
	"LiteSpeed":    "LiteSpeed",
	"FTP":          "FTP",
	"vsftpd":       "vsFTPd",
	"ProFTPD":      "ProFTPD",
	"Pure-FTPd":    "Pure-FTPd",
	"FileZilla":    "FileZilla",
	"SMTP":         "SMTP",
	"Postfix":      "Postfix",
	"Sendmail":     "Sendmail",
	"Exim":         "Exim",
	"SMTPd":        "SMTP",
	"POP3":         "POP3",
	"dovecot":      "Dovecot",
	"IMAP":         "IMAP",
	"cyrus":        "Cyrus",
	"MySQL":        "MySQL",
	"MariaDB":      "MariaDB",
	"PostgreSQL":   "PostgreSQL",
	"MongoDB":      "MongoDB",
	"Redis":        "Redis",
	"Memcached":    "Memcached",
	"Elasticsearch": "Elasticsearch",
	"MSSQL":        "MSSQL",
	"Oracle":       "Oracle",
	"RDP":          "RDP",
	"VNC":          "VNC",
	"MikroTik":     "RouterOS",
	"RouterOS":     "RouterOS",
	"Cisco":        "Cisco",
	"Switch":       "Network-Switch",
	"HP":           "HP-Printer",
	"Brother":      "Brother-Printer",
	"Canon":        "Canon-Printer",
	"Epson":        "Epson-Printer",
	"Linux":        "Linux",
	"Windows":      "Windows",
	"Proxmox":      "Proxmox-VE",
	"VMware":       "VMware",
	"Docker":       "Docker",
	"Kubernetes":   "K8s",
	"etcd":         "etcd",
	"gunicorn":     "Gunicorn",
	"uWSGI":        "uWSGI",
	"Jetty":        "Jetty",
	"Tomcat":       "Tomcat",
	"WebLogic":     "WebLogic",
	"WebSphere":    "WebSphere",
	"Jenkins":      "Jenkins",
	"GitLab":       "GitLab",
	"Gitea":        "Gitea",
	"Drone":        "Drone-CI",
	"Prometheus":   "Prometheus",
	"Grafana":      "Grafana",
	"Kibana":       "Kibana",
	"Zabbix":       "Zabbix",
	"Nagios":       "Nagios",
	"PRTG":         "PRTG",
	"Splunk":       "Splunk",
	"Graylog":      "Graylog",
	"MinIO":        "MinIO-S3",
	"Ceph":         "Ceph",
	"GlusterFS":    "GlusterFS",
	"NFS":          "NFS",
	"Samba":        "SMB",
	"SMB":          "SMB",
	"AFP":          "AFP",
	"Transmission": "BitTorrent",
	"qBittorrent":  "BitTorrent",
	"Deluge":       "BitTorrent",
	"Aria2":        "Aria2",
	"SIP":          "VoIP-SIP",
	"Asterisk":     "Asterisk-PBX",
	"FreeSWITCH":   "FreeSWITCH",
	"Kamailio":     "Kamailio",
	"OpenSIPS":     "OpenSIPS",
	"Modbus":       "Modbus-SCADA",
	"Siemens":      "Siemens-PLC",
	"ABB":          "ABB-PLC",
	"Mitsubishi":   "Mitsubishi-PLC",
	"Omron":        "Omron-PLC",
	"Beckhoff":     "Beckhoff-PLC",
	"Node-RED":     "Node-RED",
	"HomeAssistant": "Home-Assistant",
	"OpenHAB":      "OpenHAB",
}

// ScanTargetPorts scans ports on target IP using a Worker Pool pattern.
// Phase 1: Top 1000 ports (instant results)
// Phase 2: Remaining ports 1-65535 (background)
// Only OPEN ports are sent to resultCh. Channel is closed when done.
func ScanTargetPorts(target string, resultCh chan<- PortResult) {
	defer close(resultCh)

	// ═══ PHASE 1: Top Ports (priority scan) ═══
	// Scan most common ports first — user sees results in < 2 seconds.
	phase1Done := make(chan struct{})
	seenPorts := make(map[int]bool)

	phase1ResultCh := make(chan PortResult, 100)
	var phase1Wg sync.WaitGroup

	go func() {
		for _, port := range topPorts {
			phase1Wg.Add(1)
			go func(p int) {
				defer phase1Wg.Done()
				scanSinglePort(target, p, phase1ResultCh)
			}(port)
			seenPorts[port] = true

			// Throttle: small delay between batches
			time.Sleep(2 * time.Millisecond)
		}
		phase1Wg.Wait()
		close(phase1Done)
	}()

	// Forward phase 1 results
	go func() {
		for r := range phase1ResultCh {
			resultCh <- r
		}
	}()

	<-phase1Done

	// ═══ PHASE 2: Remaining ports (background scan) ═══
	portsChan := make(chan int, 500)

	// Producer: inject remaining ports (skip top ports already scanned)
	go func() {
		for port := 1; port <= 65535; port++ {
			if !seenPorts[port] {
				portsChan <- port
			}
		}
		close(portsChan)
	}()

	var phase2Wg sync.WaitGroup

	// Worker pool: 200 concurrent goroutines
	for i := 0; i < workerCount; i++ {
		phase2Wg.Add(1)
		go func() {
			defer phase2Wg.Done()
			for port := range portsChan {
				scanSinglePort(target, port, resultCh)
			}
		}()
	}

	phase2Wg.Wait()
}

// scanSinglePort probes a single port and sends result if open.
// Distinguishes between "open", "closed", and "filtered".
func scanSinglePort(target string, port int, resultCh chan<- PortResult) {
	addr := net.JoinHostPort(target, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		// ═══ ERROR CLASSIFICATION ═══
		// "Connection refused" = port is definitively CLOSED
		// "Timeout" / "i/o timeout" = port is FILTERED (firewall dropping)
		errStr := err.Error()
		if strings.Contains(errStr, "refused") {
			// Port closed — don't report, just skip
			return
		}
		// Timeout or other error — port is filtered/stealth
		// Don't report filtered ports to avoid noise
		return
	}
	conn.Close()

	// ═══ PORT IS OPEN — identify service ═══
	service := getPortService(port)

	// Banner grab to refine service identification
	banner := grabBannerFast(target, port)
	if banner != "" {
		for keyword, hint := range serviceHints {
			if strings.Contains(strings.ToLower(banner), strings.ToLower(keyword)) {
				service = hint
				break
			}
		}
	}

	resultCh <- PortResult{
		Port:    port,
		Status:  "open",
		Service: service,
	}
}

// grabBannerFast does a quick banner grab with tight timeout.
func grabBannerFast(ip string, port int) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, bannerTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(bannerTimeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return cleanBanner(string(buf[:n]))
}

// getPortService returns the service name for a well-known port.
func getPortService(port int) string {
	if svc, ok := wellKnownPorts[port]; ok {
		return svc
	}
	return "port-" + strconv.Itoa(port)
}

// cleanBanner sanitizes banner text for display.
func cleanBanner(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

// SortPortResults sorts port results by port number.
func SortPortResults(results []PortResult) []PortResult {
	sorted := make([]PortResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Port < sorted[j].Port
	})
	return sorted
}
