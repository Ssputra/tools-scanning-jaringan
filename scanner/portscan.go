package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// PortResult represents the scan result of a single port.
type PortResult struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`  // "open", "closed", "filtered"
	Service string `json:"service"` // Service hint based on well-known port names
}

// commonPorts defines ports to scan by default (Top 100 subset).
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
	8443, 8888, 9100, 27017,
}

// wellKnownPorts maps port numbers to service names.
var wellKnownPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPCBind",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1723:  "PPTP",
	3306:  "MySQL",
	3389:  "RDP",
	5900:  "VNC",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9100:  "Printer",
	27017: "MongoDB",
}

// serviceHints maps common banners/behaviors to service guesses.
var serviceHints = map[string]string{
	"SSH":   "SSH",
	"HTTP":  "HTTP",
	"FTP":   "FTP",
	"SMTP":  "SMTP",
	"POP":   "POP3",
	"IMAP":  "IMAP",
	"MikroTik": "RouterOS",
	"RouterOS": "RouterOS",
	"IIS":   "IIS/Windows",
	"Apache": "Apache",
	"nginx": "Nginx",
	"Microsoft": "Windows",
	"Linux": "Linux",
}

// PortScanConfig holds configuration for a port scan.
type PortScanConfig struct {
	Target      string
	Ports       []int           // nil = use commonPorts
	Timeout     time.Duration   // per-port connect timeout
	WorkerCount int             // concurrent goroutines
}

// ScanTargetPorts performs a port scan on the target IP and sends results
// one-by-one to the channel. Closes the channel when done.
func ScanTargetPorts(target string, resultCh chan<- PortResult) {
	cfg := PortScanConfig{
		Target:      target,
		Timeout:     800 * time.Millisecond,
		WorkerCount: 100,
	}
	ScanTargetPortsConfig(cfg, resultCh)
}

// ScanTargetPortsConfig is the configurable version of ScanTargetPorts.
func ScanTargetPortsConfig(cfg PortScanConfig, resultCh chan<- PortResult) {
	defer close(resultCh)

	ports := cfg.Ports
	if len(ports) == 0 {
		ports = commonPorts
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 100
	}

	// Quick TCP connect check to see if host is alive
	if !isHostAlive(cfg.Target, cfg.Timeout) {
		// Host seems down, still scan a few common ports to confirm
		ports = []int{22, 80, 443, 3389}
	}

	// Worker pool
	jobs := make(chan int, len(ports))
	for _, p := range ports {
		jobs <- p
	}
	close(jobs)

	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < cfg.WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				result := scanPort(cfg.Target, port, cfg.Timeout)
				mu.Lock()
				resultCh <- result
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
}

func isHostAlive(ip string, timeout time.Duration) bool {
	// Try a quick connect to common ports
	quickPorts := []int{80, 443, 22, 445, 135, 8080}
	for _, port := range quickPorts {
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, timeout/3)
		if err == nil {
			conn.Close()
			return true
		}
	}
	// Even if all fail, the host might just have a firewall — scan anyway
	return true
}

func scanPort(ip string, port int, timeout time.Duration) PortResult {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	service := getPortService(port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		// Could be closed or filtered
		return PortResult{
			Port:    port,
			Status:  "closed",
			Service: service,
		}
	}
	conn.Close()

	// Port is open — try to grab a banner for more detail
	banner := grabBanner(ip, port, timeout)
	if banner != "" {
		// Try to identify service from banner
		for keyword, hint := range serviceHints {
			if containsIgnoreCase(banner, keyword) {
				service = hint
				break
			}
		}
	}

	return PortResult{
		Port:    port,
		Status:  "open",
		Service: service,
	}
}

func grabBanner(ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}

	banner := string(buf[:n])
	banner = cleanBanner(banner)
	return banner
}

func cleanBanner(s string) string {
	// Remove newlines, carriage returns, and trim
	s = replaceAll(s, "\r\n", " ")
	s = replaceAll(s, "\n", " ")
	s = replaceAll(s, "\r", " ")
	s = trimSpace(s)
	// Truncate if too long
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

func replaceAll(s, old, new string) string {
	for {
		idx := indexOf(s, old)
		if idx == -1 {
			return s
		}
		s = s[:idx] + new+s[idx+len(old):]
	}
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return indexOf(s, substr) != -1
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func getPortService(port int) string {
	if svc, ok := wellKnownPorts[port]; ok {
		return svc
	}
	return fmt.Sprintf("port-%d", port)
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
