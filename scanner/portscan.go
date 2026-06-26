package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// PortResult represents the scan result of a single port.
type PortResult struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`  // "open", "closed"
	Service string `json:"service"` // Service hint based on well-known port names
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
	"SSH":       "SSH",
	"HTTP":      "HTTP",
	"FTP":       "FTP",
	"SMTP":      "SMTP",
	"POP":       "POP3",
	"IMAP":      "IMAP",
	"MikroTik":  "RouterOS",
	"RouterOS":  "RouterOS",
	"IIS":       "IIS/Windows",
	"Apache":    "Apache",
	"nginx":     "Nginx",
	"Microsoft": "Windows",
	"Linux":     "Linux",
}

const (
	totalPorts   = 65535
	workerCount  = 1500
	dialTimeout  = 250 * time.Millisecond
	bannerTimeout = 200 * time.Millisecond
)

// ScanTargetPorts scans ALL 65535 ports on target IP using an aggressive
// goroutine worker pool. Results (only OPEN ports) are sent to resultCh.
// Channel is closed when all ports have been scanned.
func ScanTargetPorts(target string, resultCh chan<- PortResult) {
	defer close(resultCh)

	// Distribute port numbers 1..65535 via buffered channel
	portsChan := make(chan int, 1000)

	// Producer goroutine: inject all 65535 port numbers
	go func() {
		for port := 1; port <= totalPorts; port++ {
			portsChan <- port
		}
		close(portsChan)
	}()

	var wg sync.WaitGroup
	var openCount int64

	// Spawn 1500 worker goroutines
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
				conn, err := net.DialTimeout("tcp", addr, dialTimeout)
				if err != nil {
					continue // closed/filtered — skip silently
				}
				conn.Close()
				atomic.AddInt64(&openCount, 1)

				service := getPortService(port)

				// Grab banner to identify service (only for open ports)
				banner := grabBannerFast(target, port)
				if banner != "" {
					for keyword, hint := range serviceHints {
						if containsIgnoreCase(banner, keyword) {
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
		}()
	}

	wg.Wait()
}

// grabBannerFast does a quick banner grab with a tight timeout.
func grabBannerFast(ip string, port int) string {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
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

func getPortService(port int) string {
	if svc, ok := wellKnownPorts[port]; ok {
		return svc
	}
	return fmt.Sprintf("port-%d", port)
}

func cleanBanner(s string) string {
	s = replaceAll(s, "\r\n", " ")
	s = replaceAll(s, "\n", " ")
	s = replaceAll(s, "\r", " ")
	s = trimSpace(s)
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
		s = s[:idx] + new + s[idx+len(old):]
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

// SortPortResults sorts port results by port number.
func SortPortResults(results []PortResult) []PortResult {
	sorted := make([]PortResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Port < sorted[j].Port
	})
	return sorted
}
