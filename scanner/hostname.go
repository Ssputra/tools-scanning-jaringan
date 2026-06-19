package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// GetAggressiveHostname runs a waterfall of protocol probes to discover the
// real LAN hostname of a device. It tries NetBIOS → mDNS → HTTP title
// concurrently and returns the first valid (non-empty, non-"Unknown") result.
func GetAggressiveHostname(ip string) string {
	resultCh := make(chan string, 3)
	done := make(chan struct{})

	go probeNetBIOS(ip, resultCh)
	go probeMDNS(ip, resultCh)
	go probeHTTPTitle(ip, resultCh)

	go func() {
		for i := 0; i < 3; i++ {
			<-done
		}
		close(resultCh)
	}()

	// Collect all results; prefer earliest non-empty
	best := ""
	timeout := time.After(1200 * time.Millisecond)
	for {
		select {
		case r, ok := <-resultCh:
			if !ok {
				return best
			}
			if r != "" && best == "" {
				best = r
			}
		case <-timeout:
			return best
		}
	}
}

// ── Protocol 1: NetBIOS Name Query (UDP 137) ──────────────────────

func probeNetBIOS(ip string, out chan<- string) {
	defer func() { out <- "" }()

	// Build a NetBIOS Name Query Request for "*" (wildcard) Node Status
	// Transaction ID: 0xABCD, Flags: 0x0110 (standard query), Questions: 1
	// Name: "*" encoded as NetBIOS label
	packet := buildNetBIOSQuery()
	conn, err := net.DialTimeout("udp4", ip+":137", 400*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = conn.Write(packet)
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return
	}

	name := parseNetBIOSResponse(buf[:n])
	if name != "" {
		out <- name
	}
}

func buildNetBIOSQuery() []byte {
	// NetBIOS Name Query for "*" (wildcard Node Status Request)
	// Header (12 bytes) + Question section
	packet := []byte{
		// Transaction ID
		0xAB, 0xCD,
		// Flags: Standard query, Recursion desired
		0x01, 0x10,
		// Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Name: "*" encoded as NetBIOS label
		// Length byte: 1 (for "*")
		0x01, 0x2A, 0x00,
		// Scope ID: empty (0x00)
		0x00,
		// Pad to 32-byte name block with spaces (0x20)
		0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		// Name type: 0x00 (unique) or 0x21 (workstation)
		0x00, 0x21,
		// Class: IN (Internet)
		0x00, 0x01,
	}
	return packet
}

func parseNetBIOSResponse(data []byte) string {
	// Response must have at least a header (12 bytes) + name section
	if len(data) < 57 {
		return ""
	}

	// Number of names is at offset 56 (1 byte)
	numNames := int(data[56])
	if numNames == 0 {
		return ""
	}

	// Parse name entries starting at offset 57
	// Each entry: 15 bytes name + 1 byte padding + 2 bytes type + 1 byte flags = 18 bytes
	offset := 57
	for i := 0; i < numNames && offset+18 <= len(data); i++ {
		rawName := string(data[offset : offset+15])
		nameType := data[offset+15]
		flags := data[offset+16]

		// Clean the name: strip trailing spaces
		name := strings.TrimSpace(rawName)

		// Type 0x00 = Workstation, 0x20 = Workstation, 0x03 = Messenger, 0x21 = RAS
		// Flags bit 6 (0x20) = group name (domain/workgroup), we want unique names
		isGroup := (flags & 0x20) != 0

		if name != "" && !isGroup && (nameType == 0x00 || nameType == 0x20 || nameType == 0x03 || nameType == 0x21) {
			// Convert from NetBIOS encoding: uppercase ASCII
			name = strings.ToLower(name)
			if name != "" {
				return name
			}
		}
		offset += 18
	}

	// Fallback: try to extract any workstation name from the data
	// Look for readable ASCII sequences 4+ chars
	for i := 12; i < len(data)-4; i++ {
		if data[i] >= 'A' && data[i] <= 'Z' || data[i] >= 'a' && data[i] <= 'z' || data[i] >= '0' && data[i] <= '9' || data[i] == '-' || data[i] == '_' {
			j := i
			for j < len(data) && ((data[j] >= 'A' && data[j] <= 'Z') || (data[j] >= 'a' && data[j] <= 'z') || (data[j] >= '0' && data[j] <= '9') || data[j] == '-' || data[j] == '_') {
				j++
			}
			if j-i >= 4 {
				candidate := string(data[i:j])
				lower := strings.ToLower(candidate)
				// Skip common protocol words
				if lower != "windows" && lower != "domain" && lower != "workgroup" {
					return lower
				}
			}
		}
	}

	return ""
}

// ── Protocol 2: mDNS Probe (UDP 5353) ─────────────────────────────

func probeMDNS(ip string, out chan<- string) {
	defer func() { out <- "" }()

	// Build a standard mDNS query for _services._dns-sd._udp.local
	// We query the target IP directly (unicast)
	conn, err := net.DialTimeout("udp4", ip+":5353", 400*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()

	// Build mDNS query packet
	packet := buildMDNSQuery()
	conn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = conn.Write(packet)
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return
	}

	name := parseMDNSResponse(buf[:n])
	if name != "" {
		out <- name
	}
}

func buildMDNSQuery() []byte {
	// mDNS header: ID=0, Flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	packet := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // Flags (standard query)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}

	// QNAME: _services._dns-sd._udp.local
	qname := encodeMDNSName("_services._dns-sd._udp.local")
	packet = append(packet, qname...)

	// QTYPE: PTR (12)
	packet = append(packet, 0x00, 0x0C)
	// QCLASS: IN (1) with unicast-response bit
	packet = append(packet, 0x80, 0x01)

	return packet
}

func encodeMDNSName(name string) []byte {
	var encoded []byte
	parts := strings.Split(name, ".")
	for _, part := range parts {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, []byte(part)...)
	}
	encoded = append(encoded, 0x00)
	return encoded
}

func parseMDNSResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Scan through the data for readable hostname strings
	// mDNS responses contain the queried name + additional records
	// Look for names ending in .local
	lowerData := strings.ToLower(string(data))

	// Check for .local names in the packet
	localRe := regexp.MustCompile(`([a-zA-Z0-9][a-zA-Z0-9\-_]{1,62}\.local)`)
	if matches := localRe.FindStringSubmatch(lowerData); len(matches) > 1 {
		name := matches[1]
		// Skip the query name itself if it's our probe
		if name != "_services._dns-sd._udp.local" {
			return strings.TrimSuffix(name, ".local")
		}
	}

	// Also try to extract from the response name field
	// DNS name encoding: length-prefixed labels
	offset := 12
	seen := make(map[string]bool)
	for offset < len(data)-4 {
		labelLen := int(data[offset])
		if labelLen == 0 {
			offset++
			continue
		}
		if labelLen > 63 || offset+labelLen > len(data) {
			break
		}
		offset++
		label := string(data[offset : offset+labelLen])
		offset += labelLen

		// Check if this looks like a hostname
		if labelLen >= 2 && !seen[label] {
			seen[label] = true
			lower := strings.ToLower(label)
			// Skip our probe query labels
			if lower != "_services" && lower != "_dns-sd" && lower != "_udp" && lower != "local" {
				// Check if it's a plausible device name (letters, digits, hyphens)
				validRe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,30}$`)
				if validRe.MatchString(lower) {
					return lower
				}
			}
		}
	}

	return ""
}

// ── Protocol 3: HTTP Title Scraper (Port 80/443/8080) ─────────────

func probeHTTPTitle(ip string, out chan<- string) {
	defer func() { out <- "" }()

	ports := []int{80, 8080, 443}
	for _, port := range ports {
		title := scrapeWebTitle(ip, port)
		if title != "" {
			out <- title
			return
		}
	}
}

func scrapeWebTitle(ip string, port int) string {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	var conn net.Conn
	var err error

	if port == 443 {
		// Skip certificate verification for LAN devices
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		dialer := &net.Dialer{Timeout: 300 * time.Millisecond}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 300*time.Millisecond)
	}
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Send HTTP GET request
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", ip)
	conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = conn.Write([]byte(req))
	if err != nil {
		return ""
	}

	// Read response (limited to first 4KB to avoid large pages)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 4096)
	n, err := io.ReadAtLeast(conn, buf, 20)
	if err != nil && n == 0 {
		return ""
	}

	body := string(buf[:n])

	// Extract <title> tag
	titleRe := regexp.MustCompile(`(?i)<title[^>]*>\s*(.*?)\s*</title>`)
	matches := titleRe.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}

	title := strings.TrimSpace(matches[1])
	if title == "" {
		return ""
	}

	// Decode common HTML entities
	title = strings.ReplaceAll(title, "&amp;", "&")
	title = strings.ReplaceAll(title, "&lt;", "<")
	title = strings.ReplaceAll(title, "&gt;", ">")
	title = strings.ReplaceAll(title, "&quot;", "\"")
	title = strings.ReplaceAll(title, "&#39;", "'")

	// Truncate very long titles
	if len(title) > 64 {
		title = title[:61] + "..."
	}

	// Filter out generic/default titles
	lower := strings.ToLower(title)
	badTitles := []string{
		"untitled", "index of", "welcome to nginx", "apache server",
		"default page", "test page", "it works", "hello world",
	}
	for _, bad := range badTitles {
		if strings.Contains(lower, bad) {
			return ""
		}
	}

	return title
}

// ── Utility ────────────────────────────────────────────────────────

// isPrivateIP checks if an IP address is in a private/reserved range.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// GetAggressiveHostnameParallel runs all protocols in parallel with a hard timeout.
// This is the entry point called from the scanner engine.
func GetAggressiveHostnameParallel(ip string) string {
	if !isPrivateIP(ip) {
		// For public IPs, just try rDNS as fallback
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			return strings.TrimSuffix(names[0], ".")
		}
		return "Unknown Name"
	}

	result := GetAggressiveHostname(ip)
	if result == "" {
		// Last resort: try rDNS
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			rDNS := strings.TrimSuffix(names[0], ".")
			// Only use rDNS if it's a short local name, not a long public domain
			if len(rDNS) < 40 && !strings.Contains(rDNS, ".") {
				return rDNS
			}
		}
		return "Unknown Name"
	}
	return result
}
