package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Device struct {
	IP       string
	MAC      string
	Hostname string
	Vendor   string
	OS       string
}

// ScanMode constants used by the UI to tell the engine which mode to run.
const (
	ModeActiveOnly  = "active_only"   // ARP broadcast + ARP/ICMP reply only
	ModeHybrid      = "hybrid"        // ARP broadcast + ARP/ICMP reply + passive sniffer
	ModePassiveOnly = "passive_only"  // Passive sniffer only, no ARP
	ModeExternal    = "external"      // Layer 3 ICMP TTL-trace + TCP probe (no ARP)
)

type Scanner struct {
	InterfaceName string
	ScanMode      string
	Results       chan Device
	done          chan bool
	ttlResolved   sync.Map // tracks IPs that received TTL response (key: IP string)
}

func NewScanner(ifaceName string, mode string) *Scanner {
	return &Scanner{
		InterfaceName: ifaceName,
		ScanMode:      mode,
		Results:       make(chan Device, 100),
		done:          make(chan bool),
	}
}

func (s *Scanner) Stop() {
	close(s.done)
}

// Start launches Hybrid mode: ARP broadcast + ARP/ICMP reply handler + passive sniffer.
func (s *Scanner) Start() error {
	// Open live capture
	handle, err := pcap.OpenLive(s.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap (need Administrator/Npcap?): %v", err)
	}

	// Find the matching interface details
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("error finding devices: %v", err)
	}

	var pcapDev *pcap.Interface
	for _, d := range devs {
		if d.Name == s.InterfaceName {
			pcapDev = &d
			break
		}
	}

	if pcapDev == nil {
		return fmt.Errorf("interface %s not found", s.InterfaceName)
	}

	var srcIP net.IP
	var network *net.IPNet
	for _, addr := range pcapDev.Addresses {
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			srcIP = ipv4
			network = &net.IPNet{IP: ipv4, Mask: addr.Netmask}
			break
		}
	}

	if srcIP == nil {
		return fmt.Errorf("no valid IPv4 address found on interface")
	}

	// Map interface to local MAC address
	var srcMAC net.HardwareAddr
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(srcIP) {
				srcMAC = i.HardwareAddr
				break
			}
		}
	}

	if srcMAC == nil {
		return fmt.Errorf("could not determine local MAC address")
	}

	// Track passively-seen MACs to avoid spamming duplicate results
	passiveSeen := make(map[string]bool)
	var passiveMu sync.Mutex

	// Start the Sniffer and Sender Goroutine
	go func() {
		// Menutup resource pcap secara aman
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		in := packetSource.Packets()

		// Background Goroutine: Send broadcast ARP
		go s.broadcastARP(handle, srcMAC, srcIP, network)

		// Background Goroutine: Passive Sniffer — listens to ALL packets on the wire
		go s.passiveSniff(in, srcMAC, &passiveSeen, &passiveMu)

		for {
			select {
			case <-s.done:
				return
			case packet := <-in:
				if packet == nil {
					continue
				}

				// ═══ GLOBAL FILTER: Skip packets from our own interface ═══
				if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
					eth := ethLayer.(*layers.Ethernet)
					if eth.SrcMAC.String() == srcMAC.String() {
						continue
					}
				} else {
					continue
				}

				// 1. Sniff ARP Replies
				if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					if arp.Operation == layers.ARPReply {
						targetMAC := net.HardwareAddr(arp.SourceHwAddress)
						targetIP := net.IP(arp.SourceProtAddress)

						// Skip our own packets and unusable IPs
						if targetMAC.String() == srcMAC.String() {
							continue
						}
						ipStr := targetIP.String()
						if ipStr == "0.0.0.0" || ipStr == "" || ipStr == "<nil>" {
							continue
						}

						// Initial OS detect without TTL (Passive)
						vendor, osType := DetectOS(targetMAC.String(), 0)
						s.Results <- Device{
							IP:     ipStr,
							MAC:    targetMAC.String(),
							Vendor: vendor,
							OS:     osType,
						}

						// 2. Send Active Probe (ICMP Echo Request) to trigger IP response for TTL
						s.sendICMP(handle, srcMAC, targetMAC, srcIP, targetIP)

						// 2b. Start TTL probe timeout (3 detik)
						s.startTTLTimeout(ipStr, 3*time.Second)

						// 3. Asynchronous Hostname Lookup
						go s.lookupHostname(ipStr)

						// 4. Asynchronous MikroTik Probing (Winbox Port 8291)
						go s.verifyMikrotik(ipStr)
					}
				}

				// 3. Sniff ICMP/IPv4 Replies for TTL (Active)
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ipv4 := ipLayer.(*layers.IPv4)
					if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
						icmp := icmpLayer.(*layers.ICMPv4)
						if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply || icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
							// Pastikan paket ditujukan kembali ke kita
							if ipv4.DstIP.Equal(srcIP) {
								targetIP := ipv4.SrcIP.String()
								// Filter out unusable IPs
								if targetIP == "0.0.0.0" || targetIP == "" || targetIP == "<nil>" {
									continue
								}
								var targetMAC string
								if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
									eth := ethLayer.(*layers.Ethernet)
									targetMAC = eth.SrcMAC.String()
								}

								vendor, osType := DetectOS(targetMAC, ipv4.TTL)

								// Tandai IP ini sudah menerima respons TTL
								s.ttlResolved.Store(targetIP, true)

								s.Results <- Device{
									IP:     targetIP,
									MAC:    targetMAC,
									Vendor: vendor,
									OS:     osType,
								}
								
								// Verifikasi False Positive Linux (WSL/Docker di Windows)
								if osType == "Linux / IoT Device" {
									go s.verifyWindowsPorts(targetIP)
								}
							}
						}
					}
				}
			}
		}
	}()

	return nil
}

// StartActiveOnly launches Active-Only mode: ARP broadcast + ARP/ICMP reply
// handler. The passive sniffer goroutine is NOT started, so only devices that
// reply to ARP requests within the local subnet will be detected.
func (s *Scanner) StartActiveOnly() error {
	// Open live capture
	handle, err := pcap.OpenLive(s.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap (need Administrator/Npcap?): %v", err)
	}

	// Find the matching interface details
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("error finding devices: %v", err)
	}

	var pcapDev *pcap.Interface
	for _, d := range devs {
		if d.Name == s.InterfaceName {
			pcapDev = &d
			break
		}
	}

	if pcapDev == nil {
		return fmt.Errorf("interface %s not found", s.InterfaceName)
	}

	var srcIP net.IP
	var network *net.IPNet
	for _, addr := range pcapDev.Addresses {
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			srcIP = ipv4
			network = &net.IPNet{IP: ipv4, Mask: addr.Netmask}
			break
		}
	}

	if srcIP == nil {
		return fmt.Errorf("no valid IPv4 address found on interface")
	}

	// Map interface to local MAC address
	var srcMAC net.HardwareAddr
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(srcIP) {
				srcMAC = i.HardwareAddr
				break
			}
		}
	}

	if srcMAC == nil {
		return fmt.Errorf("could not determine local MAC address")
	}

	// Start the Sniffer and Sender Goroutine (Active Only — NO passive sniffer)
	go func() {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		in := packetSource.Packets()

		// Background Goroutine: Send broadcast ARP
		go s.broadcastARP(handle, srcMAC, srcIP, network)

		// NO passiveSniff goroutine here — Active Only mode

		for {
			select {
			case <-s.done:
				return
			case packet := <-in:
				if packet == nil {
					continue
				}

				// ═══ GLOBAL FILTER: Skip packets from our own interface ═══
				if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
					eth := ethLayer.(*layers.Ethernet)
					if eth.SrcMAC.String() == srcMAC.String() {
						continue
					}
				} else {
					continue
				}

				// 1. Sniff ARP Replies
				if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					if arp.Operation == layers.ARPReply {
						targetMAC := net.HardwareAddr(arp.SourceHwAddress)
						targetIP := net.IP(arp.SourceProtAddress)

						// Skip our own packets and unusable IPs
						if targetMAC.String() == srcMAC.String() {
							continue
						}
						ipStr := targetIP.String()
						if ipStr == "0.0.0.0" || ipStr == "" || ipStr == "<nil>" {
							continue
						}

						vendor, osType := DetectOS(targetMAC.String(), 0)
						s.Results <- Device{
							IP:     ipStr,
							MAC:    targetMAC.String(),
							Vendor: vendor,
							OS:     osType,
						}

						s.sendICMP(handle, srcMAC, targetMAC, srcIP, targetIP)

						// Start TTL probe timeout (3 detik)
						s.startTTLTimeout(ipStr, 3*time.Second)

						go s.lookupHostname(ipStr)
						go s.verifyMikrotik(ipStr)
					}
				}

				// 2. Sniff ICMP/IPv4 Replies for TTL
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ipv4 := ipLayer.(*layers.IPv4)
					if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
						icmp := icmpLayer.(*layers.ICMPv4)
						if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply || icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
							if ipv4.DstIP.Equal(srcIP) {
								targetIP := ipv4.SrcIP.String()
								// Filter out unusable IPs
								if targetIP == "0.0.0.0" || targetIP == "" || targetIP == "<nil>" {
									continue
								}
								var targetMAC string
								if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
									eth := ethLayer.(*layers.Ethernet)
									targetMAC = eth.SrcMAC.String()
								}

								vendor, osType := DetectOS(targetMAC, ipv4.TTL)

								// Tandai IP ini sudah menerima respons TTL
								s.ttlResolved.Store(targetIP, true)

								s.Results <- Device{
									IP:     targetIP,
									MAC:    targetMAC,
									Vendor: vendor,
									OS:     osType,
								}

								if osType == "Linux / IoT Device" {
									go s.verifyWindowsPorts(targetIP)
								}
							}
						}
					}
				}
			}
		}
	}()

	return nil
}

// StartPassive opens pcap in promiscuous mode and runs ONLY the passive
// sniffer goroutine. No ARP broadcast is sent, no valid IPv4 or MAC is
// required on the interface. This is ideal when the laptop sits on a
// different subnet (e.g. APIPA 169.254.x.x) and just needs to listen.
func (s *Scanner) StartPassive() error {
	handle, err := pcap.OpenLive(s.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap (need Administrator/Npcap?): %v", err)
	}

	// Best-effort: find local MAC so we can filter out our own packets.
	// If we can't find it (no IP), use an empty MAC — passiveSniff will
	// simply not filter anything, which is fine.
	var localMAC net.HardwareAddr
	devs, _ := pcap.FindAllDevs()
	for _, d := range devs {
		if d.Name == s.InterfaceName {
			for _, addr := range d.Addresses {
				if ipv4 := addr.IP.To4(); ipv4 != nil {
					ifaces, _ := net.Interfaces()
					for _, i := range ifaces {
						addrs, _ := i.Addrs()
						for _, a := range addrs {
							if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(ipv4) {
								localMAC = i.HardwareAddr
							}
						}
					}
				}
			}
			break
		}
	}
	if localMAC == nil {
		localMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0} // dummy, won't filter
	}

	passiveSeen := make(map[string]bool)
	var passiveMu sync.Mutex

	go func() {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		in := packetSource.Packets()

		// Only passive sniffer — no ARP broadcast
		s.passiveSniff(in, localMAC, &passiveSeen, &passiveMu)
	}()

	return nil
}

// StartExternalScan launches a Layer 3 external/WAN scan.
// It uses ICMP TTL-trace (traceroute-style) and TCP SYN probes to discover
// hops and services beyond the local subnet. No ARP broadcast is used.
func (s *Scanner) StartExternalScan(ifaceName string) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %v", err)
	}

	// Find local IP and MAC
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("error finding devices: %v", err)
	}

	var srcIP net.IP
	var srcMAC net.HardwareAddr
	var network *net.IPNet
	for _, d := range devs {
		if d.Name == ifaceName {
			for _, addr := range d.Addresses {
				if ipv4 := addr.IP.To4(); ipv4 != nil {
					srcIP = ipv4
					network = &net.IPNet{IP: ipv4, Mask: addr.Netmask}
					break
				}
			}
			break
		}
	}
	if srcIP == nil {
		return fmt.Errorf("no valid IPv4 on interface")
	}

	// Resolve local MAC
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(srcIP) {
				srcMAC = i.HardwareAddr
				break
			}
		}
	}
	if srcMAC == nil {
		return fmt.Errorf("could not determine local MAC")
	}

	// Detect default gateway
	gateway := detectDefaultGateway()
	if gateway == "" {
		// Fallback: assume .1 on same subnet
		gw := srcIP.Mask(network.Mask)
		gw[3] = 1
		gateway = gw.String()
	}

	s.Results <- Device{
		IP:       gateway,
		MAC:      "gateway",
		Hostname: "Default Gateway",
		Vendor:   "Gateway",
		OS:       "Router/Gateway",
	}

	go func() {
		defer handle.Close()

		// --- Phase 0: Passive Public-IP Harvester (runs continuously) ---
		// Sniffs ALL traffic, extracts public IPs from SrcIP/DstIP,
		// performs reverse DNS + TCP probe on each discovered public IP.
		seenPublicIPs := make(map[string]bool)
		var publicMu sync.Mutex
		go s.passivePublicIPHarvester(handle, srcMAC, &seenPublicIPs, &publicMu)

		// Track discovered hops to avoid duplicates
		seenHops := make(map[string]bool)
		var hopMu sync.Mutex

		// --- Phase 1: ICMP TTL-trace from TTL 1 to 30 ---
		for ttl := 1; ttl <= 30; ttl++ {
			select {
			case <-s.done:
				return
			default:
			}

			hopIP := sendTTLProbe(handle, srcMAC, srcIP, gateway, ttl)
			if hopIP != "" {
				hopMu.Lock()
				if !seenHops[hopIP] {
					seenHops[hopIP] = true
					hopMu.Unlock()

					vendor, osType := DetectOS("", 0)
					s.Results <- Device{
						IP:     hopIP,
						MAC:    "discovered",
						Vendor: vendor,
						OS:     "Hop " + fmt.Sprintf("%d", ttl) + " — " + osType,
					}

					// Phase 2: TCP probe each hop on port 80/443
					go s.tcpProbeHop(hopIP)
				} else {
					hopMu.Unlock()
				}
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Phase 3: Final target — TCP connect to well-known public IPs
		targets := []string{
			"8.8.8.8",       // Google DNS
			"1.1.1.1",       // Cloudflare DNS
			"208.67.222.222", // OpenDNS
		}
		for _, target := range targets {
			select {
			case <-s.done:
				return
			default:
			}
			s.tcpProbeTarget(target)
		}
	}()

	return nil
}

// detectDefaultGateway reads the OS routing table to find the default gateway IP.
func detectDefaultGateway() string {
	// Use net package to read routes — on Windows/Linux this returns the gateway
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// sendTTLProbe crafts an ICMP Echo Request with a specific TTL and sends it
// via pcap. It then listens for either:
//   - ICMP Echo Reply (reached the target)
//   - ICMP Time Exceeded (hit a router hop)
//
// Returns the responding IP, or "" if no response within timeout.
func sendTTLProbe(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP, dstIP string, ttl int) string {
	// Build Ethernet + IPv4 + ICMP Echo Request
	ethFrame := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      uint8(ttl),
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP.To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	icmpLayer := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       0xABCD,
		Seq:      uint16(ttl),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &ethFrame, &ipLayer, &icmpLayer,
		gopacket.Payload([]byte("NETSCANNER-EXT")))

	handle.WritePacketData(buf.Bytes())

	// Listen for response (up to 500ms)
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case <-deadline:
			return ""
		case pkt, ok := <-func() <-chan gopacket.Packet {
			ch := make(chan gopacket.Packet, 10)
			go func() {
				ps := gopacket.NewPacketSource(handle, handle.LinkType())
				for p := range ps.Packets() {
					select {
					case ch <- p:
					default:
					}
				}
			}()
			return ch
		}():
			if !ok || pkt == nil {
				continue
			}

			// Skip our own packets
			if ethL := pkt.Layer(layers.LayerTypeEthernet); ethL != nil {
				eth := ethL.(*layers.Ethernet)
				if eth.SrcMAC.String() == srcMAC.String() {
					continue
				}
			}

			if ipL := pkt.Layer(layers.LayerTypeIPv4); ipL != nil {
				ipv4 := ipL.(*layers.IPv4)
				srcRespondIP := ipv4.SrcIP.String()

				// ICMP Time Exceeded — a router hop responded
				if icmpL := pkt.Layer(layers.LayerTypeICMPv4); icmpL != nil {
					icmp := icmpL.(*layers.ICMPv4)
					if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
						return srcRespondIP
					}
					// ICMP Echo Reply — we reached the target
					if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
						return srcRespondIP
					}
				}
			}
		}
	}
}

// tcpProbeHop attempts a TCP connect to port 80/443 on a discovered hop.
func (s *Scanner) tcpProbeHop(ip string) {
	ports := []int{80, 443, 22, 8080}
	for _, port := range ports {
		select {
		case <-s.done:
			return
		default:
		}
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
		if err == nil {
			conn.Close()
			s.Results <- Device{
				IP:     ip,
				MAC:    "hop",
				Vendor: getPortServiceName(port),
				OS:     fmt.Sprintf("Hop open port %d", port),
			}
			return
		}
	}
}

// tcpProbeTarget does a TCP connect scan on a specific target IP.
func (s *Scanner) tcpProbeTarget(target string) {
	ports := []int{80, 443, 22, 53}
	for _, port := range ports {
		select {
		case <-s.done:
			return
		default:
		}
		addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
		if err == nil {
			conn.Close()
			s.Results <- Device{
				IP:     target,
				MAC:    "external",
				Vendor: getPortServiceName(port),
				OS:     "External target",
			}
			return
		}
	}
}

func getPortServiceName(port int) string {
	services := map[int]string{
		53: "DNS", 80: "HTTP", 443: "HTTPS",
		22: "SSH", 8080: "HTTP-Proxy",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return fmt.Sprintf("port-%d", port)
}

func (s *Scanner) broadcastARP(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP, network *net.IPNet) {
	ip := srcIP.Mask(network.Mask)
	for {
		inc(ip)
		if !network.Contains(ip) {
			break
		}
		s.sendARPRequest(handle, srcMAC, srcIP, ip)
		time.Sleep(2 * time.Millisecond) // Cegah network flooding
	}
}

// startTTLTimeout memulai timer. Jika setelah durasi tertentu IP belum
// mendapat respons TTL (masih "Probing TTL..."), kirim status fallback
// "Firewalled / No Reply" ke result channel.
func (s *Scanner) startTTLTimeout(ip string, timeout time.Duration) {
	time.AfterFunc(timeout, func() {
		// Cek apakah scanner sudah dihentikan
		select {
		case <-s.done:
			return
		default:
		}

		// Jika IP ini belum pernah menerima respons TTL, kirim fallback
		if _, resolved := s.ttlResolved.Load(ip); !resolved {
			s.Results <- Device{
				IP: ip,
				OS: "Firewalled / No Reply",
			}
		}
	})
}

// IsPublicIP returns true if the IP is a routable public address.
// It filters out private ranges (RFC 1918), loopback, link-local, and APIPA.
func IsPublicIP(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	// Loopback: 127.0.0.0/8
	if ip[0] == 127 {
		return false
	}
	// Link-local: 169.254.0.0/16
	if ip[0] == 169 && ip[1] == 254 {
		return false
	}
	// Private 10.0.0.0/8
	if ip[0] == 10 {
		return false
	}
	// Private 172.16.0.0/12
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return false
	}
	// Private 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return false
	}
	// Multicast: 224.0.0.0/4
	if ip[0] >= 224 && ip[0] <= 239 {
		return false
	}
	// Broadcast
	if ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255 {
		return false
	}
	// 0.0.0.0
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
		return false
	}
	return true
}

// passivePublicIPHarvester sniffs all IPv4 traffic and harvests public IPs.
// For each new public IP discovered (src or dst), it performs:
//   - Reverse DNS lookup (PTR record)
//   - TCP SYN probe on port 80/443
//
// This runs as a long-lived goroutine alongside ICMP TTL-trace.
func (s *Scanner) passivePublicIPHarvester(handle *pcap.Handle, localMAC net.HardwareAddr, seen *map[string]bool, mu *sync.Mutex) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range packetSource.Packets() {
		select {
		case <-s.done:
			return
		default:
		}

		// Must be IPv4
		ipLayer := pkt.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ipv4 := ipLayer.(*layers.IPv4)

		// Extract both source and destination IPs
		candidates := []net.IP{ipv4.SrcIP, ipv4.DstIP}

		for _, ip := range candidates {
			if ip == nil || !IsPublicIP(ip) {
				continue
			}

			ipStr := ip.String()

			// Deduplicate by IP only (MAC is irrelevant for public IPs)
			mu.Lock()
			if (*seen)[ipStr] {
				mu.Unlock()
				continue
			}
			(*seen)[ipStr] = true
			mu.Unlock()

			// Aggressive Reverse DNS (PTR record)
			hostname := ""
			names, err := net.LookupAddr(ipStr)
			if err == nil && len(names) > 0 {
				hostname = names[0]
				// Strip trailing dot from PTR record
				hostname = strings.TrimSuffix(hostname, ".")
			}

			// Determine vendor hint from hostname patterns
			vendor := "Public IP"
			osType := "WAN Device"
			lowerHost := strings.ToLower(hostname)
			switch {
			case strings.Contains(lowerHost, "google") || strings.Contains(lowerHost, "gstatic") || strings.Contains(lowerHost, "1e100"):
				vendor = "Google/CDN"
				osType = "Google CDN"
			case strings.Contains(lowerHost, "cloudflare"):
				vendor = "Cloudflare"
				osType = "Cloudflare CDN"
			case strings.Contains(lowerHost, "amazonaws") || strings.Contains(lowerHost, "aws"):
				vendor = "Amazon AWS"
				osType = "AWS Cloud"
			case strings.Contains(lowerHost, "akamai"):
				vendor = "Akamai CDN"
				osType = "Akamai CDN"
			case strings.Contains(lowerHost, "azure"):
				vendor = "Microsoft Azure"
				osType = "Azure Cloud"
			case strings.Contains(lowerHost, "facebook") || strings.Contains(lowerHost, "fbcdn"):
				vendor = "Meta/Facebook"
				osType = "Meta CDN"
			case strings.Contains(lowerHost, "apple"):
				vendor = "Apple"
				osType = "Apple CDN"
			}

			s.Results <- Device{
				IP:       ipStr,
				MAC:      "public-wan",
				Hostname: hostname,
				Vendor:   vendor,
				OS:       osType,
			}

			// TCP SYN probe: port 80 and 443 (300ms timeout)
			go s.tcpProbePublicIP(ipStr)
		}
	}
}

// tcpProbePublicIP does a lightning-fast TCP connect scan on a public IP.
// If port 443 is open, it labels the device as "HTTPS / Web Server".
func (s *Scanner) tcpProbePublicIP(ip string) {
	timeout := 300 * time.Millisecond

	// Try port 443 first (most important for CDN/web detection)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err == nil {
		conn.Close()
		s.Results <- Device{
			IP:     ip,
			MAC:    "public-wan",
			Vendor: "HTTPS / Web Server",
			OS:     "Web Server (port 443 open)",
		}
		return
	}

	// Try port 80
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), timeout)
	if err == nil {
		conn.Close()
		s.Results <- Device{
			IP:     ip,
			MAC:    "public-wan",
			Vendor: "HTTP / Web Server",
			OS:     "Web Server (port 80 open)",
		}
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Crafting and Injecting ARP Packet
func (s *Scanner) sendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	handle.WritePacketData(buf.Bytes())
}

// Crafting and Injecting ICMP Packet
func (s *Scanner) sendICMP(handle *pcap.Handle, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
	}
	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1,
		Seq:      1,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &icmp, gopacket.Payload([]byte("ping")))
	handle.WritePacketData(buf.Bytes())
}

// Aggressive Multi-Protocol Hostname Lookup
// Uses NetBIOS (UDP 137) → mDNS (UDP 5353) → HTTP Title Scraping (Port 80/443/8080)
func (s *Scanner) lookupHostname(ip string) {
	hostname := GetAggressiveHostnameParallel(ip)

	// Aggressive Override: derive OS from hostname when possible.
	// This sends an OS hint alongside the hostname so the UI can replace
	// the ambiguous TTL-based guess (e.g. "Linux / IoT Device") with the
	// real device type (e.g. "Android" from "redmi-note-13-pro").
	osFromHostname := OverrideOSFromHostname(hostname, "")

	s.Results <- Device{
		IP:       ip,
		Hostname: hostname,
		OS:       osFromHostname,
	}
}

// verifyWindowsPorts attempts to connect to Windows-specific ports (135, 445)
// If open, it means it's likely a Windows machine running WSL/Docker with TTL=64
func (s *Scanner) verifyWindowsPorts(ip string) {
	timeout := 500 * time.Millisecond
	
	// Check Port 135 (RPC)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "135"), timeout)
	if err == nil {
		conn.Close()
		s.Results <- Device{IP: ip, OS: "Windows (WSL/Docker Active)"}
		return
	}

	// Check Port 445 (SMB)
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(ip, "445"), timeout)
	if err == nil {
		conn.Close()
		s.Results <- Device{IP: ip, OS: "Windows (WSL/Docker Active)"}
		return
	}
}

// verifyMikrotik attempts to connect to MikroTik Winbox Port (8291)
func (s *Scanner) verifyMikrotik(ip string) {
	timeout := 300 * time.Millisecond
	
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "8291"), timeout)
	if err == nil {
		conn.Close()
		s.Results <- Device{
			IP:     ip,
			Vendor: "MikroTik",
			OS:     "MikroTik (RouterOS)",
		}
	}
}

// passiveSniff runs as a goroutine and examines every raw packet captured in
// promiscuous mode. It extracts Source MAC + Source IP from Layer 2/3 headers
// regardless of whether the packet is aimed at our subnet. This is critical for
// detecting devices that sit on a different subnet (e.g., a MikroTik with a
// static IP while the laptop has an APIPA 169.254.x.x address).
func (s *Scanner) passiveSniff(packets <-chan gopacket.Packet, localMAC net.HardwareAddr, seen *map[string]bool, mu *sync.Mutex) {
	for {
		select {
		case <-s.done:
			return
		case pkt, ok := <-packets:
			if !ok || pkt == nil {
				return
			}

			// --- Layer 2: Ethernet Header ---
			ethLayer := pkt.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth := ethLayer.(*layers.Ethernet)
			srcMAC := eth.SrcMAC

			// Ignore packets originating from our own interface
			if srcMAC.String() == localMAC.String() {
				continue
			}

			// Ignore broadcast / multicast sources
			if srcMAC[0]&0x01 != 0 {
				continue
			}

			// --- Layer 3: IPv4 Header ---
			ipLayer := pkt.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue // Only interested in IPv4 packets for passive detection
			}
			ipv4 := ipLayer.(*layers.IPv4)
			srcIP := ipv4.SrcIP.String()

			// Filter out empty/unusable IPs
			if srcIP == "0.0.0.0" || srcIP == "" || srcIP == "<nil>" {
				continue
			}

			macStr := srcMAC.String()

			// Deduplicate: only report each MAC+IP combo once
			key := macStr + "|" + srcIP
			mu.Lock()
			if (*seen)[key] {
				mu.Unlock()
				continue
			}
			(*seen)[key] = true
			mu.Unlock()

			// Detect vendor and OS hint
			vendor, osType := DetectOS(macStr, ipv4.TTL)

			// Special tag for MikroTik OUI detected passively
			if isMikroTikOUI(macStr) {
				vendor = "MikroTik"
				osType = "MikroTik (Passive Detected)"
			}

			s.Results <- Device{
				IP:     srcIP,
				MAC:    macStr,
				Vendor: vendor,
				OS:     osType,
			}

			// Lakukan lookup Hostname untuk perangkat yang ditemukan secara pasif
			go s.lookupHostname(srcIP)

			// Also attempt active verification for MikroTik Winbox port
			if isMikroTikOUI(macStr) {
				go s.verifyMikrotik(srcIP)
			}
		}
	}
}

// isMikroTikOUI checks if a MAC address belongs to known MikroTik OUI prefixes.
func isMikroTikOUI(mac string) bool {
	mikroTikPrefixes := []string{
		"00:0c:42",
		"4c:5e:0c",
		"64:d1:54",
		"d4:ca:6d",
		"e8:28:c1",
		"2c:c8:1b",
		"6c:3b:6b",
		"74:4d:28",
		"b8:69:f4",
		"c4:ad:34",
		"cc:2d:e0",
		"dc:2c:6e",
	}
	macLower := strings.ToLower(mac)
	for _, prefix := range mikroTikPrefixes {
		if strings.HasPrefix(macLower, prefix) {
			return true
		}
	}
	return false
}
