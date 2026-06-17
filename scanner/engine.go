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

				// 1. Sniff ARP Replies
				if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					if arp.Operation == layers.ARPReply {
						targetMAC := net.HardwareAddr(arp.SourceHwAddress)
						targetIP := net.IP(arp.SourceProtAddress)

						// Initial OS detect without TTL (Passive)
						vendor, osType := DetectOS(targetMAC.String(), 0)
						s.Results <- Device{
							IP:     targetIP.String(),
							MAC:    targetMAC.String(),
							Vendor: vendor,
							OS:     osType,
						}

						// 2. Send Active Probe (ICMP Echo Request) to trigger IP response for TTL
						s.sendICMP(handle, srcMAC, targetMAC, srcIP, targetIP)

						// 2b. Start TTL probe timeout (3 detik)
						s.startTTLTimeout(targetIP.String(), 3*time.Second)

						// 3. Asynchronous Hostname Lookup
						go s.lookupHostname(targetIP.String())

						// 4. Asynchronous MikroTik Probing (Winbox Port 8291)
						go s.verifyMikrotik(targetIP.String())
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

				// 1. Sniff ARP Replies
				if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					if arp.Operation == layers.ARPReply {
						targetMAC := net.HardwareAddr(arp.SourceHwAddress)
						targetIP := net.IP(arp.SourceProtAddress)

						vendor, osType := DetectOS(targetMAC.String(), 0)
						s.Results <- Device{
							IP:     targetIP.String(),
							MAC:    targetMAC.String(),
							Vendor: vendor,
							OS:     osType,
						}

						s.sendICMP(handle, srcMAC, targetMAC, srcIP, targetIP)

						// Start TTL probe timeout (3 detik)
						s.startTTLTimeout(targetIP.String(), 3*time.Second)

						go s.lookupHostname(targetIP.String())
						go s.verifyMikrotik(targetIP.String())
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

// Asynchronous Reverse DNS Lookup
func (s *Scanner) lookupHostname(ip string) {
	names, err := net.LookupAddr(ip)
	hostname := "Unknown Name"
	if err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	s.Results <- Device{
		IP:       ip,
		Hostname: hostname,
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
