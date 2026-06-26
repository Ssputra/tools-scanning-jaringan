package ui

import (
	"fmt"
	"netscanner/scanner"
	"net"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket/pcap"
)

// ── Application States ──────────────────────────────────────────────
const (
	stateSelectMode    = iota // Halaman 1: Pilih mode scanning
	stateSelectIface          // Halaman 2: Pilih network interface
	stateScanning             // Halaman 3: Tabel hasil scan
	stateInputPortIP          // Halaman 4: Form input IP target port scan
	statePortScanning         // Halaman 5: Tabel hasil port scan
)

// ── Scan Mode Constants (indices into modeLabels) ───────────────────
const (
	modeActiveOnly  = 0
	modeHybrid      = 1
	modePassiveOnly = 2
	modePortScanner = 3
)

// Mode menu labels
var modeLabels = []string{
	"[1] Active Scan Only        (Hanya ARP Broadcast, deteksi subnet otomatis)",
	"[2] Hybrid Scan             (ARP Broadcast + Passive Sniffing, butuh IP valid)",
	"[3] Pure Passive Sniffing   (Hanya mendengarkan kabel LAN, tidak peduli IP / beda subnet)",
	"[4] Custom Port Scanner     (Input IP target manual, scan port populer)",
}

type model struct {
	state          int
	scanMode       int // modeActiveOnly, modeHybrid, atau modePassiveOnly
	interfaces     []pcap.Interface
	cursor         int
	modeCursor     int // cursor untuk halaman mode selection
	scanner        *scanner.Scanner
	devices        map[string]scanner.Device // key: IP
	table          table.Model
	err            error
	logMessage     string
	terminalWidth  int // lebar terminal aktif
	terminalHeight int // tinggi terminal aktif
	// Port Scanner fields
	portInput   textinput.Model
	targetPortIP string
	portResults  []scanner.PortResult
	portTable    table.Model
	portChan     <-chan scanner.PortResult
	portScanDone bool
}

type DeviceFoundMsg scanner.Device

// ── Port Scanner Messages ──────────────────────────────────────────
type PortResultMsg scanner.PortResult
type PortScanDoneMsg struct{}

func InitialModel() tea.Model {
	ifaces, err := pcap.FindAllDevs()

	// Text input for port scanner IP
	ti := textinput.New()
	ti.Placeholder = "Masukkan IP Target (Contoh: 192.168.1.1)"
	ti.Focus()
	ti.CharLimit = 45
	ti.Width = 40

	m := model{
		state:      stateSelectMode, // Mulai dari halaman pilih mode
		interfaces: ifaces,
		devices:    make(map[string]scanner.Device),
		logMessage: "Pilih mode scanning untuk memulai.",
		portInput:  ti,
	}

	// Error handling khusus untuk perizinan dan pcap
	if err != nil {
		m.err = fmt.Errorf("gagal melist interface jaringan. Pastikan:\n1. Npcap terinstall (Windows) atau libpcap (Linux).\n2. Jalankan aplikasi ini sebagai Administrator/Sudo.\n\nDetail Error: %v", err)
	}

	columns := []table.Column{
		{Title: "IP Address", Width: 18},
		{Title: "MAC Address", Width: 20},
		{Title: "Hostname", Width: 18},
		{Title: "Vendor", Width: 18},
		{Title: "Estimated OS", Width: 22},
	}
	m.table = table.New(
		table.WithColumns(columns),
		table.WithHeight(10),
		table.WithFocused(true), // PENTING: Agar navigasi panah berfungsi
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Bold(false)
	m.table.SetStyles(s)

	// Port Scanner result table
	fpColumns := []table.Column{
		{Title: "Port", Width: 8},
		{Title: "Status", Width: 10},
		{Title: "Service", Width: 20},
	}
	m.portTable = table.New(
		table.WithColumns(fpColumns),
		table.WithHeight(15),
		table.WithFocused(true),
	)
	fpStyles := table.DefaultStyles()
	fpStyles.Header = fpStyles.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(true)
	fpStyles.Selected = fpStyles.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Bold(false)
	m.portTable.SetStyles(fpStyles)

	return m
}

// Goroutine bridge ke BubbleTea loop
func waitForDevice(sub chan scanner.Device) tea.Cmd {
	return func() tea.Msg {
		return DeviceFoundMsg(<-sub)
	}
}

// waitForPortResult reads one port scan result from the channel.
func waitForPortResult(ch <-chan scanner.PortResult) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return PortScanDoneMsg{}
		}
		return PortResultMsg(r)
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.terminalWidth = msg.Width
		m.terminalHeight = msg.Height

		// Atur lebar tabel = lebar terminal - margin(2) - border luar(2) - padding dalam(4)
		m.table.SetWidth(msg.Width - 8)

		// Atur tinggi tabel dinamis: terminal - margin/border/padding(7) - header(1) - footer(2) - spasi(2)
		tableHeight := msg.Height - 12
		if tableHeight < 3 {
			tableHeight = 3
		}
		m.table.SetHeight(tableHeight)

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.scanner != nil {
				m.scanner.Stop()
			}
			return m, tea.Quit

		case "up", "k":
			switch m.state {
			case stateSelectMode:
				if m.modeCursor > 0 {
					m.modeCursor--
				}
			case stateSelectIface:
				if m.cursor > 0 {
					m.cursor--
				}
			}

		case "down", "j":
			switch m.state {
			case stateSelectMode:
				if m.modeCursor < len(modeLabels)-1 {
					m.modeCursor++
				}
			case stateSelectIface:
				if m.cursor < len(m.interfaces)-1 {
					m.cursor++
				}
			}

		case "enter", "s":
			switch m.state {
			// ── Halaman 1: Mode Selection ───────────────────────
			case stateSelectMode:
				if m.modeCursor == modePortScanner {
					// Port Scanner mode → langsung ke form input IP
					m.scanMode = modePortScanner
					m.state = stateInputPortIP
					m.portInput.SetValue("")
					m.portInput.Focus()
					m.logMessage = "Masukkan IP target untuk port scan. Enter untuk mulai, Esc untuk batal."
					return m, textinput.Blink
				}
				m.scanMode = m.modeCursor
				m.state = stateSelectIface
				m.cursor = 0
				switch m.scanMode {
				case modeActiveOnly:
					m.logMessage = "Mode: Active Scan Only dipilih. Pilih interface jaringan..."
				case modeHybrid:
					m.logMessage = "Mode: Hybrid Scan dipilih. Pilih interface jaringan..."
				case modePassiveOnly:
					m.logMessage = "Mode: Pure Passive Sniffing dipilih. Pilih interface jaringan..."
				}

			// ── Halaman 4: Port Scanner IP Input ───────────────
			case stateInputPortIP:
				ip := strings.TrimSpace(m.portInput.Value())
				if ip == "" {
					m.logMessage = "IP tidak boleh kosong! Ketik IP target."
					return m, textinput.Blink
				}
				// Validate IP format
				if net.ParseIP(ip) == nil {
					m.logMessage = "Format IP tidak valid! Contoh: 192.168.1.1"
					return m, textinput.Blink
				}
				m.targetPortIP = ip
				m.state = statePortScanning
				m.portResults = nil
				m.portScanDone = false
				m.logMessage = "Port scanning " + ip + " sedang berjalan..."

				portChan := make(chan scanner.PortResult, 50)
				m.portChan = portChan
				go scanner.ScanTargetPorts(ip, portChan)
				return m, waitForPortResult(m.portChan)

			// ── Halaman 2: Interface Selection ──────────────────
			case stateSelectIface:
				if len(m.interfaces) > 0 {
					m.state = stateScanning
					selectedIface := m.interfaces[m.cursor]

					// Map UI mode index ke engine ScanMode constant
					var engineMode string
					switch m.scanMode {
					case modeActiveOnly:
						engineMode = scanner.ModeActiveOnly
					case modeHybrid:
						engineMode = scanner.ModeHybrid
					case modePassiveOnly:
						engineMode = scanner.ModePassiveOnly
					}

					m.scanner = scanner.NewScanner(selectedIface.Name, engineMode)

					var err error
					switch m.scanMode {
					case modeActiveOnly:
						m.logMessage = "Mode: Active Scan Only (ARP Broadcast saja) via " + selectedIface.Name + "..."
						err = m.scanner.StartActiveOnly()
					case modeHybrid:
						m.logMessage = "Mode: Hybrid Scan (ARP + Passive Sniffing) via " + selectedIface.Name + "..."
						err = m.scanner.Start()
					case modePassiveOnly:
						m.logMessage = "Mode: Pure Passive Sniffing (Mendengarkan ocehan paket di kabel LAN) via " + selectedIface.Name + "..."
						err = m.scanner.StartPassive()
					}
					if err != nil {
						m.err = err
						return m, nil
					}
					// Mulai mendengarkan goroutine scanner
					return m, waitForDevice(m.scanner.Results)
				}
			}

		case "backspace", "esc":
			switch m.state {
			case stateSelectIface:
				m.state = stateSelectMode
				m.logMessage = "Pilih mode scanning untuk memulai."
			case stateInputPortIP:
				m.state = stateSelectMode
				m.logMessage = "Pilih mode scanning untuk memulai."
				m.portInput.SetValue("")
			case statePortScanning:
				// Kembali ke form input, stop scan
				m.state = stateInputPortIP
				m.portInput.Focus()
				m.logMessage = "Masukkan IP target untuk port scan."
				m.portChan = nil
			}
		}

	case DeviceFoundMsg:
		// Smart merge so background Hostname probing doesn't overwrite OS/Vendor
		d, exists := m.devices[msg.IP]
		if !exists {
			d = scanner.Device(msg)
		} else {
			if msg.MAC != "" { d.MAC = msg.MAC }
			if msg.Hostname != "" { d.Hostname = msg.Hostname }
			if msg.Vendor != "" && msg.Vendor != "Unknown Vendor" { d.Vendor = msg.Vendor }
			if msg.OS != "" && msg.OS != "Unknown OS" && msg.OS != "Probing TTL..." { d.OS = msg.OS }
		}
		m.devices[msg.IP] = d

		// Sorting IP dinamis untuk tabel
		var ips []string
		for ip := range m.devices {
			ips = append(ips, ip)
		}
		sort.Strings(ips)

		var rows []table.Row
		for _, ip := range ips {
			d := m.devices[ip]
			rows = append(rows, table.Row{d.IP, d.MAC, d.Hostname, d.Vendor, d.OS})
		}
		m.table.SetRows(rows)
		return m, waitForDevice(m.scanner.Results) // Dengarkan hasil selanjutnya

	case PortResultMsg:
		r := scanner.PortResult(msg)
		m.portResults = append(m.portResults, r)

		// Update port table sorted by port number
		sorted := scanner.SortPortResults(m.portResults)
		var rows []table.Row
		for _, r := range sorted {
			rows = append(rows, table.Row{
				fmt.Sprintf("%d", r.Port),
				r.Status,
				r.Service,
			})
		}
		m.portTable.SetRows(rows)
		return m, waitForPortResult(m.portChan)

	case PortScanDoneMsg:
		m.portScanDone = true
		m.portChan = nil
		openCount := 0
		for _, r := range m.portResults {
			if r.Status == "open" {
				openCount++
			}
		}
		m.logMessage = fmt.Sprintf("Port scan selesai: %d port ditemukan terbuka dari %d port di %s. Tekan 'b' atau Esc untuk kembali.",
			openCount, len(m.portResults), m.targetPortIP)
	}

	// Update list/table default BubbleTea
	if m.state == stateScanning {
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		cmds = append(cmds, cmd)
	}
	if m.state == statePortScanning {
		var cmd tea.Cmd
		m.portTable, cmd = m.portTable.Update(msg)
		cmds = append(cmds, cmd)
	}
	if m.state == stateInputPortIP {
		var cmd tea.Cmd
		m.portInput, cmd = m.portInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if m.err != nil {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Padding(1, 2).Render(fmt.Sprintf("ERROR\n\n%v\n\nTekan 'q' untuk keluar.", m.err))
	}

	containerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("27")). // Kode warna biru
		Padding(1, 2).
		Width(m.terminalWidth - 2). // Sisakan margin tipis agar aman di CMD
		Height(m.terminalHeight - 3)

	header := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true).Render("*** SUPER AWESOME SCANNER ***")

	var middleContent string
	switch m.state {
	// ── Halaman 1: Mode Selection ───────────────────────────────
	case stateSelectMode:
		var s strings.Builder
		s.WriteString(lipgloss.NewStyle().Bold(true).Render("Pilih Mode Scanning") + " (Gunakan panah ↑/↓, Enter untuk pilih):\n\n")
		for i, label := range modeLabels {
			cursor := "  "
			style := lipgloss.NewStyle()
			if m.modeCursor == i {
				cursor = "▸ "
				style = style.Bold(true).Foreground(lipgloss.Color("86"))
			} else {
				style = style.Foreground(lipgloss.Color("252"))
			}
			s.WriteString(style.Render(cursor+label) + "\n")
		}
		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n  Tip: Gunakan 'Pure Passive' jika laptop kamu beda subnet / IP APIPA.\n"))
		middleContent = s.String()

	// ── Halaman 2: Interface List ───────────────────────────────
	case stateSelectIface:
		var s strings.Builder
		var modeTag string
		switch m.scanMode {
		case modeActiveOnly:
			modeTag = "Active Scan Only"
		case modeHybrid:
			modeTag = "Hybrid Scan"
		case modePassiveOnly:
			modeTag = "Pure Passive Sniffing"
		}
		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("Mode: "+modeTag) + "\n")
		s.WriteString("Pilih Network Interface (Gunakan panah ↑/↓, Enter untuk pilih, Esc kembali):\n\n")
		for i, iface := range m.interfaces {
			cursor := "  "
			if m.cursor == i {
				cursor = "▸ "
			}
			desc := iface.Description
			if desc == "" {
				desc = iface.Name
			}
			ipStr := "Tanpa IPv4"
			if len(iface.Addresses) > 0 {
				ipStr = iface.Addresses[0].IP.String()
			}
			s.WriteString(fmt.Sprintf("%s[%-15s] %s\n", cursor, ipStr, desc))
		}
		s.WriteString("\nTekan Enter (atau 's') untuk memulai, Esc untuk kembali, 'q' untuk keluar.\n")
		middleContent = s.String()

	// ── Halaman 3: Scanning Results ─────────────────────────────
	case stateScanning:
		middleContent = m.table.View()

	// ── Halaman 4: Port Scanner IP Input ──────────────────────
	case stateInputPortIP:
		var s strings.Builder
		s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")).Render("═══ Custom Port Scanner ═══") + "\n\n")
		s.WriteString("Masukkan IP address target yang ingin di-scan:\n\n")

		// Styled input box
		inputBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("86")).
			Padding(0, 1).
			Width(50).
			Render(m.portInput.View())
		s.WriteString(inputBox + "\n\n")

		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(
			"  Contoh: 192.168.1.1, 10.0.0.1, 172.16.0.1\n" +
				"  Port yang di-scan: 21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080,8443,9100\n\n" +
				"  Enter untuk mulai scan | Esc untuk kembali"))
		middleContent = s.String()

	// ── Halaman 5: Port Scanning Results ──────────────────────
	case statePortScanning:
		var s strings.Builder
		title := "═══ Port Scan: " + m.targetPortIP + " ═══"
		if m.portScanDone {
			title = "═══ Port Scan Complete: " + m.targetPortIP + " ═══"
		}
		s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render(title) + "\n")

		if len(m.portResults) == 0 && !m.portScanDone {
			s.WriteString("\n  Sedang memindai port pada " + m.targetPortIP + "...\n")
			s.WriteString("  Menggunakan TCP connect scan dengan " + fmt.Sprintf("%d", 24) + " port populer.\n\n")
			s.WriteString("  Mohon tunggu...\n")
		} else {
			openCount := 0
			for _, r := range m.portResults {
				if r.Status == "open" {
					openCount++
				}
			}
			s.WriteString(fmt.Sprintf("  Port terbuka: %d | Total di-scan: %d\n\n", openCount, len(m.portResults)))
			s.WriteString(m.portTable.View())
		}

		if m.portScanDone {
			s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n  Tekan 'b' atau Esc untuk kembali.\n"))
		} else {
			s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n  Tekan 'b' atau Esc untuk membatalkan.\n"))
		}
		middleContent = s.String()
	}

	logLine := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render("Log: " + m.logMessage)
	keysLine := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("Keybindings: ↑/↓ untuk navigasi, Enter untuk pilih, 'q' untuk Quit")

	content := lipgloss.JoinVertical(lipgloss.Left,
		header,
		"", // Spasi
		middleContent,
		"", // Spasi
		logLine,
		keysLine,
	)

	return containerStyle.Render(content)
}
