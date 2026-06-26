package ui

import (
	"fmt"
	"netscanner/scanner"
	"net"
	"sort"
	"strings"
	"time"

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
	modeLocalLAN    = 0
	modeExternal    = 1
	modePassiveOnly = 2
	modePortScanner = 3
)

// Mode menu labels
var modeLabels = []string{
	"[1] Local LAN Scan           (Layer 2 ARP, deteksi subnet otomatis di segmen yang sama)",
	"[2] External / WAN Scan      (Layer 3 ICMP, lacak rute gateway & scan beda subnet)",
	"[3] Pure Passive Sniffing    (Hanya mendengarkan kabel LAN, tidak peduli IP / beda subnet)",
	"[4] Custom Port Scanner      (Input IP target manual, scan port populer)",
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

// ── Interface Refresh Ticker ──────────────────────────────────────
type tickRefreshInterfacesMsg time.Time

func doInterfaceTick() tea.Cmd {
	return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
		return tickRefreshInterfacesMsg(t)
	})
}

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

		// Lipgloss .Width(n) sets CONTENT width only.
		// Border (1+1) + Padding (2+2) = 6 characters added OUTSIDE the content.
		// So to fit within terminal: container.ContentWidth = msg.Width - 6
		safeWidth := msg.Width - 6
		safeHeight := msg.Height - 4
		if safeWidth < 70 {
			safeWidth = 70
		}
		if safeHeight < 10 {
			safeHeight = 10
		}

		// Inner table: subtract 2 more for table internal padding
		availableWidth := safeWidth - 2
		if availableWidth < 60 {
			availableWidth = 60
		}

		// Responsive column widths — proportional to available terminal space
		newCols := []table.Column{
			{Title: "IP Address", Width: int(float32(availableWidth) * 0.15)},
			{Title: "MAC Address", Width: int(float32(availableWidth) * 0.15)},
			{Title: "Hostname", Width: int(float32(availableWidth) * 0.25)},
			{Title: "Vendor", Width: int(float32(availableWidth) * 0.20)},
			{Title: "Estimated OS", Width: int(float32(availableWidth) * 0.25)},
		}
		// Ensure minimum column widths so headers don't get clipped
		for i := range newCols {
			if newCols[i].Width < 10 {
				newCols[i].Width = 10
			}
		}

		m.table.SetColumns(newCols)
		m.table.SetWidth(availableWidth)

		tableHeight := safeHeight - 8
		if tableHeight < 3 {
			tableHeight = 3
		}
		m.table.SetHeight(tableHeight)

	case tea.KeyMsg:
		key := msg.String()

		// ══════════════════════════════════════════════════════════════
		// UNIVERSAL BACK NAVIGATION — runs before any component gets the event
		// ══════════════════════════════════════════════════════════════
		if key == "esc" || key == "b" {
			switch m.state {
			case stateSelectMode:
				// Root menu — do nothing (or quit)
			case stateSelectIface:
				m.state = stateSelectMode
				m.logMessage = "Pilih mode scanning untuk memulai."
				return m, nil
			case stateScanning:
				if m.scanner != nil {
					m.scanner.Stop()
				}
				m.state = stateSelectIface
				m.logMessage = "Pilih interface jaringan."
				return m, nil
			case stateInputPortIP:
				m.state = stateSelectMode
				m.logMessage = "Pilih mode scanning untuk memulai."
				m.portInput.SetValue("")
				return m, nil
			case statePortScanning:
				m.state = stateInputPortIP
				m.portInput.Focus()
				m.logMessage = "Masukkan IP target untuk port scan."
				m.portChan = nil
				return m, nil
			}
		}

		// Quit from anywhere
		if key == "ctrl+c" || key == "q" {
			if m.scanner != nil {
				m.scanner.Stop()
			}
			return m, tea.Quit
		}

		// ══════════════════════════════════════════════════════════════
		// STATE-ISOLATED KEY HANDLING — protects textinput/table from swallowing keys
		// ══════════════════════════════════════════════════════════════

		// stateInputPortIP: only enter goes through to logic, rest → textinput
		if m.state == stateInputPortIP {
			if key == "enter" {
				ip := strings.TrimSpace(m.portInput.Value())
				if ip == "" {
					m.logMessage = "IP tidak boleh kosong! Ketik IP target."
					return m, textinput.Blink
				}
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
			}
			// backspace, letters, numbers, dots → textinput only
			var cmd tea.Cmd
			m.portInput, cmd = m.portInput.Update(msg)
			return m, cmd
		}

		// statePortScanning: arrow keys → table scrolling, everything else ignored
		if m.state == statePortScanning {
			var cmd tea.Cmd
			m.portTable, cmd = m.portTable.Update(msg)
			return m, cmd
		}

		// ══════════════════════════════════════════════════════════════
		// REMAINING STATES: mode selection, interface, scanning
		// ══════════════════════════════════════════════════════════════
		switch key {
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
			case stateSelectMode:
				if m.modeCursor == modePortScanner {
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
				case modeLocalLAN:
					m.logMessage = "Local LAN Scan dipilih. Pilih interface jaringan..."
				case modeExternal:
					m.logMessage = "External / WAN Scan dipilih. Pilih interface jaringan..."
				case modePassiveOnly:
					m.logMessage = "Pure Passive Sniffing dipilih. Pilih interface jaringan..."
				}
				return m, doInterfaceTick()

			case stateSelectIface:
				if len(m.interfaces) > 0 {
					m.state = stateScanning
					selectedIface := m.interfaces[m.cursor]

					var engineMode string
					switch m.scanMode {
					case modeLocalLAN:
						engineMode = scanner.ModeActiveOnly
					case modeExternal:
						engineMode = scanner.ModeExternal
					case modePassiveOnly:
						engineMode = scanner.ModePassiveOnly
					}

					m.scanner = scanner.NewScanner(selectedIface.Name, engineMode)

					var err error
					switch m.scanMode {
					case modeLocalLAN:
						m.logMessage = "Local LAN Scan (ARP Broadcast) via " + selectedIface.Name + "..."
						err = m.scanner.StartActiveOnly()
					case modeExternal:
						m.logMessage = "External / WAN Scan (ICMP TTL Trace) via " + selectedIface.Name + "..."
						err = m.scanner.StartExternalScan(selectedIface.Name)
					case modePassiveOnly:
						m.logMessage = "Pure Passive Sniffing (Mendengarkan ocehan paket di kabel LAN) via " + selectedIface.Name + "..."
						err = m.scanner.StartPassive()
					}
					if err != nil {
						m.err = err
						return m, nil
					}
					return m, waitForDevice(m.scanner.Results)
				}
			}
		}

	case DeviceFoundMsg:
		d, exists := m.devices[msg.IP]
		if !exists {
			d = scanner.Device(msg)
		} else {
			if msg.MAC != "" {
				d.MAC = msg.MAC
			}
			if msg.Hostname != "" {
				d.Hostname = msg.Hostname
			}
			if msg.Vendor != "" && msg.Vendor != "Unknown Vendor" {
				d.Vendor = msg.Vendor
			}
			if msg.OS != "" && msg.OS != "Unknown OS" && msg.OS != "Probing TTL..." {
				d.OS = msg.OS
			}
		}
		m.devices[msg.IP] = d

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
		return m, waitForDevice(m.scanner.Results)

	case PortResultMsg:
		r := scanner.PortResult(msg)
		m.portResults = append(m.portResults, r)

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
		m.logMessage = fmt.Sprintf("Port scan selesai: %d port terbuka dari %d port di %s.",
			openCount, len(m.portResults), m.targetPortIP)

	case tickRefreshInterfacesMsg:
		// Auto-refresh network interfaces while user is on interface selection page
		if m.state == stateSelectIface {
			newIfaces, err := pcap.FindAllDevs()
			if err == nil {
				m.interfaces = newIfaces
				// Keep cursor in bounds
				if m.cursor >= len(m.interfaces) && len(m.interfaces) > 0 {
					m.cursor = len(m.interfaces) - 1
				}
			}
			return m, doInterfaceTick()
		}
	}

	// Table scrolling for scanning state
	if m.state == stateScanning {
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if m.err != nil {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Padding(1, 2).Render(fmt.Sprintf("ERROR\n\n%v\n\nTekan 'q' untuk keluar.", m.err))
	}

	// Lipgloss: .Width(n) = content only. Border(1+1) + Padding(2+2) = +6 total.
	// So container content width = terminal width - 6
	safeW := m.terminalWidth - 6
	safeH := m.terminalHeight - 4
	if safeW < 70 {
		safeW = 70
	}
	if safeH < 10 {
		safeH = 10
	}

	containerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("27")).
		Padding(1, 2).
		Width(safeW).
		Height(safeH)

	header := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true).Render("*** SUPER AWESOME SCANNER ***")

	var middleContent string
	switch m.state {
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

	case stateSelectIface:
		var s strings.Builder
		var modeTag string
		switch m.scanMode {
		case modeLocalLAN:
			modeTag = "Local LAN Scan"
		case modeExternal:
			modeTag = "External / WAN Scan"
		case modePassiveOnly:
			modeTag = "Pure Passive Sniffing"
		}
		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("Mode: "+modeTag) + "\n")
		s.WriteString("Pilih Network Interface (Gunakan panah ↑/↓, Enter untuk pilih):\n\n")
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
		middleContent = s.String()

	case stateScanning:
		middleContent = m.table.View()

	case stateInputPortIP:
		var s strings.Builder
		s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")).Render("═══ Custom Port Scanner ═══") + "\n\n")
		s.WriteString("Masukkan IP address target yang ingin di-scan:\n\n")
		inputBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("86")).
			Padding(0, 1).
			Width(50).
			Render(m.portInput.View())
		s.WriteString(inputBox + "\n\n")
		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(
			"  Contoh: 192.168.1.1, 10.0.0.1, 172.16.0.1\n" +
				"  Port yang di-scan: SEMUA port (1 - 65535) via 1500 goroutine worker"))
		middleContent = s.String()

	case statePortScanning:
		var s strings.Builder
		title := "═══ Port Scan: " + m.targetPortIP + " ═══"
		if m.portScanDone {
			title = "═══ Port Scan Complete: " + m.targetPortIP + " ═══"
		}
		s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render(title) + "\n")

		if len(m.portResults) == 0 && !m.portScanDone {
			s.WriteString("\n  Scanning all 65535 ports on " + m.targetPortIP + "... please wait.\n")
			s.WriteString("  1500 goroutine workers | TCP connect | 250ms timeout per port\n\n")
			s.WriteString("  Sedang memindai...\n")
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
		middleContent = s.String()
	}

	// Universal footer
	logLine := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render("Log: " + m.logMessage)
	keysLine := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("• [esc/b] Kembali • [q] Keluar")

	content := lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		middleContent,
		"",
		logLine,
		keysLine,
	)

	return containerStyle.Render(content)
}
