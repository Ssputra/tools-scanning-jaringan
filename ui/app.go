package ui

import (
	"fmt"
	"netscanner/scanner"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket/pcap"
)

// ── Application States ──────────────────────────────────────────────
const (
	stateSelectMode  = iota // Halaman 1: Pilih mode scanning
	stateSelectIface        // Halaman 2: Pilih network interface
	stateScanning           // Halaman 3: Tabel hasil scan
)

// ── Scan Mode Constants (indices into modeLabels) ───────────────────
const (
	modeActiveOnly   = 0
	modeHybrid       = 1
	modePassiveOnly  = 2
)

// Mode menu labels
var modeLabels = []string{
	"[1] Active Scan Only        (Hanya ARP Broadcast, deteksi subnet otomatis)",
	"[2] Hybrid Scan             (ARP Broadcast + Passive Sniffing, butuh IP valid)",
	"[3] Pure Passive Sniffing   (Hanya mendengarkan kabel LAN, tidak peduli IP / beda subnet)",
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
}

type DeviceFoundMsg scanner.Device

func InitialModel() tea.Model {
	ifaces, err := pcap.FindAllDevs()
	m := model{
		state:      stateSelectMode, // Mulai dari halaman pilih mode
		interfaces: ifaces,
		devices:    make(map[string]scanner.Device),
		logMessage: "Pilih mode scanning untuk memulai.",
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

	return m
}

// Goroutine bridge ke BubbleTea loop
func waitForDevice(sub chan scanner.Device) tea.Cmd {
	return func() tea.Msg {
		return DeviceFoundMsg(<-sub)
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
				m.scanMode = m.modeCursor
				m.state = stateSelectIface
				m.cursor = 0 // reset cursor untuk interface list
				switch m.scanMode {
				case modeActiveOnly:
					m.logMessage = "Mode: Active Scan Only dipilih. Pilih interface jaringan..."
				case modeHybrid:
					m.logMessage = "Mode: Hybrid Scan dipilih. Pilih interface jaringan..."
				case modePassiveOnly:
					m.logMessage = "Mode: Pure Passive Sniffing dipilih. Pilih interface jaringan..."
				}

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
			// Navigasi mundur antar halaman
			if m.state == stateSelectIface {
				m.state = stateSelectMode
				m.logMessage = "Pilih mode scanning untuk memulai."
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
	}

	// Update list/table default BubbleTea
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
