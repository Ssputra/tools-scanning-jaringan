# Local Network Asset Inventory & Diagnostic Tool

Aplikasi TUI berbasis [Bubble Tea](https://github.com/charmbracelet/bubbletea) untuk manajemen jaringan internal yang berfungsi mendeteksi perangkat-perangkat di jaringan lokal melalui antarmuka terminal.

Aplikasi ini menggunakan protokol ARP dan ICMP secara asinkron untuk menemukan _IP Address_, _MAC Address_, _Device Type Hint_ (berdasarkan OUI prefix), dan _Estimated OS_ (berdasarkan TTL IPv4).

## Fitur Utama
1. **Pemilihan Interface Jaringan**: Pengguna dapat memilih network interface mana yang akan digunakan untuk scanning.
2. **ARP Scanning Asinkron**: Mengirimkan broadcast ARP secara agresif untuk menemukan perangkat di subnet lokal secara _real-time_ tanpa memblokir antarmuka pengguna (TUI).
3. **OS Fingerprinting via ICMP (TTL)**: Mengirimkan ICMP Echo Request untuk membaca nilai TTL balasan. TTL standar (contoh: 128 untuk Windows, 64 untuk Linux/Mobile) digunakan untuk memperkirakan jenis sistem operasi.
4. **Device Type Hinting via OUI**: Membaca prefix _MAC Address_ untuk mendeteksi _vendor_ tertentu seperti Apple, MikroTik (`4C:5E:0C`, `64:D1:54`), atau perangkat Mobile/Android.
5. **Dashboard TUI Modern**: Menggunakan tabel yang rapi dari library _Bubble Tea_ dan _Lipgloss_ untuk merender log _status_, tabel inventaris, dan _shortcut_ kontrol.

## Prasyarat (Prerequisites)

Aplikasi ini menggunakan `github.com/google/gopacket` untuk mengirim dan mencium lalu lintas jaringan tingkat rendah (_raw sockets_). Oleh karena itu, aplikasi ini memerlukan hak akses tinggi dan _library_ pihak ketiga.

### Untuk Windows
- **Npcap**: Anda wajib menginstal Npcap. Pastikan Anda mencentang _"Install Npcap in WinPcap API-compatible Mode"_ saat proses instalasi. [Unduh Npcap di sini](https://npcap.com/#download).
- **Hak Akses**: Buka terminal as Administrator (`Run as Administrator`) saat mengeksekusi `go run main.go`.

### Untuk Linux
- **libpcap**: Instal dependensi pengembangan `libpcap`.
  ```bash
  sudo apt-get install libpcap-dev
  ```
- **Hak Akses**: Jalankan menggunakan `sudo`.
  ```bash
  sudo go run main.go
  ```

### Untuk macOS
- macOS secara *native* sudah menyertakan `libpcap`. 
- **Hak Akses**: Jalankan menggunakan `sudo`.
  ```bash
  sudo go run main.go
  ```

## Cara Instalasi dan Penggunaan

1. Clone atau salin repository ini.
2. Unduh dan sinkronisasikan _dependencies_:
   ```bash
   go mod tidy
   ```
3. Bangun (_build_) aplikasi:
   ```bash
   go build -o netscanner main.go
   ```
4. Jalankan aplikasi (dengan hak akses Administrator / root):
   - Di Windows: `.\netscanner.exe` (Di Command Prompt / PowerShell yang terbuka sebagai Administrator).
   - Di Linux / macOS: `sudo ./netscanner`

## Struktur Kode
- `main.go` - Entrypoint aplikasi.
- `ui/app.go` - Model *state-machine* Bubble Tea untuk rendering UI (Tabel, List Interface, Error Handling).
- `scanner/engine.go` - Logika pemindaian (_Pcap live capture_, broadcast ARP, _injection_ paket ICMP).
- `scanner/fingerprint.go` - Logika penentuan estimasi _Operating System_ (OS) dan Vendor berbasis TTL & OUI MAC Address.
