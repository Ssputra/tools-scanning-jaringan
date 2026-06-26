package scanner

import (
	"strings"
)

// DetectOS guesses the OS and Vendor based on MAC OUI and TTL
func DetectOS(mac string, ttl uint8) (string, string) {
	// --- Aggressive Override: Local Administered MAC (Randomized) ---
	// IEEE 802: if bit 1 (LSB of first byte) == 1, MAC is locally administered.
	// Parse raw MAC bytes before stripping separators.
	rawHex := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	vendor := "Unknown Vendor"

	if len(rawHex) >= 2 {
		// First byte as two hex digits
		var firstByte byte
		if len(rawHex) >= 2 {
			for _, b := range []byte(rawHex[:2]) {
				firstByte <<= 4
				if b >= '0' && b <= '9' {
					firstByte |= b - '0'
				} else if b >= 'A' && b <= 'F' {
					firstByte |= b - 'A' + 10
				}
			}
		}
		// Bit 1 (0x02) = Locally Administered / Randomized MAC
		if firstByte&0x02 != 0 {
			vendor = "Randomized MAC (Privacy)"
		}
	}

	osType := "Unknown OS"

	// --- OUI Vendor Matching (only if not already overridden by Randomized MAC) ---
	oui6 := rawHex
	if len(oui6) >= 6 {
		oui6 = oui6[:6]
	}

	appleOUIs := []string{"000393", "3CD0F8", "F4F15A"}
	mikrotikOUIs := []string{"4C5E0C", "64D154", "D4CA6D", "000C42", "E828C1"}
	androidOUIs := []string{"CCB11A", "484BAA", "90187C", "001122"}

	if vendor == "Unknown Vendor" {
		for _, oui := range appleOUIs {
			if strings.HasPrefix(oui6, oui) {
				vendor = "Apple"
				break
			}
		}
	}
	if vendor == "Unknown Vendor" {
		for _, oui := range mikrotikOUIs {
			if strings.HasPrefix(oui6, oui) {
				vendor = "MikroTik"
				break
			}
		}
	}
	if vendor == "Unknown Vendor" {
		for _, oui := range androidOUIs {
			if strings.HasPrefix(oui6, oui) {
				vendor = "Mobile/Android"
				break
			}
		}
	}

	// --- OS Fingerprinting via TTL (Active Fingerprinting) ---
	if ttl == 0 {
		osType = "Probing TTL..."
	} else if ttl > 64 && ttl <= 128 {
		osType = "Windows"
	} else if ttl <= 64 {
		if vendor == "Apple" {
			osType = "macOS/iOS"
		} else if vendor == "MikroTik" {
			osType = "MikroTik Device"
		} else if vendor == "Mobile/Android" {
			osType = "Android Device"
		} else {
			osType = "Linux / IoT Device"
		}
	} else {
		osType = "Network Device / Other"
	}

	return vendor, osType
}

// OverrideOSFromHostname performs aggressive OS detection by inspecting hostname
// patterns. When the TTL-based estimate is ambiguous (e.g., "Linux / IoT Device"
// for TTL=64), the hostname often reveals the real OS (Android, iOS, Windows).
func OverrideOSFromHostname(hostname, currentOS string) string {
	if hostname == "" {
		return currentOS
	}

	h := strings.ToLower(hostname)

	// Android device families
	androidKeywords := []string{
		"android", "redmi", "poco", "xiaomi", "samsung", "galaxy",
		"oppo", "vivo", "realme", "infinix", "asus",
	}
	for _, kw := range androidKeywords {
		if strings.Contains(h, kw) {
			return "Android"
		}
	}

	// Apple device families
	appleKeywords := []string{
		"iphone", "ipad", "macbook", "apple", "airpods", "homepod",
	}
	for _, kw := range appleKeywords {
		if strings.Contains(h, kw) {
			return "Apple Device (iOS/macOS)"
		}
	}

	// Windows device families
	winKeywords := []string{
		"win", "desktop", "laptop",
	}
	for _, kw := range winKeywords {
		if strings.Contains(h, kw) {
			return "Windows"
		}
	}

	return currentOS
}
