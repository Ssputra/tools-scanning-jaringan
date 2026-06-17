package scanner

import (
	"strings"
)

// DetectOS guesses the OS and Vendor based on MAC OUI and TTL
func DetectOS(mac string, ttl uint8) (string, string) {
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(mac) >= 6 {
		mac = mac[:6]
	}

	vendor := "Unknown Vendor"
	osType := "Unknown OS"

	// 1. OUI Vendor Matching (Passive Fingerprinting)
	appleOUIs := []string{"000393", "3CD0F8", "F4F15A"}
	mikrotikOUIs := []string{"4C5E0C", "64D154", "D4CA6D", "000C42", "E828C1"}
	androidOUIs := []string{"CCB11A", "484BAA", "90187C", "001122"} // Common mobile device mock

	for _, oui := range appleOUIs {
		if strings.HasPrefix(mac, oui) {
			vendor = "Apple"
			break
		}
	}
	if vendor == "Unknown Vendor" {
		for _, oui := range mikrotikOUIs {
			if strings.HasPrefix(mac, oui) {
				vendor = "MikroTik"
				break
			}
		}
	}
	if vendor == "Unknown Vendor" {
		for _, oui := range androidOUIs {
			if strings.HasPrefix(mac, oui) {
				vendor = "Mobile/Android"
				break
			}
		}
	}

	// 2. OS Fingerprinting via TTL (Active Fingerprinting)
	// Windows typically uses 128. Linux/macOS/IoT typically use 64. 
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
