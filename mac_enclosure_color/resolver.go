package main

// resolveColor maps a Mac's product type, model name, and MobileGestalt
// DeviceEnclosureColor numeric code to a human-readable color name.
//
// The mapping mirrors the convention used by munkireport's iBridge module
// (https://github.com/munkireport/ibridge), which is the canonical reference
// in the Mac admin community. The same numeric code maps to different colors
// on different Mac product lines (e.g. code 3 = Yellow on iMac, Gold on
// MacBook Air), so model name disambiguation is required.
func resolveColor(productType, model string, code int, codeKnown bool) string {
	// Model-specific forced values (these override any code-based logic).
	if productType == "Macmini8,1" || productType == "iMacPro1,1" {
		return "Space Gray"
	}
	if productType == "iMac20,1" || productType == "iMac20,2" {
		return "Silver"
	}
	if model == "Mac mini" || model == "Mac Pro" || model == "Mac Studio" {
		return "Silver"
	}

	if !codeKnown {
		return "Unknown"
	}

	// Universal codes (apply across all models).
	switch code {
	case 1:
		return "Silver"
	case 2:
		return "Space Gray"
	case 4:
		return "Green"
	case 5:
		return "Blue"
	case 6:
		return "Red"
	case 9:
		return "Space Black"
	case 12:
		return "Indigo"
	case 13:
		return "Citrus"
	case 14:
		return "Blush"
	}

	// Model-disambiguated codes.
	switch {
	case code == 3 && model == "iMac":
		return "Yellow"
	case code == 3 && model == "MacBook Air":
		return "Gold"
	case code == 7 && model == "iMac":
		return "Purple"
	case code == 7 && model == "MacBook Air":
		return "Midnight"
	case code == 8 && model == "iMac":
		return "Orange"
	case code == 8 && model == "MacBook Air":
		return "Starlight"
	case code == 11 && model == "MacBook Air":
		return "Sky Blue"
	}

	return "Unknown"
}
