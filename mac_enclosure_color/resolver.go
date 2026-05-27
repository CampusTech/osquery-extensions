package main

// colorRule is a single ordered matching rule. The first rule that matches all
// non-empty fields wins. An empty ProductType / ModelName means "any". HasCode
// indicates whether the Code field should be matched at all; false means the
// rule applies regardless of the DeviceEnclosureColor value.
type colorRule struct {
	ProductType string
	ModelName   string
	Code        int
	HasCode     bool
	Color       string
}

// colorRules is the ordered table of how to map a Mac's identifying
// fields to its human-readable enclosure color name. The order matters:
// model-specific rules MUST come before universal-code rules so that they
// take precedence (e.g. iMac+code=3 -> Yellow before universal Sky Blue).
//
// Mirrors munkireport/ibridge (https://github.com/munkireport/ibridge),
// the canonical reference for this mapping in the Mac admin community.
var colorRules = []colorRule{
	// Model-forced (no code lookup needed).
	{ProductType: "Macmini8,1", Color: "Space Gray"},
	{ProductType: "iMacPro1,1", Color: "Space Gray"},
	{ProductType: "iMac20,1", Color: "Silver"},
	{ProductType: "iMac20,2", Color: "Silver"},
	{ModelName: "Mac mini", Color: "Silver"},
	{ModelName: "Mac Pro", Color: "Silver"},
	{ModelName: "Mac Studio", Color: "Silver"},

	// Model-disambiguated codes (same code, different color depending on model).
	{ModelName: "iMac", Code: 3, HasCode: true, Color: "Yellow"},
	{ModelName: "MacBook Air", Code: 3, HasCode: true, Color: "Gold"},
	{ModelName: "iMac", Code: 7, HasCode: true, Color: "Purple"},
	{ModelName: "MacBook Air", Code: 7, HasCode: true, Color: "Midnight"},
	{ModelName: "iMac", Code: 8, HasCode: true, Color: "Orange"},
	{ModelName: "MacBook Air", Code: 8, HasCode: true, Color: "Starlight"},

	// Universal codes (apply to every model).
	{Code: 1, HasCode: true, Color: "Silver"},
	{Code: 2, HasCode: true, Color: "Space Gray"},
	{Code: 4, HasCode: true, Color: "Green"},
	{Code: 5, HasCode: true, Color: "Blue"},
	{Code: 6, HasCode: true, Color: "Red"},
	{Code: 9, HasCode: true, Color: "Space Black"},
	{Code: 11, HasCode: true, Color: "Sky Blue"},
	{Code: 12, HasCode: true, Color: "Indigo"},
	{Code: 13, HasCode: true, Color: "Citrus"},
	{Code: 14, HasCode: true, Color: "Blush"},
}

// resolveColor returns the human-readable color name for a Mac given its
// product type (e.g. "Mac16,5"), model name (e.g. "MacBook Pro"), and the
// numeric DeviceEnclosureColor from MobileGestalt. codeKnown is false when
// MobileGestalt did not return a DeviceEnclosureColor (entitlement-gated or
// missing); rules requiring a code will skip in that case.
func resolveColor(productType, model string, code int, codeKnown bool) string {
	for _, r := range colorRules {
		if r.ProductType != "" && r.ProductType != productType {
			continue
		}
		if r.ModelName != "" && r.ModelName != model {
			continue
		}
		if r.HasCode {
			if !codeKnown || r.Code != code {
				continue
			}
		}
		return r.Color
	}
	return "Unknown"
}
