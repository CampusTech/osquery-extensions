package main

import "testing"

func TestResolveColor(t *testing.T) {
	cases := []struct {
		name        string
		productType string
		model       string
		code        int
		codeKnown   bool
		want        string
	}{
		{"M4 MBP code 9", "Mac16,5", "MacBook Pro", 9, true, "Space Black"},
		{"MacBook Air code 7 Midnight", "Mac15,12", "MacBook Air", 7, true, "Midnight"},
		{"MacBook Air code 8 Starlight", "Mac15,12", "MacBook Air", 8, true, "Starlight"},
		{"MacBook Air code 3 Gold", "MacBookAir10,1", "MacBook Air", 3, true, "Gold"},
		{"iMac code 3 Yellow", "iMac21,1", "iMac", 3, true, "Yellow"},
		{"iMac code 7 Purple", "iMac21,1", "iMac", 7, true, "Purple"},
		{"iMac code 8 Orange", "iMac21,1", "iMac", 8, true, "Orange"},
		{"Mac mini 2018 forced", "Macmini8,1", "Mac mini", 0, false, "Space Gray"},
		{"iMac Pro 1,1 forced", "iMacPro1,1", "iMac", 0, false, "Space Gray"},
		{"iMac 20,1 forced silver", "iMac20,1", "iMac", 0, false, "Silver"},
		{"Mac Studio forced silver", "Mac14,13", "Mac Studio", 9, true, "Silver"},
		{"Mac Pro forced silver", "MacPro7,1", "Mac Pro", 0, false, "Silver"},
		{"Universal code 2 Space Gray", "MacBookPro16,1", "MacBook Pro", 2, true, "Space Gray"},
		{"MacBook Air code 11 Sky Blue", "Mac15,12", "MacBook Air", 11, true, "Sky Blue"},
		{"Code 11 not MacBook Air is Unknown", "Mac16,5", "MacBook Pro", 11, true, "Unknown"},
		{"Code 12 Indigo", "Mac17,1", "MacBook", 12, true, "Indigo"},
		{"Code 13 Citrus", "Mac17,1", "MacBook", 13, true, "Citrus"},
		{"Code 14 Blush", "Mac17,1", "MacBook", 14, true, "Blush"},
		{"Unknown when no code and no model match", "Mac16,5", "MacBook Pro", 0, false, "Unknown"},
		{"Unknown code returns Unknown", "Mac16,5", "MacBook Pro", 99, true, "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveColor(tc.productType, tc.model, tc.code, tc.codeKnown)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
