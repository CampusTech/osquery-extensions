package main

// Gestalt is the minimal subset of MobileGestalt we need to look up enclosure
// color information. The interface exists so callers can inject a fake during
// testing; the production implementation lives in gestalt_darwin.go and calls
// /usr/lib/libMobileGestalt.dylib via cgo.
type Gestalt interface {
	// Int returns the integer value for key, and whether the key was present
	// with a numeric (or numeric-castable) value.
	Int(key string) (int, bool)
	// String returns the string value for key, and whether the key was present.
	String(key string) (string, bool)
}

// fakeGestalt is a deterministic in-memory Gestalt for tests.
type fakeGestalt struct {
	ints    map[string]int
	strings map[string]string
}

func (f fakeGestalt) Int(key string) (int, bool) {
	v, ok := f.ints[key]
	return v, ok
}

func (f fakeGestalt) String(key string) (string, bool) {
	v, ok := f.strings[key]
	return v, ok
}
