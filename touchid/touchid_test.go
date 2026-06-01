package main

import (
	"errors"
	"reflect"
	"testing"
)

// Real output captured from `bioutil -r -s` on Apple Silicon (macOS 15+).
// Note the three extra timeout lines that position-based parsing would trip on.
const systemBioutil = `System Touch ID configuration:
	Biometrics functionality: 1
	Biometrics for unlock: 1
	Biometric timeout (in seconds): 172800
	Match timeout (in seconds): 14400
	Passcode input timeout (in seconds): 561600
Operation performed successfully.`

const userBioutil = `User Touch ID configuration:
	Biometrics for unlock: 1
	Biometrics for ApplePay: 1
	Effective biometrics for unlock: 1
	Effective biometrics for ApplePay: 1
Operation performed successfully.`

const userBioutilCount = "User 501:\t1 biometric template(s)\nOperation performed successfully."

const spiBridge = `Controller:

      Model Identifier: Mac16,5
      Firmware Version: mBoot-18000.120.36`

// scriptedRunner dispatches on the first argument (e.g. "-r", "-r -s", "-c",
// "SPiBridgeDataType") so a single runner can serve every call generate makes.
func scriptedRunner(t *testing.T, responses map[string]struct {
	out []byte
	err error
}) cmdRunner {
	t.Helper()
	return func(uid int, name string, args ...string) ([]byte, error) {
		key := ""
		for _, a := range args {
			key += a + " "
		}
		key = key[:len(key)-1]
		r, ok := responses[key]
		if !ok {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return r.out, r.err
	}
}

func TestParseBioutil_IgnoresHeaderAndFooter(t *testing.T) {
	f := parseBioutil([]byte(systemBioutil))
	if f["Biometrics functionality"] != "1" {
		t.Errorf("functionality: got %q", f["Biometrics functionality"])
	}
	if f["Biometrics for unlock"] != "1" {
		t.Errorf("unlock: got %q", f["Biometrics for unlock"])
	}
	if _, present := f["System Touch ID configuration"]; present {
		t.Error("header line should not be parsed as a field")
	}
	if _, present := f["Operation performed successfully"]; present {
		t.Error("footer line should not be parsed as a field")
	}
}

func TestParseFingerprintCount(t *testing.T) {
	cases := map[string]int{
		"User 501:\t1 biometric template(s)": 1,
		"User 501:\t3 biometric template(s)": 3,
		"User 501:\t0 biometric template(s)": 0,
		"garbage output":                     0,
	}
	for in, want := range cases {
		if got := parseFingerprintCount([]byte(in)); got != want {
			t.Errorf("parseFingerprintCount(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestGenerateSystem_AppleSilicon(t *testing.T) {
	run := scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"SPiBridgeDataType": {out: []byte(spiBridge)},
		"-r -s":             {out: []byte(systemBioutil)},
	})

	rows, err := generateSystem(run)
	if err != nil {
		t.Fatalf("generateSystem error: %v", err)
	}
	want := map[string]string{
		"touchid_compatible": "1",
		"secure_enclave":     "Mac16,5",
		"touchid_enabled":    "1",
		"touchid_unlock":     "1",
	}
	if !reflect.DeepEqual(rows[0], want) {
		t.Errorf("row mismatch\n got: %#v\nwant: %#v", rows[0], want)
	}
}

func TestGenerateSystem_BioutilError(t *testing.T) {
	run := scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"SPiBridgeDataType": {out: []byte(spiBridge)},
		"-r -s":             {err: errors.New("bioutil failed")},
	})

	rows, err := generateSystem(run)
	if err != nil {
		t.Fatalf("generateSystem should swallow runner errors: %v", err)
	}
	// Chip still resolves; touch ID flags default to 0/incompatible.
	if rows[0]["secure_enclave"] != "Mac16,5" {
		t.Errorf("secure_enclave: got %q", rows[0]["secure_enclave"])
	}
	if rows[0]["touchid_compatible"] != "0" {
		t.Errorf("expected incompatible when bioutil errors; got %q", rows[0]["touchid_compatible"])
	}
}

func TestGenerateUser_RequiresUID(t *testing.T) {
	_, err := generateUser(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error when no uid constraint provided")
	}
}

func TestGenerateUser_PopulatedRow(t *testing.T) {
	run := scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"-r": {out: []byte(userBioutil)},
		"-c": {out: []byte(userBioutilCount)},
	})

	rows, err := generateUser([]string{"501"}, run, func(string) bool { return true })
	if err != nil {
		t.Fatalf("generateUser error: %v", err)
	}
	want := map[string]string{
		"uid":                     "501",
		"fingerprints_registered": "1",
		"touchid_unlock":          "1",
		"touchid_applepay":        "1",
		"effective_unlock":        "1",
		"effective_applepay":      "1",
	}
	if !reflect.DeepEqual(rows[0], want) {
		t.Errorf("row mismatch\n got: %#v\nwant: %#v", rows[0], want)
	}
}

func TestGenerateUser_ZeroFingerprintsForcesEffectiveZero(t *testing.T) {
	// bioutil -r reports effective=1, but -c reports 0 templates: the
	// workaround must force effective flags to 0.
	zeroCount := "User 501:\t0 biometric template(s)"
	run := scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"-r": {out: []byte(userBioutil)}, // says effective unlock/applepay = 1
		"-c": {out: []byte(zeroCount)},
	})

	rows, _ := generateUser([]string{"501"}, run, func(string) bool { return true })
	if rows[0]["effective_unlock"] != "0" || rows[0]["effective_applepay"] != "0" {
		t.Errorf("zero fingerprints should force effective flags to 0; got %#v", rows[0])
	}
	// The configured (non-effective) flags should remain as bioutil reported.
	if rows[0]["touchid_unlock"] != "1" {
		t.Errorf("configured unlock should stay 1; got %q", rows[0]["touchid_unlock"])
	}
}

func TestGenerateUser_SkipsNonexistentUID(t *testing.T) {
	rows, err := generateUser([]string{"99999"}, nil, func(string) bool { return false })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected no rows for nonexistent uid; got %d", len(rows))
	}
}

func TestColumns(t *testing.T) {
	sys := []string{"touchid_compatible", "secure_enclave", "touchid_enabled", "touchid_unlock"}
	for i, c := range systemColumns() {
		if c.Name != sys[i] {
			t.Errorf("systemColumns[%d] = %q, want %q", i, c.Name, sys[i])
		}
	}
	usr := []string{"uid", "fingerprints_registered", "touchid_unlock", "touchid_applepay", "effective_unlock", "effective_applepay"}
	for i, c := range userColumns() {
		if c.Name != usr[i] {
			t.Errorf("userColumns[%d] = %q, want %q", i, c.Name, usr[i])
		}
	}
}
