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

// Output of `bioutil -c -s` (run as root): one line per enrolled user.
const allCounts = "User 501:\t1 biometric template(s)\nUser 503:\t2 biometric template(s)\nOperation performed successfully."

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

func TestParseFingerprintCounts_SingleUser(t *testing.T) {
	got := parseFingerprintCounts([]byte("User 501:\t3 biometric template(s)\nOperation performed successfully."))
	if got["501"] != 3 {
		t.Errorf("uid 501: got %d, want 3", got["501"])
	}
}

func TestParseFingerprintCounts_MultiUser(t *testing.T) {
	got := parseFingerprintCounts([]byte(allCounts))
	want := map[string]int{"501": 1, "503": 2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParseFingerprintCounts_Garbage(t *testing.T) {
	got := parseFingerprintCounts([]byte("nonsense\nOperation performed successfully."))
	if len(got) != 0 {
		t.Errorf("expected empty map for garbage; got %#v", got)
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
	// Chip still resolves from system_profiler.
	if rows[0]["secure_enclave"] != "Mac16,5" {
		t.Errorf("secure_enclave: got %q", rows[0]["secure_enclave"])
	}
	// When bioutil -r -s fails the integer flag columns are unknown and must be
	// omitted (NULL), not asserted as "0".
	for _, k := range []string{"touchid_compatible", "touchid_enabled", "touchid_unlock"} {
		if _, present := rows[0][k]; present {
			t.Errorf("expected %s omitted (NULL) when bioutil errors; got %q", k, rows[0][k])
		}
	}
}

// userRunner serves `bioutil -c -s` (allCounts) plus a per-user `bioutil -r`
// whose result is given by rResult. A nil rResult means `-r` errors (user not
// logged in).
func userRunner(t *testing.T, rOut []byte, rErr error) cmdRunner {
	t.Helper()
	return scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"-c -s": {out: []byte(allCounts)},
		"-r":    {out: rOut, err: rErr},
	})
}

// allLocal returns a localUsersFunc enumerating the given uids.
func allLocal(uids ...string) localUsersFunc {
	return func() []string { return uids }
}

func TestGenerateUser_NoConstraintEnumeratesAllLocalAccounts(t *testing.T) {
	// Three local accounts. -c -s reports counts for 501 (1) and 503 (2); 502
	// has no templates and is absent from -c -s. Only 501 is "logged in" (its
	// -r succeeds); the others' -r errors. Every account still gets a row.
	run := func(uid int, name string, args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "-c" && args[1] == "-s":
			return []byte(allCounts), nil
		case len(args) == 1 && args[0] == "-r" && uid == 501:
			return []byte(userBioutil), nil
		case len(args) == 1 && args[0] == "-r":
			return nil, errors.New("not logged in")
		}
		t.Fatalf("unexpected command: uid=%d %s %v", uid, name, args)
		return nil, nil
	}

	rows, err := generateUser(nil, run, func(string) bool { return true }, allLocal("501", "502", "503"))
	if err != nil {
		t.Fatalf("generateUser error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected a row per local account (501, 502, 503); got %d: %#v", len(rows), rows)
	}
	byUID := map[string]map[string]string{}
	for _, r := range rows {
		byUID[r["uid"]] = r
	}
	// 501: logged in, 1 fingerprint, flags populated.
	if byUID["501"]["fingerprints_registered"] != "1" || byUID["501"]["touchid_unlock"] != "1" {
		t.Errorf("501 row wrong: %#v", byUID["501"])
	}
	// 502: no enrolled templates (absent from -c -s => known 0), logged out =>
	// flags omitted (NULL).
	if byUID["502"]["fingerprints_registered"] != "0" {
		t.Errorf("502 count: got %q, want 0", byUID["502"]["fingerprints_registered"])
	}
	if _, present := byUID["502"]["touchid_unlock"]; present {
		t.Errorf("502 logged-out flags should be omitted (NULL); got %q", byUID["502"]["touchid_unlock"])
	}
	// 503: 2 fingerprints from -c -s, logged out => flags omitted (NULL).
	if byUID["503"]["fingerprints_registered"] != "2" {
		t.Errorf("503 count: got %q, want 2", byUID["503"]["fingerprints_registered"])
	}
	if _, present := byUID["503"]["touchid_unlock"]; present {
		t.Errorf("503 logged-out flags should be omitted (NULL); got %q", byUID["503"]["touchid_unlock"])
	}
}

func TestGenerateUser_PopulatedRow(t *testing.T) {
	run := userRunner(t, []byte(userBioutil), nil)

	rows, err := generateUser([]string{"501"}, run, func(string) bool { return true }, func() []string { return nil })
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

func TestGenerateUser_LoggedOutUserHasCountButOmittedFlags(t *testing.T) {
	// `-r` fails (logged out) but `-c -s` still reports a count: the row must
	// carry the real count, with config flags omitted (NULL) — NOT 0.
	run := userRunner(t, nil, errors.New("Failed to get user context"))

	rows, _ := generateUser([]string{"501"}, run, func(string) bool { return true }, func() []string { return nil })
	if len(rows) != 1 {
		t.Fatalf("expected 1 row; got %d", len(rows))
	}
	got := rows[0]
	if got["fingerprints_registered"] != "1" {
		t.Errorf("count should come from -c -s even when logged out; got %q", got["fingerprints_registered"])
	}
	for _, k := range []string{"touchid_unlock", "touchid_applepay", "effective_unlock", "effective_applepay"} {
		if _, present := got[k]; present {
			t.Errorf("flag %s should be omitted (NULL) when logged out; got %q", k, got[k])
		}
	}
}

func TestGenerateUser_ZeroFingerprintsForcesEffectiveZero(t *testing.T) {
	// bioutil -r reports effective=1, but the user has no enrolled templates
	// (absent from -c -s): the workaround must force effective flags to 0.
	run := scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"-c -s": {out: []byte("Operation performed successfully.")}, // nobody enrolled
		"-r":    {out: []byte(userBioutil)},                          // says effective = 1
	})

	rows, _ := generateUser([]string{"501"}, run, func(string) bool { return true }, func() []string { return nil })
	if rows[0]["fingerprints_registered"] != "0" {
		t.Errorf("expected 0 fingerprints; got %q", rows[0]["fingerprints_registered"])
	}
	if rows[0]["effective_unlock"] != "0" || rows[0]["effective_applepay"] != "0" {
		t.Errorf("zero fingerprints should force effective flags to 0; got %#v", rows[0])
	}
	// The configured (non-effective) flags should remain as bioutil reported.
	if rows[0]["touchid_unlock"] != "1" {
		t.Errorf("configured unlock should stay 1; got %q", rows[0]["touchid_unlock"])
	}
}

func TestGenerateUser_CountUnknownDoesNotZeroEffective(t *testing.T) {
	// `-c -s` fails (e.g. not root): count is unknown. `-r` reports effective=1.
	// The zero-fingerprint workaround must NOT fire, since we don't actually
	// know the count is 0 — flags must stay as bioutil reported.
	run := scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"-c -s": {err: errors.New("not root")},
		"-r":    {out: []byte(userBioutil)},
	})

	rows, _ := generateUser([]string{"501"}, run, func(string) bool { return true }, func() []string { return nil })
	got := rows[0]
	if _, present := got["fingerprints_registered"]; present {
		t.Errorf("count should be omitted (NULL) when -c -s fails; got %q", got["fingerprints_registered"])
	}
	if got["effective_unlock"] != "1" || got["effective_applepay"] != "1" {
		t.Errorf("effective flags must be preserved when count unknown; got %#v", got)
	}
}

func TestGenerateUser_SkipsNonexistentUID(t *testing.T) {
	run := scriptedRunner(t, map[string]struct {
		out []byte
		err error
	}{
		"-c -s": {out: []byte(allCounts)},
	})
	rows, err := generateUser([]string{"99999"}, run, func(string) bool { return false }, func() []string { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected no rows for nonexistent uid; got %d", len(rows))
	}
}

func TestColumns(t *testing.T) {
	sys := []string{"touchid_compatible", "secure_enclave", "touchid_enabled", "touchid_unlock"}
	sysCols := systemColumns()
	if len(sysCols) != len(sys) {
		t.Fatalf("systemColumns: got %d columns, want %d", len(sysCols), len(sys))
	}
	for i, c := range sysCols {
		if c.Name != sys[i] {
			t.Errorf("systemColumns[%d] = %q, want %q", i, c.Name, sys[i])
		}
	}

	usr := []string{"uid", "fingerprints_registered", "touchid_unlock", "touchid_applepay", "effective_unlock", "effective_applepay"}
	usrCols := userColumns()
	if len(usrCols) != len(usr) {
		t.Fatalf("userColumns: got %d columns, want %d", len(usrCols), len(usr))
	}
	for i, c := range usrCols {
		if c.Name != usr[i] {
			t.Errorf("userColumns[%d] = %q, want %q", i, c.Name, usr[i])
		}
	}
}
