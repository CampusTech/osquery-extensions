package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// Absolute paths to the system binaries we shell out to. Hard-coding the paths
// avoids depending on PATH and avoids picking up a planted binary earlier in
// the search order.
const (
	bioutilPath       = "/usr/bin/bioutil"
	systemProfilerBin = "/usr/sbin/system_profiler"
)

// cmdRunner abstracts external command execution so tests can inject canned
// output without spawning subprocesses. uid, when >= 0, requests that the
// command run as that user id; uid < 0 means "current user".
type cmdRunner func(uid int, name string, args ...string) ([]byte, error)

// parseBioutil parses the human-readable output of `bioutil -r` / `bioutil -r -s`
// into a label->value map. bioutil emits one "Label: value" pair per line; we
// key on the label text rather than line position so additional lines in newer
// macOS releases don't shift the fields we care about.
//
// Example input:
//
//	System Touch ID configuration:
//		Biometrics functionality: 1
//		Biometrics for unlock: 1
//		Biometric timeout (in seconds): 172800
//	Operation performed successfully.
//
// yields {"Biometrics functionality": "1", "Biometrics for unlock": "1",
// "Biometric timeout (in seconds)": "172800"}. Header lines that end in a colon
// with no value (e.g. "System Touch ID configuration:") and the trailing
// "Operation performed successfully." line are ignored.
func parseBioutil(out []byte) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue // no colon -> not a key/value line
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" || val == "" {
			continue // section header like "System Touch ID configuration:"
		}
		fields[key] = val
	}
	return fields
}

// boolField returns "1" if the named bioutil field is present and equal to "1",
// "0" otherwise. bioutil reports these flags as the literal characters 0/1.
func boolField(fields map[string]string, key string) string {
	if fields[key] == "1" {
		return "1"
	}
	return "0"
}

// parseFingerprintCount extracts the enrolled-template count from `bioutil -c`
// output, e.g. "User 501:\t1 biometric template(s)" -> 1. Returns 0 if the
// count can't be found.
func parseFingerprintCount(out []byte) int {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			// The count is the integer immediately preceding "biometric".
			if strings.HasPrefix(f, "biometric") && i > 0 {
				if n, err := strconv.Atoi(fields[i-1]); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

// defaultCmdRunner runs the command, optionally as a different uid, and returns
// its stdout. Dropping to a uid is done via `launchctl asuser`, which executes
// the command inside that user's GUI/per-user launchd domain — necessary for
// bioutil, whose per-user Touch ID data lives in the user's Secure Enclave
// keybag context.
func defaultCmdRunner(uid int, name string, args ...string) ([]byte, error) {
	if uid >= 0 {
		full := append([]string{"asuser", strconv.Itoa(uid), name}, args...)
		return exec.Command("/bin/launchctl", full...).Output()
	}
	return exec.Command(name, args...).Output()
}
