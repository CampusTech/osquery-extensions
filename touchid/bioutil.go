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

// parseFingerprintCounts extracts enrolled-template counts from `bioutil -c`
// (single user) or `bioutil -c -s` (all enrolled users, root) output, keyed by
// uid. Each data line looks like "User 501:\t1 biometric template(s)". Users
// with zero enrolled templates do not appear in `-c -s` output, so a uid absent
// from the returned map should be treated as count 0.
func parseFingerprintCounts(out []byte) map[string]int {
	counts := make(map[string]int)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// Expect: ["User", "<uid>:", "<n>", "biometric", "template(s)"]
		if len(fields) < 4 || fields[0] != "User" {
			continue
		}
		uid := strings.TrimSuffix(fields[1], ":")
		if _, err := strconv.Atoi(uid); err != nil {
			continue
		}
		for i, f := range fields {
			if strings.HasPrefix(f, "biometric") && i > 0 {
				if n, err := strconv.Atoi(fields[i-1]); err == nil {
					counts[uid] = n
				}
				break
			}
		}
	}
	return counts
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
