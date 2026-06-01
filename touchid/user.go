package main

import (
	"context"
	"os/user"
	"strconv"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// userColumns is the schema for touchid_user_config.
func userColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("uid"),
		table.IntegerColumn("fingerprints_registered"),
		table.IntegerColumn("touchid_unlock"),
		table.IntegerColumn("touchid_applepay"),
		table.IntegerColumn("effective_unlock"),
		table.IntegerColumn("effective_applepay"),
	}
}

// uidLookup verifies a uid maps to a real account; injected for testability.
type uidLookup func(uid string) bool

func defaultUIDLookup(uid string) bool {
	_, err := user.LookupId(uid)
	return err == nil
}

// localUsersFunc returns the uids of real local accounts; injected for
// testability.
type localUsersFunc func() []string

// minHumanUID is the conventional floor for real (non-system) macOS accounts.
// System and service accounts use uids below 500; the first human account is
// 501. We cap at 60000 to exclude transient/Setup Assistant accounts.
const (
	minHumanUID = 501
	maxHumanUID = 60000
)

// defaultLocalUsers enumerates real local accounts via Directory Services,
// returning their uids. Output of `dscl . -list /Users UniqueID` is two
// columns: account name and uid.
func defaultLocalUsers() []string {
	out, err := defaultCmdRunner(-1, "/usr/bin/dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return nil
	}
	var uids []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < minHumanUID || n > maxHumanUID {
			continue
		}
		uids = append(uids, fields[1])
	}
	return uids
}

// generateUser builds touchid_user_config rows. Two bioutil data sources with
// different access models are combined:
//
//   - Enrolled fingerprint count: `bioutil -c -s` run as root (the context
//     fleetd/orbit provides) reports counts for ALL enrolled users at once and
//     does NOT require the user to be logged in.
//   - Config flags (unlock / ApplePay / effective): `bioutil -r` must run
//     inside the target user's launchd domain via `launchctl asuser`, which
//     only exists while the user is logged in. There is no admin form to read
//     another user's config flags.
//
// Target uid selection: the query's `uid =` constraints if any, else every
// real local account. For a user whose config flags can't be read (e.g. logged
// out), the count is still reported and the four flag columns are left empty
// rather than defaulted to 0 (which would misrepresent an enabled-but-offline
// user as disabled).
//
// Dependencies are injected so the function is unit-testable.
func generateUser(uids []string, run cmdRunner, lookup uidLookup, localUsers localUsersFunc) ([]map[string]string, error) {
	// Counts for all enrolled users. `bioutil -c -s` requires root (the context
	// fleetd/orbit provides) but works regardless of the users' login state.
	// countsKnown distinguishes "successfully read, user has 0 templates" from
	// "couldn't read counts at all" (e.g. not running as root) — they must be
	// reported differently.
	counts := map[string]int{}
	countsKnown := false
	if out, err := run(-1, bioutilPath, "-c", "-s"); err == nil {
		counts = parseFingerprintCounts(out)
		countsKnown = true
	}

	if len(uids) == 0 {
		// No constraint: report every real local account.
		uids = localUsers()
	}

	var results []map[string]string
	for _, uidStr := range uids {
		uid, err := strconv.Atoi(uidStr)
		if err != nil || !lookup(uidStr) {
			continue // skip non-numeric or nonexistent uids
		}

		count, hasCount := counts[uidStr]
		// When -c -s succeeded, a uid absent from its output has 0 templates.
		if countsKnown {
			hasCount = true
			// count is already its zero value when absent.
		}

		// These are IntegerColumns: a column we can't determine must be omitted
		// from the row map so osquery reports it as NULL (an empty string is not
		// a valid integer value). So we only ever SET keys we actually know.
		row := map[string]string{"uid": uidStr}
		if hasCount {
			row["fingerprints_registered"] = strconv.Itoa(count)
		}

		// Config flags require the user's launchd domain; this fails (and the
		// flags stay NULL/omitted) when the user isn't logged in.
		if out, err := run(uid, bioutilPath, "-r"); err == nil {
			fields := parseBioutil(out)
			row["touchid_unlock"] = boolField(fields, "Biometrics for unlock")
			row["touchid_applepay"] = boolField(fields, "Biometrics for ApplePay")
			row["effective_unlock"] = boolField(fields, "Effective biometrics for unlock")
			row["effective_applepay"] = boolField(fields, "Effective biometrics for ApplePay")

			// Workaround for a long-standing bioutil quirk: the "Effective" flags
			// in `bioutil -r` can report 1 even with no fingerprints enrolled.
			// Only apply it when we KNOW the count is genuinely 0 — not when the
			// count is merely unknown because -c -s couldn't run.
			if hasCount && count == 0 {
				row["effective_unlock"] = "0"
				row["effective_applepay"] = "0"
			}
		}

		results = append(results, row)
	}

	return results, nil
}

// uidConstraints extracts the values of all `uid =` constraints from the query.
func uidConstraints(qc table.QueryContext) []string {
	var uids []string
	if c, ok := qc.Constraints["uid"]; ok {
		for _, con := range c.Constraints {
			if con.Operator == table.OperatorEquals {
				uids = append(uids, con.Expression)
			}
		}
	}
	return uids
}

// osqueryUserGenerate adapts generateUser to osquery-go's table.NewPlugin.
func osqueryUserGenerate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	return generateUser(uidConstraints(qc), defaultCmdRunner, defaultUIDLookup, defaultLocalUsers)
}
