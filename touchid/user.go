package main

import (
	"context"
	"errors"
	"os/user"
	"strconv"

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

// generateUser builds one touchid_user_config row per uid named in the query's
// `uid =` constraints. A uid constraint is required: per-user Touch ID state is
// only meaningful for a specific account, and bioutil must run in that user's
// context. Dependencies are injected so the function is unit-testable.
func generateUser(uids []string, run cmdRunner, lookup uidLookup) ([]map[string]string, error) {
	if len(uids) == 0 {
		return nil, errors.New("the touchid_user_config table requires a constraint WHERE uid =")
	}

	var results []map[string]string
	for _, uidStr := range uids {
		uid, err := strconv.Atoi(uidStr)
		if err != nil || !lookup(uidStr) {
			continue // skip non-numeric or nonexistent uids
		}

		row := map[string]string{
			"uid":                     uidStr,
			"fingerprints_registered": "0",
			"touchid_unlock":          "0",
			"touchid_applepay":        "0",
			"effective_unlock":        "0",
			"effective_applepay":      "0",
		}

		if out, err := run(uid, bioutilPath, "-r"); err == nil {
			fields := parseBioutil(out)
			row["touchid_unlock"] = boolField(fields, "Biometrics for unlock")
			row["touchid_applepay"] = boolField(fields, "Biometrics for ApplePay")
			row["effective_unlock"] = boolField(fields, "Effective biometrics for unlock")
			row["effective_applepay"] = boolField(fields, "Effective biometrics for ApplePay")
		}

		count := 0
		if out, err := run(uid, bioutilPath, "-c"); err == nil {
			count = parseFingerprintCount(out)
		}
		row["fingerprints_registered"] = strconv.Itoa(count)

		// Workaround for a long-standing bioutil quirk: the "Effective" flags in
		// `bioutil -r` can report 1 even with no fingerprints enrolled. With zero
		// templates, Touch ID cannot actually be used, so force the effective
		// flags to 0.
		if count == 0 {
			row["effective_unlock"] = "0"
			row["effective_applepay"] = "0"
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
	return generateUser(uidConstraints(qc), defaultCmdRunner, defaultUIDLookup)
}
