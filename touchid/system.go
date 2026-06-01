package main

import (
	"context"
	"regexp"

	"github.com/osquery/osquery-go/plugin/table"
)

// systemColumns is the schema for touchid_system_config.
func systemColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("touchid_compatible"),
		table.TextColumn("secure_enclave"),
		table.IntegerColumn("touchid_enabled"),
		table.IntegerColumn("touchid_unlock"),
	}
}

// chipRegexp matches the Apple Silicon SoC identifier from
// `system_profiler SPiBridgeDataType`, e.g. "Model Identifier: Mac16,5".
// Every Apple Silicon Mac carries a Secure Enclave on-die, so the presence of
// this identifier is what we report in secure_enclave.
var chipRegexp = regexp.MustCompile(`Model Identifier:\s*(\S+)`)

// generateSystem builds the single touchid_system_config row. External
// dependencies are injected so the function is unit-testable.
//
// Apple Silicon only: the Secure Enclave is integrated into the SoC, so rather
// than probing for a discrete T1/T2 chip (Intel-era) we report the SoC model
// identifier reported by system_profiler.
func generateSystem(run cmdRunner) ([]map[string]string, error) {
	secureEnclave := ""
	if out, err := run(-1, systemProfilerBin, "SPiBridgeDataType"); err == nil {
		if m := chipRegexp.FindSubmatch(out); m != nil {
			secureEnclave = string(m[1])
		}
	}

	// secure_enclave is a TextColumn, so "" (no chip identifier found) is a valid
	// value. The three integer flag columns are only set when bioutil -r -s
	// succeeds; otherwise they are omitted so osquery reports them as NULL
	// (unknown) rather than asserting a false "0"/disabled.
	row := map[string]string{
		"secure_enclave": secureEnclave,
	}

	if out, err := run(-1, bioutilPath, "-r", "-s"); err == nil {
		fields := parseBioutil(out)
		// "Biometrics functionality" present means the hardware supports Touch ID.
		if _, ok := fields["Biometrics functionality"]; ok {
			row["touchid_compatible"] = "1"
		} else {
			row["touchid_compatible"] = "0"
		}
		row["touchid_enabled"] = boolField(fields, "Biometrics functionality")
		row["touchid_unlock"] = boolField(fields, "Biometrics for unlock")
	}

	return []map[string]string{row}, nil
}

// osquerySystemGenerate adapts generateSystem to osquery-go's table.NewPlugin.
func osquerySystemGenerate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	return generateSystem(defaultCmdRunner)
}
