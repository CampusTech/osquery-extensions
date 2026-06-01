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
		// Hardware-presence flags derived from IORegistry, NOT bioutil.
		// touchid_compatible above is true on every Apple Silicon Mac (the
		// Secure Enclave is on-die), so it cannot distinguish a Mac with a
		// physical Touch ID sensor from a keyboard-less Mac mini/Studio. These
		// two columns provide that distinction:
		//   touchid_builtin        – a built-in Touch ID sensor exists (laptops).
		//   touchid_sensor_present – ANY Touch ID sensor is usable, built-in OR
		//                            an attached accessory (Magic Keyboard with
		//                            Touch ID). This is the correct gate for
		//                            "the user can enroll a fingerprint".
		table.IntegerColumn("touchid_builtin"),
		table.IntegerColumn("touchid_sensor_present"),
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

	// Built-in sensor: a laptop exposes one or more AppleBiometricSensor nodes
	// in the IORegistry; keyboard-less desktops expose none. These columns are
	// independent of bioutil, so they are always set (defaulting to "0").
	builtin := false
	if out, err := run(-1, ioregPath, "-r", "-c", "AppleBiometricSensor"); err == nil {
		builtin = countRegistryNodes(out) > 0
	}
	row["touchid_builtin"] = boolValue(builtin)

	// Any usable sensor: built-in, OR an attached Touch ID accessory such as a
	// Magic Keyboard with Touch ID. The accessory registers no AppleBiometricSensor
	// node, but it DOES register an AppleMesaAccessory node ("Mesa" is Apple's
	// codename for the Touch ID sensor subsystem; the "Accessory" suffix denotes
	// an external sensor). Verified on hardware: AppleMesaAccessory is 1 with a
	// Touch ID keyboard attached and 0 on a keyboard-less mini/Studio. This is a
	// capability class, not a product-string match, so an old pre-Touch-ID Magic
	// Keyboard (no Mesa accessory) correctly reads as no sensor. Note the sibling
	// classes AppleMesaSEPDriver / AppleMesaResources are NOT usable here — they
	// are SEP scaffolding present on every Apple Silicon Mac regardless of an
	// attached sensor. The accessory probe is skipped when a built-in sensor is
	// already present.
	sensorPresent := builtin
	if !sensorPresent {
		if out, err := run(-1, ioregPath, "-r", "-c", "AppleMesaAccessory"); err == nil {
			sensorPresent = countRegistryNodes(out) > 0
		}
	}
	row["touchid_sensor_present"] = boolValue(sensorPresent)

	return []map[string]string{row}, nil
}

// osquerySystemGenerate adapts generateSystem to osquery-go's table.NewPlugin.
func osquerySystemGenerate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	return generateSystem(defaultCmdRunner)
}
