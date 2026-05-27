package main

import (
	"errors"
	"reflect"
	"testing"
)

// staticRunner returns canned output for /usr/sbin/system_profiler and nothing
// for any other command. err overrides for both cases when non-nil.
func staticRunner(output []byte, err error) cmdRunner {
	return func(name string, args ...string) ([]byte, error) {
		return output, err
	}
}

const mbpProfilerJSON = `{
  "SPHardwareDataType": [
    {
      "machine_name": "MacBook Pro",
      "machine_model": "Mac16,5"
    }
  ]
}`

func TestGenerate_PopulatedRow(t *testing.T) {
	g := fakeGestalt{
		ints:    map[string]int{"DeviceEnclosureColor": 9},
		strings: map[string]string{"ProductType": "Mac16,5"},
	}
	run := staticRunner([]byte(mbpProfilerJSON), nil)

	rows, err := generate(g, run)
	if err != nil {
		t.Fatalf("generate returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}

	want := map[string]string{
		"color":        "Space Black",
		"color_code":   "9",
		"model":        "MacBook Pro",
		"product_type": "Mac16,5",
	}
	if !reflect.DeepEqual(rows[0], want) {
		t.Errorf("row mismatch\n  got: %#v\n want: %#v", rows[0], want)
	}
}

func TestGenerate_MissingColorCode(t *testing.T) {
	g := fakeGestalt{
		ints:    map[string]int{}, // no DeviceEnclosureColor
		strings: map[string]string{"ProductType": "Mac16,5"},
	}
	run := staticRunner([]byte(mbpProfilerJSON), nil)

	rows, err := generate(g, run)
	if err != nil {
		t.Fatalf("generate returned error: %v", err)
	}
	got := rows[0]
	if got["color"] != "Unknown" {
		t.Errorf("expected Unknown color when no code; got %q", got["color"])
	}
	if got["color_code"] != "" {
		t.Errorf("expected empty color_code when no code; got %q", got["color_code"])
	}
}

func TestGenerate_SystemProfilerError(t *testing.T) {
	g := fakeGestalt{
		ints:    map[string]int{"DeviceEnclosureColor": 9},
		strings: map[string]string{"ProductType": "Mac16,5"},
	}
	run := staticRunner(nil, errors.New("system_profiler failed"))

	rows, err := generate(g, run)
	if err != nil {
		t.Fatalf("generate should swallow runner errors; got: %v", err)
	}
	got := rows[0]
	if got["model"] != "" {
		t.Errorf("expected empty model when system_profiler errors; got %q", got["model"])
	}
	// code 9 is a universal rule, so color resolution should still work
	if got["color"] != "Space Black" {
		t.Errorf("expected Space Black even without model lookup; got %q", got["color"])
	}
}

func TestGenerate_MacStudioForcedSilver(t *testing.T) {
	g := fakeGestalt{
		ints:    map[string]int{"DeviceEnclosureColor": 9}, // would normally be Space Black
		strings: map[string]string{"ProductType": "Mac14,13"},
	}
	studioJSON := `{"SPHardwareDataType":[{"machine_name":"Mac Studio"}]}`
	run := staticRunner([]byte(studioJSON), nil)

	rows, _ := generate(g, run)
	if rows[0]["color"] != "Silver" {
		t.Errorf("Mac Studio should force Silver regardless of code; got %q", rows[0]["color"])
	}
}

func TestColumns(t *testing.T) {
	cols := columns()
	want := []string{"color", "color_code", "model", "product_type"}
	if len(cols) != len(want) {
		t.Fatalf("expected %d columns, got %d", len(want), len(cols))
	}
	for i, name := range want {
		if cols[i].Name != name {
			t.Errorf("column[%d]: got %q, want %q", i, cols[i].Name, name)
		}
	}
}
