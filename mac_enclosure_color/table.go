package main

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/osquery/osquery-go/plugin/table"
)

// cmdRunner abstracts external command execution so tests can inject canned
// output without spawning subprocesses.
type cmdRunner func(name string, args ...string) ([]byte, error)

// defaultCmdRunner runs the command and returns its combined stdout.
func defaultCmdRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// columns is the schema published to osquery.
func columns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("color"),
		table.TextColumn("color_code"),
		table.TextColumn("model"),
		table.TextColumn("product_type"),
	}
}

// generate returns a single row describing this Mac's enclosure color.
// All external dependencies are passed in so the function is unit-testable.
func generate(g Gestalt, run cmdRunner) ([]map[string]string, error) {
	productType, _ := g.String("ProductType")
	code, codeKnown := g.Int("DeviceEnclosureColor")

	model := ""
	if out, err := run("/usr/sbin/system_profiler", "SPHardwareDataType", "-json"); err == nil {
		model = parseModelName(out)
	}

	color := resolveColor(productType, model, code, codeKnown)

	row := map[string]string{
		"color":        color,
		"color_code":   "",
		"model":        model,
		"product_type": productType,
	}
	if codeKnown {
		row["color_code"] = fmt.Sprintf("%d", code)
	}
	return []map[string]string{row}, nil
}

// osqueryGenerate is the adapter used by osquery-go's table.NewPlugin. It wires
// up the production dependencies and delegates to generate().
func osqueryGenerate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	return generate(newMobileGestalt(), defaultCmdRunner)
}
