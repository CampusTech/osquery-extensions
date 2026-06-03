package main

import (
	"context"
	"os/exec"
	"strconv"
	"sync"

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
		table.TextColumn("color"),         // resolved human name, or "Unknown"
		table.IntegerColumn("color_code"), // raw DeviceEnclosureColor; empty (NULL) if absent
		table.TextColumn("model"),         // Model Name, e.g. "MacBook Pro"
		table.TextColumn("product_type"),  // ProductType, e.g. "Mac16,5"
	}
}

// modelNameFunc returns the Mac's Model Name. Injected so generate is testable
// without spawning system_profiler.
type modelNameFunc func() string

// generate returns a single row describing this Mac's enclosure color.
// All external dependencies are passed in so the function is unit-testable.
func generate(g Gestalt, modelName modelNameFunc) ([]map[string]string, error) {
	productType, _ := g.String("ProductType")
	code, codeKnown := g.Int("DeviceEnclosureColor")

	model := modelName()
	color := resolveColor(productType, model, code, codeKnown)

	row := map[string]string{
		"color":        color,
		"model":        model,
		"product_type": productType,
	}
	// color_code is an IntegerColumn: omit it (NULL) when unknown rather than
	// setting "" (an invalid integer value).
	if codeKnown {
		row["color_code"] = strconv.Itoa(code)
	}
	return []map[string]string{row}, nil
}

// readModelName fetches the Model Name from system_profiler. Split out so it can
// be memoized (the model never changes for the process lifetime).
func readModelName(run cmdRunner) string {
	out, err := run("/usr/sbin/system_profiler", "SPHardwareDataType", "-json")
	if err != nil {
		return ""
	}
	return parseModelName(out)
}

// The model name is static per process; cache it so we don't spawn
// system_profiler (which can take seconds) on every query.
var (
	modelOnce   sync.Once
	cachedModel string
)

func cachedModelName() string {
	modelOnce.Do(func() {
		cachedModel = readModelName(defaultCmdRunner)
	})
	return cachedModel
}

// osqueryGenerate is the adapter used by osquery-go's table.NewPlugin. It wires
// up the production dependencies (cgo MobileGestalt + memoized model name) and
// delegates to generate().
func osqueryGenerate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	return generate(newMobileGestalt(), cachedModelName)
}
