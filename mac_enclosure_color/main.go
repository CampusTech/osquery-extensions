// Command mac_enclosure_color is an osquery extension that exposes a
// mac_enclosure_color table returning the running Mac's enclosure color.
//
// Data sources:
//   - MobileGestalt (private dylib) for ProductType and DeviceEnclosureColor,
//     accessed via cgo through the Gestalt interface in gestalt_darwin.go.
//   - system_profiler (public CLI) for the Model Name string; MobileGestalt's
//     marketing-name keys return the OS name ("macOS") on recent macOS, so we
//     shell out for this.
//
// Build:
//
//	GOOS=darwin go build -ldflags "-X main.version=0.4.1" -o mac_enclosure_color.ext
//
// Run standalone (for testing):
//
//	osqueryi --extension ./mac_enclosure_color.ext
//
// Deploy with Fleet's fleetd / orbit by packaging the binary alongside the
// agent and letting orbit auto-load extensions in its extensions dir.
package main

import (
	"github.com/CampusTech/osquery-extensions/extserver"
	"github.com/osquery/osquery-go/plugin/table"
)

// version is reported in osquery_extensions.version. Release builds set it
// with -ldflags "-X main.version=<tag without v>".
var version = "dev"

func main() {
	extserver.Main("mac_enclosure_color", version,
		table.NewPlugin("mac_enclosure_color", columns(), osqueryGenerate))
}
