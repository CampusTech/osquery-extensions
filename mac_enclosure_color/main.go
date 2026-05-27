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
//	GOOS=darwin go build -o mac_enclosure_color.ext
//
// Run standalone (for testing):
//
//	osqueryi --extension ./mac_enclosure_color.ext
//
// Deploy with Fleet's fleetd / orbit by packaging the binary alongside the
// agent and letting orbit auto-load extensions in its extensions dir.
package main

import (
	"flag"
	"log"
	"time"

	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	socket := flag.String("socket", "", "Path to the osquery extension socket")
	timeout := flag.Int("timeout", 3, "Seconds to wait for a successful connection")
	interval := flag.Int("interval", 3, "Seconds between connection checks")
	verbose := flag.Bool("verbose", false, "Enable verbose extension logging")
	flag.Parse()
	_ = *verbose

	if *socket == "" {
		log.Fatalln("--socket is required")
	}

	server, err := osquery.NewExtensionManagerServer(
		"mac_enclosure_color",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		log.Fatalf("error creating extension manager: %s", err)
	}

	server.RegisterPlugin(table.NewPlugin("mac_enclosure_color", columns(), osqueryGenerate))

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
