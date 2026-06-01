// Command touchid is an osquery extension that exposes two macOS Touch ID
// tables:
//
//   - touchid_system_config: system-wide Touch ID / Secure Enclave state, from
//     `bioutil -r -s` and `system_profiler SPiBridgeDataType`.
//   - touchid_user_config: per-user Touch ID state and enrolled fingerprint
//     count, from `bioutil -r` and `bioutil -c` run as the target uid. Requires
//     a `WHERE uid = ` constraint.
//
// The logic is a clean-room reimplementation: it parses bioutil output by line
// label rather than by field position, so it stays correct on newer macOS
// releases that add extra configuration lines.
//
// Build:
//
//	GOOS=darwin go build -o touchid.ext
//
// Run standalone (for testing):
//
//	osqueryi --extension ./touchid.ext
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
		"touchid",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		log.Fatalf("error creating extension manager: %s", err)
	}

	server.RegisterPlugin(table.NewPlugin("touchid_system_config", systemColumns(), osquerySystemGenerate))
	server.RegisterPlugin(table.NewPlugin("touchid_user_config", userColumns(), osqueryUserGenerate))

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
