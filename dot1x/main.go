// Command dot1x is an osquery extension that exposes a dot1x table with
// per-interface 802.1X / EAPOL supplicant state (EAP method, supplicant
// state, failure codes, authenticator MAC, ...).
//
// The table implementation lives in macadmins/osquery-extension (PR #113,
// tables/dot1x). This wrapper registers ONLY the dot1x table so it can be
// loaded alongside fleetd, whose built-in extension already bundles the
// other macadmins tables -- loading the full macadmins extension would
// collide on those table names and crash-loop orbit.
//
// Once PR #113 ships in a fleetd release, delete this extension: fleetd will
// register dot1x itself and this copy would collide with it.
//
// Build:
//
//	GOOS=darwin go build -o dot1x.ext
//
// Run standalone (for testing):
//
//	osqueryi --extension ./dot1x.ext
package main

import (
	"flag"
	"log"
	"time"

	"github.com/macadmins/osquery-extension/tables/dot1x"
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
		"dot1x",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		log.Fatalf("error creating extension manager: %s", err)
	}

	server.RegisterPlugin(table.NewPlugin("dot1x", dot1x.Dot1XStatusColumns(), dot1x.Dot1XStatusGenerate))

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
