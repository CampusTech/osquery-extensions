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
	"context"
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

	client, err := osquery.NewClient(*socket, time.Duration(*timeout)*time.Second)
	if err != nil {
		log.Fatalf("error creating extension manager client: %s", err)
	}
	defer client.Close()

	server, err := newServer(*socket, client, time.Duration(*timeout)*time.Second, time.Duration(*interval)*time.Second)
	if err != nil {
		log.Fatalf("error creating extension manager: %s", err)
	}

	if err := run(context.Background(), server, client, time.Duration(*interval)*time.Second); err != nil {
		log.Fatalln(err)
	}
}

func newServer(socket string, client osquery.ExtensionManager, timeout, interval time.Duration) (*osquery.ExtensionManagerServer, error) {
	server, err := osquery.NewExtensionManagerServer(
		"dot1x",
		socket,
		osquery.WithClient(client),
		osquery.ServerTimeout(timeout),
		osquery.ServerPingInterval(interval),
	)
	if err != nil {
		return nil, err
	}
	server.RegisterPlugin(table.NewPlugin("dot1x", dot1x.Dot1XStatusColumns(), dot1x.Dot1XStatusGenerate))
	return server, nil
}

// run serves the extension until ctx is cancelled or osquery goes away.
func run(_ context.Context, server *osquery.ExtensionManagerServer, _ osquery.ExtensionManager, _ time.Duration) error {
	return server.Run()
}
