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
//	GOOS=darwin go build -ldflags "-X main.version=0.4.1" -o dot1x.ext
//
// Run standalone (for testing):
//
//	osqueryi --extension ./dot1x.ext
package main

import (
	"github.com/CampusTech/osquery-extensions/extserver"
	"github.com/macadmins/osquery-extension/tables/dot1x"
	"github.com/osquery/osquery-go/plugin/table"
)

// version is reported in osquery_extensions.version; the Fleet install
// policy gates on it. Release builds set it with
// -ldflags "-X main.version=<tag without v>".
var version = "dev"

func main() {
	extserver.Main("dot1x", version,
		table.NewPlugin("dot1x", dot1x.Dot1XStatusColumns(), dot1x.Dot1XStatusGenerate))
}
