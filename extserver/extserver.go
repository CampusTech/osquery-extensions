// Package extserver runs a Campus osquery extension. It replaces osquery-go's
// ExtensionManagerServer.Run, whose failure handling wedged osqueryd's
// extension manager on several Macs (first seen on Fleet host 671,
// 2026-10-05):
//
//   - Run exits on the first failed ping. "timeout after 200ms" is not
//     osqueryd being gone: it is osquery-go's client lock wait (200ms by
//     default), which can fail even uncontended after a scheduling stall.
//   - The exited extension leaves its registration for osqueryd to reap, and
//     osqueryd 5.23.1 can block reaping indefinitely behind a running query.
//     Every respawn is then refused with "Duplicate extension registered" and
//     exits, every ~3s, until osqueryd restarts.
//
// Run instead waits up to the connection timeout for the client lock,
// tolerates transient ping failures, retries duplicate registrations
// in-process with backoff, and always deregisters on the way out (including
// on SIGTERM/SIGINT).
package extserver

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	osquery "github.com/osquery/osquery-go"
)

const (
	// maxPingFailures consecutive failed pings mean osquery is really gone.
	maxPingFailures = 3
	// maxRetryBackoff caps the wait between duplicate-registration retries.
	maxRetryBackoff = time.Minute
)

// Main parses the standard osquery extension flags (--socket, --timeout,
// --interval, --verbose), registers plugins as extension name/version and
// serves until osquery goes away or the process is signalled.
func Main(name, version string, plugins ...osquery.OsqueryPlugin) {
	socket := flag.String("socket", "", "Path to the osquery extension socket")
	timeoutSec := flag.Int("timeout", 3, "Seconds to wait for a successful connection")
	intervalSec := flag.Int("interval", 3, "Seconds between connection checks")
	verbose := flag.Bool("verbose", false, "Enable verbose extension logging")
	flag.Parse()
	_ = *verbose

	if *socket == "" {
		log.Fatalln("--socket is required")
	}
	timeout := time.Duration(*timeoutSec) * time.Second
	interval := time.Duration(*intervalSec) * time.Second

	// Wait up to timeout for the client's socket lock instead of osquery-go's
	// 200ms default.
	client, err := osquery.NewClient(*socket, timeout, osquery.DefaultWaitTime(timeout))
	if err != nil {
		log.Fatalf("error creating extension manager client: %s", err)
	}

	server, err := newServer(name, version, *socket, client, timeout, plugins...)
	if err != nil {
		client.Close()
		log.Fatalf("error creating extension manager: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err = run(ctx, server, client, interval)
	stop()
	client.Close()
	if err != nil {
		log.Fatalln(err)
	}
}

func newServer(name, version, socket string, client osquery.ExtensionManager, timeout time.Duration, plugins ...osquery.OsqueryPlugin) (*osquery.ExtensionManagerServer, error) {
	server, err := osquery.NewExtensionManagerServer(
		name,
		socket,
		osquery.WithClient(client),
		osquery.ServerTimeout(timeout),
		osquery.ExtensionVersion(version),
	)
	if err != nil {
		return nil, err
	}
	server.RegisterPlugin(plugins...)
	return server, nil
}

// run registers the extension and serves until ctx is cancelled, osquery asks
// it to shut down, or maxPingFailures consecutive pings fail.
func run(ctx context.Context, server *osquery.ExtensionManagerServer, client osquery.ExtensionManager, interval time.Duration) error {
	// Always deregister on the way out so osqueryd never has to reap a stale
	// registration itself.
	defer func() {
		if err := server.Shutdown(context.Background()); err != nil {
			log.Println(err)
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // runs before Shutdown: stops registration retries

	served := make(chan error, 1)
	go func() { served <- start(ctx, server, interval) }()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-served:
			return err
		case <-ticker.C:
			status, err := client.Ping()
			if err == nil && status.Code != 0 {
				err = fmt.Errorf("status %d: %s", status.Code, status.Message)
			}
			if err == nil {
				failures = 0
				continue
			}
			failures++
			if failures >= maxPingFailures {
				return fmt.Errorf("osquery unreachable, %d pings failed: %w", failures, err)
			}
			log.Printf("ping %d/%d failed: %v", failures, maxPingFailures, err)
		}
	}
}

// start registers and serves. While osqueryd still holds a stale registration
// with our name it refuses us as a duplicate; its extension watcher normally
// reaps the stale entry within a couple of --extensions_interval periods, so
// retry in-process with backoff instead of exiting into a respawn loop.
//
// ponytail: a retry that races run's shutdown can register just before the
// process exits; osqueryd then reaps it like any dead extension.
func start(ctx context.Context, server *osquery.ExtensionManagerServer, backoff time.Duration) error {
	for {
		err := server.Start()
		if err == nil || !strings.Contains(err.Error(), "Duplicate extension registered") {
			return err
		}
		log.Printf("%v; retrying in %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxRetryBackoff)
	}
}
