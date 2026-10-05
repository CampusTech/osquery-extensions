package extserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	osquery "github.com/osquery/osquery-go"
	gen "github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/plugin/table"
)

const (
	testInterval = 10 * time.Millisecond
	testVersion  = "1.2.3"
)

// fakeOsquery stands in for osqueryd's extension manager. ping and register
// are given the 1-based call number so a test can script a sequence of
// responses.
type fakeOsquery struct {
	osquery.ExtensionManager // methods the extension never calls

	ping     func(n int) error
	register func(n int) *gen.ExtensionStatus

	pings, registers, deregisters atomic.Int32

	mu      sync.Mutex
	version string
}

func (f *fakeOsquery) Close() {}

func (f *fakeOsquery) Ping() (*gen.ExtensionStatus, error) {
	if err := f.ping(int(f.pings.Add(1))); err != nil {
		return nil, err
	}
	return &gen.ExtensionStatus{Code: 0, Message: "OK"}, nil
}

func (f *fakeOsquery) RegisterExtension(info *gen.InternalExtensionInfo, _ gen.ExtensionRegistry) (*gen.ExtensionStatus, error) {
	f.mu.Lock()
	f.version = info.Version
	f.mu.Unlock()
	return f.register(int(f.registers.Add(1))), nil
}

func (f *fakeOsquery) DeregisterExtension(gen.ExtensionRouteUUID) (*gen.ExtensionStatus, error) {
	f.deregisters.Add(1)
	return &gen.ExtensionStatus{Code: 0, Message: "OK"}, nil
}

func registered(n int) *gen.ExtensionStatus {
	return &gen.ExtensionStatus{Code: 0, Message: "OK", UUID: gen.ExtensionRouteUUID(n)}
}

// duplicate is what osqueryd answers while a stale registration with our name
// is still in its registry (osquery/extensions/interface.cpp).
func duplicate(int) *gen.ExtensionStatus {
	return &gen.ExtensionStatus{Code: 1, Message: "Duplicate extension registered"}
}

func healthy(int) error { return nil }

// startRun runs the extension against f in the background and returns a
// cancel func plus the channel run's result arrives on.
func startRun(t *testing.T, f *fakeOsquery) (context.CancelFunc, <-chan error) {
	t.Helper()
	// The server listens on <socket>.<uuid>; keep the path short enough for
	// a unix socket (macOS t.TempDir() paths are too long).
	dir, err := os.MkdirTemp("/tmp", "extserver")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	plugin := table.NewPlugin("t", []table.ColumnDefinition{table.TextColumn("c")},
		func(context.Context, table.QueryContext) ([]map[string]string, error) { return nil, nil })
	server, err := newServer("test", testVersion, filepath.Join(dir, "em"), f, time.Second, plugin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- run(ctx, server, f, testInterval) }()
	return cancel, done
}

// waitFor polls cond until it holds, failing the test if run exits first.
func waitFor(t *testing.T, done <-chan error, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case err := <-done:
			t.Fatalf("run exited before %s: %v", what, err)
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(testInterval / 2):
		}
	}
}

func stop(t *testing.T, cancel context.CancelFunc, done <-chan error) error {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
		return nil
	}
}

// Host 671, 2026-10-05: a single failed ping ("timeout after 200ms") made
// dot1x.ext exit, leaving a registration osqueryd never reaped. One blip must
// not kill the extension, and shutting down must deregister.
func TestTransientPingFailureDoesNotExit(t *testing.T) {
	f := &fakeOsquery{
		ping: func(n int) error {
			if n == 1 {
				return errors.New("timeout after 200ms")
			}
			return nil
		},
		register: registered,
	}
	cancel, done := startRun(t, f)

	waitFor(t, done, "pings to recover", func() bool { return f.pings.Load() >= 5 })

	if err := stop(t, cancel, done); err != nil {
		t.Fatalf("run returned %v after cancel, want nil", err)
	}
	if got := f.deregisters.Load(); got != 1 {
		t.Errorf("deregistered %d times on shutdown, want 1", got)
	}
}

// Host 671, 2026-10-05: with a stale dot1x registration in osqueryd, every
// respawned dot1x.ext was refused as a duplicate, exited with status 1 and
// was respawned again, every ~3s for hours. The extension must keep retrying
// in-process until osquery reaps the stale entry.
func TestDuplicateRegistrationRetries(t *testing.T) {
	f := &fakeOsquery{
		ping: healthy,
		register: func(n int) *gen.ExtensionStatus {
			if n <= 2 {
				return duplicate(n)
			}
			return registered(n)
		},
	}
	cancel, done := startRun(t, f)

	waitFor(t, done, "registration to succeed", func() bool { return f.registers.Load() >= 3 })
	pings := f.pings.Load()
	waitFor(t, done, "pings after registering", func() bool { return f.pings.Load() >= pings+3 })

	if err := stop(t, cancel, done); err != nil {
		t.Fatalf("run returned %v after cancel, want nil", err)
	}
	if got := f.registers.Load(); got != 3 {
		t.Errorf("registered %d times, want 3", got)
	}
}

// Tolerating blips must not keep an orphaned extension alive once osquery
// is really gone.
func TestExitsWhenOsqueryGone(t *testing.T) {
	f := &fakeOsquery{
		ping:     func(int) error { return errors.New("broken pipe") },
		register: registered,
	}
	_, done := startRun(t, f)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run returned nil, want an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run kept going with osquery gone")
	}
	if got := f.deregisters.Load(); got != 1 {
		t.Errorf("deregistered %d times, want 1", got)
	}
}

// The fleet install policy gates on osquery_extensions.version, so the
// extension must register with a version.
func TestRegistersVersion(t *testing.T) {
	f := &fakeOsquery{ping: healthy, register: registered}
	cancel, done := startRun(t, f)
	waitFor(t, done, "registration", func() bool { return f.registers.Load() >= 1 })
	_ = stop(t, cancel, done)

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.version != testVersion {
		t.Errorf("registered version %q, want %q", f.version, testVersion)
	}
}
