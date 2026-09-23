package main

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServeCmd_MissingFirelineFlag, TestServeCmd_BadFirelinePath, and
// TestServeCmd_BadCELSyntax below only exercise serve's flag parsing and
// Fireline loading/compiling, all of which fail before net.Listen is ever
// reached, so none of them bind a real port. TestServeCmd_Serves (further
// down) is the one test that runs the real server end to end.

func TestServeCmd_MissingFirelineFlag(t *testing.T) {
	_, err := runCmd(t, newServeCmd(), "--addr", ":0")
	if err == nil {
		t.Fatal("expected an error for a missing --fireline flag, got nil")
	}
}

func TestServeCmd_BadFirelinePath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")

	_, err := runCmd(t, newServeCmd(), "--addr", ":0", "--fireline", missing)
	if err == nil {
		t.Fatal("expected an error for a missing --fireline file, got nil")
	}
}

func TestServeCmd_BadCELSyntax(t *testing.T) {
	path := writeFirelineFixture(t, `
name: baseline
version: "1"
rules:
  - id: bad-rule
    when: "severity_raw =="
    tolerance: 0s
`)

	_, err := runCmd(t, newServeCmd(), "--addr", ":0", "--fireline", path)
	if err == nil {
		t.Fatal("expected an error for invalid CEL syntax, got nil")
	}
}

// TestServeCmd_Serves runs the real server on an OS-assigned port (--addr
// 127.0.0.1:0), confirms it actually answers a request, then cancels the
// command's context and confirms the graceful-shutdown path added to
// serve.go makes cmd.Execute() return cleanly (nil, not an error) instead
// of hanging forever. internal/api/api_test.go already covers the handler's
// own behavior in detail; this test is specifically about serve.go's own
// wiring: does the listener actually come up, and does it actually stop.
func TestServeCmd_Serves(t *testing.T) {
	setUpTurso(t)
	path := writeFirelineFixture(t, evalTestFirelineYAML)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cmd := newServeCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--addr", "127.0.0.1:0", "--fireline", path})

	pr, pw := io.Pipe()
	cmd.SetOut(pw)
	cmd.SetErr(pw)

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil {
		t.Fatalf("read startup line: %v", err)
	}
	addr := parseListeningAddr(t, line)

	resp, err := http.Get("http://" + addr + "/api/v1/observations")
	if err != nil {
		t.Fatalf("GET /api/v1/observations: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Execute after context cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down within 5s of context cancellation")
	}
}

func TestServeCmd_BadStorageBackend(t *testing.T) {
	path := writeFirelineFixture(t, evalTestFirelineYAML)
	t.Setenv("FIRELINE_STORAGE_BACKEND", "mysql")

	_, err := runCmd(t, newServeCmd(), "--addr", ":0", "--fireline", path)
	if err == nil {
		t.Fatal("expected an error for an unknown FIRELINE_STORAGE_BACKEND, got nil")
	}
}

// parseListeningAddr extracts "host:port" from a line shaped like
// `listening on 127.0.0.1:54321 (turso backend, fireline "baseline" v1)`,
// matching exactly what serve.go's cmd.Printf writes.
func parseListeningAddr(t *testing.T, line string) string {
	t.Helper()
	const prefix = "listening on "
	rest, ok := strings.CutPrefix(line, prefix)
	if !ok {
		t.Fatalf("unexpected startup line: %q", line)
	}
	addr, _, ok := strings.Cut(rest, " (")
	if !ok {
		t.Fatalf("unexpected startup line: %q", line)
	}
	return addr
}
