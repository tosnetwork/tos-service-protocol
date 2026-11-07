package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactorindex"
)

func TestCommandRefusesIncompleteConfiguration(t *testing.T) {
	var out bytes.Buffer
	if err := run(nil, &out); err == nil {
		t.Fatal("no command was accepted")
	}
	if err := run([]string{"help"}, &out); err != nil || !strings.Contains(out.String(), "discover") {
		t.Fatalf("help: %v %q", err, out.String())
	}
	if err := run([]string{"fund"}, &out); err == nil {
		t.Fatal("an unknown command was accepted")
	}
	directory := t.TempDir()
	network := filepath.Join(directory, "network.json")
	if err := os.WriteFile(network, []byte(`{"network_id":"tos-testnet","genesis_root_hash":"sha256:`+strings.Repeat("11", 32)+
		`","genesis_file_hash":"sha256:`+strings.Repeat("22", 32)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--network-domain", network, "--rpc", "https://a.example,https://b.example,https://c.example",
		"--registry-code-boc", filepath.Join(directory, "code"), "--registry-code-hash", "tvm-cell-sha256:" + strings.Repeat("33", 32),
		"--state-dir", directory, "--buyer-wallet", "0:" + strings.Repeat("21", 32)}
	err := run(append([]string{"discover"}, base...), &out)
	if err == nil || !strings.Contains(err.Error(), "--actor-code-hash") {
		t.Fatalf("a run without a pinned actor release was not refused: %v", err)
	}
	withActor := append(append([]string{"call"}, base...), "--actor-code-hash", "tvm-cell-sha256:"+strings.Repeat("44", 32))
	if err := run(withActor, &out); err == nil {
		t.Fatal("a call without custody flags was accepted")
	}
}

func TestRequestsPagesFromACanonicalCursor(t *testing.T) {
	if after, err := parseAfterRequestID(""); err != nil || after != nil {
		t.Fatalf("an empty cursor is the first page: %v %v", after, err)
	}
	for value, want := range map[string]uint64{"0": 0, "100": 100, "18446744073709551615": 1<<64 - 1} {
		after, err := parseAfterRequestID(value)
		if err != nil || after == nil || *after != want {
			t.Fatalf("%q: %v %v", value, after, err)
		}
	}
	for _, bad := range []string{"-1", "+1", "01", "1e3", " 1", "1 ", "0x10", "18446744073709551616", "abc"} {
		if _, err := parseAfterRequestID(bad); err == nil {
			t.Fatalf("cursor %q was accepted", bad)
		}
	}
	var out bytes.Buffer
	err := run([]string{"requests", "--actor", "0:" + strings.Repeat("21", 32), "--after-request-id", "01"}, &out)
	if err == nil || !strings.Contains(err.Error(), "--after-request-id") {
		t.Fatalf("a non-canonical cursor reached the chain: %v", err)
	}
}

type cursorRecorder struct{ after *uint64 }

func (c *cursorRecorder) Requests(_ string, _ serviceactorindex.RequestFilter, _ int, after *uint64) (*serviceactorindex.RequestPage, error) {
	c.after = after
	return &serviceactorindex.RequestPage{}, nil
}

func TestRequestsPassesTheCursorToTheIndex(t *testing.T) {
	recorder := &cursorRecorder{}
	cursor := uint64(100)
	if _, err := requestPage(recorder, "0:"+strings.Repeat("21", 32), serviceactorindex.RequestFilter{}, 100, &cursor); err != nil {
		t.Fatal(err)
	}
	if recorder.after == nil || *recorder.after != 100 {
		t.Fatalf("the index read the first page instead of continuing after 100: %v", recorder.after)
	}
}
