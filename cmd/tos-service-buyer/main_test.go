package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
