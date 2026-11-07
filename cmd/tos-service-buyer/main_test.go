package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
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

type fixedEndpoints struct{}

func (fixedEndpoints) Endpoints() []string                                { return []string{"https://a.example/jsonRPC"} }
func (fixedEndpoints) CheckEndpointGenesis(context.Context, string) error { return nil }

// The vault URL carries the vault master key, so call takes it only from
// VAULT_URL: there is no flag that would put it on the command line, and a
// leftover --vault-url is refused without being echoed.
func TestCallReadsTheVaultURLOnlyFromTheEnvironment(t *testing.T) {
	const masterKey = "6d61737465722d6b65792d6d61737465722d6b65792d6d61737465722d6b6579"
	secret := "file:///private/vault.json?master_key=" + masterKey
	t.Setenv("VAULT_URL", secret)

	// The sender call builds hands tosctl exactly VAULT_URL, recorded from
	// the fake tosctl's exec-time environment.
	directory := t.TempDir()
	binary, config := filepath.Join(directory, "tosctl"), filepath.Join(directory, "config.json")
	script := "#!/bin/sh\ncat /proc/$$/environ > " + directory + "/environ\n" +
		"printf '%s\\n' \"$@\" > " + directory + "/argv\necho 'OK Service Actor call message submitted to x'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"chain_rpc":{"urls":["https://a.example"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(script))
	sender, err := newCallSender(binary, hex.EncodeToString(digest[:]), config, "buyer", fixedEndpoints{})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendCall(context.Background(), buyersdk.ServiceActorCallIntent{
		Actor: "0:" + strings.Repeat("21", 32), QueryID: 7}); err != nil {
		t.Fatalf("call: %v", err)
	}
	environ, err := os.ReadFile(filepath.Join(directory, "environ"))
	if err != nil {
		t.Fatalf("custody did not run: %v", err)
	}
	if string(environ) != "VAULT_URL="+secret+"\x00" {
		t.Fatalf("custody environment carries %d bytes, not exactly VAULT_URL from the environment", len(environ))
	}
	argv, err := os.ReadFile(filepath.Join(directory, "argv"))
	if err != nil || len(argv) == 0 || bytes.Contains(argv, []byte(masterKey)) {
		t.Fatalf("custody argv is missing or carries the vault key: %v", err)
	}

	var usage bytes.Buffer
	previous := usageOutput
	usageOutput = &usage
	t.Cleanup(func() { usageOutput = previous })

	var out bytes.Buffer
	if err := run([]string{"call", "--help"}, &out); err != nil {
		t.Fatalf("call --help: %v", err)
	}
	if !strings.Contains(usage.String(), "-tosctl-config") {
		t.Fatalf("call --help printed no flag usage: %q", usage.String())
	}
	if strings.Contains(usage.String(), "vault") {
		t.Fatalf("call still documents a vault flag: %q", usage.String())
	}
	usage.Reset()
	err = run([]string{"call", "--vault-url", secret}, &out)
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("a --vault-url flag was not refused: %v", err)
	}
	for name, text := range map[string]string{"error": err.Error(), "usage": usage.String(), "stdout": out.String()} {
		if strings.Contains(text, secret) || strings.Contains(text, masterKey) {
			t.Fatalf("the refused vault URL was echoed on %s: %q", name, text)
		}
	}
}
