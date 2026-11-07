package buyersdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testMasterKey = "6d61737465722d6b65792d6d61737465722d6b65792d6d61737465722d6b6579"

// custodyRecorder is a fake tosctl that records, per subcommand ("wallet" for
// the Preflight binding check, "agent" for the call), its exact exec-time
// environment and command line from /proc, before any shell initialization
// can add to them, and its arguments.
type custodyRecorder struct {
	directory, binary, config string
}

func newCustodyRecorder(t *testing.T, prepared []byte, failing bool) custodyRecorder {
	t.Helper()
	directory := t.TempDir()
	recorder := custodyRecorder{directory: directory, binary: filepath.Join(directory, "tosctl"),
		config: filepath.Join(directory, "config.json")}
	if err := os.WriteFile(filepath.Join(directory, "prepared.json"), prepared, 0o600); err != nil {
		t.Fatal(err)
	}
	record := "cat /proc/$$/environ > " + directory + "/$1.environ\n" +
		"cat /proc/$$/cmdline > " + directory + "/$1.cmdline\n" +
		"printf '%s\\n' \"$@\" > " + directory + "/$1.argv\n"
	answer := "if [ \"$1\" = wallet ]; then cat " + directory + "/prepared.json; " +
		"else echo 'OK Service Actor call message submitted to " + saActor + "'; fi\n"
	if failing {
		// A custody failure that echoes the credential on both streams.
		answer = "echo \"vault: $VAULT_URL\"; echo \"vault: $VAULT_URL\" >&2; exit 1\n"
	}
	if err := os.WriteFile(recorder.binary, []byte("#!/bin/sh\n"+record+answer), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recorder.config, []byte(`{"chain_rpc":{"urls":["https://a.example"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return recorder
}

func (r custodyRecorder) sender(t *testing.T, vaultURL string) *TOSCTLServiceActorSender {
	t.Helper()
	runner, err := newPinnedExecRunner(r.binary, r.config)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewTOSCTLServiceActorSender(TOSCTLServiceActorSenderConfig{BinaryPath: r.binary,
		BinarySHA256: hex.EncodeToString(runner.identity.digest[:]), ConfigPath: r.config, WalletName: "buyer",
		VaultURL: vaultURL, Endpoints: vetter{endpoints: []string{"https://a.example/jsonRPC"}}})
	if err != nil {
		t.Fatal(err)
	}
	return sender
}

// recorded returns the NUL- or newline-separated entries one invocation
// recorded; a missing record fails the test, so a fake that never ran cannot
// pass as an empty environment.
func (r custodyRecorder) recorded(t *testing.T, subcommand, kind string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.directory, subcommand+"."+kind))
	if err != nil {
		t.Fatalf("%s did not record its %s: %v", subcommand, kind, err)
	}
	separator := []byte{0}
	if kind == "argv" {
		separator = []byte{'\n'}
	}
	var entries []string
	for _, entry := range bytes.Split(raw, separator) {
		if len(entry) != 0 {
			entries = append(entries, string(entry))
		}
	}
	return entries
}

func (r custodyRecorder) assertNoCredentialOnCommandLine(t *testing.T, subcommand, vaultURL string) {
	t.Helper()
	argv := r.recorded(t, subcommand, "argv")
	cmdline := r.recorded(t, subcommand, "cmdline")
	if len(argv) == 0 || argv[0] != subcommand || len(cmdline) == 0 {
		t.Fatalf("%s recorded no command line: argv %q cmdline %q", subcommand, argv, cmdline)
	}
	for _, entry := range append(argv, cmdline...) {
		if strings.Contains(entry, vaultURL) || strings.Contains(entry, testMasterKey) {
			t.Fatalf("%s command line carries the vault credential: %q", subcommand, entry)
		}
	}
}

func testVaultURL(t *testing.T) string {
	return "file://" + filepath.Join(t.TempDir(), "vault.json") + "?master_key=" + testMasterKey
}

// The vault URL reaches custody only as its single environment variable, on
// both custody invocations a call makes; no argument carries it.
func TestVaultURLReachesCustodyOnlyThroughTheEnvironment(t *testing.T) {
	vaultURL := testVaultURL(t)
	intent := testIntent()
	recorder := newCustodyRecorder(t, preparedOutput(t, saBuyer, saActor, 700_000_000, intent), false)
	sender := recorder.sender(t, vaultURL)
	if err := sender.Preflight(context.Background(), intent); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if err := sender.SendCall(context.Background(), intent); err != nil {
		t.Fatalf("call: %v", err)
	}
	for _, subcommand := range []string{"wallet", "agent"} {
		recorder.assertNoCredentialOnCommandLine(t, subcommand, vaultURL)
		if environment := recorder.recorded(t, subcommand, "environ"); len(environment) != 1 ||
			environment[0] != "VAULT_URL="+vaultURL {
			t.Fatalf("%s environment = %q, want exactly VAULT_URL", subcommand, environment)
		}
	}
}

// Without a configured vault URL custody gets an empty environment: nothing
// of the caller's, not even a VAULT_URL the caller happens to hold.
func TestCustodyNeverInheritsTheCallerEnvironment(t *testing.T) {
	t.Setenv("VAULT_URL", testVaultURL(t))
	t.Setenv("TOS_BUYER_ENVIRONMENT_SENTINEL", "inherited")
	intent := testIntent()
	recorder := newCustodyRecorder(t, preparedOutput(t, saBuyer, saActor, 700_000_000, intent), false)
	sender := recorder.sender(t, "")
	if err := sender.Preflight(context.Background(), intent); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if err := sender.SendCall(context.Background(), intent); err != nil {
		t.Fatalf("call: %v", err)
	}
	for _, subcommand := range []string{"wallet", "agent"} {
		recorder.recorded(t, subcommand, "argv")
		if environment := recorder.recorded(t, subcommand, "environ"); len(environment) != 0 {
			names := make([]string, 0, len(environment))
			for _, entry := range environment {
				name, _, _ := strings.Cut(entry, "=")
				names = append(names, name)
			}
			t.Fatalf("%s inherited %d caller variables: %q", subcommand, len(names), names)
		}
	}
}

// A custody failure that prints the credential does not carry it into the
// errors the buyer returns, journals or prints.
func TestCustodyFailureDoesNotSurfaceTheVaultURL(t *testing.T) {
	vaultURL := testVaultURL(t)
	intent := testIntent()
	recorder := newCustodyRecorder(t, preparedOutput(t, saBuyer, saActor, 700_000_000, intent), true)
	sender := recorder.sender(t, vaultURL)
	preflight := sender.Preflight(context.Background(), intent)
	call := sender.SendCall(context.Background(), intent)
	for name, err := range map[string]error{"preflight": preflight, "call": call} {
		if err == nil {
			t.Fatalf("%s: a failed custody run was accepted", name)
		}
		if strings.Contains(err.Error(), vaultURL) || strings.Contains(err.Error(), testMasterKey) {
			t.Fatalf("%s error carries the vault credential: %v", name, err)
		}
	}
	for _, subcommand := range []string{"wallet", "agent"} {
		recorder.assertNoCredentialOnCommandLine(t, subcommand, vaultURL)
		if environment := recorder.recorded(t, subcommand, "environ"); len(environment) != 1 ||
			environment[0] != "VAULT_URL="+vaultURL {
			t.Fatalf("%s did not reach its credential-printing failure: %q", subcommand, environment)
		}
	}
}
