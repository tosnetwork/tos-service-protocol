package buyersdk

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestPinnedTOSCTLRunnerRejectsExecutableSubstitutionAndPinsConfigBytes(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "tosctl")
	config := filepath.Join(directory, "config.json")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"network":"original"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := newPinnedExecRunner(binary, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"network":"substituted"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if string(runner.config) != `{"network":"original"}` {
		t.Fatal("custody runner did not pin configuration bytes")
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.run(context.Background(), binary, "wallet", "ls"); err == nil ||
		!strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("substituted executable was not rejected: %v", err)
	}
}

func base64BOC(value *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(value.ToBOC())
}

type testTOSCTLPaths struct{ binary, config, wallet string }

func testTOSCTLSender(t *testing.T) testTOSCTLPaths {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "tosctl")
	config := filepath.Join(dir, "tosctl-config.json")
	if err := os.WriteFile(binary, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return testTOSCTLPaths{binary: binary, config: config, wallet: "buyer"}
}
