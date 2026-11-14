package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestReadSignedActionIsStrictAndRequiresAuthoritySignature(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "signed.json")
	signature := &nativev1.SignatureV1{KeyId: "mldsa44:" + strings.Repeat("11", 32), Mldsa44Signature: make([]byte, 2420)}
	value := &nativev1.SignedNativeActionV1{Action: &nativev1.NativeActionV1{Protocol: "test"},
		AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := readSignedAction(path)
	if err != nil || parsed.GetAction().GetProtocol() != "test" || len(parsed.GetAuthoritySignatures()) != 1 {
		t.Fatalf("read signed action: %+v %v", parsed, err)
	}
	if err := os.WriteFile(path, append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSignedAction(path); err == nil {
		t.Fatal("unknown signed action field was accepted")
	}
	// The Registry admits at most 8 signatures; a ninth is refused here.
	for count, accepted := range map[int]bool{8: true, 9: false} {
		value.AuthoritySignatures = nil
		for range count {
			value.AuthoritySignatures = append(value.AuthoritySignatures, signature)
		}
		raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSignedAction(path); (err == nil) != accepted {
			t.Fatalf("%d signatures: accepted = %v", count, err == nil)
		}
	}
}

func TestPublicationNonceAndPrivateTokenFailClosed(t *testing.T) {
	if _, err := nonce(strings.Repeat("0", 64)); err == nil {
		t.Fatal("zero publication nonce was accepted")
	}
	if _, err := nonce(strings.Repeat("A", 64)); err == nil {
		t.Fatal("noncanonical publication nonce was accepted")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("public Gateway bearer token file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := readToken(path); err != nil || token != "secret" {
		t.Fatalf("private token: %q %v", token, err)
	}
}

func TestStateDirectoryMustBeOwnerPrivateAndNotASymlink(t *testing.T) {
	base := t.TempDir()
	fresh := filepath.Join(base, "fresh")
	if _, err := openJournal(fresh); err != nil {
		t.Fatalf("fresh state directory: %v", err)
	}
	for _, directory := range []string{fresh, filepath.Join(fresh, "journal")} {
		info, err := os.Lstat(directory)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s was not created owner-private: %v %v", directory, info, err)
		}
	}
	broad := filepath.Join(base, "broad")
	if err := os.Mkdir(broad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(broad, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(broad); err == nil {
		t.Fatal("world-readable state directory was used")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(fresh, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(link); err == nil {
		t.Fatal("symlinked state directory was used")
	}
	if err := os.Chmod(filepath.Join(fresh, "journal"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(fresh); err == nil {
		t.Fatal("group-accessible journal directory was used")
	}
	if _, err := openJournal("relative"); err == nil {
		t.Fatal("relative state directory was used")
	}
}

func TestCommandFlagsFailClosed(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	base := []string{"--state-dir", state, "--gateway", "https://gateway.example", "--caller-id", "caller"}
	prepareBase := append(append([]string(nil), base...), "--network-id", "n", "--genesis-root", "r", "--genesis-file", "f",
		"--registry-code-hash", "h", "--owner-agent-id", "agent_"+strings.Repeat("ab", 32), "--manifest-json", "/manifest.json")
	cases := map[string][]string{
		"unknown mode":             {"publish", "--state-dir", state},
		"no state dir":             {"status"},
		"positional argument":      {"status", "--state-dir", state, "extra"},
		"apply without hash":       append([]string{"apply"}, base...),
		"preview without hash":     append([]string{"preview"}, base...),
		"prepare without owner":    append([]string{"prepare"}, base...),
		"rpc without pinned actor": append(append([]string{"prepare"}, prepareBase...), "--rpc", "http://a,http://b,http://c"),
		"pinned actor without rpc": append(append([]string{"prepare"}, prepareBase...), "--actor-code-hash", "tvm-cell-sha256:"+strings.Repeat("11", 32)),
		"apply takes no manifest":  append(append([]string{"apply"}, base...), "--action-hash", "sha256:"+strings.Repeat("11", 32), "--manifest-json", "/m.json"),
	}
	for name, arguments := range cases {
		if err := run(arguments, io.Discard, io.Discard); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if err := run([]string{"status", "--state-dir", state, "--action-hash", "sha256:" + strings.Repeat("11", 32)}, io.Discard, io.Discard); err == nil {
		t.Fatal("status of an unjournaled publication succeeded")
	}
	var out strings.Builder
	if err := run([]string{"status", "--state-dir", state}, &out, io.Discard); err != nil || out.Len() != 0 {
		t.Fatalf("status of an empty journal: %q %v", out.String(), err)
	}
}
