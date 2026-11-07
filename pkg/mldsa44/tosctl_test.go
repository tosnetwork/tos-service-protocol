package mldsa44_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type registryVector struct {
	ContractCodeHash  string `json:"contract_code_hash"`
	AgentRegistration struct {
		Policy struct {
			Controllers []struct {
				PublicKeyHex string `json:"public_key_hex"`
				KeyID        string `json:"key_id"`
			} `json:"controllers"`
		} `json:"policy"`
		Expected vectorExpected `json:"expected"`
	} `json:"agent_registration"`
	CapabilityRegistration struct {
		Expected vectorExpected `json:"expected"`
	} `json:"capability_registration"`
}

type vectorExpected struct {
	ActionHash      string `json:"action_hash"`
	ActionBOCBase64 string `json:"action_boc_base64"`
	SignatureHex    string `json:"signature_hex"`
}

func loadVector(t *testing.T) (registryVector, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../nativecore/testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector registryVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.AgentRegistration.Policy.Controllers) != 1 {
		t.Fatal("frozen vector must name exactly one controller")
	}
	key, err := hex.DecodeString(vector.AgentRegistration.Policy.Controllers[0].PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return vector, key
}

func decode(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func actionBOC(t *testing.T, expected vectorExpected) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(expected.ActionBOCBase64)
	if err != nil {
		t.Fatal(err)
	}
	root, err := cell.FromBOC(raw)
	if err != nil || "sha256:"+hex.EncodeToString(root.Hash()) != expected.ActionHash {
		t.Fatalf("frozen action BOC does not match its hash: %v", err)
	}
	return raw
}

func TestKeyIDMatchesTheFrozenController(t *testing.T) {
	vector, key := loadVector(t)
	id, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	if text := mldsa44.KeyIDText(id); text != vector.AgentRegistration.Policy.Controllers[0].KeyID {
		t.Fatalf("key ID = %s", text)
	}
	// The derivation is domain || 01 00 || key; a big-endian suite or a
	// missing domain must give a different identity.
	for _, prefix := range [][]byte{[]byte("TOS-PQ-CONSENSUS-KEY-v1\x00\x01"), {0x01, 0x00}} {
		other := sha256.Sum256(append(append([]byte(nil), prefix...), key...))
		if other == id {
			t.Fatal("key ID ignores its domain or suite encoding")
		}
	}
	if _, err := mldsa44.KeyID(key[:mldsa44.PublicKeySize-1]); err == nil {
		t.Fatal("short key accepted")
	}
	for _, bad := range []string{
		"", "ed25519:" + strings.Repeat("11", 32), "mldsa44:" + strings.Repeat("AA", 32),
		"mldsa44:" + strings.Repeat("11", 31), "mldsa44:" + strings.Repeat("00", 32), " mldsa44:" + strings.Repeat("11", 32),
	} {
		if _, err := mldsa44.ParseKeyIDText(bad); err == nil {
			t.Fatalf("key ID text %q accepted", bad)
		}
	}
	if parsed, err := mldsa44.ParseKeyIDText(mldsa44.KeyIDText(id)); err != nil || parsed != id {
		t.Fatal("canonical key ID text refused")
	}
}

func TestFrozenSignaturesVerifyThroughTheHelper(t *testing.T) {
	helper := mldsa44test.RequireTosctl(t)
	vector, key := loadVector(t)
	ctx := context.Background()
	for name, expected := range map[string]vectorExpected{
		"agent": vector.AgentRegistration.Expected, "capability": vector.CapabilityRegistration.Expected,
	} {
		t.Run(name, func(t *testing.T) {
			boc := actionBOC(t, expected)
			signature := decode(t, expected.SignatureHex)
			if err := helper.Verify(ctx, mldsa44.UseRegistry, boc, key, signature); err != nil {
				t.Fatalf("frozen signature refused: %v", err)
			}
			flipped := append([]byte(nil), signature...)
			flipped[100] ^= 1
			if err := helper.Verify(ctx, mldsa44.UseRegistry, boc, key, flipped); !errors.Is(err, mldsa44.ErrInvalidSignature) {
				t.Fatalf("flipped signature: %v", err)
			}
			hash := decode(t, strings.TrimPrefix(expected.ActionHash, "sha256:"))
			for _, use := range []mldsa44.Use{mldsa44.UseAgentPacket, mldsa44.UseAgentContact} {
				if err := helper.Verify(ctx, use, hash, key, signature); !errors.Is(err, mldsa44.ErrInvalidSignature) {
					t.Fatalf("registry signature verified under %s: %v", use, err)
				}
			}
		})
	}
	// The other registration's action does not carry this signature.
	if err := helper.Verify(ctx, mldsa44.UseRegistry, actionBOC(t, vector.CapabilityRegistration.Expected), key,
		decode(t, vector.AgentRegistration.Expected.SignatureHex)); !errors.Is(err, mldsa44.ErrInvalidSignature) {
		t.Fatalf("signature verified over another action: %v", err)
	}
	if err := helper.Verify(ctx, mldsa44.UseRegistry, []byte("not a boc"), key,
		decode(t, vector.AgentRegistration.Expected.SignatureHex)); !errors.Is(err, mldsa44.ErrMalformed) {
		t.Fatalf("non-BOC registry payload: %v", err)
	}
}

func TestCustodySignsEachUseUnderItsOwnContext(t *testing.T) {
	custody := mldsa44test.NewCustody(t, "alpha")
	helper := mldsa44test.RequireTosctl(t)
	vector, _ := loadVector(t)
	ctx := context.Background()
	boc := actionBOC(t, vector.AgentRegistration.Expected)
	registry, err := custody.Signer.Sign(ctx, "alpha", mldsa44.UseRegistry, boc)
	if err != nil {
		t.Fatal(err)
	}
	if mldsa44.KeyIDText(registry.KeyID) != custody.KeyID(t, "alpha") || string(registry.PublicKey) != string(custody.PublicKeys["alpha"]) {
		t.Fatal("custody signed with another key")
	}
	if err := helper.Verify(ctx, mldsa44.UseRegistry, boc, registry.PublicKey, registry.Signature); err != nil {
		t.Fatal(err)
	}
	message := []byte("agent packet preimage")
	packet, err := custody.Signer.Sign(ctx, "alpha", mldsa44.UseAgentPacket, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Verify(ctx, mldsa44.UseAgentPacket, message, packet.PublicKey, packet.Signature); err != nil {
		t.Fatal(err)
	}
	if err := helper.Verify(ctx, mldsa44.UseAgentContact, message, packet.PublicKey, packet.Signature); !errors.Is(err, mldsa44.ErrInvalidSignature) {
		t.Fatalf("packet signature verified as a contact card: %v", err)
	}
	if _, err := custody.Signer.Sign(ctx, "missing", mldsa44.UseAgentPacket, message); !errors.Is(err, mldsa44.ErrUnavailable) {
		t.Fatalf("unknown controller: %v", err)
	}
	if _, err := custody.Signer.Sign(ctx, "--controller", mldsa44.UseAgentPacket, message); !errors.Is(err, mldsa44.ErrMalformed) {
		t.Fatalf("option-shaped controller name: %v", err)
	}
	if _, err := helper.Sign(ctx, "alpha", mldsa44.UseAgentPacket, message); !errors.Is(err, mldsa44.ErrUnavailable) {
		t.Fatalf("verification-only helper signed: %v", err)
	}
}

// writeScript writes an executable stand-in for tosctl and returns its pin.
func writeScript(t *testing.T, directory, body string) (string, string) {
	t.Helper()
	path := filepath.Join(directory, "tosctl")
	content := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func TestHelperIsPinnedAndItsAnswersAreChecked(t *testing.T) {
	directory := t.TempDir()
	key := make([]byte, mldsa44.PublicKeySize)
	key[0] = 7
	id, _ := mldsa44.KeyID(key)
	signature := make([]byte, mldsa44.SignatureSize)
	message := []byte("preimage")
	ctx := context.Background()

	answer := `{"valid":true,"suite":"ML-DSA-44","context":"TOS-AGENT-PACKET-V1","key_id":"` + hex.EncodeToString(id[:]) + `"}`
	path, pin := writeScript(t, directory, "echo '"+answer+"'")
	helper, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: path, SHA256: pin})
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Verify(ctx, mldsa44.UseAgentPacket, message, key, signature); err != nil {
		t.Fatalf("well-formed helper answer refused: %v", err)
	}
	// The same answer is wrong for another context.
	if err := helper.Verify(ctx, mldsa44.UseAgentContact, message, key, signature); !errors.Is(err, mldsa44.ErrUnavailable) {
		t.Fatalf("answer for another context accepted: %v", err)
	}
	other := append([]byte(nil), key...)
	other[1] = 9
	if err := helper.Verify(ctx, mldsa44.UseAgentPacket, message, other, signature); !errors.Is(err, mldsa44.ErrUnavailable) {
		t.Fatalf("answer for another key accepted: %v", err)
	}
	if err := helper.Verify(ctx, mldsa44.UseAgentPacket, message, key[:10], signature); !errors.Is(err, mldsa44.ErrMalformed) {
		t.Fatalf("short key: %v", err)
	}
	if err := helper.Verify(ctx, mldsa44.UseAgentPacket, message, key, signature[:10]); !errors.Is(err, mldsa44.ErrMalformed) {
		t.Fatalf("short signature: %v", err)
	}

	// Rewriting the file in place (same inode) after it was pinned must not
	// change what runs: the rewritten script would refuse every signature,
	// the pinned snapshot still answers valid.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	rewrite, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rewrite.WriteString("#!/bin/sh\necho 'rewritten' >&2; exit 1\n"); err != nil {
		t.Fatal(err)
	}
	if err := rewrite.Close(); err != nil {
		t.Fatal(err)
	}
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) {
		t.Fatal("the rewrite replaced the inode instead of rewriting it")
	}
	if err := helper.Verify(ctx, mldsa44.UseAgentPacket, message, key, signature); err != nil {
		t.Fatalf("the rewritten bytes ran instead of the pinned snapshot: %v", err)
	}
	if _, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: path, SHA256: strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("the rewritten file matched an unrelated pin")
	}

	for name, body := range map[string]string{
		"invalid":  "echo 'command failed: verification failed' >&2; exit 1",
		"trailing": "echo '" + answer + "'; echo '{}'",
		"unknown":  `echo '{"valid":true,"suite":"ML-DSA-44","context":"TOS-AGENT-PACKET-V1","key_id":"` + hex.EncodeToString(id[:]) + `","extra":1}'`,
		"false":    `echo '{"valid":false,"suite":"ML-DSA-44","context":"TOS-AGENT-PACKET-V1","key_id":"` + hex.EncodeToString(id[:]) + `"}'`,
		"silent":   "exit 0",
	} {
		t.Run(name, func(t *testing.T) {
			path, pin := writeScript(t, t.TempDir(), body)
			helper, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: path, SHA256: pin})
			if err != nil {
				t.Fatal(err)
			}
			want := mldsa44.ErrUnavailable
			if name == "invalid" {
				want = mldsa44.ErrInvalidSignature
			}
			if err := helper.Verify(ctx, mldsa44.UseAgentPacket, message, key, signature); !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}

	scriptPath, scriptPin := writeScript(t, t.TempDir(), "exit 0")
	wrongPin := strings.Repeat("0", 64)
	for name, config := range map[string]mldsa44.TosctlConfig{
		"wrong pin":      {Binary: scriptPath, SHA256: wrongPin},
		"uppercase pin":  {Binary: scriptPath, SHA256: strings.ToUpper(scriptPin)},
		"relative path":  {Binary: "tosctl", SHA256: scriptPin},
		"unclean path":   {Binary: filepath.Dir(scriptPath) + "/./tosctl", SHA256: scriptPin},
		"half custody":   {Binary: scriptPath, SHA256: scriptPin, ConfigPath: "/tmp/config.json"},
		"relative store": {Binary: scriptPath, SHA256: scriptPin, ConfigPath: "config.json", VaultURL: "file://x"},
	} {
		if _, err := mldsa44.NewTosctl(config); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := os.Chmod(scriptPath, 0o720); err != nil {
		t.Fatal(err)
	}
	if _, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: scriptPath, SHA256: scriptPin}); err == nil {
		t.Fatal("group-writable helper accepted")
	}
	link := filepath.Join(t.TempDir(), "tosctl")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: link, SHA256: pin}); err == nil {
		t.Fatal("symbolic link accepted")
	}
}

func TestFakeIsNotTheHelper(t *testing.T) {
	fake := &mldsa44test.Fake{}
	ctx := context.Background()
	signature, err := fake.Sign(ctx, "alpha", mldsa44.UseAgentPacket, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.Verify(ctx, mldsa44.UseAgentPacket, []byte("m"), signature.PublicKey, signature.Signature); err != nil {
		t.Fatal(err)
	}
	if err := fake.Verify(ctx, mldsa44.UseAgentContact, []byte("m"), signature.PublicKey, signature.Signature); !errors.Is(err, mldsa44.ErrInvalidSignature) {
		t.Fatal("fake ignores the context")
	}
	helper := mldsa44test.RequireTosctl(t)
	if err := helper.Verify(ctx, mldsa44.UseAgentPacket, []byte("m"), signature.PublicKey, signature.Signature); err == nil {
		t.Fatal("the real helper accepted a fake signature")
	}
}

// An agent-guarantor signature covers exactly a 32-byte digest under its own
// context: it verifies only as agent-guarantor, and a signature made for any
// other use over the same bytes never verifies as agent-guarantor.
func TestAgentGuarantorUseIsSeparateAndExactlyThirtyTwoBytes(t *testing.T) {
	if context, err := mldsa44.UseAgentGuarantor.Context(); err != nil || context != "TOS-AGENT-GUARANTOR-V1" {
		t.Fatalf("agent-guarantor context = %q, %v", context, err)
	}
	custody := mldsa44test.NewCustody(t, "alpha")
	helper := mldsa44test.RequireTosctl(t)
	ctx := context.Background()
	digest := sha256.Sum256([]byte("guarantor statement"))
	signed, err := custody.Signer.Sign(ctx, "alpha", mldsa44.UseAgentGuarantor, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Verify(ctx, mldsa44.UseAgentGuarantor, digest[:], signed.PublicKey, signed.Signature); err != nil {
		t.Fatalf("agent-guarantor signature refused: %v", err)
	}
	for _, other := range []mldsa44.Use{mldsa44.UseAgentPacket, mldsa44.UseAgentContact} {
		if err := helper.Verify(ctx, other, digest[:], signed.PublicKey, signed.Signature); !errors.Is(err, mldsa44.ErrInvalidSignature) {
			t.Fatalf("agent-guarantor signature verified as %s: %v", other, err)
		}
		foreign, err := custody.Signer.Sign(ctx, "alpha", other, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := helper.Verify(ctx, mldsa44.UseAgentGuarantor, digest[:], foreign.PublicKey, foreign.Signature); !errors.Is(err, mldsa44.ErrInvalidSignature) {
			t.Fatalf("%s signature verified as agent-guarantor: %v", other, err)
		}
	}
	for _, size := range []int{0, 31, 33} {
		message := make([]byte, size)
		if _, err := custody.Signer.Sign(ctx, "alpha", mldsa44.UseAgentGuarantor, message); !errors.Is(err, mldsa44.ErrMalformed) {
			t.Fatalf("%d-byte agent-guarantor message signed: %v", size, err)
		}
		if err := helper.Verify(ctx, mldsa44.UseAgentGuarantor, message, signed.PublicKey, signed.Signature); !errors.Is(err, mldsa44.ErrMalformed) {
			t.Fatalf("%d-byte agent-guarantor message verified: %v", size, err)
		}
	}
	fake := &mldsa44test.Fake{}
	if _, err := fake.Sign(ctx, "alpha", mldsa44.UseAgentGuarantor, digest[:31]); !errors.Is(err, mldsa44.ErrMalformed) {
		t.Fatalf("fake signed a 31-byte agent-guarantor message: %v", err)
	}
}
