package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func signatureFile(t *testing.T, value externalSignature) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signature.json")
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signingFixture(t *testing.T) (signingPackage, *cell.Cell, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 32)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	return signingPackage{
		SigningPayloadHex:        hex.EncodeToString(payload),
		ExecutionSignerPublicKey: hex.EncodeToString(publicKey),
		QueryID:                  7,
	}, cell.BeginCell().MustStoreUInt(1, 1).EndCell(), privateKey
}

func TestApplyExternalSignature(t *testing.T) {
	value, receipt, privateKey := signingFixture(t)
	payload, _ := hex.DecodeString(value.SigningPayloadHex)
	signed := externalSignature{Schema: "tosctl-ed25519-signature-v1", Algorithm: "Ed25519",
		PublicKeyHex: value.ExecutionSignerPublicKey, MessageHex: value.SigningPayloadHex,
		SignatureHex: hex.EncodeToString(ed25519.Sign(privateKey, payload))}
	if err := applyExternalSignature(&value, receipt, signatureFile(t, signed)); err != nil {
		t.Fatal(err)
	}
	if value.Schema != "tos.service.software-work-settlement-release.v2" ||
		value.ReleaseBodyBOCBase64 == "" || value.SignatureHex == "" {
		t.Fatalf("incomplete signed release: %+v", value)
	}
}

func TestApplyExternalSignatureRejectsWrongPayload(t *testing.T) {
	value, receipt, privateKey := signingFixture(t)
	wrong := strings.Repeat("00", 32)
	payload, _ := hex.DecodeString(wrong)
	signed := externalSignature{Schema: "tosctl-ed25519-signature-v1", Algorithm: "Ed25519",
		PublicKeyHex: value.ExecutionSignerPublicKey, MessageHex: wrong,
		SignatureHex: hex.EncodeToString(ed25519.Sign(privateKey, payload))}
	if err := applyExternalSignature(&value, receipt, signatureFile(t, signed)); err == nil {
		t.Fatal("wrong signing payload accepted")
	}
}

func TestApplyExternalSignatureRejectsInvalidSignature(t *testing.T) {
	value, receipt, privateKey := signingFixture(t)
	payload, _ := hex.DecodeString(value.SigningPayloadHex)
	signature := ed25519.Sign(privateKey, payload)
	signature[0] ^= 1
	signed := externalSignature{Schema: "tosctl-ed25519-signature-v1", Algorithm: "Ed25519",
		PublicKeyHex: value.ExecutionSignerPublicKey, MessageHex: value.SigningPayloadHex,
		SignatureHex: hex.EncodeToString(signature)}
	if err := applyExternalSignature(&value, receipt, signatureFile(t, signed)); err == nil {
		t.Fatal("invalid signature accepted")
	}
}

func TestOutcomeRequiresExplicitSuccessfulExitCode(t *testing.T) {
	valid := `{"quote_commitment":"q","execution_id":"e","input_digest":"i",` +
		`"result_digest":"r","source_digest":"s","toolchain_digest":"t",` +
		`"sandbox_digest":"x","exit_code":0}`
	var decoded outcome
	if err := json.Unmarshal([]byte(valid), &decoded); err != nil {
		t.Fatalf("explicit success rejected: %v", err)
	}
	missing := strings.Replace(valid, `,"exit_code":0`, "", 1)
	if err := json.Unmarshal([]byte(missing), &decoded); err == nil {
		t.Fatal("missing exit_code accepted as implicit success")
	}
	failed := strings.Replace(valid, `"exit_code":0`, `"exit_code":1`, 1)
	if err := json.Unmarshal([]byte(failed), &decoded); err == nil {
		t.Fatal("failed execution accepted")
	}
}
