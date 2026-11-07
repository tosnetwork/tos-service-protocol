package nativecore

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func testSoftwareWorkManifest() SoftwareWorkManifestV1 {
	return SoftwareWorkManifestV1{
		Protocol: SoftwareWorkManifestProtocolV1, Version: "1.0.0", Name: "Deterministic Go test",
		Description: "Run the committed Go test suite without network access.", Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive", "immutable-repository-commit"},
		InputSchemaDigest:   "sha256:" + strings.Repeat("11", 32), OutputSchemaDigest: "sha256:" + strings.Repeat("22", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("33", 32),
		Invocation:      SoftwareWorkInvocationV1{Executable: "/usr/local/bin/go", Arguments: []string{"test", "./...", "-count=1"}, WorkingDirectory: "/workspace/source"},
		NetworkPolicy:   "none", Limits: SoftwareWorkLimitsV1{CPUMillis: 120000, MemoryBytes: 1073741824, ScratchBytes: 2147483648, OutputBytes: 16777216, WallClockMillis: 180000},
		ArtifactMediaTypes: []string{"application/vnd.tos.service.software-artifact.v1+tar"}, ReportMediaTypes: []string{"application/vnd.tos.service.test-report.v1+json"},
		SuccessCondition: "exit-code-zero-and-valid-reports", RefundConditions: []string{NoAttestedResponseRefund},
		EndpointCommitment: "sha256:dca9babcd44775f2c19ef571964c01e2e75b15254d0d16f2349c8d446f76c44c", ExecutionSignerAuthorization: SettlementAttestorAuthorization(testAttestorKeyText), RetentionSeconds: 86400,
		SupportedAssets: []SoftwareWorkAssetV1{{Kind: NativeTOSAsset}},
		Settlement: SoftwareWorkSettlementV1{Rail: ServiceActorRail, ActorWorkchain: 0,
			ActorAccountID: bytes.Repeat([]byte{0x77}, 32), ActorCodeHash: bytes.Repeat([]byte{0x88}, 32), AttestorKey: testAttestorKeyText},
	}
}

var testAttestorKeyText = "mldsa44:" + strings.Repeat("99", 32)

func TestSoftwareWorkManifestCanonicalEncoding(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	first, firstDigest, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, secondDigest, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || firstDigest != secondDigest {
		t.Fatal("software-work manifest encoding is not deterministic")
	}
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSoftwareWorkManifestJSON(jsonBytes)
	if err != nil {
		t.Fatal(err)
	}
	third, thirdDigest, err := CanonicalSoftwareWorkManifest(decoded)
	if err != nil || !bytes.Equal(first, third) || firstDigest != thirdDigest {
		t.Fatal("JSON projection changed canonical manifest")
	}
}

func TestSoftwareWorkManifestCanonicalCBORDecoder(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	encoded, _, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCanonicalSoftwareWorkManifestCBOR(encoded)
	if err != nil || decoded.Version != manifest.Version {
		t.Fatalf("canonical CBOR decode failed: %v", err)
	}
	// Replace the canonical definite-length map header with an indefinite map
	// and break. It has identical semantics but a forbidden alternate encoding.
	if encoded[0] != 0xb5 {
		t.Fatalf("unexpected manifest map header: %x", encoded[0])
	}
	nonCanonical := append([]byte{0xbf}, encoded[1:]...)
	nonCanonical = append(nonCanonical, 0xff)
	if _, err := DecodeCanonicalSoftwareWorkManifestCBOR(nonCanonical); err == nil {
		t.Fatal("non-canonical manifest CBOR accepted")
	}
}

func TestSoftwareWorkManifestRejectsCircularCapabilityID(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"capability_id":"cap_`+strings.Repeat("aa", 32)+`"}`)...)
	if _, err := DecodeSoftwareWorkManifestJSON(encoded); err == nil {
		t.Fatal("manifest accepted circular capability_id field")
	}
}

func TestSoftwareWorkManifestRejectsShellAndNonObjectiveRefunds(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	manifest.Invocation.Executable = "/bin/sh"
	if err := ValidateSoftwareWorkManifest(manifest); err == nil {
		t.Fatal("manifest accepted a general-purpose shell")
	}
	manifest = testSoftwareWorkManifest()
	manifest.RefundConditions = []string{"executor-infrastructure-failure"}
	if err := ValidateSoftwareWorkManifest(manifest); err == nil {
		t.Fatal("manifest accepted a subjective refund condition")
	}
}

func TestSoftwareWorkManifestSettlementKeys(t *testing.T) {
	encoded, _, err := CanonicalSoftwareWorkManifest(testSoftwareWorkManifest())
	if err != nil {
		t.Fatal(err)
	}
	var generic map[uint64]any
	if err := cbor.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	assets, ok := generic[20].([]any)
	if !ok || len(assets) != 1 {
		t.Fatalf("key 20 is not a one-element array: %#v", generic[20])
	}
	if asset, ok := assets[0].(map[any]any); !ok || len(asset) != 1 || asset[uint64(0)] != NativeTOSAsset {
		t.Fatalf("key 20 entry is not {0: native-tos}: %#v", assets[0])
	}
	settlement, ok := generic[21].(map[any]any)
	if !ok || len(settlement) != 5 || settlement[uint64(1)] != ServiceActorRail || settlement[uint64(2)] != uint64(0) ||
		!bytes.Equal(settlement[uint64(3)].([]byte), bytes.Repeat([]byte{0x77}, 32)) ||
		!bytes.Equal(settlement[uint64(4)].([]byte), bytes.Repeat([]byte{0x88}, 32)) || settlement[uint64(5)] != testAttestorKeyText {
		t.Fatalf("key 21 is not {1 rail, 2 wc, 3 account bytes, 4 code bytes, 5 attestor text}: %#v", generic[21])
	}
	if generic[16].([]any)[0] != NoAttestedResponseRefund {
		t.Fatalf("key 16 is %#v", generic[16])
	}

	for name, edit := range map[string]func(*SoftwareWorkManifestV1){
		"old refund value": func(m *SoftwareWorkManifestV1) { m.RefundConditions = []string{"not-started-before-deadline"} },
		"two refund values": func(m *SoftwareWorkManifestV1) {
			m.RefundConditions = []string{NoAttestedResponseRefund, NoAttestedResponseRefund}
		},
		"stablecoin asset": func(m *SoftwareWorkManifestV1) { m.SupportedAssets = []SoftwareWorkAssetV1{{Kind: "USDT"}} },
		"two assets": func(m *SoftwareWorkManifestV1) {
			m.SupportedAssets = append(m.SupportedAssets, SoftwareWorkAssetV1{Kind: NativeTOSAsset})
		},
		"no assets":              func(m *SoftwareWorkManifestV1) { m.SupportedAssets = nil },
		"other rail":             func(m *SoftwareWorkManifestV1) { m.Settlement.Rail = "tos.service.escrow.v2" },
		"masterchain actor":      func(m *SoftwareWorkManifestV1) { m.Settlement.ActorWorkchain = -1 },
		"short actor":            func(m *SoftwareWorkManifestV1) { m.Settlement.ActorAccountID = m.Settlement.ActorAccountID[:31] },
		"zero actor":             func(m *SoftwareWorkManifestV1) { m.Settlement.ActorAccountID = make([]byte, 32) },
		"short code hash":        func(m *SoftwareWorkManifestV1) { m.Settlement.ActorCodeHash = nil },
		"attestor text form":     func(m *SoftwareWorkManifestV1) { m.Settlement.AttestorKey = strings.Repeat("99", 32) },
		"key 18 not attestor":    func(m *SoftwareWorkManifestV1) { m.ExecutionSignerAuthorization = "sha256:" + strings.Repeat("55", 32) },
		"key 18 of raw key id":   func(m *SoftwareWorkManifestV1) { m.ExecutionSignerAuthorization = "sha256:" + strings.Repeat("99", 32) },
		"attestor without key18": func(m *SoftwareWorkManifestV1) { m.Settlement.AttestorKey = "mldsa44:" + strings.Repeat("98", 32) },
	} {
		manifest := testSoftwareWorkManifest()
		edit(&manifest)
		if err := ValidateSoftwareWorkManifest(manifest); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A map with an extra key 22 decodes but is not the canonical encoding.
	var withExtra map[uint64]any
	_ = cbor.Unmarshal(encoded, &withExtra)
	withExtra[22] = "extra"
	mode, _ := cbor.CanonicalEncOptions().EncMode()
	extended, _ := mode.Marshal(withExtra)
	if _, err := DecodeCanonicalSoftwareWorkManifestCBOR(extended); err == nil {
		t.Error("a manifest with an unknown key was accepted")
	}
}
