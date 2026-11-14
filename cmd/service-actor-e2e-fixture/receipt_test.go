package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	testCapability = "cap_" + "33333333333333333333333333333333" + "33333333333333333333333333333333"
	testAgent      = "agent_" + "44444444444444444444444444444444" + "44444444444444444444444444444444"
	testBuyer      = "0:2121212121212121212121212121212121212121212121212121212121212121"
	testActor      = "0:7777777777777777777777777777777777777777777777777777777777777777"
	testToolchain  = "sha256:9624bca74096f810c5b24e489521dde124fadcfa1808581648b38bdc1ba1b105"
	testPrice      = "110000000"
)

type receiptCase struct {
	receipt nativecore.SoftwareWorkReceiptV1
	args    []string
	dir     string
}

// newReceiptCase builds a valid Quote package, the request snapshot it
// produces for one execution and input, and a Receipt binding exactly
// those, and returns receipt-check arguments that release it.
func newReceiptCase(t *testing.T) receiptCase {
	t.Helper()
	dir := t.TempDir()
	network := servicefixture.Network()
	networkJSON, err := json.Marshal(map[string]string{"network_id": network.NetworkId,
		"genesis_root_hash": network.GenesisRootHash, "genesis_file_hash": network.GenesisFileHash})
	if err != nil {
		t.Fatal(err)
	}
	networkPath := filepath.Join(dir, "network.json")
	if err := os.WriteFile(networkPath, networkJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	var attestorID [32]byte
	copy(attestorID[:], bytes.Repeat([]byte{0x99}, 32))
	attestor := mldsa44.KeyIDText(attestorID)
	manifest := servicefixture.Manifest("1.0.0", servicefixture.Settlement{ActorAccount: bytes.Repeat([]byte{0x77}, 32),
		ActorCodeHash: bytes.Repeat([]byte{0x88}, 32), AttestorKey: attestor})
	manifest.ToolchainDigest = testToolchain
	manifestCBOR, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(nativecore.TransportBindingV1{
		SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	if err != nil {
		t.Fatal(err)
	}
	termsHash := strings.Repeat("5a", 32)
	pkg := &nativev1.QuoteProposalPackageV1{Proposal: &nativev1.QuoteProposalV1{ProposalId: "provider-1",
		CapabilityId: testCapability, CapabilityVersion: "1.0.0", ProviderAgentId: testAgent, ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: 2_000_000_000,
		Actor:         &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)},
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), PolicyVersion: 2, TermsHash: termsHash,
		PriceNanotos: testPrice, StorageFeeNanotos: "200000000", AttestorKeyId: attestor},
		CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: transport.ToBOC()}
	packageBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(dir, "quote.pb")
	if err := os.WriteFile(packagePath, packageBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, pkg.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	request := nativecore.ServiceRequestV1{}
	copy(request.QuoteCommitment[:], quote.Hash())
	copy(request.ExecutionID[:], bytes.Repeat([]byte{0x22}, 32))
	copy(request.InputDigest[:], bytes.Repeat([]byte{0x23}, 32))
	requestCell, err := nativecore.BuildServiceRequestCellV1(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := nativecore.SoftwareWorkReceiptV1{QuoteCommitment: commitment,
		ExecutionID: "sha256:" + strings.Repeat("22", 32), InputDigest: "sha256:" + strings.Repeat("23", 32),
		ResultDigest: "sha256:" + strings.Repeat("44", 32), ArtifactDigest: "sha256:" + strings.Repeat("55", 32),
		ReportDigest: "sha256:" + strings.Repeat("66", 32), SourceDigest: "sha256:" + strings.Repeat("67", 32),
		ToolchainDigest: testToolchain, SandboxDigest: manifestDigest, ChargedAtomicAmount: testPrice,
		ProviderAgentID: testAgent, CompletedAt: 1786753000}
	root, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return receiptCase{receipt: receipt, dir: dir, args: []string{"receipt-check",
		"--receipt-boc", base64.StdEncoding.EncodeToString(root.ToBOC()),
		"--response-hash", hex.EncodeToString(root.Hash()),
		"--quote-package", packagePath, "--network-domain", networkPath,
		"--execution-id", receipt.ExecutionID, "--input-digest", receipt.InputDigest,
		"--source-digest", receipt.SourceDigest,
		"--snapshot-request-hash", hex.EncodeToString(requestCell.Hash()), "--snapshot-terms-hash", termsHash,
		"--snapshot-price-nanotos", testPrice, "--snapshot-attestor-key", attestor, "--snapshot-caller", testBuyer,
		"--capability-id", testCapability, "--version", "1.0.0", "--buyer-wallet", testBuyer, "--actor", testActor,
		"--attestor", attestor, "--provider-agent-id", testAgent, "--toolchain-digest", testToolchain,
		"--manifest-digest", manifestDigest}}
}

func (c receiptCase) with(flag, value string) []string {
	changed := append([]string(nil), c.args...)
	for index := 1; index < len(changed); index += 2 {
		if changed[index] == flag {
			changed[index+1] = value
			return changed
		}
	}
	panic("unknown flag " + flag)
}

func (c receiptCase) value(flag string) string {
	for index := 1; index < len(c.args); index += 2 {
		if c.args[index] == flag {
			return c.args[index+1]
		}
	}
	panic("unknown flag " + flag)
}

// rawReceiptBOC builds a Receipt root the way the builder lays it out but
// with any completion time and exit code, so the check is shown to refuse
// cells the builder would never produce.
func (c receiptCase) rawReceiptBOC(t *testing.T, completedAt uint64, exitCode int64) (string, string) {
	t.Helper()
	root, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(c.receipt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := root.BeginParse()
	if err != nil {
		t.Fatal(err)
	}
	magic, _ := s.LoadUInt(32)
	schema, _ := s.LoadUInt(16)
	if _, err := s.LoadUInt(64); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadInt(32); err != nil {
		t.Fatal(err)
	}
	builder := cell.BeginCell().MustStoreUInt(magic, 32).MustStoreUInt(schema, 16).MustStoreUInt(completedAt, 64).
		MustStoreInt(exitCode, 32)
	for s.RefsNum() > 0 {
		ref, err := s.LoadRefCell()
		if err != nil {
			t.Fatal(err)
		}
		builder.MustStoreRef(ref)
	}
	forged := builder.EndCell()
	return base64.StdEncoding.EncodeToString(forged.ToBOC()), hex.EncodeToString(forged.Hash())
}

func TestReceiptCheckReleasesOnlyTheExactBinding(t *testing.T) {
	c := newReceiptCase(t)
	var out bytes.Buffer
	if err := run(c.args, &out); err != nil {
		t.Fatalf("exact binding refused: %v", err)
	}
	if !strings.Contains(out.String(), `"releasable":true`) {
		t.Fatalf("unexpected output %s", out.String())
	}
	// Every expected value is load-bearing: changing any one refuses.
	for index := 1; index < len(c.args); index += 2 {
		flag := c.args[index]
		if flag == "--receipt-boc" || flag == "--quote-package" || flag == "--network-domain" {
			continue
		}
		value := c.args[index+1]
		last := value[len(value)-1]
		replacement := byte('0')
		if last == '0' {
			replacement = '1'
		}
		if err := run(c.with(flag, value[:len(value)-1]+string(replacement)), &bytes.Buffer{}); err == nil {
			t.Fatalf("a Receipt was released with %s changed", flag)
		}
	}
}

func TestReceiptCheckRefuses(t *testing.T) {
	c := newReceiptCase(t)
	boc, _ := base64.StdEncoding.DecodeString(c.value("--receipt-boc"))
	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	failedBOC, failedHash := c.rawReceiptBOC(t, c.receipt.CompletedAt, 1)
	incompleteBOC, incompleteHash := c.rawReceiptBOC(t, 0, 0)
	// The canonical serialization carries a CRC32C; the same cell without
	// it, or with an index, is another encoding of the same Receipt.
	noCRCBOC := base64.StdEncoding.EncodeToString(root.ToBOCWithOptions(cell.BOCSerializeOptions{}))
	indexBOC := base64.StdEncoding.EncodeToString(root.ToBOCWithOptions(cell.BOCSerializeOptions{WithCRC32C: true, WithIndex: true}))
	otherNetwork := filepath.Join(c.dir, "other-network.json")
	if err := os.WriteFile(otherNetwork, []byte(`{"network_id":"tos-other","genesis_root_hash":"sha256:`+
		strings.Repeat("11", 32)+`","genesis_file_hash":"sha256:`+strings.Repeat("22", 32)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	packageBytes, err := os.ReadFile(c.value("--quote-package"))
	if err != nil {
		t.Fatal(err)
	}
	unknownField := filepath.Join(c.dir, "unknown-field.pb")
	if err := os.WriteFile(unknownField, protowire.AppendVarint(protowire.AppendTag(append([]byte(nil), packageBytes...),
		999, protowire.VarintType), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"missing flag":            c.args[:len(c.args)-2],
		"non-base64 receipt":      c.with("--receipt-boc", "!!"),
		"oversized receipt":       c.with("--receipt-boc", base64.StdEncoding.EncodeToString(make([]byte, maxReceiptBOCBytes+1))),
		"trailing BOC bytes":      c.with("--receipt-boc", base64.StdEncoding.EncodeToString(append(append([]byte(nil), boc...), 0))),
		"BOC without CRC32C":      c.with("--receipt-boc", noCRCBOC),
		"BOC with an index":       c.with("--receipt-boc", indexBOC),
		"nonzero exit code":       withAll(c.args, map[string]string{"--receipt-boc": failedBOC, "--response-hash": failedHash}),
		"zero completion time":    withAll(c.args, map[string]string{"--receipt-boc": incompleteBOC, "--response-hash": incompleteHash}),
		"uppercase response hash": c.with("--response-hash", strings.ToUpper(c.value("--response-hash"))),
		"zero execution ID":       c.with("--execution-id", "sha256:"+strings.Repeat("00", 32)),
		"another network":         c.with("--network-domain", otherNetwork),
		"unknown package field":   c.with("--quote-package", unknownField),
		"another capability":      c.with("--capability-id", "cap_"+strings.Repeat("34", 32)),
	}
	if failedHash == c.value("--response-hash") || incompleteHash == c.value("--response-hash") || noCRCBOC == c.value("--receipt-boc") || indexBOC == c.value("--receipt-boc") {
		t.Fatal("a forged Receipt equals the valid one")
	}
	for name, args := range cases {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func withAll(args []string, values map[string]string) []string {
	changed := append([]string(nil), args...)
	for index := 1; index < len(changed); index += 2 {
		if value, ok := values[changed[index]]; ok {
			changed[index+1] = value
		}
	}
	return changed
}
