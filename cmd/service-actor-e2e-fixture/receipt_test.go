package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
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
	return newReceiptCaseWithAttestor(t, 0x99)
}

// newReceiptCaseWithAttestor names the attestor key id byte the Quote
// package's manifest and proposal carry.
func newReceiptCaseWithAttestor(t *testing.T, attestorByte byte) receiptCase {
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
	copy(attestorID[:], bytes.Repeat([]byte{attestorByte}, 32))
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
	oversizePackage := filepath.Join(c.dir, "oversize.pb")
	if err := os.WriteFile(oversizePackage, make([]byte, maxQuotePackageBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyPackage := filepath.Join(c.dir, "empty.pb")
	if err := os.WriteFile(emptyPackage, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	other := func(prefix string) string { return prefix + strings.Repeat("ab", 32) }
	cases := map[string]struct {
		args []string
		why  string
	}{
		"missing flag":            {c.args[:len(c.args)-2], "receipt-check needs --manifest-digest"},
		"non-base64 receipt":      {c.with("--receipt-boc", "!!"), "not bounded standard base64"},
		"oversized receipt":       {c.with("--receipt-boc", base64.StdEncoding.EncodeToString(make([]byte, maxReceiptBOCBytes+1))), "not bounded standard base64"},
		"trailing BOC bytes":      {c.with("--receipt-boc", base64.StdEncoding.EncodeToString(append(append([]byte(nil), boc...), 0))), "Receipt BOC"},
		"BOC without CRC32C":      {c.with("--receipt-boc", noCRCBOC), "not the canonical serialization"},
		"BOC with an index":       {c.with("--receipt-boc", indexBOC), "not the canonical serialization"},
		"nonzero exit code":       {withAll(c.args, map[string]string{"--receipt-boc": failedBOC, "--response-hash": failedHash}), "did not succeed"},
		"zero completion time":    {withAll(c.args, map[string]string{"--receipt-boc": incompleteBOC, "--response-hash": incompleteHash}), "completion time"},
		"uppercase response hash": {c.with("--response-hash", strings.ToUpper(c.value("--response-hash"))), "--response-hash is not in its canonical form"},
		"zero execution ID":       {c.with("--execution-id", "sha256:"+strings.Repeat("00", 32)), "zero sha256 digest"},
		"another network":         {c.with("--network-domain", otherNetwork), "request_hash"},
		"unknown package field":   {c.with("--quote-package", unknownField), "not canonically encoded"},
		"oversized package":       {c.with("--quote-package", oversizePackage), "Quote package is outside its bounds"},
		"empty package":           {c.with("--quote-package", emptyPackage), "Quote package is outside its bounds"},
		"another capability":      {c.with("--capability-id", "cap_"+strings.Repeat("34", 32)), "package identity"},
		"another request":         {c.with("--snapshot-request-hash", strings.Repeat("cd", 32)), "request_hash is"},
		// Only the offer check differs; the Receipt agrees with the changed value.
		"offer price only": {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.ChargedAtomicAmount = "120000000" },
			map[string]string{"--snapshot-price-nanotos": "120000000"}), "offer price"},
		"offer provider only": {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.ProviderAgentID = other("agent_") },
			map[string]string{"--provider-agent-id": other("agent_")}), "offer provider"},
		"offer manifest only": {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.SandboxDigest = other("sha256:") },
			map[string]string{"--manifest-digest": other("sha256:")}), "offer manifest"},
		"manifest toolchain only": {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.ToolchainDigest = other("sha256:") },
			map[string]string{"--toolchain-digest": other("sha256:")}), "manifest toolchain"},
		// Only the Receipt differs from the anchored request.
		"receipt quote":     {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.QuoteCommitment = other("tvm-cell-sha256:") }, nil), "quote_commitment"},
		"receipt execution": {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.ExecutionID = other("sha256:") }, nil), "execution_id"},
		"receipt input":     {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.InputDigest = other("sha256:") }, nil), "input_digest"},
		"receipt source":    {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.SourceDigest = other("sha256:") }, nil), "source_digest"},
		"receipt charge":    {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.ChargedAtomicAmount = "1" }, nil), "charged_atomic_amount"},
		"receipt provider":  {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.ProviderAgentID = other("agent_") }, nil), "provider_agent_id"},
		"receipt toolchain": {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.ToolchainDigest = other("sha256:") }, nil), "toolchain_digest"},
		"receipt sandbox":   {c.receiptWith(t, func(r *nativecore.SoftwareWorkReceiptV1) { r.SandboxDigest = other("sha256:") }, nil), "sandbox_digest"},
		"another response":  {c.with("--response-hash", strings.Repeat("ef", 32)), "response_hash"},
	}
	// Only the offer's attestor differs: the snapshot and the attestor agree
	// with each other but not with the accepted Quote.
	offered := newReceiptCaseWithAttestor(t, 0x98)
	cases["offer attestor only"] = struct {
		args []string
		why  string
	}{withAll(offered.args, map[string]string{"--attestor": c.value("--attestor"),
		"--snapshot-attestor-key": c.value("--attestor")}), "offer attestor"}
	if failedHash == c.value("--response-hash") || incompleteHash == c.value("--response-hash") || noCRCBOC == c.value("--receipt-boc") || indexBOC == c.value("--receipt-boc") {
		t.Fatal("a forged Receipt equals the valid one")
	}
	for name, refusal := range cases {
		err := run(refusal.args, &bytes.Buffer{})
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), refusal.why) {
			t.Errorf("%s was refused for another reason: %v", name, err)
		}
	}
}

// receiptWith returns arguments carrying a Receipt changed by mutate and
// the given flag overrides.
func (c receiptCase) receiptWith(t *testing.T, mutate func(*nativecore.SoftwareWorkReceiptV1), overrides map[string]string) []string {
	t.Helper()
	receipt := c.receipt
	mutate(&receipt)
	root, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"--receipt-boc": base64.StdEncoding.EncodeToString(root.ToBOC()),
		"--response-hash": hex.EncodeToString(root.Hash())}
	for flag, value := range overrides {
		values[flag] = value
	}
	return withAll(c.args, values)
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

// A charge wider than Coins decodes but is not what the builder encodes, so
// the Receipt is refused as non-canonical.
func TestDecodeCanonicalReceiptRefusesAWideCharge(t *testing.T) {
	c := newReceiptCase(t)
	root, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(c.receipt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := root.BeginParse()
	if err != nil {
		t.Fatal(err)
	}
	head, err := s.LoadSlice(32 + 16 + 64 + 32)
	if err != nil {
		t.Fatal(err)
	}
	builder := cell.BeginCell().MustStoreSlice(head, 32+16+64+32)
	for index := 0; index < 3; index++ {
		ref, err := s.LoadRefCell()
		if err != nil {
			t.Fatal(err)
		}
		builder.MustStoreRef(ref)
	}
	economic, err := s.LoadRefCell()
	if err != nil {
		t.Fatal(err)
	}
	e, err := economic.BeginParse()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.LoadBigUInt(128); err != nil {
		t.Fatal(err)
	}
	provider, err := e.LoadSlice(256)
	if err != nil {
		t.Fatal(err)
	}
	wide := new(big.Int).Lsh(big.NewInt(1), 121)
	forged := builder.MustStoreRef(cell.BeginCell().MustStoreBigUInt(wide, 128).MustStoreSlice(provider, 256).EndCell()).EndCell()
	if _, err := nativecore.DecodeSoftwareWorkReceiptCellV1(forged); err != nil {
		t.Fatalf("the decoder no longer accepts a wide charge, so this test lost its subject: %v", err)
	}
	_, _, err = decodeCanonicalReceipt(base64.StdEncoding.EncodeToString(forged.ToBOC()))
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("a wide-charge Receipt was not refused as non-canonical: %v", err)
	}
}
