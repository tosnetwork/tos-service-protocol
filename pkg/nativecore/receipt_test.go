package nativecore

import (
	"crypto/ed25519"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func validReceipt() SoftwareWorkReceiptV1 {
	return SoftwareWorkReceiptV1{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("11", 32),
		ExecutionID:     "sha256:" + strings.Repeat("22", 32), InputDigest: "sha256:" + strings.Repeat("33", 32),
		ResultDigest: "sha256:" + strings.Repeat("44", 32), ArtifactDigest: "sha256:" + strings.Repeat("55", 32),
		ReportDigest: "sha256:" + strings.Repeat("66", 32), SourceDigest: "sha256:" + strings.Repeat("77", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("88", 32), SandboxDigest: "sha256:" + strings.Repeat("99", 32),
		ChargedAtomicAmount: "25000000", ProviderAgentID: "agent_" + strings.Repeat("aa", 32),
		CompletedAt: 1786753000, ExitCode: 0,
	}
}

func TestSoftwareWorkReceiptAndSettlementIntentRoundTrip(t *testing.T) {
	receipt, commitment, err := BuildSoftwareWorkReceiptCellV1(validReceipt())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSoftwareWorkReceiptCellV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ChargedAtomicAmount != "25000000" || decoded.ProviderAgentID != "agent_"+strings.Repeat("aa", 32) ||
		commitment != digestString(receipt.Hash()) {
		t.Fatalf("unexpected Receipt: %+v %s", decoded, commitment)
	}
	quote := cell.BeginCell().MustStoreUInt(1, 1).EndCell()
	intent, err := BuildEscrowSettlementIntentV2(42,
		testRawAddress(t, "EQCMqzUxrDnAvtAs4dsVR9ReCB5oX_Kx7rJJNcjajorucdcS"),
		quote, receipt, big.NewInt(25_000_000), 7)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	signature := ed25519.Sign(private, intent.Hash())
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), intent.Hash(), signature) {
		t.Fatal("settlement intent signature did not verify")
	}
	body, err := BuildEscrowReleaseBodyV2(7, receipt, signature)
	if err != nil {
		t.Fatal(err)
	}
	s := body.MustBeginParse()
	op, _ := s.LoadUInt(32)
	query, _ := s.LoadUInt(64)
	if op != EscrowReleaseOpcode || query != 7 {
		t.Fatalf("unexpected release header: %x %d", op, query)
	}
}

func TestSoftwareWorkReceiptRejectsNonSuccessfulOrZeroEvidence(t *testing.T) {
	failed := validReceipt()
	failed.ExitCode = 1
	if _, _, err := BuildSoftwareWorkReceiptCellV1(failed); err == nil {
		t.Fatal("accepted failed execution as releasable Receipt")
	}
	zero := validReceipt()
	zero.ReportDigest = "sha256:" + strings.Repeat("00", 32)
	if _, _, err := BuildSoftwareWorkReceiptCellV1(zero); err == nil {
		t.Fatal("accepted zero evidence digest")
	}
	if _, err := BuildEscrowRefundBodyV2(0); err == nil {
		t.Fatal("accepted zero pending query ID")
	}
}
