package nativecore

import (
	"strings"
	"testing"
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

func TestSoftwareWorkReceiptRoundTrip(t *testing.T) {
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
}
