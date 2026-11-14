package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

func receiptFixture(t *testing.T) (nativecore.SoftwareWorkReceiptV1, []string) {
	t.Helper()
	receipt := nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("11", 32),
		ExecutionID:     "sha256:" + strings.Repeat("22", 32), InputDigest: "sha256:" + strings.Repeat("33", 32),
		ResultDigest: "sha256:" + strings.Repeat("44", 32), ArtifactDigest: "sha256:" + strings.Repeat("55", 32),
		ReportDigest: "sha256:" + strings.Repeat("66", 32), SourceDigest: "sha256:" + strings.Repeat("77", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("88", 32), SandboxDigest: "sha256:" + strings.Repeat("99", 32),
		ChargedAtomicAmount: "110000000", ProviderAgentID: "agent_" + strings.Repeat("aa", 32),
		CompletedAt: 1786753000,
	}
	root, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, []string{"receipt-check",
		"--receipt-boc", base64.StdEncoding.EncodeToString(root.ToBOC()),
		"--response-hash", hex.EncodeToString(root.Hash()),
		"--quote-commitment", receipt.QuoteCommitment, "--execution-id", receipt.ExecutionID,
		"--input-digest", receipt.InputDigest, "--source-digest", receipt.SourceDigest,
		"--price-nanotos", receipt.ChargedAtomicAmount, "--provider-agent-id", receipt.ProviderAgentID,
		"--toolchain-digest", receipt.ToolchainDigest, "--manifest-digest", receipt.SandboxDigest}
}

func TestReceiptCheckReleasesOnlyTheExactBinding(t *testing.T) {
	_, args := receiptFixture(t)
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatalf("exact binding refused: %v", err)
	}
	if !strings.Contains(out.String(), `"releasable":true`) {
		t.Fatalf("unexpected output %s", out.String())
	}
	// Every expected value is load-bearing: changing any one refuses.
	for index := 1; index < len(args); index += 2 {
		if args[index] == "--receipt-boc" {
			continue
		}
		changed := append([]string(nil), args...)
		value := changed[index+1]
		last := value[len(value)-1]
		replacement := byte('0')
		if last == '0' {
			replacement = '1'
		}
		changed[index+1] = value[:len(value)-1] + string(replacement)
		if err := run(changed, &bytes.Buffer{}); err == nil {
			t.Fatalf("a Receipt was released with %s changed", args[index])
		}
	}
}

func TestReceiptCheckRefusesMalformedInput(t *testing.T) {
	_, args := receiptFixture(t)
	for name, mutate := range map[string]func([]string) []string{
		"missing flag":       func(a []string) []string { return a[:len(a)-2] },
		"non-base64 receipt": func(a []string) []string { a[2] = "!!"; return a },
		"trailing BOC bytes": func(a []string) []string {
			raw, _ := base64.StdEncoding.DecodeString(a[2])
			a[2] = base64.StdEncoding.EncodeToString(append(raw, 0))
			return a
		},
		"uppercase response hash": func(a []string) []string { a[4] = strings.ToUpper(a[4]); return a },
	} {
		if err := run(mutate(append([]string(nil), args...)), &bytes.Buffer{}); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
