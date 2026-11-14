package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"regexp"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const maxReceiptBOCBytes = 4 << 10

var responseHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReceiptExpectation is what the attestor knows about a request independently
// of the executor: the finalized request, the Quote, the staged source and the
// published manifest. A Receipt is releasable only if it binds exactly these.
type ReceiptExpectation struct {
	receiptBOC, responseHash, quoteCommitment, executionID, inputDigest   string
	sourceDigest, price, providerAgentID, toolchainDigest, manifestDigest string
}

func (r *ReceiptExpectation) addFlags(set *flag.FlagSet) {
	set.StringVar(&r.receiptBOC, "receipt-boc", "", "receipt-check: standard base64 Receipt BOC the executor recorded")
	set.StringVar(&r.responseHash, "response-hash", "", "receipt-check: 64 lowercase hex response hash the executor recorded")
	set.StringVar(&r.quoteCommitment, "quote-commitment", "", "receipt-check: tvm-cell-sha256:<hex> Accepted Quote commitment")
	set.StringVar(&r.executionID, "execution-id", "", "receipt-check: sha256:<hex> execution ID the request commits")
	set.StringVar(&r.inputDigest, "input-digest", "", "receipt-check: sha256:<hex> input digest the request commits")
	set.StringVar(&r.sourceDigest, "source-digest", "", "receipt-check: sha256:<hex> of the staged source archive")
	set.StringVar(&r.price, "price-nanotos", "", "receipt-check: price the request snapshotted, in nanoTOS")
	// --provider-agent-id, --toolchain-digest and --manifest-digest are shared
	// with the other commands and copied in by run.
}

// check decodes the Receipt, requires its canonical encoding, its cell hash
// to be the recorded response hash, every binding to match, and a successful
// completed execution. Any difference refuses the signature.
func (r *ReceiptExpectation) check() (map[string]any, error) {
	for name, value := range map[string]string{"receipt-boc": r.receiptBOC, "response-hash": r.responseHash,
		"quote-commitment": r.quoteCommitment, "execution-id": r.executionID, "input-digest": r.inputDigest,
		"source-digest": r.sourceDigest, "price-nanotos": r.price, "provider-agent-id": r.providerAgentID,
		"toolchain-digest": r.toolchainDigest, "manifest-digest": r.manifestDigest} {
		if value == "" {
			return nil, fmt.Errorf("receipt-check needs --%s", name)
		}
	}
	if !responseHashPattern.MatchString(r.responseHash) {
		return nil, errors.New("--response-hash must be 64 lowercase hex")
	}
	boc, err := base64.StdEncoding.Strict().DecodeString(r.receiptBOC)
	if err != nil || len(boc) == 0 || len(boc) > maxReceiptBOCBytes {
		return nil, errors.New("the Receipt BOC is not bounded standard base64")
	}
	root, err := cell.FromBOC(boc)
	if err != nil {
		return nil, fmt.Errorf("the Receipt BOC does not decode: %w", err)
	}
	receipt, err := nativecore.DecodeSoftwareWorkReceiptCellV1(root)
	if err != nil {
		return nil, err
	}
	rebuilt, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(receipt)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("the Receipt is not canonical")
	}
	hash := hex.EncodeToString(root.Hash())
	mismatches := []string{}
	for _, field := range []struct{ name, got, want string }{
		{"response_hash", hash, r.responseHash},
		{"quote_commitment", receipt.QuoteCommitment, r.quoteCommitment},
		{"execution_id", receipt.ExecutionID, r.executionID},
		{"input_digest", receipt.InputDigest, r.inputDigest},
		{"source_digest", receipt.SourceDigest, r.sourceDigest},
		{"charged_atomic_amount", receipt.ChargedAtomicAmount, r.price},
		{"provider_agent_id", receipt.ProviderAgentID, r.providerAgentID},
		{"toolchain_digest", receipt.ToolchainDigest, r.toolchainDigest},
		{"sandbox_digest", receipt.SandboxDigest, r.manifestDigest},
	} {
		if field.got != field.want {
			mismatches = append(mismatches, fmt.Sprintf("%s is %q, expected %q", field.name, field.got, field.want))
		}
	}
	if receipt.ExitCode != 0 || receipt.CompletedAt == 0 {
		mismatches = append(mismatches, "the Receipt is not a successful completed execution")
	}
	if len(mismatches) != 0 {
		return nil, fmt.Errorf("the Receipt is not releasable: %v", mismatches)
	}
	return map[string]any{"releasable": true, "response_hash": hash, "result_digest": receipt.ResultDigest,
		"artifact_digest": receipt.ArtifactDigest, "report_digest": receipt.ReportDigest,
		"completed_at": receipt.CompletedAt, "exit_code": receipt.ExitCode}, nil
}
