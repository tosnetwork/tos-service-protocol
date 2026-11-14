package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const (
	maxReceiptBOCBytes   = 4 << 10
	maxQuotePackageBytes = 2 << 20
)

var (
	hex64Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sha256Pattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	atomicPattern    = regexp.MustCompile(`^[1-9][0-9]{0,37}$`)
	rawAddrPattern   = regexp.MustCompile(`^0:[0-9a-f]{64}$`)
	attestorPattern  = regexp.MustCompile(`^mldsa44:[0-9a-f]{64}$`)
	errNotReleasable = errors.New("the Receipt is not releasable")
)

// ReceiptExpectation is what the attestor knows independently of the
// executor. The request snapshot (request hash, terms hash, price, attestor
// key, caller) is read from finalized actor state. The Accepted Quote
// commitment is rebuilt from the Quote package the buyer accepted, and the
// claimed execution ID and input digest must reproduce the snapshot's
// request hash together with it. Only then are they the request's values,
// and the Receipt must bind exactly them.
type ReceiptExpectation struct {
	receiptBOC, responseHash, quotePackage, executionID, inputDigest, sourceDigest          string
	snapshotRequestHash, snapshotTermsHash, snapshotPrice, snapshotAttestor, snapshotCaller string

	// Shared with the other commands; copied in by run.
	networkPath, capabilityID, version, buyer, actor, attestor string
	providerAgentID, toolchainDigest, manifestDigest           string
}

func (r *ReceiptExpectation) addFlags(set *flag.FlagSet) {
	set.StringVar(&r.receiptBOC, "receipt-boc", "", "receipt-check: standard base64 Receipt BOC the executor recorded")
	set.StringVar(&r.responseHash, "response-hash", "", "receipt-check: 64 lowercase hex response hash the executor recorded")
	set.StringVar(&r.quotePackage, "quote-package", "", "receipt-check: binary QuoteProposalPackageV1 the buyer accepted")
	set.StringVar(&r.executionID, "execution-id", "", "receipt-check: sha256:<hex> claimed execution ID")
	set.StringVar(&r.inputDigest, "input-digest", "", "receipt-check: sha256:<hex> claimed input digest")
	set.StringVar(&r.sourceDigest, "source-digest", "", "receipt-check: sha256:<hex> of the staged source archive")
	set.StringVar(&r.snapshotRequestHash, "snapshot-request-hash", "", "receipt-check: request_hash of the finalized request snapshot")
	set.StringVar(&r.snapshotTermsHash, "snapshot-terms-hash", "", "receipt-check: terms_hash of the finalized request snapshot")
	set.StringVar(&r.snapshotPrice, "snapshot-price-nanotos", "", "receipt-check: price of the finalized request snapshot, in nanoTOS")
	set.StringVar(&r.snapshotAttestor, "snapshot-attestor-key", "", "receipt-check: mldsa44:<key id> of the finalized request snapshot")
	set.StringVar(&r.snapshotCaller, "snapshot-caller", "", "receipt-check: raw caller of the finalized request snapshot")
}

// check refuses unless the Quote package validates, the claimed execution
// ID and input digest reproduce the snapshot's request hash with the rebuilt
// Quote commitment, the offer matches the snapshot and the attestor, and the
// canonical Receipt binds exactly these values. Any difference refuses the
// signature.
func (r *ReceiptExpectation) check() (map[string]any, error) {
	if err := r.requireInputs(); err != nil {
		return nil, err
	}
	network, err := readNetwork(r.networkPath)
	if err != nil {
		return nil, err
	}
	pkg, err := readQuotePackage(r.quotePackage)
	if err != nil {
		return nil, err
	}
	validated, err := quoteexchange.ValidatePortable(network, &nativev1.RequestQuoteProposalRequest{
		CapabilityId: r.capabilityID, CapabilityVersion: r.version, BuyerAddress: r.buyer}, pkg)
	if err != nil {
		return nil, err
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, validated.Proposal)
	if err != nil {
		return nil, err
	}
	var request nativecore.ServiceRequestV1
	copy(request.QuoteCommitment[:], quote.Hash())
	request.ExecutionID, _ = digest32(r.executionID)
	request.InputDigest, _ = digest32(r.inputDigest)
	requestCell, err := nativecore.BuildServiceRequestCellV1(request)
	if err != nil {
		return nil, err
	}
	mismatches := compare([]field{
		{"request_hash", hex.EncodeToString(requestCell.Hash()), r.snapshotRequestHash},
		{"offer actor", validated.Rail.Actor, r.actor},
		{"offer terms_hash", hex.EncodeToString(validated.Rail.TermsHash[:]), r.snapshotTermsHash},
		{"offer price", validated.Rail.Price.String(), r.snapshotPrice},
		{"offer attestor", mldsa44.KeyIDText(validated.Rail.AttestorKeyID), r.snapshotAttestor},
		{"attestor", r.attestor, r.snapshotAttestor},
		{"caller", r.buyer, r.snapshotCaller},
		{"offer provider", validated.Proposal.GetProviderAgentId(), r.providerAgentID},
		{"offer manifest", validated.Proposal.GetManifestDigest(), r.manifestDigest},
		{"manifest toolchain", validated.Manifest.ToolchainDigest, r.toolchainDigest},
	})
	if len(mismatches) != 0 {
		return nil, fmt.Errorf("%w: the request is not the one the attestor knows: %s", errNotReleasable,
			strings.Join(mismatches, "; "))
	}
	receipt, hash, err := decodeCanonicalReceipt(r.receiptBOC)
	if err != nil {
		return nil, err
	}
	mismatches = compare([]field{
		{"response_hash", hash, r.responseHash},
		{"quote_commitment", receipt.QuoteCommitment, commitment},
		{"execution_id", receipt.ExecutionID, r.executionID},
		{"input_digest", receipt.InputDigest, r.inputDigest},
		{"source_digest", receipt.SourceDigest, r.sourceDigest},
		{"charged_atomic_amount", receipt.ChargedAtomicAmount, r.snapshotPrice},
		{"provider_agent_id", receipt.ProviderAgentID, r.providerAgentID},
		{"toolchain_digest", receipt.ToolchainDigest, r.toolchainDigest},
		{"sandbox_digest", receipt.SandboxDigest, r.manifestDigest},
	})
	if len(mismatches) != 0 {
		return nil, fmt.Errorf("%w: %s", errNotReleasable, strings.Join(mismatches, "; "))
	}
	return map[string]any{"releasable": true, "response_hash": hash, "request_hash": r.snapshotRequestHash,
		"quote_commitment": commitment, "result_digest": receipt.ResultDigest, "artifact_digest": receipt.ArtifactDigest,
		"report_digest": receipt.ReportDigest, "completed_at": receipt.CompletedAt, "exit_code": receipt.ExitCode}, nil
}

func (r *ReceiptExpectation) requireInputs() error {
	for _, input := range []struct {
		name, value string
		pattern     *regexp.Regexp
	}{
		{"receipt-boc", r.receiptBOC, nil}, {"response-hash", r.responseHash, hex64Pattern},
		{"quote-package", r.quotePackage, nil}, {"network-domain", r.networkPath, nil},
		{"execution-id", r.executionID, sha256Pattern}, {"input-digest", r.inputDigest, sha256Pattern},
		{"source-digest", r.sourceDigest, sha256Pattern},
		{"snapshot-request-hash", r.snapshotRequestHash, hex64Pattern},
		{"snapshot-terms-hash", r.snapshotTermsHash, hex64Pattern},
		{"snapshot-price-nanotos", r.snapshotPrice, atomicPattern},
		{"snapshot-attestor-key", r.snapshotAttestor, attestorPattern},
		{"snapshot-caller", r.snapshotCaller, rawAddrPattern},
		{"capability-id", r.capabilityID, nil}, {"version", r.version, nil},
		{"buyer-wallet", r.buyer, rawAddrPattern}, {"actor", r.actor, rawAddrPattern},
		{"attestor", r.attestor, attestorPattern}, {"provider-agent-id", r.providerAgentID, nil},
		{"toolchain-digest", r.toolchainDigest, sha256Pattern}, {"manifest-digest", r.manifestDigest, sha256Pattern},
	} {
		if input.value == "" {
			return fmt.Errorf("receipt-check needs --%s", input.name)
		}
		if input.pattern != nil && !input.pattern.MatchString(input.value) {
			return fmt.Errorf("--%s is not in its canonical form", input.name)
		}
	}
	for _, value := range []string{r.executionID, r.inputDigest} {
		if _, err := digest32(value); err != nil {
			return err
		}
	}
	return nil
}

func digest32(text string) ([32]byte, error) {
	var value [32]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(text, "sha256:"))
	if err != nil || len(raw) != 32 || !sha256Pattern.MatchString(text) {
		return value, errors.New("invalid sha256 digest")
	}
	copy(value[:], raw)
	if value == ([32]byte{}) {
		return value, errors.New("zero sha256 digest")
	}
	return value, nil
}

func readQuotePackage(path string) (*nativev1.QuoteProposalPackageV1, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxQuotePackageBytes {
		return nil, errors.New("the Quote package is outside its bounds")
	}
	pkg := &nativev1.QuoteProposalPackageV1{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, pkg); err != nil || pkg.GetProposal() == nil {
		return nil, errors.New("the Quote package does not decode")
	}
	// Exactly the deterministic encoding of what decoded, so no unknown or
	// duplicated field rides along with the accepted terms.
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(pkg)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("the Quote package is not canonically encoded")
	}
	return pkg, nil
}

// decodeCanonicalReceipt accepts only the canonical single-root BOC of a
// canonical Receipt cell and returns the Receipt and its cell hash.
func decodeCanonicalReceipt(text string) (nativecore.SoftwareWorkReceiptV1, string, error) {
	var none nativecore.SoftwareWorkReceiptV1
	boc, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(boc) == 0 || len(boc) > maxReceiptBOCBytes {
		return none, "", errors.New("the Receipt BOC is not bounded standard base64")
	}
	root, err := cell.FromBOC(boc)
	if err != nil {
		return none, "", fmt.Errorf("the Receipt BOC does not decode: %w", err)
	}
	if !bytes.Equal(root.ToBOC(), boc) {
		return none, "", errors.New("the Receipt BOC is not the canonical serialization")
	}
	// The decoder refuses a failed or incomplete execution and any other
	// shape; a value the builder would not encode (a charge wider than
	// Coins) is refused by rebuilding.
	receipt, err := nativecore.DecodeSoftwareWorkReceiptCellV1(root)
	if err != nil {
		return none, "", err
	}
	rebuilt, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(receipt)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return none, "", errors.New("the Receipt is not canonical")
	}
	return receipt, hex.EncodeToString(root.Hash()), nil
}

type field struct{ name, got, want string }

func compare(fields []field) []string {
	var mismatches []string
	for _, f := range fields {
		if f.got != f.want {
			mismatches = append(mismatches, fmt.Sprintf("%s is %q, expected %q", f.name, f.got, f.want))
		}
	}
	return mismatches
}
