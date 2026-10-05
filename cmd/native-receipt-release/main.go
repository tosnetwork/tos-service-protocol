// Command native-receipt-release builds a canonical software-work Receipt and
// the escrow v2 settlement intent for a funded escrow, then optionally verifies
// an external Ed25519 signature and emits the release body. It never reads or
// handles a private key.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type descriptor struct {
	Digest string `json:"Digest"`
}

type outcome struct {
	Quote, Execution, Input, Result, Source, Toolchain, Sandbox string
	Artifact, Report                                            descriptor
	Completed                                                   uint64
}

func (o *outcome) UnmarshalJSON(data []byte) error {
	var value struct {
		Quote            string `json:"quote_commitment"`
		Execution        string `json:"execution_id"`
		Input            string `json:"input_digest"`
		Result           string `json:"result_digest"`
		Source           string `json:"source_digest"`
		Toolchain        string `json:"toolchain_digest"`
		Sandbox          string `json:"sandbox_digest"`
		Artifact, Report descriptor
		Completed        uint64 `json:"completed_at_unix"`
		ExitCode         *int32 `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value.ExitCode == nil || *value.ExitCode != 0 {
		return errors.New("execution outcome is not successful")
	}
	*o = outcome{value.Quote, value.Execution, value.Input, value.Result, value.Source,
		value.Toolchain, value.Sandbox, value.Artifact, value.Report, value.Completed}
	return nil
}

type signingPackage struct {
	Schema                   string `json:"schema"`
	ReceiptCommitment        string `json:"receipt_commitment"`
	ReceiptBOCBase64         string `json:"receipt_boc_base64"`
	SettlementIntent         string `json:"settlement_intent"`
	SigningPayloadHex        string `json:"signing_payload_hex"`
	ExecutionSignerPublicKey string `json:"execution_signer_public_key_hex"`
	QueryID                  uint64 `json:"query_id"`
	SignatureHex             string `json:"signature_hex,omitempty"`
	ReleaseBodyBOCBase64     string `json:"release_body_boc_base64,omitempty"`
}

type externalSignature struct {
	Schema       string `json:"schema"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"public_key_hex"`
	MessageHex   string `json:"message_hex"`
	SignatureHex string `json:"signature_hex"`
}

// escrowRelease names the finalized escrow v2 account a Receipt releases and
// the network whose GLOBALID the settlement intent must carry.
type escrowRelease struct {
	Network  *nativev1.NetworkDomain
	GlobalID int32
	Escrow   string
	Data     *cell.Cell
	QueryID  uint64
}

func buildSigningPackage(out outcome, release escrowRelease) (signingPackage, *cell.Cell, error) {
	state, err := nativecore.DecodeEscrowDataV2(release.Data, release.Network)
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("decode escrow v2 state: %w", err)
	}
	if state.Status != nativecore.EscrowStatusFundedV2 {
		return signingPackage{}, nil, errors.New("escrow is not funded")
	}
	if out.Quote != state.QuoteCommitment {
		return signingPackage{}, nil, errors.New("execution outcome does not bind the escrow's Accepted Quote")
	}
	quote, err := nativecore.DecodeAcceptedQuoteV2(state.AcceptedQuote, release.Network)
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("decode Accepted Quote: %w", err)
	}
	receipt, commitment, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment: out.Quote, ExecutionID: out.Execution, InputDigest: out.Input,
		ResultDigest: out.Result, ArtifactDigest: out.Artifact.Digest, ReportDigest: out.Report.Digest,
		SourceDigest: out.Source, ToolchainDigest: out.Toolchain, SandboxDigest: out.Sandbox,
		ChargedAtomicAmount: state.FundedAtomicAmount, ProviderAgentID: quote.Terms.Proposal.ProviderAgentId,
		CompletedAt: out.Completed, ExitCode: 0,
	})
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("build Receipt: %w", err)
	}
	amount, ok := new(big.Int).SetString(state.FundedAtomicAmount, 10)
	if !ok {
		return signingPackage{}, nil, errors.New("invalid funded amount")
	}
	intent, err := nativecore.BuildEscrowSettlementIntentV2(release.GlobalID, release.Escrow, state.AcceptedQuote,
		receipt, amount, release.QueryID)
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("build settlement intent: %w", err)
	}
	return signingPackage{
		Schema:            "tos.service.software-work-settlement-signing.v2",
		ReceiptCommitment: commitment, ReceiptBOCBase64: base64.StdEncoding.EncodeToString(receipt.ToBOC()),
		SettlementIntent:         "tvm-cell-sha256:" + hex.EncodeToString(intent.Hash()),
		SigningPayloadHex:        hex.EncodeToString(intent.Hash()),
		ExecutionSignerPublicKey: hex.EncodeToString(state.ExecutionSignerEd25519), QueryID: release.QueryID,
	}, receipt, nil
}

func applyExternalSignature(value *signingPackage, receipt *cell.Cell, path string) error {
	var signed externalSignature
	if err := decode(path, &signed); err != nil {
		return fmt.Errorf("decode external signature: %w", err)
	}
	if signed.Schema != "tosctl-ed25519-signature-v1" || signed.Algorithm != "Ed25519" ||
		signed.PublicKeyHex != value.ExecutionSignerPublicKey || signed.MessageHex != value.SigningPayloadHex {
		return errors.New("external signature metadata does not match the settlement intent")
	}
	publicKey, err := hex.DecodeString(signed.PublicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid external signature public key")
	}
	signature, err := hex.DecodeString(signed.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid external signature encoding")
	}
	payload, _ := hex.DecodeString(value.SigningPayloadHex)
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("external signature verification failed")
	}
	body, err := nativecore.BuildEscrowReleaseBodyV2(value.QueryID, receipt, signature)
	if err != nil {
		return fmt.Errorf("build release body: %w", err)
	}
	value.Schema = "tos.service.software-work-settlement-release.v2"
	value.SignatureHex = signed.SignatureHex
	value.ReleaseBodyBOCBase64 = base64.StdEncoding.EncodeToString(body.ToBOC())
	return nil
}

func main() {
	outPath := flag.String("outcome", "", "successful outcome JSON")
	dataPath := flag.String("escrow-data", "", "finalized escrow v2 account data BOC (Base64)")
	networkID := flag.String("network", "", "canonical network ID")
	genesisRoot := flag.String("genesis-root", "", "sha256 genesis root")
	genesisFile := flag.String("genesis-file", "", "sha256 genesis file")
	globalID := flag.Int("global-id", 0, "network global ID (ConfigParam 19)")
	escrow := flag.String("escrow", "", "escrow address")
	query := flag.Uint64("query-id", 0, "non-zero query ID")
	signaturePath := flag.String("signature-file", "", "optional tosctl wallet sign JSON")
	flag.Parse()
	var out outcome
	if err := decode(*outPath, &out); err != nil {
		fail(err)
	}
	if *globalID == 0 || *globalID < math.MinInt32 || *globalID > math.MaxInt32 || *networkID == "" {
		fail(errors.New("--network and a non-zero 32-bit --global-id are required"))
	}
	data, err := readCell(*dataPath)
	if err != nil {
		fail(err)
	}
	result, receipt, err := buildSigningPackage(out, escrowRelease{
		Network:  &nativev1.NetworkDomain{NetworkId: *networkID, GenesisRootHash: *genesisRoot, GenesisFileHash: *genesisFile},
		GlobalID: int32(*globalID), Escrow: *escrow, Data: data, QueryID: *query})
	if err != nil {
		fail(err)
	}
	if *signaturePath != "" {
		if err := applyExternalSignature(&result, receipt, *signaturePath); err != nil {
			fail(err)
		}
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(encoded))
}

func readCell(path string) (*cell.Cell, error) {
	if path == "" {
		return nil, errors.New("required input path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	boc, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		return nil, err
	}
	return cell.FromBOC(boc)
}

func decode(path string, target any) error {
	if path == "" {
		return errors.New("required input path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
