// Command native-escrow-vector derives a deterministic stablecoin escrow v2
// StateInit, its buyer acceptance body and a successful Receipt from explicit
// inputs. The output is the input half of the cross-language escrow vectors:
// the escrow contract itself is then run on it (see
// scripts/generate-escrow-v2-vectors.sh) and its results are what the Go codec
// is tested against.
//
// Only the released escrow v2 code is accepted; any other code is refused.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// Output is the escrow vector input document.
type Output struct {
	Schema              string                  `json:"schema"`
	Network             *nativev1.NetworkDomain `json:"network"`
	BaseUnix            uint64                  `json:"base_unix"`
	AcceptByUnix        uint64                  `json:"accept_by_unix"`
	FundingDeadline     uint64                  `json:"funding_deadline"`
	ExecutionDeadline   uint64                  `json:"execution_deadline"`
	RefundAvailableAt   uint64                  `json:"refund_available_at"`
	ReceiptCompletedAt  uint64                  `json:"receipt_completed_at"`
	BuyerAddress        string                  `json:"buyer_address"`
	ProviderAddress     string                  `json:"provider_address"`
	AssetMasterAddress  string                  `json:"asset_master_address"`
	AssetWalletCodeHash string                  `json:"asset_wallet_code_hash"`
	AmountAtomic        string                  `json:"amount_atomic"`
	SignerSeedHex       string                  `json:"signer_seed_hex"`
	SignerPublicKeyHex  string                  `json:"signer_public_key_hex"`
	ProviderAgentID     string                  `json:"provider_agent_id"`
	ProviderOfferDigest string                  `json:"provider_offer_digest"`
	EscrowAddress       string                  `json:"escrow_address"`
	EscrowCodeHash      string                  `json:"escrow_code_hash"`
	EscrowDataHash      string                  `json:"escrow_data_hash"`
	QuoteCommitment     string                  `json:"quote_commitment"`
	StateInitBOC        string                  `json:"state_init_boc_base64"`
	AcceptQueryID       uint64                  `json:"accept_query_id"`
	AcceptBodyBOC       string                  `json:"accept_body_boc_base64"`
	ReceiptBOC          string                  `json:"receipt_boc_base64"`
}

// Input holds every value the vector depends on.
type Input struct {
	Network         *nativev1.NetworkDomain
	BaseUnix        uint64
	BuyerAddress    string
	ProviderAddress string
	MasterAddress   string
	EscrowCode      *cell.Cell
	WalletCode      *cell.Cell
	SignerSeed      []byte
	AcceptQueryID   uint64
}

func main() {
	escrowCodePath := flag.String("escrow-code", "", "escrow v2 code BOC (Base64); defaults to the embedded release")
	walletCodePath := flag.String("wallet-code", "", "stablecoin wallet code BOC (Base64)")
	buyer := flag.String("buyer", "", "raw buyer wallet address")
	provider := flag.String("provider", "", "raw provider wallet address")
	master := flag.String("master", "", "raw stablecoin master address")
	base := flag.Uint64("base-unix", 0, "unix time the vector's deadlines are counted from")
	seed := flag.String("signer-seed", "", "hex Ed25519 seed of the test execution signer")
	networkID := flag.String("network", "tos:escrow-v2-vector", "canonical network ID")
	flag.Parse()
	if *walletCodePath == "" {
		fail(errors.New("--wallet-code is required"))
	}
	escrowCode, err := nativecore.EscrowV2Code()
	if err != nil {
		fail(err)
	}
	if *escrowCodePath != "" {
		if escrowCode, err = decodeCode(*escrowCodePath); err != nil {
			fail(err)
		}
	}
	walletCode, err := decodeCode(*walletCodePath)
	if err != nil {
		fail(err)
	}
	signerSeed, err := hex.DecodeString(*seed)
	if err != nil {
		fail(errors.New("invalid signer seed"))
	}
	network := &nativev1.NetworkDomain{NetworkId: *networkID,
		GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	output, err := Build(Input{Network: network, BaseUnix: *base, BuyerAddress: *buyer, ProviderAddress: *provider,
		MasterAddress: *master, EscrowCode: escrowCode, WalletCode: walletCode, SignerSeed: signerSeed, AcceptQueryID: 2})
	if err != nil {
		fail(err)
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(encoded))
}

// Build derives the escrow vector input. Escrow code other than the released
// v2 contract is refused by nativecore.BuildEscrowStateInitV2.
func Build(input Input) (*Output, error) {
	if input.Network == nil || input.WalletCode == nil || len(input.SignerSeed) != ed25519.SeedSize ||
		input.BaseUnix == 0 || input.BaseUnix > 1<<40 || input.AcceptQueryID == 0 {
		return nil, errors.New("invalid escrow vector input")
	}
	masterAddress, err := address.ParseRawAddr(input.MasterAddress)
	if err != nil || masterAddress.Workchain() != 0 || masterAddress.StringRaw() != input.MasterAddress {
		return nil, errors.New("invalid stablecoin master address")
	}
	acceptBy, funding, execution, refund := input.BaseUnix+100, input.BaseUnix+300, input.BaseUnix+500, input.BaseUnix+700
	completedAt := input.BaseUnix + 30
	signer := ed25519.NewKeyFromSeed(input.SignerSeed)
	signerPublic, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("invalid signer key")
	}
	transport := nativecore.TransportBindingV1{SecurityMode: nativecore.TransportLoopbackHTTP,
		MaxRequestBytes: 1 << 20, BaseURL: "http://127.0.0.1:18080"}
	terms := nativecore.EscrowTermsV1{BuyerAddress: input.BuyerAddress, ProviderAddress: input.ProviderAddress,
		FundingDeadline: funding, RefundAvailableAt: refund}
	termsCell, err := nativecore.BuildEscrowTermsCellV1(terms)
	if err != nil {
		return nil, err
	}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(signerPublic)
	if err != nil {
		return nil, err
	}
	_, transportDigest, err := nativecore.BuildTransportBindingCellV1(transport)
	if err != nil {
		return nil, err
	}
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	providerAgent := "agent_" + strings.Repeat("44", 32)
	const amount = "25000000"
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("33", 32), CapabilityVersion: "1.0.0",
		ProviderAgentId: providerAgent, ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: acceptBy,
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(termsCell.Hash()), DisputePolicyDigest: disputeDigest,
		MaximumPrice: &nativev1.MoneyV1{AtomicAmount: amount, Asset: &nativev1.TOSAssetIdentityV1{
			Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: masterAddress.Data(),
				CodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32)},
			WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(input.WalletCode.Hash()), Decimals: 6}}}
	offerDigest := "sha256:" + strings.Repeat("77", 32)
	extension := nativecore.PaidDemandQuoteExtensionV1{ProviderOfferCanonical: []byte("canonical-escrow-v2-vector-provider-offer"),
		ProviderOfferBindingDigest: "sha256:" + strings.Repeat("66", 32), ProviderOfferDigest: offerDigest,
		AcceptByUnix: acceptBy, ExecutionDeadline: execution}
	quote, _, _, err := nativecore.BuildAcceptedQuoteCommitmentV2(input.Network, proposal,
		"sha256:"+hex.EncodeToString(authorization.Hash()), extension)
	if err != nil {
		return nil, err
	}
	identity, err := nativecore.BuildEscrowStateInitV2(0, input.EscrowCode, nativecore.EscrowInitV2{Network: input.Network,
		AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signerPublic, TransportBinding: transport,
		AssetMasterAddress: input.MasterAddress, AssetWalletCode: input.WalletCode})
	if err != nil {
		return nil, err
	}
	accept, err := nativecore.BuildPaidDemandAcceptBodyV2(input.AcceptQueryID, identity.QuoteCommitment, offerDigest)
	if err != nil {
		return nil, err
	}
	receipt, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment: identity.QuoteCommitment, ExecutionID: vectorDigest("execution"),
		InputDigest: vectorDigest("input"), ResultDigest: vectorDigest("result"), ArtifactDigest: vectorDigest("artifact"),
		ReportDigest: vectorDigest("report"), SourceDigest: vectorDigest("source"), ToolchainDigest: vectorDigest("toolchain"),
		SandboxDigest: vectorDigest("sandbox"), ChargedAtomicAmount: amount, ProviderAgentID: providerAgent,
		CompletedAt: completedAt, ExitCode: 0})
	if err != nil {
		return nil, err
	}
	return &Output{Schema: "tos.service.escrow-v2-vector-input.v1", Network: input.Network, BaseUnix: input.BaseUnix,
		AcceptByUnix: acceptBy, FundingDeadline: funding, ExecutionDeadline: execution, RefundAvailableAt: refund,
		ReceiptCompletedAt: completedAt, BuyerAddress: input.BuyerAddress, ProviderAddress: input.ProviderAddress,
		AssetMasterAddress: input.MasterAddress, AssetWalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(input.WalletCode.Hash()),
		AmountAtomic: amount, SignerSeedHex: hex.EncodeToString(input.SignerSeed), SignerPublicKeyHex: hex.EncodeToString(signerPublic),
		ProviderAgentID: providerAgent, ProviderOfferDigest: offerDigest, EscrowAddress: identity.Address,
		EscrowCodeHash: identity.CodeHash, EscrowDataHash: "tvm-cell-sha256:" + hex.EncodeToString(identity.Data.Hash()),
		QuoteCommitment: identity.QuoteCommitment, StateInitBOC: identity.StateInitBOC, AcceptQueryID: input.AcceptQueryID,
		AcceptBodyBOC: base64.StdEncoding.EncodeToString(accept.ToBOC()),
		ReceiptBOC:    base64.StdEncoding.EncodeToString(receipt.ToBOC())}, nil
}

func vectorDigest(label string) string {
	sum := sha256.Sum256([]byte("tos-escrow-v2-vector-" + label))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeCode(path string) (*cell.Cell, error) {
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

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
