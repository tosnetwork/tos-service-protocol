package nativecore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The vector file is produced by scripts/generate-escrow-v2-vectors.sh, which
// runs the released escrow contract in the TOS sandbox. Every expected value
// below was produced or accepted by that contract, not by this package.
const escrowV2ContractVectorPath = "testdata/escrow_v2_contract_vectors.json"

type escrowV2VectorRuntime struct {
	Status       uint8  `json:"status"`
	Funded       string `json:"funded"`
	Settled      string `json:"settled"`
	ReceiptHash  string `json:"receipt_hash"`
	PendingQuery uint64 `json:"pending_query"`
	AcceptedAt   uint64 `json:"accepted_at"`
}

type escrowV2VectorStep struct {
	AtUnix    uint64                `json:"at_unix"`
	BodyBOC   string                `json:"body_boc_base64"`
	ExitCode  int                   `json:"exit_code"`
	DataBOC   string                `json:"data_boc_base64"`
	DataHash  string                `json:"data_hash"`
	Runtime   escrowV2VectorRuntime `json:"runtime"`
	QueryID   uint64                `json:"query_id"`
	Charged   string                `json:"charged"`
	IntentBOC string                `json:"intent_boc_base64"`
	Intent    string                `json:"intent_hash"`
	Signature string                `json:"signature_hex"`
}

type escrowV2ContractVector struct {
	Schema     string `json:"schema"`
	Provenance struct {
		TOSCommit    string `json:"tos_commit"`
		CodeHash     string `json:"escrow_code_hash"`
		CodeBOCSHA   string `json:"escrow_code_boc_sha256"`
		EscrowSource string `json:"escrow_source"`
	} `json:"provenance"`
	GlobalID int32 `json:"global_id"`
	Input    struct {
		Network            *nativev1.NetworkDomain `json:"network"`
		EscrowAddress      string                  `json:"escrow_address"`
		EscrowCodeHash     string                  `json:"escrow_code_hash"`
		EscrowDataHash     string                  `json:"escrow_data_hash"`
		QuoteCommitment    string                  `json:"quote_commitment"`
		StateInitBOC       string                  `json:"state_init_boc_base64"`
		AcceptQueryID      uint64                  `json:"accept_query_id"`
		AcceptBodyBOC      string                  `json:"accept_body_boc_base64"`
		ReceiptBOC         string                  `json:"receipt_boc_base64"`
		SignerPublicKeyHex string                  `json:"signer_public_key_hex"`
		ProviderOffer      string                  `json:"provider_offer_digest"`
		AmountAtomic       string                  `json:"amount_atomic"`
		AcceptByUnix       uint64                  `json:"accept_by_unix"`
		ExecutionDeadline  uint64                  `json:"execution_deadline"`
		FundingDeadline    uint64                  `json:"funding_deadline"`
		RefundAvailableAt  uint64                  `json:"refund_available_at"`
		BuyerAddress       string                  `json:"buyer_address"`
		ProviderAddress    string                  `json:"provider_address"`
		AssetMasterAddress string                  `json:"asset_master_address"`
	} `json:"input"`
	Deployed struct {
		DataBOC        string                `json:"data_boc_base64"`
		DataHash       string                `json:"data_hash"`
		Runtime        escrowV2VectorRuntime `json:"runtime"`
		GetEscrowState []string              `json:"get_escrow_state"`
		Wallet         string                `json:"get_escrow_wallet"`
	} `json:"deployed"`
	Accepted escrowV2VectorStep `json:"accepted"`
	Funded   escrowV2VectorStep `json:"funded"`
	Released escrowV2VectorStep `json:"released"`
	Refunded escrowV2VectorStep `json:"refunded"`
	Refused  []struct {
		Case      string `json:"case"`
		GlobalID  int32  `json:"global_id"`
		IntentBOC string `json:"intent_boc_base64"`
		BodyBOC   string `json:"body_boc_base64"`
		DataBOC   string `json:"data_boc_base64"`
		ExitCode  int    `json:"exit_code"`
	} `json:"refused"`
}

func loadEscrowV2ContractVector(t *testing.T) escrowV2ContractVector {
	t.Helper()
	raw, err := os.ReadFile(escrowV2ContractVectorPath)
	if err != nil {
		t.Fatalf("the contract vector is required: %v", err)
	}
	var vector escrowV2ContractVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Schema != "tos.service.escrow-v2-contract-vectors.v1" || len(vector.Provenance.TOSCommit) != 40 {
		t.Fatalf("unexpected vector schema or provenance: %s %q", vector.Schema, vector.Provenance.TOSCommit)
	}
	return vector
}

func vectorCell(t *testing.T, encoded string) *cell.Cell {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	value, err := cell.FromBOC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestEscrowV2CodeIsTheReleasedContract(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	if vector.Provenance.CodeHash != EscrowV2CodeHash || vector.Input.EscrowCodeHash != EscrowV2CodeHash {
		t.Fatalf("vector code %s, allowlisted code %s", vector.Provenance.CodeHash, EscrowV2CodeHash)
	}
	code, err := EscrowV2Code()
	if err != nil {
		t.Fatal(err)
	}
	if digestString(code.Hash()) != EscrowV2CodeHash {
		t.Fatal("embedded escrow code does not hash to the allowlisted code hash")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(escrowV2CodeBOC), ""))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != vector.Provenance.CodeBOCSHA {
		t.Fatal("embedded escrow BOC is not the artifact the vectors were produced with")
	}
}

func TestEscrowV2RefusesAnyOtherCode(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	stateInit := vectorCell(t, vector.Input.StateInitBOC).MustBeginParse()
	stateInit.MustLoadUInt(3)
	code := stateInit.MustLoadRef().MustToCell()
	if err := RequireEscrowV2Code(code); err != nil {
		t.Fatalf("the contract's own code was refused: %v", err)
	}
	other := cell.BeginCell().MustStoreUInt(0xabcdef02, 32).EndCell()
	if err := RequireEscrowV2Code(other); err == nil {
		t.Fatal("arbitrary escrow code was accepted")
	}
	if err := RequireEscrowV2CodeHash(strings.ToUpper(EscrowV2CodeHash)); err == nil {
		t.Fatal("a non-canonical spelling of the code hash was accepted")
	}
	if err := RequireEscrowV2Code(nil); err == nil {
		t.Fatal("missing escrow code was accepted")
	}
	state, err := DecodeEscrowDataV2(vectorCell(t, vector.Deployed.DataBOC), vector.Input.Network)
	if err != nil {
		t.Fatal(err)
	}
	init := EscrowInitV2{Network: vector.Input.Network, AcceptedQuote: state.AcceptedQuote,
		Terms: EscrowTermsV1{BuyerAddress: state.BuyerAddress, ProviderAddress: state.ProviderAddress,
			FundingDeadline: state.FundingDeadline, RefundAvailableAt: state.RefundAvailableAt},
		ExecutionSignerEd25519: state.ExecutionSignerEd25519, TransportBinding: state.TransportBinding,
		AssetMasterAddress: state.AssetMasterAddress, AssetWalletCode: state.AssetWalletCode}
	identity, err := BuildEscrowStateInitV2(0, code, init)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Address != vector.Input.EscrowAddress || identity.StateInitBOC == "" ||
		digestString(identity.Data.Hash()) != "tvm-cell-sha256:"+vector.Deployed.DataHash {
		t.Fatalf("rebuilt escrow %s differs from the deployed contract %s", identity.Address, vector.Input.EscrowAddress)
	}
	if _, err := BuildEscrowStateInitV2(0, other, init); err == nil {
		t.Fatal("an escrow StateInit was built for code other than the released contract")
	}
}

func assertEscrowV2Runtime(t *testing.T, name string, state *EscrowStateV2, want escrowV2VectorRuntime) {
	t.Helper()
	receipt := ""
	if want.ReceiptHash != strings.Repeat("0", 64) {
		receipt = "tvm-cell-sha256:" + want.ReceiptHash
	}
	if state.Status != want.Status || state.FundedAtomicAmount != want.Funded || state.SettledAtomicAmount != want.Settled ||
		state.ReceiptCommitment != receipt || state.PendingQueryID != want.PendingQuery || state.AcceptedAtUnix != want.AcceptedAt {
		t.Fatalf("%s: Go decoded %+v, contract stored %+v", name, state, want)
	}
}

func TestEscrowV2DecodesEveryStateTheContractWrites(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	steps := []struct {
		name    string
		data    string
		runtime escrowV2VectorRuntime
		status  uint8
	}{
		{"deployed", vector.Deployed.DataBOC, vector.Deployed.Runtime, EscrowStatusPendingAcceptanceV2},
		{"accepted", vector.Accepted.DataBOC, vector.Accepted.Runtime, EscrowStatusAwaitingFundingV2},
		{"funded", vector.Funded.DataBOC, vector.Funded.Runtime, EscrowStatusFundedV2},
		{"released", vector.Released.DataBOC, vector.Released.Runtime, EscrowStatusReleasePendingV2},
		{"refunded", vector.Refunded.DataBOC, vector.Refunded.Runtime, EscrowStatusRefundPendingV2},
	}
	for _, step := range steps {
		state, err := DecodeEscrowDataV2(vectorCell(t, step.data), vector.Input.Network)
		if err != nil {
			t.Fatalf("%s: Go refused a state the contract wrote: %v", step.name, err)
		}
		if state.Status != step.status {
			t.Fatalf("%s: status %d, want %d", step.name, state.Status, step.status)
		}
		assertEscrowV2Runtime(t, step.name, state, step.runtime)
		if state.QuoteCommitment != vector.Input.QuoteCommitment || state.BuyerAddress != vector.Input.BuyerAddress ||
			state.ProviderAddress != vector.Input.ProviderAddress || state.AssetMasterAddress != vector.Input.AssetMasterAddress ||
			state.FundingDeadline != vector.Input.FundingDeadline || state.RefundAvailableAt != vector.Input.RefundAvailableAt ||
			state.AcceptByUnix != vector.Input.AcceptByUnix || state.ExecutionDeadline != vector.Input.ExecutionDeadline ||
			hex.EncodeToString(state.ExecutionSignerEd25519) != vector.Input.SignerPublicKeyHex {
			t.Fatalf("%s: committed terms decoded as %+v", step.name, state)
		}
	}
	if got := vector.Deployed.GetEscrowState; len(got) != 6 || got[0] != "0" || got[4] != "0" {
		t.Fatalf("unexpected get_escrow_state at deployment: %v", got)
	}
	if vector.Released.Runtime.ReceiptHash != hex.EncodeToString(vectorCell(t, vector.Input.ReceiptBOC).Hash()) {
		t.Fatal("the contract recorded a Receipt other than the one released against")
	}
}

func TestEscrowV2WalletMatchesTheContract(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	state, err := DecodeEscrowDataV2(vectorCell(t, vector.Deployed.DataBOC), vector.Input.Network)
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := DeriveEscrowAssetWalletV2(vector.Input.EscrowAddress, state)
	if err != nil {
		t.Fatal(err)
	}
	if wallet != vector.Deployed.Wallet {
		t.Fatalf("Go derives wallet %s, contract get_escrow_wallet returns %s", wallet, vector.Deployed.Wallet)
	}
}

func TestEscrowV2SettlementIntentMatchesTheContract(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	state, err := DecodeEscrowDataV2(vectorCell(t, vector.Funded.DataBOC), vector.Input.Network)
	if err != nil {
		t.Fatal(err)
	}
	receipt := vectorCell(t, vector.Input.ReceiptBOC)
	charged, ok := new(big.Int).SetString(vector.Released.Charged, 10)
	if !ok {
		t.Fatal("invalid charged amount")
	}
	intent, err := BuildEscrowSettlementIntentV2(vector.GlobalID, vector.Input.EscrowAddress, state.AcceptedQuote,
		receipt, charged, vector.Released.QueryID)
	if err != nil {
		t.Fatal(err)
	}
	accepted := vectorCell(t, vector.Released.IntentBOC)
	if hex.EncodeToString(intent.Hash()) != vector.Released.Intent || !equalBytes(intent.Hash(), accepted.Hash()) {
		t.Fatalf("Go intent %x, contract-accepted intent %s", intent.Hash(), vector.Released.Intent)
	}
	if intent.Dump() != accepted.Dump() {
		t.Fatalf("Go intent bits differ from the accepted intent:\n%s\n%s", intent.Dump(), accepted.Dump())
	}
	public, err := hex.DecodeString(vector.Input.SignerPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(vector.Released.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, intent.Hash(), signature) {
		t.Fatal("the signature the contract accepted does not verify over the Go intent")
	}
	body, err := BuildEscrowReleaseBodyV2(vector.Released.QueryID, receipt, signature)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(body.Hash(), vectorCell(t, vector.Released.BodyBOC).Hash()) {
		t.Fatal("Go release body differs from the body the contract accepted")
	}
	refund, err := BuildEscrowRefundBodyV2(vector.Refunded.QueryID)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(refund.Hash(), vectorCell(t, vector.Refunded.BodyBOC).Hash()) {
		t.Fatal("Go refund body differs from the body the contract accepted")
	}
	accept, err := BuildPaidDemandAcceptBodyV2(vector.Input.AcceptQueryID, vector.Input.QuoteCommitment, vector.Input.ProviderOffer)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(accept.Hash(), vectorCell(t, vector.Accepted.BodyBOC).Hash()) {
		t.Fatal("Go accept body differs from the body the contract accepted")
	}
}

func TestEscrowV2MatchesTheContractsRefusals(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	state, err := DecodeEscrowDataV2(vectorCell(t, vector.Funded.DataBOC), vector.Input.Network)
	if err != nil {
		t.Fatal(err)
	}
	receipt := vectorCell(t, vector.Input.ReceiptBOC)
	charged, _ := new(big.Int).SetString(vector.Released.Charged, 10)
	cases := map[string]bool{}
	for _, refused := range vector.Refused {
		cases[refused.Case] = true
		switch {
		case strings.Contains(refused.Case, "another network"):
			if refused.ExitCode != 2407 || refused.GlobalID == vector.GlobalID {
				t.Fatalf("unexpected refusal record %+v", refused)
			}
			// The contract refused a signature over this exact intent; Go must
			// produce exactly it for that network, so the network id sits where
			// the contract reads it.
			intent, err := BuildEscrowSettlementIntentV2(refused.GlobalID, vector.Input.EscrowAddress, state.AcceptedQuote,
				receipt, charged, vector.Released.QueryID)
			if err != nil {
				t.Fatal(err)
			}
			if !equalBytes(intent.Hash(), vectorCell(t, refused.IntentBOC).Hash()) {
				t.Fatal("Go intent for another network differs from the one the contract refused")
			}
		case strings.Contains(refused.Case, "version 1 intent"):
			if refused.ExitCode != 2407 {
				t.Fatalf("unexpected refusal record %+v", refused)
			}
			intent, err := BuildEscrowSettlementIntentV2(vector.GlobalID, vector.Input.EscrowAddress, state.AcceptedQuote,
				receipt, charged, vector.Released.QueryID)
			if err != nil {
				t.Fatal(err)
			}
			if equalBytes(intent.Hash(), vectorCell(t, refused.IntentBOC).Hash()) {
				t.Fatal("Go builds the version 1 intent layout the contract refuses")
			}
		case strings.Contains(refused.Case, "data at version 1"):
			if refused.ExitCode != 2401 {
				t.Fatalf("unexpected refusal record %+v", refused)
			}
			if _, err := DecodeEscrowDataV2(vectorCell(t, refused.DataBOC), vector.Input.Network); err == nil {
				t.Fatal("Go decoded version 1 escrow data that the contract refuses")
			}
		default:
			t.Fatalf("unknown refusal case %q", refused.Case)
		}
	}
	if len(cases) != 3 {
		t.Fatalf("expected three contract refusals, got %v", cases)
	}
}

// Every data cell the contract wrote must stop decoding as soon as any part of
// it is changed in a way the contract would refuse.
func TestEscrowV2DecoderFailsClosedOnContractData(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	data := vectorCell(t, vector.Released.DataBOC)
	root := data.MustBeginParse()
	magic := root.MustLoadUInt(32)
	root.MustLoadUInt(16)
	status := root.MustLoadUInt(8)
	hashes := root.MustLoadSlice(256 * 3)
	refs := make([]*cell.Cell, 4)
	for i := range refs {
		refs[i] = root.MustLoadRef().MustToCell()
	}
	rebuild := func(version, status uint64, trailing bool) *cell.Cell {
		builder := cell.BeginCell().MustStoreUInt(magic, 32).MustStoreUInt(version, 16).MustStoreUInt(status, 8).
			MustStoreSlice(hashes, 256*3)
		for _, ref := range refs {
			builder.MustStoreRef(ref)
		}
		if trailing {
			builder.MustStoreUInt(0, 1)
		}
		return builder.EndCell()
	}
	if _, err := DecodeEscrowDataV2(rebuild(escrowStateVersion, status, false), vector.Input.Network); err != nil {
		t.Fatalf("positive control: unchanged contract data refused: %v", err)
	}
	for name, mutated := range map[string]*cell.Cell{
		"version 1":     rebuild(1, status, false),
		"version 3":     rebuild(3, status, false),
		"unknown state": rebuild(escrowStateVersion, 5, false),
		"other state":   rebuild(escrowStateVersion, uint64(EscrowStatusFundedV2), false),
		"trailing bit":  rebuild(escrowStateVersion, status, true),
	} {
		if _, err := DecodeEscrowDataV2(mutated, vector.Input.Network); err == nil {
			t.Fatalf("%s: decoder accepted mutated contract data", name)
		}
	}
	if _, err := strconv.Atoi(vector.Deployed.GetEscrowState[1]); err != nil {
		t.Fatal(err)
	}
}
