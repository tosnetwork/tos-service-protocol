package toschain

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type relayRustFixture struct {
	Schema              string `json:"schema"`
	Account             string `json:"account"`
	ControllerPublicKey string `json:"controller_public_key"`
	Target              string `json:"target"`
	ExactSignedBOC      string `json:"exact_signed_boc"`
	GlobalID            int32  `json:"global_id"`
	ControllerEpoch     uint64 `json:"controller_epoch"`
	Seqno               uint32 `json:"seqno"`
	ValidUntil          uint32 `json:"valid_until"`
	AmountAtomic        string `json:"amount_atomic"`
}

type fixedAccountResolver struct {
	wantNetwork agentrelay.NetworkDomain
	wantAccount string
	resolved    ResolvedRelayAgentAccount
}

func (resolver fixedAccountResolver) ResolveFinalizedAgentAccount(_ context.Context, network agentrelay.NetworkDomain,
	account string) (ResolvedRelayAgentAccount, error) {
	if network != resolver.wantNetwork || account != resolver.wantAccount {
		return ResolvedRelayAgentAccount{}, os.ErrNotExist
	}
	return resolver.resolved, nil
}

func TestAgentAccountNativeSendInspectorUsesFinalizedAuthorityAndExactBOC(t *testing.T) {
	fixture, boc, key := loadRelayRustFixture(t)
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: fixture.GlobalID,
		ZeroStateRootHash: shaDigest("1"), ZeroStateFileHash: shaDigest("2"), WorkchainID: -1}
	nativeAsset := agentrelay.AssetIdentity{AssetNamespace: "tos.native", AssetIdentifier: "tos:testnet", Unit: "nanotos"}
	inspector := AgentAccountNativeSendInspector{Accounts: fixedAccountResolver{wantNetwork: network,
		wantAccount: fixture.Account, resolved: ResolvedRelayAgentAccount{Account: agentgift.FinalizedAgentAccount{
			Active: true, Address: fixture.Account, OwnerAddress: fixture.Target, CodeHash: agentgift.AgentAccountCodeHash,
			DeploymentID: shaDigest("d"), GlobalID: fixture.GlobalID, TVMVersion: agentgift.MinimumAgentAccountTVMVersion,
			ControllerPublicKey: key, ControllerEpoch: fixture.ControllerEpoch, Seqno: fixture.Seqno,
			BalanceAtomic: 2_000_000_000, MaxPerTxAtomic: 2_000_000_000,
			DailyRemainingAtomic: 2_000_000_000, DefaultTaskTimeoutSecs: 3_600},
			FinalizedTime: 1_999_999_000, AuthorizedAgentID: "agent:client"}},
		NativeAsset: nativeAsset, FeeReserveAtomic: 1_000_000, MinimumInclusionMargin: 60}
	request := agentrelay.RelayQuoteRequestBody{Network: network, Mode: agentrelay.ModeRelayExact}
	resolved, err := inspector.Accounts.ResolveFinalizedAgentAccount(t.Context(), network, fixture.Account)
	if err != nil {
		t.Fatal(err)
	}
	authorityDigest, err := AgentAccountRelayAuthorityDigest(network, resolved)
	if err != nil {
		t.Fatal(err)
	}

	inspected, err := inspector.InspectTransaction(t.Context(), request, AgentAccountNativeSendRelayProfile(), boc,
		agentrelay.InspectionReadyToBroadcast)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.SourceAccount != fixture.Account || inspected.SourceAccountAuthorityDigest != authorityDigest ||
		inspected.AuthorizedAgentID != "agent:client" || inspected.SourceSequence != uint64(fixture.Seqno) ||
		inspected.ValidUntilUnix != uint64(fixture.ValidUntil) || inspected.Destination != fixture.Target ||
		inspected.ValueAtomic != fixture.AmountAtomic || !strings.HasPrefix(inspected.SignedTransactionCellHash, "tvm-cell-sha256:") {
		t.Fatalf("wrong inspected transaction: %+v", inspected)
	}

	mutated := append([]byte(nil), boc...)
	mutated[len(mutated)-1] ^= 1
	if _, err := inspector.InspectTransaction(t.Context(), request, AgentAccountNativeSendRelayProfile(), mutated,
		agentrelay.InspectionReadyToBroadcast); err == nil {
		t.Fatal("mutated exact BOC was accepted")
	}
	wrongNetwork := network
	wrongNetwork.GlobalID++
	request.Network = wrongNetwork
	if _, err := inspector.InspectTransaction(t.Context(), request, AgentAccountNativeSendRelayProfile(), boc,
		agentrelay.InspectionReadyToBroadcast); err == nil {
		t.Fatal("cross-network exact BOC was accepted")
	}
}

func TestAgentAccountRelayProjectsOnlyBoundSponsorshipBeforeFinality(t *testing.T) {
	fixture, boc, key := loadRelayRustFixture(t)
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: fixture.GlobalID,
		ZeroStateRootHash: shaDigest("1"), ZeroStateFileHash: shaDigest("2"), WorkchainID: -1}
	nativeAsset := agentrelay.AssetIdentity{AssetNamespace: "tos.native", AssetIdentifier: "tos:testnet", Unit: "nanotos"}
	value, err := strconv.ParseUint(fixture.AmountAtomic, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	account := agentgift.FinalizedAgentAccount{Active: true, Address: fixture.Account, OwnerAddress: fixture.Target,
		CodeHash: agentgift.AgentAccountCodeHash, DeploymentID: shaDigest("d"), GlobalID: fixture.GlobalID,
		TVMVersion: agentgift.MinimumAgentAccountTVMVersion, ControllerPublicKey: key,
		ControllerEpoch: fixture.ControllerEpoch, Seqno: fixture.Seqno, BalanceAtomic: value,
		MaxPerTxAtomic: value, DailyRemainingAtomic: value, DefaultTaskTimeoutSecs: 3_600}
	resolver := &fixedAccountResolver{wantNetwork: network, wantAccount: fixture.Account,
		resolved: ResolvedRelayAgentAccount{Account: account, FinalizedTime: 1_999_999_000,
			AuthorizedAgentID: "agent:client"}}
	inspector := AgentAccountNativeSendInspector{Accounts: resolver, NativeAsset: nativeAsset,
		FeeReserveAtomic: 1_000_000, MinimumInclusionMargin: 60}
	request := agentrelay.RelayQuoteRequestBody{Network: network, Mode: agentrelay.ModeSponsorAndRelay,
		RequestedSponsorship: &agentrelay.AssetAmount{Asset: nativeAsset, AmountAtomic: "1000000"}}

	if _, err := inspector.InspectTransaction(t.Context(), request, AgentAccountNativeSendRelayProfile(), boc,
		agentrelay.InspectionAdmission); err != nil {
		t.Fatalf("exact Agreement-bound sponsorship did not cover admission shortfall: %v", err)
	}
	if _, err := inspector.InspectTransaction(t.Context(), request, AgentAccountNativeSendRelayProfile(), boc,
		agentrelay.InspectionReadyToBroadcast); err == nil {
		t.Fatal("pending sponsorship was counted as finalized broadcast balance")
	}
	resolver.resolved.Account.BalanceAtomic += 1_000_000
	if _, err := inspector.InspectTransaction(t.Context(), request, AgentAccountNativeSendRelayProfile(), boc,
		agentrelay.InspectionReadyToBroadcast); err != nil {
		t.Fatalf("finalized sponsored balance did not pass broadcast inspection: %v", err)
	}
	wrongAsset := request
	wrongAsset.RequestedSponsorship = &agentrelay.AssetAmount{Asset: agentrelay.AssetIdentity{
		AssetNamespace: "external", AssetIdentifier: "external-unit", Unit: "micro"}, AmountAtomic: "1000000"}
	if _, err := inspector.InspectTransaction(t.Context(), wrongAsset, AgentAccountNativeSendRelayProfile(), boc,
		agentrelay.InspectionAdmission); err == nil {
		t.Fatal("non-native pending sponsorship was applied to the source balance")
	}
}

func TestAgentAccountRelayAuthorityDigestExcludesMutableBalanceButBindsPrincipal(t *testing.T) {
	fixture, _, key := loadRelayRustFixture(t)
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: fixture.GlobalID,
		ZeroStateRootHash: shaDigest("1"), ZeroStateFileHash: shaDigest("2"), WorkchainID: -1}
	resolved := ResolvedRelayAgentAccount{Account: agentgift.FinalizedAgentAccount{Active: true,
		Address: fixture.Account, OwnerAddress: fixture.Target, CodeHash: agentgift.AgentAccountCodeHash,
		DeploymentID: shaDigest("d"), GlobalID: fixture.GlobalID, TVMVersion: agentgift.MinimumAgentAccountTVMVersion,
		ControllerPublicKey: key, ControllerEpoch: fixture.ControllerEpoch, Seqno: fixture.Seqno,
		BalanceAtomic: 1, MaxPerTxAtomic: 2, DailyRemainingAtomic: 2, DefaultTaskTimeoutSecs: 3_600},
		AuthorizedAgentID: "agent:client"}
	first, err := AgentAccountRelayAuthorityDigest(network, resolved)
	if err != nil {
		t.Fatal(err)
	}
	resolved.Account.BalanceAtomic++
	resolved.Account.Seqno++
	resolved.Account.DailyRemainingAtomic--
	second, err := AgentAccountRelayAuthorityDigest(network, resolved)
	if err != nil || second != first {
		t.Fatal("mutable finalized account state changed the stable authority projection")
	}
	resolved.AuthorizedAgentID = "agent:other"
	third, err := AgentAccountRelayAuthorityDigest(network, resolved)
	if err != nil || third == first {
		t.Fatal("Agent principal substitution did not change the authority projection")
	}
	resolved.AuthorizedAgentID = "agent:client"
	wrongWorkchain := network
	wrongWorkchain.WorkchainID = 0
	if _, err := AgentAccountRelayAuthorityDigest(wrongWorkchain, resolved); err == nil {
		t.Fatal("source Agent Account was accepted under another workchain")
	}
}

func TestAgentAccountDirectPaymentBinderRejectsSemanticSubstitution(t *testing.T) {
	fixture, _, _ := loadRelayRustFixture(t)
	asset := agentrelay.AssetIdentity{AssetNamespace: "tos.native", AssetIdentifier: "tos:testnet", Unit: "nanotos"}
	obligation := agentcommerce.SettlementObligation{AgreementBodyDigest: shaDigest("3"),
		AgreementObligationID: "payment:relay", ObligationInstanceID: shaDigest("4"), Sequence: 1,
		PayerAgentID: "agent:client", PayeeAgentID: "agent:provider",
		Amount: agentcommerce.AgreementAmount{AssetNamespace: asset.AssetNamespace, AssetIdentifier: asset.AssetIdentifier,
			AmountAtomic: fixture.AmountAtomic, Unit: asset.Unit}, ExpiresAtUnix: uint64(fixture.ValidUntil),
		MaximumAggregateAmount: agentcommerce.AgreementAmount{AssetNamespace: asset.AssetNamespace,
			AssetIdentifier: asset.AssetIdentifier, AmountAtomic: fixture.AmountAtomic, Unit: asset.Unit},
		SettlementAdapterURI: agentrelay.DirectPaymentAdapterURI, SettlementParametersDigest: shaDigest("5"),
		StableActionID: shaDigest("6")}
	network := agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: fixture.GlobalID,
		ZeroStateRootHash: shaDigest("1"), ZeroStateFileHash: shaDigest("2"), WorkchainID: -1}
	networkDigest, _ := agentrelay.NetworkDomainDigest(network)
	payment, err := agentcommerce.BuildDomainBoundAgreementPaymentRequest("owner:client", "agent:client", "tos:testnet",
		networkDigest, []byte(fixture.Target), obligation)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := codec.Marshal(payment)
	if err != nil {
		t.Fatal(err)
	}
	intent := AgentAccountNativeSendIntent{SchemaVersion: 1, NetworkDigest: networkDigest, SourceAccount: fixture.Account,
		ControllerEpoch: fixture.ControllerEpoch, SourceSequence: uint64(fixture.Seqno),
		ValidUntilUnix: uint64(fixture.ValidUntil), Destination: fixture.Target, ValueAtomic: fixture.AmountAtomic}
	intentDigest, _ := AgentAccountNativeSendIntentDigest(intent)
	inspected := agentrelay.InspectedTransaction{NetworkDigest: networkDigest, SourceAccount: fixture.Account,
		ControllerEpoch: fixture.ControllerEpoch, SourceSequence: uint64(fixture.Seqno), ValidUntilUnix: uint64(fixture.ValidUntil), Destination: fixture.Target,
		ValueAtomic: fixture.AmountAtomic, TransactionIntentDigest: intentDigest}
	request := agentrelay.RelayExecutionRequest{QuoteRequest: agentrelay.SignedRelayQuoteRequest{
		Body: agentrelay.RelayQuoteRequestBody{RequesterAgentID: "agent:client", Network: network,
			TransactionIntentDigest: intentDigest}},
		UnderlyingActionRequest: canonical,
		AuthorizedAction:        agentcommerce.AuthorizedAction{ActionKind: "payment.direct", StableActionID: payment.StableActionID}}
	binder := AgentAccountDirectPaymentBinder{NativeAsset: asset}
	if err := binder.VerifyActionTransaction(request, inspected); err != nil {
		t.Fatal(err)
	}

	mutated := inspected
	mutated.Destination = "0:" + strings.Repeat("f", 64)
	if err := binder.VerifyActionTransaction(request, mutated); err == nil {
		t.Fatal("destination substitution was accepted")
	}
	mutated = inspected
	mutated.ValueAtomic = "999"
	if err := binder.VerifyActionTransaction(request, mutated); err == nil {
		t.Fatal("amount substitution was accepted")
	}
	mutated = inspected
	mutated.NetworkDigest = shaDigest("9")
	if err := binder.VerifyActionTransaction(request, mutated); err == nil {
		t.Fatal("same display network ID on a different chain domain was accepted")
	}
}

func loadRelayRustFixture(t *testing.T) (relayRustFixture, []byte, ed25519.PublicKey) {
	t.Helper()
	var fixture relayRustFixture
	raw, err := os.ReadFile("../agentgift/testdata/rust_agent_native_send_v1.json")
	if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.Schema != "tos.agent-gift.rust-fixture.v1" {
		t.Fatal("invalid Rust Agent Account fixture")
	}
	boc, err := base64.StdEncoding.DecodeString(fixture.ExactSignedBOC)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(fixture.ControllerPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatal("invalid fixture controller key")
	}
	return fixture, boc, ed25519.PublicKey(key)
}

func shaDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
