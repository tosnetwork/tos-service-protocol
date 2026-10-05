package nativecore

import (
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestPaidDemandEscrowV2StartsPendingAcceptance(t *testing.T) {
	terms := EscrowTermsV1{BuyerAddress: testRawAddress(t, "EQBjK7o8stJ-pMAnTBApq9i0fBQOdXmZCvZNAdI5x55ime5W"),
		ProviderAddress: testRawAddress(t, "EQCjpcsMfVKfcm1eCOZ0F28f_db-jUire_GuCGyLzKp1qCrW"),
		FundingDeadline: 1_786_752_100, RefundAvailableAt: 1_786_756_000}
	signer := []byte(strings.Repeat("s", 32))
	walletCode := cell.BeginCell().MustStoreUInt(0x12345678, 32).EndCell()
	termsCell, _ := BuildEscrowTermsCellV1(terms)
	authorization, _ := BuildEscrowAuthorizationCellV1(signer)
	_, transportDigest, _ := BuildTransportBindingCellV1(testEscrowTransport())
	_, disputeDigest := BuildObjectiveDisputePolicyCellV1()
	network := &nativev1.NetworkDomain{NetworkId: "tos-escrow-test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	masterID := []byte(strings.Repeat("m", 32))
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("33", 32), CapabilityVersion: "1.0.0",
		ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: 1_786_752_000,
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(termsCell.Hash()), DisputePolicyDigest: disputeDigest,
		MaximumPrice: &nativev1.MoneyV1{AtomicAmount: "25000000", Asset: &nativev1.TOSAssetIdentityV1{
			Master:         &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: masterID, CodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32)},
			WalletCodeHash: digestString(walletCode.Hash()), Decimals: 6}}}
	extension := PaidDemandQuoteExtensionV1{ProviderOfferCanonical: []byte("canonical-signed-provider-offer"),
		ProviderOfferBindingDigest: "sha256:" + strings.Repeat("66", 32), ProviderOfferDigest: "sha256:" + strings.Repeat("77", 32),
		AcceptByUnix: proposal.ExpiresAtUnixSeconds, ExecutionDeadline: 1_786_755_000}
	quote, _, _, err := BuildAcceptedQuoteCommitmentV2(network, proposal, "sha256:"+hex.EncodeToString(authorization.Hash()), extension)
	if err != nil {
		t.Fatal(err)
	}
	master := address.NewAddress(0, 0, masterID).StringRaw()
	identity, err := BuildEscrowStateInitV2(0, testEscrowV2Code(t), EscrowInitV2{
		Network: network, AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signer,
		TransportBinding: testEscrowTransport(), AssetMasterAddress: master, AssetWalletCode: walletCode})
	if err != nil {
		t.Fatal(err)
	}
	state, err := DecodeEscrowDataV2(identity.Data, network)
	if err != nil || state.Status != EscrowStatusPendingAcceptanceV2 || state.AcceptByUnix != extension.AcceptByUnix ||
		state.ExecutionDeadline != extension.ExecutionDeadline || state.ProviderOfferDigest != extension.ProviderOfferDigest || state.AcceptedAtUnix != 0 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	body, err := BuildPaidDemandAcceptBodyV2(1, identity.QuoteCommitment, extension.ProviderOfferDigest)
	if err != nil || body == nil {
		t.Fatal("accept operation is not deterministically constructible", err)
	}
}

func TestPaidDemandEscrowV2RejectsFundingDeadlineOutOfOrder(t *testing.T) {
	// The escrow contract enforces accept_by <= funding_deadline <
	// execution_deadline < refund_at. The builder must refuse to construct an
	// escrow the chain would reject at accept time.
	signer := []byte(strings.Repeat("s", 32))
	walletCode := cell.BeginCell().MustStoreUInt(0x12345678, 32).EndCell()
	network := &nativev1.NetworkDomain{NetworkId: "tos-escrow-test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	masterID := []byte(strings.Repeat("m", 32))
	master := address.NewAddress(0, 0, masterID).StringRaw()

	build := func(fundingDeadline, acceptBy, executionDeadline, refundAt uint64) error {
		terms := EscrowTermsV1{BuyerAddress: testRawAddress(t, "EQBjK7o8stJ-pMAnTBApq9i0fBQOdXmZCvZNAdI5x55ime5W"),
			ProviderAddress: testRawAddress(t, "EQCjpcsMfVKfcm1eCOZ0F28f_db-jUire_GuCGyLzKp1qCrW"),
			FundingDeadline: fundingDeadline, RefundAvailableAt: refundAt}
		termsCell, _ := BuildEscrowTermsCellV1(terms)
		authorization, _ := BuildEscrowAuthorizationCellV1(signer)
		_, transportDigest, _ := BuildTransportBindingCellV1(testEscrowTransport())
		_, disputeDigest := BuildObjectiveDisputePolicyCellV1()
		proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("33", 32), CapabilityVersion: "1.0.0",
			ProviderAgentId: "agent_" + strings.Repeat("44", 32), ManifestDigest: "sha256:" + strings.Repeat("55", 32),
			TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: acceptBy,
			EscrowTermsDigest: "sha256:" + hex.EncodeToString(termsCell.Hash()), DisputePolicyDigest: disputeDigest,
			MaximumPrice: &nativev1.MoneyV1{AtomicAmount: "25000000", Asset: &nativev1.TOSAssetIdentityV1{
				Master:         &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: masterID, CodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32)},
				WalletCodeHash: digestString(walletCode.Hash()), Decimals: 6}}}
		extension := PaidDemandQuoteExtensionV1{ProviderOfferCanonical: []byte("canonical-signed-provider-offer"),
			ProviderOfferBindingDigest: "sha256:" + strings.Repeat("66", 32), ProviderOfferDigest: "sha256:" + strings.Repeat("77", 32),
			AcceptByUnix: acceptBy, ExecutionDeadline: executionDeadline}
		quote, _, _, err := BuildAcceptedQuoteCommitmentV2(network, proposal, "sha256:"+hex.EncodeToString(authorization.Hash()), extension)
		if err != nil {
			return err
		}
		_, err = BuildEscrowStateInitV2(0, testEscrowV2Code(t), EscrowInitV2{
			Network: network, AcceptedQuote: quote, Terms: terms, ExecutionSignerEd25519: signer,
			TransportBinding: testEscrowTransport(), AssetMasterAddress: master, AssetWalletCode: walletCode})
		return err
	}

	if err := build(1_786_752_100, 1_786_752_000, 1_786_755_000, 1_786_756_000); err != nil {
		t.Fatalf("valid ordering rejected: %v", err)
	}
	if err := build(1_786_751_900, 1_786_752_000, 1_786_755_000, 1_786_756_000); err == nil {
		t.Fatal("funding_deadline < accept_by must be rejected")
	}
	if err := build(1_786_755_000, 1_786_752_000, 1_786_755_000, 1_786_756_000); err == nil {
		t.Fatal("funding_deadline == execution_deadline must be rejected")
	}
}
