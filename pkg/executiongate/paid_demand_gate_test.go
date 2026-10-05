package executiongate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

type paidEscrowFake struct{ value *toschain.FinalizedEscrowV2 }

func (fake paidEscrowFake) ResolveFinalizedV2(context.Context, string) (*toschain.FinalizedEscrowV2, bool, error) {
	return fake.value, true, nil
}

type paidOfferResolver struct{ key ed25519.PublicKey }

func (resolver paidOfferResolver) AuthorizeProviderOfferKey(_ commerce.ProviderProofContext,
	_ commerce.PaidDemandQuoteBindingBody, key ed25519.PublicKey, _ time.Time) error {
	if !resolver.key.Equal(key) {
		return errors.New("untrusted Provider Offer key")
	}
	return nil
}

func TestPaidDemandGateRequiresExactFinalizedAgreementOfferAndInputs(t *testing.T) {
	gate, request := paidDemandFixture(t)
	evidence, err := gate.ClaimPaidDemandExecution(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.AgreementBodyDigest == "" || evidence.ProviderOfferDigest == "" || evidence.AcceptedAtUnix == 0 {
		t.Fatalf("missing Paid Demand authority evidence: %+v", evidence)
	}
	if _, err = gate.ClaimPaidDemandExecution(context.Background(), request); err != nil {
		t.Fatalf("same semantic execution must be idempotent: %v", err)
	}
	changed := request
	changed.ExecutionID = digest("31")
	if _, err = gate.ClaimPaidDemandExecution(context.Background(), changed); err == nil {
		t.Fatal("same accepted Quote admitted a second execution")
	}
	changed = request
	changed.InputDigest = digest("32")
	if _, err = gate.ClaimPaidDemandExecution(context.Background(), changed); err == nil {
		t.Fatal("uncommitted private input reached execution")
	}
}

func TestPaidDemandGateSerializesConflictingTransportClaims(t *testing.T) {
	gate, first := paidDemandFixture(t)
	second := first
	second.ExecutionID = digest("91")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, request := range []Request{first, second} {
		go func(request Request) {
			<-start
			_, err := gate.ClaimPaidDemandExecution(context.Background(), request)
			results <- err
		}(request)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("conflicting transports produced %d successful claims, want 1", successes)
	}
}

func TestPaidDemandGateRejectsTombstonedProviderAgent(t *testing.T) {
	gate, request := paidDemandFixture(t)
	gate.native.(nativeFake).values[gate.providerAgent].GetAgent().Tombstoned = true
	if _, err := gate.ClaimPaidDemandExecution(context.Background(), request); err == nil {
		t.Fatal("tombstoned provider Agent executed work")
	}
}

func TestPaidDemandGateRequiresTheReleasedEscrowCode(t *testing.T) {
	gate, request := paidDemandFixture(t)
	gate.paidEscrow.(paidEscrowFake).value.Reference.ContractCodeHash = cellHash("55")
	if _, err := gate.ClaimPaidDemandExecution(context.Background(), request); err == nil {
		t.Fatal("an escrow running other code authorized execution")
	}
}

func TestPaidDemandStorePersistsNewFinalityHighWater(t *testing.T) {
	gate, request := paidDemandFixture(t)
	if _, err := gate.ClaimPaidDemandExecution(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	escrow := gate.paidEscrow.(paidEscrowFake).value
	escrow.Reference.FinalizedCheckpoint = 60
	escrow.Reference.TransactionHash = digest("60")
	for id, state := range gate.native.(nativeFake).values {
		state.Reference.FinalizedCheckpoint += 20
		state.Reference.TransactionHash = digest("6" + id[len(id)-1:])
	}
	if _, err := gate.ClaimPaidDemandExecution(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	escrow.Reference.FinalizedCheckpoint = 39
	if _, err := gate.ClaimPaidDemandExecution(context.Background(), request); err == nil {
		t.Fatal("persisted escrow checkpoint accepted a regression")
	}
}

func TestPaidDemandGateRejectsUnacceptedOrExpiredEscrow(t *testing.T) {
	gate, request := paidDemandFixture(t)
	resolved := gate.paidEscrow.(paidEscrowFake).value
	resolved.State.Status = nativecore.EscrowStatusAwaitingFundingV2
	if _, err := gate.ClaimPaidDemandExecution(context.Background(), request); err == nil {
		t.Fatal("unfunded buyer acceptance authorized execution")
	}
	resolved.State.Status = nativecore.EscrowStatusFundedV2
	resolved.State.ExecutionDeadline = uint64(gate.now().Unix())
	if _, err := gate.ClaimPaidDemandExecution(context.Background(), request); err == nil {
		t.Fatal("expired execution authorized work")
	}
}

func paidDemandFixture(t *testing.T) (*Gate, Request) {
	t.Helper()
	now := time.Unix(2_000_000_000, 0).UTC()
	network := &nativev1.NetworkDomain{NetworkId: "gate-paid-demand", GenesisRootHash: digest("41"), GenesisFileHash: digest("42")}
	provider := "agent_" + strings.Repeat("43", 32)
	buyer := "agent:buyer"
	providerWallet := "0:" + strings.Repeat("44", 32)
	buyerWallet := "0:" + strings.Repeat("45", 32)
	masterBytes := bytes.Repeat([]byte{0x46}, 32)
	master := "0:" + hex.EncodeToString(masterBytes)
	capabilityID := "cap_" + strings.Repeat("47", 32)
	manifest, inputDigest, sourceDigest := digest("48"), digest("49"), digest("4a")
	transport := nativecore.TransportBindingV1{SecurityMode: 1, MaxRequestBytes: 4096, BaseURL: "https://provider.test"}
	_, transportDigest, err := nativecore.BuildTransportBindingCellV1(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	executionKey := bytes.Repeat([]byte{0x4b}, 32)
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(executionKey)
	if err != nil {
		t.Fatal(err)
	}
	signerDigest := "sha256:" + hex.EncodeToString(authorization.Hash())
	escrowTerms := nativecore.EscrowTermsV1{BuyerAddress: buyerWallet, ProviderAddress: providerWallet,
		FundingDeadline: uint64(now.Add(20 * time.Minute).Unix()), RefundAvailableAt: uint64(now.Add(2 * time.Hour).Unix())}
	escrowTermsCell, err := nativecore.BuildEscrowTermsCellV1(escrowTerms)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{CapabilityId: capabilityID, CapabilityVersion: "1.0.0", ProviderAgentId: provider,
		ManifestDigest: manifest, TransportBindingDigest: transportDigest,
		MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: 0, AccountId: masterBytes, CodeHash: cellHash("4c")}, WalletCodeHash: cellHash("4d"), Decimals: 6}, AtomicAmount: "1000"},
		EscrowTermsDigest: digestFromCell(escrowTermsCell.Hash()), DisputePolicyDigest: disputeDigest,
		ExpiresAtUnixSeconds: uint64(now.Add(10 * time.Minute).Unix())}
	_, projection, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal, signerDigest)
	if err != nil {
		t.Fatal(err)
	}
	profile := commerce.PaidDemandQuoteProfileDigest()
	agreement := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:gate", Version: 1, NetworkContext: network.NetworkId,
		Participants:     []commerce.AgreementParticipant{{AgentID: buyer, Roles: []string{"buyer"}}, {AgentID: provider, Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("execute exact reviewed inputs"),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: buyer, BeneficiaryAgentID: provider, DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("pay"), Amount: &commerce.AgreementAmount{AssetNamespace: "tos.contract", AssetIdentifier: master, AmountAtomic: "1000", Unit: "atomic"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective", SettlementAdapterURI: paiddemand.SettlementAdapterURI,
				SettlementParameters: []byte(providerWallet), AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: provider, BeneficiaryAgentID: buyer,
				SubjectContentType: "text/plain", Subject: []byte("bounded work"), AttachmentDigests: []string{inputDigest, sourceDigest},
				RequiredExtensions:    []string{"tos.input." + strings.TrimPrefix(inputDigest, "sha256:"), "tos.source." + strings.TrimPrefix(sourceDigest, "sha256:")},
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective", AuthorizationPredicateIDs: []string{"predicate:provider"}},
		},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "wallet", SubjectNamespace: "tos.wallet", SubjectIdentifier: buyerWallet, RepresentedAgentID: buyer},
				ObligationIDs: []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: provider},
				ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		}, ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	agreement, err = commerce.PrepareAgreementTargets(agreement)
	if err != nil {
		t.Fatal(err)
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(agreement)
	binding := commerce.PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: network.NetworkId,
		AgreementBodyDigest: agreementDigest, AgreementObligationIDs: []string{"pay", "work"},
		AgreementAuthorizationPredicateIDs:  []string{"predicate:buyer", "predicate:provider"},
		AgreementAuthorizationTargetDigests: []string{agreement.AuthorizationPredicates[0].EvidenceTargetProjectionDigest, agreement.AuthorizationPredicates[1].EvidenceTargetProjectionDigest},
		EvidenceProfileURI:                  commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile,
		DemandMutationDigest: digest("4e"), ProviderOfferID: "offer:gate", ProviderAgentID: provider, BuyerAgentID: buyer,
		BuyerWallet: buyerWallet, ProviderWallet: providerWallet, NativeQuoteTermsProjectionDigest: projection,
		AcceptByUnix: proposal.ExpiresAtUnixSeconds}
	providerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4f}, ed25519.SeedSize))
	proof := commerce.ProviderProofContext{SchemaVersion: 1, NetworkContext: network.NetworkId, ProviderAgentID: provider,
		Purpose: "provider-offer.sign", PublicKey: "ed25519:" + hex.EncodeToString(providerKey.Public().(ed25519.PublicKey)), AgentGeneration: 1,
		ControllerPolicyDigest: digest("50"), DelegationDigest: digest("51"), ScopeBoundsDigest: digest("52"), OwnerMandateDigest: digest("53"),
		IssuanceAuthorityReferenceDigest: digest("54"), ValidFromUnix: uint64(now.Add(-time.Hour).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	offer, err := commerce.SignProviderOffer(binding, proof, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := paidOfferResolver{key: providerKey.Public().(ed25519.PublicKey)}
	quote, commitment, err := paiddemand.BuildAcceptedQuote(paiddemand.QuoteBuildInput{Agreement: agreement, ProviderOffer: offer,
		ProviderOfferResolver: resolver, Network: network, Proposal: proposal, ExecutionSignerAuthorization: signerDigest,
		EscrowTerms: escrowTerms, ExecutionDeadlineUnix: uint64(now.Add(90 * time.Minute).Unix()), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	offerDigest, _ := commerce.ProviderOfferDigest(offer)
	paidEscrow := &toschain.FinalizedEscrowV2{State: &nativecore.EscrowStateV2{Status: nativecore.EscrowStatusFundedV2,
		QuoteCommitment: commitment, BuyerAddress: buyerWallet, ProviderAddress: providerWallet,
		FundingDeadline: escrowTerms.FundingDeadline, RefundAvailableAt: escrowTerms.RefundAvailableAt,
		AcceptByUnix: proposal.ExpiresAtUnixSeconds, ExecutionDeadline: uint64(now.Add(90 * time.Minute).Unix()),
		ProviderOfferDigest: offerDigest, AcceptedAtUnix: uint64(now.Add(-time.Minute).Unix()), FundedAtomicAmount: "1000", AcceptedQuote: quote},
		Reference: reference(40, nativecore.EscrowV2CodeHash, "56")}
	codeHash := cellHash("57")
	agentState := &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain), TvmStateHash: cellHash("58"),
		Reference: reference(41, codeHash, "59"), State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: provider, Generation: 1, Sequence: 1, LastActionHash: digest("5a")}}}
	capabilityState := &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain), TvmStateHash: cellHash("5b"),
		Reference: reference(42, codeHash, "5c"), State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID,
			OwnerAgentId: provider, Generation: 1, Sequence: 1, LastActionHash: digest("5d"), Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: manifest}}}}}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	gate, err := NewPaidDemand(PaidDemandConfig{Directory: directory, EscrowResolver: paidEscrowFake{paidEscrow},
		NativeResolver: nativeFake{values: map[string]*nativev1.NativeStateV1{provider: agentState, capabilityID: capabilityState}},
		Network:        network, RegistryCodeHash: codeHash, ProviderAgentID: provider, ProviderAddress: providerWallet,
		ManifestDigest: manifest, TransportDigest: transportDigest, ExecutionSignerAuthorization: signerDigest,
		Agreement: agreement, ProviderOfferResolver: resolver, Timeout: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return gate, Request{EscrowAddress: "0:" + strings.Repeat("5e", 32), QuoteCommitment: commitment,
		ExecutionID: digest("5f"), InputDigest: inputDigest, SourceDigest: sourceDigest}
}

func digestFromCell(value []byte) string { return "sha256:" + hex.EncodeToString(value) }

type nativeFake struct {
	values map[string]*nativev1.NativeStateV1
}

func (f nativeFake) ResolveFinalizedState(_ context.Context, objectID, _ string) (*nativev1.NativeStateV1, bool, time.Time, error) {
	state, ok := f.values[objectID]
	if !ok {
		return nil, false, time.Time{}, nil
	}
	return proto.Clone(state).(*nativev1.NativeStateV1), true, time.Unix(2_000_000_000, 0), nil
}

func reference(checkpoint uint64, codeHash, txSuffix string) *nativev1.ChainReference {
	return &nativev1.ChainReference{
		ContractCodeHash: codeHash, TransactionHash: digest(txSuffix), FinalizedCheckpoint: checkpoint,
	}
}

func digest(pair string) string   { return "sha256:" + strings.Repeat(pair, 32) }
func cellHash(pair string) string { return "tvm-cell-sha256:" + strings.Repeat(pair, 32) }
