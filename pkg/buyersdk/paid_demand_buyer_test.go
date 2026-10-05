package buyersdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type paidOfferKeyResolver struct{ key ed25519.PublicKey }

func (resolver paidOfferKeyResolver) AuthorizeProviderOfferKey(_ commerce.ProviderProofContext,
	_ commerce.PaidDemandQuoteBindingBody, key ed25519.PublicKey, _ time.Time) error {
	if !resolver.key.Equal(key) {
		return errors.New("wrong Provider Offer key")
	}
	return nil
}

type paidEscrowFake struct {
	state *toschain.FinalizedEscrowV2
}

func (fake *paidEscrowFake) ResolveFinalizedV2(context.Context, string) (*toschain.FinalizedEscrowV2, bool, error) {
	if fake.state == nil {
		return nil, false, nil
	}
	state := *fake.state.State
	return &toschain.FinalizedEscrowV2{State: &state,
		Reference: proto.Clone(fake.state.Reference).(*nativev1.ChainReference), FinalizedAt: fake.state.FinalizedAt}, true, nil
}

type paidDeployerFake struct {
	resolver *paidEscrowFake
	network  *nativev1.NetworkDomain
	purchase *PreparedPaidDemandPurchase
	calls    int
}

func (fake *paidDeployerFake) PreparePaidDemandDeployment(_ context.Context,
	purchase *PreparedPaidDemandPurchase) (*PreparedPaidDemandDeployment, error) {
	fake.purchase = purchase
	return &PreparedPaidDemandDeployment{EscrowAddress: purchase.Escrow.Address,
		QuoteCommitment: purchase.QuoteCommitment, StateInitBOCBase64: purchase.Escrow.StateInitBOC,
		StateInitHash: purchase.Escrow.Address, AttachedNanoTOS: 1, MessageBOCBase64: "prepared", MessageHash: paidTestDigest("91")}, nil
}

func (fake *paidDeployerFake) BroadcastPaidDemandDeployment(_ context.Context,
	_ *PreparedPaidDemandDeployment) error {
	fake.calls++
	state, err := nativecore.DecodeEscrowDataV2(fake.purchase.Escrow.Data, fake.network)
	if err != nil {
		return err
	}
	fake.resolver.state = &toschain.FinalizedEscrowV2{State: state,
		Reference:   &nativev1.ChainReference{Account: fake.purchase.Escrow.Address, ContractCodeHash: fake.purchase.Escrow.CodeHash, FinalizedCheckpoint: 10},
		FinalizedAt: time.Unix(1_900_000_000, 0)}
	return nil
}

type paidEffectAuthorizer struct {
	key ed25519.PrivateKey
}

func (authority paidEffectAuthorizer) AuthorizeCustodyEffect(_ context.Context,
	request CustodyEffectRequest) (commerce.CustodyEffectAuthorization, error) {
	stable, _, err := commerce.DeriveStableActionID("escrow.transition", request.SemanticFields)
	if err != nil {
		return commerce.CustodyEffectAuthorization{}, err
	}
	exact, err := commerce.ExactRequestDigest(request.CanonicalRequest)
	if err != nil {
		return commerce.CustodyEffectAuthorization{}, err
	}
	return commerce.SignCustodyEffectAuthorization(commerce.CustodyEffectAuthorization{SchemaVersion: 1,
		AuthorityID: "authority:test", OwnerID: "owner:test", AgentID: "agent:buyer",
		SourceAccount: request.SourceAccount, NetworkID: request.NetworkID, NetworkGlobalID: request.NetworkGlobalID,
		ActionKind: request.ActionKind, StableActionID: stable, ExactRequestDigest: exact, WriterGeneration: 1,
		WriterFenceDigest: paidTestDigest("92"), PolicyRevision: 1, MandateDigest: paidTestDigest("93"),
		ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64), AgreementBodyDigest: request.AgreementDigest,
		ObligationID: request.ObligationID, Destination: request.Destination, AmountNanoTOS: request.AmountNanoTOS,
		BodyHash: request.BodyHash, StateInitHashOrZero: request.StateInitHashOrZero,
		ExpiresAtUnix: request.ExpiresAtUnix}, authority.key)
}

type paidActionFake struct {
	resolver  *paidEscrowFake
	intents   []WalletActionIntent
	ambiguous bool
}

func (fake *paidActionFake) PrepareWalletAction(_ context.Context,
	intent WalletActionIntent) (*PreparedWalletAction, error) {
	fake.intents = append(fake.intents, intent)
	return &PreparedWalletAction{Intent: intent, MessageBOCBase64: "prepared", MessageHash: paidTestDigest("94")}, nil
}

func (fake *paidActionFake) BroadcastWalletAction(_ context.Context, prepared *PreparedWalletAction) error {
	switch prepared.Intent.TransitionKind {
	case "escrow.accept":
		fake.resolver.state.State.Status = nativecore.EscrowStatusAwaitingFundingV2
		fake.resolver.state.State.AcceptedAtUnix = 1_900_000_001
	case "escrow.fund":
		fake.resolver.state.State.Status = nativecore.EscrowStatusFundedV2
		fake.resolver.state.State.FundedAtomicAmount = "100"
	default:
		return errors.New("unexpected effect")
	}
	if fake.ambiguous {
		return errors.New("injected ambiguous broadcast")
	}
	return nil
}

type paidDemandBuyerFixture struct {
	buyer    *PaidDemandBuyer
	config   PaidDemandBuyerConfig
	input    PaidDemandPurchaseInput
	resolver *paidEscrowFake
	deployer *paidDeployerFake
	actions  *paidActionFake
	now      time.Time
}

func TestPaidDemandBuyerDeploysAcceptsAndFundsExactlyOnce(t *testing.T) {
	fixture := newPaidDemandBuyerFixture(t)
	purchase, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	installPaidEscrow(t, fixture, purchase)
	if _, err := fixture.buyer.Deploy(context.Background(), purchase); err != nil {
		t.Fatal(err)
	}
	if fixture.deployer.calls != 0 {
		t.Fatal("already finalized pending escrow was redeployed")
	}
	accepted, err := fixture.buyer.Accept(context.Background(), purchase)
	if err != nil || accepted.State.Status != nativecore.EscrowStatusAwaitingFundingV2 {
		t.Fatalf("accept state=%+v err=%v", accepted, err)
	}
	funded, err := fixture.buyer.Fund(context.Background(), purchase)
	if err != nil || funded.State.Status != nativecore.EscrowStatusFundedV2 {
		t.Fatalf("fund state=%+v err=%v", funded, err)
	}
	if len(fixture.actions.intents) != 2 || fixture.actions.intents[0].TransitionKind != "escrow.accept" ||
		fixture.actions.intents[1].TransitionKind != "escrow.fund" ||
		fixture.actions.intents[0].StableActionID == fixture.actions.intents[1].StableActionID {
		t.Fatalf("effects=%+v", fixture.actions.intents)
	}
	if _, err := fixture.buyer.Accept(context.Background(), purchase); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.buyer.Fund(context.Background(), purchase); err != nil {
		t.Fatal(err)
	}
	if len(fixture.actions.intents) != 2 {
		t.Fatal("finalized transitions were submitted twice")
	}
}

func TestPaidDemandBuyerDeploysOnlyPendingStateBeforeAcceptance(t *testing.T) {
	fixture := newPaidDemandBuyerFixture(t)
	purchase, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	deployed, err := fixture.buyer.Deploy(context.Background(), purchase)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.deployer.calls != 1 || deployed.State.Status != nativecore.EscrowStatusPendingAcceptanceV2 ||
		deployed.State.AcceptedAtUnix != 0 || deployed.State.FundedAtomicAmount != "0" || len(fixture.actions.intents) != 0 {
		t.Fatalf("deployment created authority or value: %+v", deployed.State)
	}
	if _, err := fixture.buyer.Deploy(context.Background(), purchase); err != nil {
		t.Fatal(err)
	}
	if fixture.deployer.calls != 1 {
		t.Fatal("finalized pending escrow was redeployed")
	}
}

func TestPaidDemandBuyerRequiresTheReleasedEscrowCode(t *testing.T) {
	fixture := newPaidDemandBuyerFixture(t)
	config := fixture.config
	config.EscrowCode = cell.BeginCell().MustStoreUInt(0x9999, 16).EndCell()
	if _, err := NewPaidDemandBuyer(config); err == nil {
		t.Fatal("a Paid Demand buyer was configured with escrow code other than the released contract")
	}
	purchase, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	installPaidEscrow(t, fixture, purchase)
	fixture.resolver.state.Reference.ContractCodeHash = "tvm-cell-sha256:" + strings.Repeat("ab", 32)
	if _, err := fixture.buyer.Accept(context.Background(), purchase); err == nil {
		t.Fatal("the buyer accepted an escrow observed running other code")
	}
}

func TestPaidDemandBuyerResolvesAmbiguousAcceptanceWithoutReplacement(t *testing.T) {
	fixture := newPaidDemandBuyerFixture(t)
	purchase, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	installPaidEscrow(t, fixture, purchase)
	fixture.actions.ambiguous = true
	if _, err := fixture.buyer.Accept(context.Background(), purchase); err != nil {
		t.Fatal(err)
	}
	if len(fixture.actions.intents) != 1 {
		t.Fatal("ambiguous acceptance allocated a replacement action")
	}
}

func TestPaidDemandBuyerAcceptanceEvidenceRequiresIndependentFinalizedState(t *testing.T) {
	fixture := newPaidDemandBuyerFixture(t)
	purchase, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	installPaidEscrow(t, fixture, purchase)
	accepted, err := fixture.buyer.Accept(context.Background(), purchase)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := fixture.buyer.BuyerAcceptEvidence(purchase, accepted)
	if err != nil {
		t.Fatal(err)
	}
	native := paiddemand.NativeEvidenceVerifier{ProviderOffers: fixture.buyer.offerResolver,
		BuyerAccepts: paiddemand.QuorumBuyerAcceptVerifier{Resolver: fixture.resolver, Network: fixture.buyer.base.network,
			ProviderOffers: fixture.buyer.offerResolver, Timeout: time.Second}}
	if err := (commerce.PaidDemandQuoteEvidenceVerifier{Native: native}).VerifyAgreementEvidence(evidence, fixture.now); err != nil {
		t.Fatalf("verify finalized buyer evidence: %v", err)
	}
	fixture.resolver.state.State.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("f", 64)
	if err := (commerce.PaidDemandQuoteEvidenceVerifier{Native: native}).VerifyAgreementEvidence(evidence, fixture.now); err == nil {
		t.Fatal("divergent finalized Quote was accepted")
	}
}

func newPaidDemandBuyerFixture(t *testing.T) paidDemandBuyerFixture {
	t.Helper()
	base := newBuyerFixture(t, BudgetLimits{Window: time.Hour, MaxPurchases: 2,
		MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "200"})
	now := base.now.UTC()
	provider := base.input.Proposal.ProviderAgentId
	buyerAgent := "agent:buyer"
	profile := commerce.PaidDemandQuoteProfileDigest()
	master := "0:" + hex.EncodeToString(base.input.Proposal.MaximumPrice.Asset.Master.AccountId)
	agreement := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:paid-buyer", Version: 1,
		NetworkContext:   base.network.NetworkId,
		Participants:     []commerce.AgreementParticipant{{AgentID: buyerAgent, Roles: []string{"buyer"}}, {AgentID: provider, Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("perform exact software work"),
		Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: buyerAgent, BeneficiaryAgentID: provider, DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("pay"), Amount: &commerce.AgreementAmount{AssetNamespace: "tos.contract", AssetIdentifier: master, AmountAtomic: "100", Unit: "atomic"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective", SettlementAdapterURI: paiddemand.SettlementAdapterURI,
				SettlementParameters: []byte(base.input.EscrowTerms.ProviderAddress), AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: provider, BeneficiaryAgentID: buyerAgent,
				SubjectContentType: "text/plain", Subject: []byte("work"), ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile",
				DisputePolicy: "objective", AuthorizationPredicateIDs: []string{"predicate:provider"}},
		}, AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "wallet", SubjectNamespace: "tos.wallet", SubjectIdentifier: base.buyerAddress, RepresentedAgentID: buyerAgent},
				ObligationIDs: []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: provider},
				ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		}, ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	var err error
	agreement, err = commerce.PrepareAgreementTargets(agreement)
	if err != nil {
		t.Fatal(err)
	}
	authorization, _ := nativecore.BuildEscrowAuthorizationCellV1(base.input.ExecutionSignerEd25519)
	_, projection, err := nativecore.BuildAcceptedQuoteCommitment(base.network, base.input.Proposal,
		"sha256:"+hex.EncodeToString(authorization.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(agreement)
	binding := commerce.PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: base.network.NetworkId,
		AgreementBodyDigest: agreementDigest, AgreementObligationIDs: []string{"pay", "work"},
		AgreementAuthorizationPredicateIDs:  []string{"predicate:buyer", "predicate:provider"},
		AgreementAuthorizationTargetDigests: []string{agreement.AuthorizationPredicates[0].EvidenceTargetProjectionDigest, agreement.AuthorizationPredicates[1].EvidenceTargetProjectionDigest},
		EvidenceProfileURI:                  commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile,
		DemandMutationDigest: paidTestDigest("95"), ProviderOfferID: "offer:buyer", ProviderAgentID: provider, BuyerAgentID: buyerAgent,
		BuyerWallet: base.buyerAddress, ProviderWallet: base.input.EscrowTerms.ProviderAddress,
		NativeQuoteTermsProjectionDigest: projection, AcceptByUnix: base.input.Proposal.ExpiresAtUnixSeconds}
	providerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	proof := commerce.ProviderProofContext{SchemaVersion: 1, NetworkContext: base.network.NetworkId, ProviderAgentID: provider,
		Purpose: "provider-offer.sign", PublicKey: "ed25519:" + hex.EncodeToString(providerKey.Public().(ed25519.PublicKey)), AgentGeneration: 1,
		ControllerPolicyDigest: paidTestDigest("96"), DelegationDigest: paidTestDigest("97"), ScopeBoundsDigest: paidTestDigest("98"), OwnerMandateDigest: paidTestDigest("99"),
		IssuanceAuthorityReferenceDigest: paidTestDigest("9a"), ValidFromUnix: uint64(now.Add(-time.Hour).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	offer, err := commerce.SignProviderOffer(binding, proof, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &paidEscrowFake{}
	deployer := &paidDeployerFake{resolver: resolver, network: base.network}
	actions := &paidActionFake{resolver: resolver}
	custodyKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))
	escrowCode, err := nativecore.EscrowV2Code()
	if err != nil {
		t.Fatal(err)
	}
	config := PaidDemandBuyerConfig{NativeClient: base.native, AssetResolver: base.assets,
		Network: base.network, RegistryCodeHash: base.registryCodeHash, BuyerAddress: base.buyerAddress,
		AssetWalletCode: base.walletCode, BudgetLimits: base.limits, CallerID: "buyer-test", EscrowResolver: resolver,
		ProviderOfferResolver: paidOfferKeyResolver{providerKey.Public().(ed25519.PublicKey)}, EscrowCode: escrowCode,
		Deployer: deployer, ActionSender: actions, EffectAuthorizer: paidEffectAuthorizer{key: custodyKey},
		OwnerID: "owner:test", AgentID: buyerAgent, NetworkGlobalID: -3, ActionNanoTOS: 100_000_000,
		PollInterval: 10 * time.Millisecond, FinalityTimeout: time.Second, Now: func() time.Time { return now }}
	paidBuyer, err := NewPaidDemandBuyer(config)
	if err != nil {
		t.Fatal(err)
	}
	return paidDemandBuyerFixture{buyer: paidBuyer, config: config, input: PaidDemandPurchaseInput{Agreement: agreement,
		ProviderOffer: offer, Proposal: base.input.Proposal, ManifestJSON: base.input.ManifestJSON,
		EscrowTerms: base.input.EscrowTerms, ExecutionSignerEd25519: base.input.ExecutionSignerEd25519,
		TransportBinding: base.input.TransportBinding, ExecutionDeadlineUnix: uint64(now.Add(90 * time.Minute).Unix())},
		resolver: resolver, deployer: deployer, actions: actions, now: now}
}

func paidTestDigest(pair string) string { return "sha256:" + strings.Repeat(pair, 32) }

func installPaidEscrow(t *testing.T, fixture paidDemandBuyerFixture, purchase *PreparedPaidDemandPurchase) {
	t.Helper()
	state, err := nativecore.DecodeEscrowDataV2(purchase.Escrow.Data, fixture.buyer.base.network)
	if err != nil {
		t.Fatal(err)
	}
	fixture.resolver.state = &toschain.FinalizedEscrowV2{State: state,
		Reference:   &nativev1.ChainReference{Account: purchase.Escrow.Address, ContractCodeHash: purchase.Escrow.CodeHash, FinalizedCheckpoint: 12},
		FinalizedAt: fixture.now}
}
