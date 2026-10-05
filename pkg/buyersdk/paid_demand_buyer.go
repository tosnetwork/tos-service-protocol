package buyersdk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/paiddemand"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type PaidDemandEscrowResolver interface {
	ResolveFinalizedV2(context.Context, string) (*toschain.FinalizedEscrowV2, bool, error)
}

type CustodyEffectRequest struct {
	ActionKind          string
	SemanticFields      map[string]commerce.SemanticValue
	CanonicalRequest    []byte
	AgreementDigest     string
	ObligationID        string
	SourceAccount       string
	NetworkID           string
	NetworkGlobalID     int32
	Destination         string
	AmountNanoTOS       uint64
	BodyHash            string
	StateInitHashOrZero string
	ExpiresAtUnix       uint64
}

type CustodyEffectAuthorizer interface {
	AuthorizeCustodyEffect(context.Context, CustodyEffectRequest) (commerce.CustodyEffectAuthorization, error)
}

type PaidDemandBuyerConfig struct {
	NativeClient           NativeClient
	AssetResolver          AssetResolver
	Network                *nativev1.NetworkDomain
	RegistryCodeHash       string
	BuyerAddress           string
	AssetWalletCode        *cell.Cell
	BudgetLimits           BudgetLimits
	EscrowResolver         PaidDemandEscrowResolver
	ProviderOfferResolver  commerce.ProviderOfferKeyResolver
	EscrowCode             *cell.Cell
	Deployer               PaidDemandEscrowDeployer
	ActionSender           WalletActionSender
	EffectAuthorizer       CustodyEffectAuthorizer
	OwnerID                string
	AgentID                string
	CallerID               string
	NetworkGlobalID        int32
	ActionNanoTOS          uint64
	ActionAuthorizationTTL time.Duration
	PollInterval           time.Duration
	FinalityTimeout        time.Duration
	Now                    func() time.Time
}

type PaidDemandBuyer struct {
	base                   *buyerBase
	escrowResolver         PaidDemandEscrowResolver
	offerResolver          commerce.ProviderOfferKeyResolver
	escrowCode             *cell.Cell
	deployer               PaidDemandEscrowDeployer
	actionSender           WalletActionSender
	authorizer             CustodyEffectAuthorizer
	ownerID, agentID       string
	networkGlobalID        int32
	actionNanoTOS          uint64
	actionAuthorizationTTL time.Duration
	pollInterval           time.Duration
	finalityTimeout        time.Duration
	now                    func() time.Time
}

type PaidDemandPurchaseInput struct {
	Agreement     commerce.AgentAgreementBody
	ProviderOffer commerce.SignedProviderOffer
	Proposal      *nativev1.QuoteProposalV1
	// ManifestCanonical is the preferred business-neutral execution manifest.
	// ManifestJSON/ManifestCBOR retain compatibility with the legacy software
	// work profile and must never be supplied together with it.
	ManifestCanonical      []byte
	ManifestJSON           []byte
	ManifestCBOR           []byte
	EscrowTerms            nativecore.EscrowTermsV1
	ExecutionSignerEd25519 []byte
	TransportBinding       nativecore.TransportBindingV1
	ExecutionDeadlineUnix  uint64
}

type PreparedPaidDemandPurchase struct {
	Agreement           commerce.AgentAgreementBody
	ProviderOffer       commerce.SignedProviderOffer
	Proposal            *nativev1.QuoteProposalV1
	ManifestCBOR        []byte
	ManifestDigest      string
	AgreementDigest     string
	QuoteCommitment     string
	QuoteBOCBase64      string
	Escrow              nativecore.EscrowIdentityV2
	AssetMasterAddress  string
	BuyerWalletAddress  string
	AmountAtomic        string
	PaymentObligationID string
}

func NewPaidDemandBuyer(config PaidDemandBuyerConfig) (*PaidDemandBuyer, error) {
	if config.NativeClient == nil || config.AssetResolver == nil || config.Network == nil ||
		config.RegistryCodeHash == "" || config.BuyerAddress == "" || config.AssetWalletCode == nil ||
		!config.BudgetLimits.permits("1") || config.CallerID == "" || len(config.CallerID) > 256 {
		return nil, errors.New("invalid Paid Demand verifier configuration")
	}
	base := &buyerBase{nativeClient: config.NativeClient, assetResolver: config.AssetResolver,
		limits: config.BudgetLimits, network: proto.Clone(config.Network).(*nativev1.NetworkDomain),
		registryCodeHash: config.RegistryCodeHash, buyerAddress: config.BuyerAddress,
		walletCode: config.AssetWalletCode, callerID: config.CallerID}
	if config.EscrowResolver == nil || config.ProviderOfferResolver == nil ||
		config.EscrowCode == nil || config.Deployer == nil || config.ActionSender == nil || config.EffectAuthorizer == nil ||
		config.OwnerID == "" || config.AgentID == "" || config.NetworkGlobalID == 0 {
		return nil, errors.New("invalid Paid Demand buyer configuration")
	}
	if err := nativecore.RequireEscrowV2Code(config.EscrowCode); err != nil {
		return nil, err
	}
	if config.ActionNanoTOS == 0 {
		config.ActionNanoTOS = 100_000_000
	}
	if config.ActionNanoTOS > 1_000_000_000 {
		return nil, errors.New("Paid Demand action fee budget is invalid")
	}
	if config.ActionAuthorizationTTL == 0 {
		config.ActionAuthorizationTTL = 2 * time.Minute
	}
	if config.ActionAuthorizationTTL < 10*time.Second || config.ActionAuthorizationTTL > 10*time.Minute {
		return nil, errors.New("Paid Demand action authorization TTL is invalid")
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.FinalityTimeout == 0 {
		config.FinalityTimeout = 5 * time.Minute
	}
	if config.PollInterval < 10*time.Millisecond || config.FinalityTimeout <= config.PollInterval || config.FinalityTimeout > time.Hour {
		return nil, errors.New("Paid Demand finality policy is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	base.pollInterval, base.finalityTimeout, base.now = config.PollInterval, config.FinalityTimeout, config.Now
	return &PaidDemandBuyer{base: base, escrowResolver: config.EscrowResolver,
		offerResolver: config.ProviderOfferResolver, escrowCode: config.EscrowCode,
		deployer: config.Deployer, actionSender: config.ActionSender, authorizer: config.EffectAuthorizer,
		ownerID: config.OwnerID, agentID: config.AgentID, networkGlobalID: config.NetworkGlobalID,
		actionNanoTOS: config.ActionNanoTOS, pollInterval: config.PollInterval,
		actionAuthorizationTTL: config.ActionAuthorizationTTL,
		finalityTimeout:        config.FinalityTimeout, now: config.Now}, nil
}

// Deploy creates only the deterministic pending-acceptance account. It cannot
// satisfy a buyer authorization predicate or receive stablecoin until the
// separately custody-authorized accept transition has finalized.
func (buyer *PaidDemandBuyer) Deploy(ctx context.Context,
	purchase *PreparedPaidDemandPurchase) (*toschain.FinalizedEscrowV2, error) {
	if buyer == nil || ctx == nil || purchase == nil {
		return nil, errors.New("invalid Paid Demand deployment request")
	}
	if current, found, err := buyer.escrowResolver.ResolveFinalizedV2(ctx, purchase.Escrow.Address); err != nil {
		return nil, err
	} else if found {
		if current == nil || current.State == nil || current.State.Status != nativecore.EscrowStatusPendingAcceptanceV2 ||
			current.State.QuoteCommitment != purchase.QuoteCommitment {
			return nil, errors.New("existing Paid Demand account conflicts with reviewed purchase")
		}
		return current, nil
	}
	prepared, err := buyer.deployer.PreparePaidDemandDeployment(ctx, purchase)
	if err != nil {
		return nil, err
	}
	if err := buyer.deployer.BroadcastPaidDemandDeployment(ctx, prepared); err != nil {
		if current, waitErr := buyer.waitForStatus(ctx, purchase, nativecore.EscrowStatusPendingAcceptanceV2); waitErr == nil {
			return current, nil
		}
		return nil, err
	}
	return buyer.waitForStatus(ctx, purchase, nativecore.EscrowStatusPendingAcceptanceV2)
}

func (buyer *PaidDemandBuyer) PreparePurchase(ctx context.Context,
	input PaidDemandPurchaseInput) (*PreparedPaidDemandPurchase, error) {
	if buyer == nil || ctx == nil || input.Proposal == nil ||
		manifestInputCount(input) != 1 || len(input.ManifestCanonical) > 1<<20 ||
		len(input.ManifestJSON) > 1<<20 || len(input.ManifestCBOR) > 1<<20 {
		return nil, errors.New("invalid Paid Demand purchase input")
	}
	now := buyer.now().UTC()
	if now.Unix() < 0 || input.EscrowTerms.BuyerAddress != buyer.base.buyerAddress ||
		input.ProviderOffer.Binding.BuyerAgentID != buyer.agentID ||
		input.ProviderOffer.Binding.AcceptByUnix <= uint64(now.Unix()) ||
		input.EscrowTerms.FundingDeadline <= uint64(now.Unix()) {
		return nil, errors.New("Paid Demand buyer identity or deadline is invalid")
	}
	manifestCBOR, manifestDigest, err := canonicalPaidDemandManifest(input)
	if err != nil || manifestDigest != input.Proposal.ManifestDigest {
		return nil, errors.New("manifest does not match Paid Demand Quote")
	}
	if err := buyer.base.validateCapability(ctx, input.Proposal); err != nil {
		return nil, err
	}
	asset, err := buyer.base.resolveAsset(ctx, input.Proposal)
	if err != nil {
		return nil, err
	}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(input.ExecutionSignerEd25519)
	if err != nil {
		return nil, err
	}
	quote, commitment, err := paiddemand.BuildAcceptedQuote(paiddemand.QuoteBuildInput{Agreement: input.Agreement,
		ProviderOffer: input.ProviderOffer, ProviderOfferResolver: buyer.offerResolver, Network: buyer.base.network,
		Proposal: input.Proposal, ExecutionSignerAuthorization: "sha256:" + hex.EncodeToString(authorization.Hash()),
		EscrowTerms: input.EscrowTerms, ExecutionDeadlineUnix: input.ExecutionDeadlineUnix, Now: now})
	if err != nil {
		return nil, err
	}
	escrow, err := nativecore.BuildEscrowStateInitV2(0, buyer.escrowCode, nativecore.EscrowInitV2{
		Network: buyer.base.network, AcceptedQuote: quote, Terms: input.EscrowTerms,
		ExecutionSignerEd25519: append([]byte(nil), input.ExecutionSignerEd25519...),
		TransportBinding:       input.TransportBinding, AssetMasterAddress: asset.MasterAddress,
		AssetWalletCode: buyer.base.walletCode})
	if err != nil || escrow.QuoteCommitment != commitment {
		return nil, errors.New("build canonical Paid Demand escrow")
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(input.Agreement)
	if len(input.ManifestCanonical) != 0 {
		manifest, decodeErr := paiddemand.DecodeCanonicalExecutionManifest(manifestCBOR)
		if decodeErr != nil || manifest.AgreementBodyDigest != agreementDigest ||
			!manifestMatchesPaidDemandWork(input.Agreement, input.ProviderOffer.Binding, manifest) {
			return nil, errors.New("generic execution manifest does not match the bound Agreement work")
		}
	}
	paymentObligation := ""
	for _, obligation := range input.Agreement.Obligations {
		if obligation.Amount != nil && obligation.ObligorAgentID == buyer.agentID && obligation.SettlementAdapterURI == paiddemand.SettlementAdapterURI {
			if paymentObligation != "" {
				return nil, errors.New("Paid Demand purchase has multiple buyer payment obligations")
			}
			paymentObligation = obligation.ObligationID
		}
	}
	if paymentObligation == "" {
		return nil, errors.New("Paid Demand buyer payment obligation is missing")
	}
	return &PreparedPaidDemandPurchase{Agreement: input.Agreement, ProviderOffer: input.ProviderOffer,
		Proposal: proto.Clone(input.Proposal).(*nativev1.QuoteProposalV1), ManifestCBOR: append([]byte(nil), manifestCBOR...),
		ManifestDigest: manifestDigest, AgreementDigest: agreementDigest, QuoteCommitment: commitment,
		QuoteBOCBase64: base64.StdEncoding.EncodeToString(quote.ToBOC()), Escrow: escrow,
		AssetMasterAddress: asset.MasterAddress, BuyerWalletAddress: asset.BuyerWalletAddress,
		AmountAtomic: input.Proposal.MaximumPrice.AtomicAmount, PaymentObligationID: paymentObligation}, nil
}

func manifestInputCount(input PaidDemandPurchaseInput) int {
	count := 0
	for _, value := range [][]byte{input.ManifestCanonical, input.ManifestJSON, input.ManifestCBOR} {
		if len(value) != 0 {
			count++
		}
	}
	return count
}

func canonicalPaidDemandManifest(input PaidDemandPurchaseInput) ([]byte, string, error) {
	if len(input.ManifestCanonical) != 0 {
		manifest, err := paiddemand.DecodeCanonicalExecutionManifest(input.ManifestCanonical)
		if err != nil {
			return nil, "", err
		}
		return paiddemand.CanonicalExecutionManifest(manifest)
	}
	var manifest nativecore.SoftwareWorkManifestV1
	var err error
	if len(input.ManifestCBOR) != 0 {
		manifest, err = nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(input.ManifestCBOR)
	} else {
		manifest, err = nativecore.DecodeSoftwareWorkManifestJSON(input.ManifestJSON)
	}
	if err != nil {
		return nil, "", fmt.Errorf("decode legacy Paid Demand manifest: %w", err)
	}
	return nativecore.CanonicalSoftwareWorkManifest(manifest)
}

func manifestMatchesPaidDemandWork(agreement commerce.AgentAgreementBody, binding commerce.PaidDemandQuoteBindingBody,
	manifest paiddemand.ExecutionManifestV1) bool {
	bound := make(map[string]bool, len(binding.AgreementObligationIDs))
	for _, id := range binding.AgreementObligationIDs {
		bound[id] = true
	}
	want := make([]string, 0)
	for _, obligation := range agreement.Obligations {
		if bound[obligation.ObligationID] && obligation.Amount == nil &&
			obligation.ObligorAgentID == binding.ProviderAgentID && obligation.BeneficiaryAgentID == binding.BuyerAgentID {
			want = append(want, obligation.ObligationID)
		}
	}
	sort.Strings(want)
	return slices.Equal(want, manifest.WorkObligationIDs)
}

func (buyer *PaidDemandBuyer) Accept(ctx context.Context,
	purchase *PreparedPaidDemandPurchase) (*toschain.FinalizedEscrowV2, error) {
	resolved, err := buyer.resolveExact(ctx, purchase)
	if err != nil {
		return nil, err
	}
	if paidDemandStatusSatisfies(resolved.State.Status, nativecore.EscrowStatusAwaitingFundingV2) {
		return resolved, nil
	}
	if resolved.State.Status != nativecore.EscrowStatusPendingAcceptanceV2 ||
		resolved.State.AcceptByUnix <= uint64(buyer.now().Unix()) {
		return nil, errors.New("Paid Demand escrow cannot be accepted")
	}
	offerDigest, err := commerce.ProviderOfferDigest(purchase.ProviderOffer)
	if err != nil || offerDigest != resolved.State.ProviderOfferDigest {
		return nil, errors.New("Paid Demand Provider Offer changed before acceptance")
	}
	queryID := deterministicQueryID("accept", purchase.QuoteCommitment)
	body, err := nativecore.BuildPaidDemandAcceptBodyV2(queryID, purchase.QuoteCommitment, offerDigest)
	if err != nil {
		return nil, err
	}
	request := escrowEffectRequest{SchemaVersion: 1, TransitionKind: "accept", AgreementDigest: purchase.AgreementDigest,
		ObligationID: purchase.PaymentObligationID, EscrowAddress: purchase.Escrow.Address,
		QuoteCommitment: purchase.QuoteCommitment, ExpectedStatus: nativecore.EscrowStatusPendingAcceptanceV2,
		BodyHash: cellDigestText(body), AmountNanoTOS: buyer.actionNanoTOS}
	if err := buyer.submitEffect(ctx, purchase, request, body, resolved.State.AcceptByUnix); err != nil {
		// Broadcast errors are ambiguous. Query the same deterministic state;
		// never allocate or submit another semantic acceptance action.
		if current, resolveErr := buyer.waitForStatus(ctx, purchase, nativecore.EscrowStatusAwaitingFundingV2); resolveErr == nil {
			return current, nil
		}
		return nil, err
	}
	return buyer.waitForStatus(ctx, purchase, nativecore.EscrowStatusAwaitingFundingV2)
}

func (buyer *PaidDemandBuyer) Fund(ctx context.Context,
	purchase *PreparedPaidDemandPurchase) (*toschain.FinalizedEscrowV2, error) {
	resolved, err := buyer.resolveExact(ctx, purchase)
	if err != nil {
		return nil, err
	}
	if paidDemandStatusSatisfies(resolved.State.Status, nativecore.EscrowStatusFundedV2) {
		return resolved, nil
	}
	if resolved.State.Status != nativecore.EscrowStatusAwaitingFundingV2 ||
		resolved.State.FundingDeadline < uint64(buyer.now().Unix()) {
		return nil, errors.New("Paid Demand escrow is not accepted and fundable")
	}
	queryID := deterministicQueryID("fund", purchase.QuoteCommitment)
	funding := FundingIntent{NetworkID: buyer.base.network.NetworkId, EscrowAddress: purchase.Escrow.Address,
		QuoteCommitment: purchase.QuoteCommitment, Asset: proto.Clone(purchase.Proposal.MaximumPrice.Asset).(*nativev1.TOSAssetIdentityV1),
		BuyerAddress: buyer.base.buyerAddress, BuyerWallet: purchase.BuyerWalletAddress,
		AmountAtomic: purchase.AmountAtomic, QueryID: queryID}
	body, err := BuildStablecoinFundingBody(funding, buyer.actionNanoTOS/2)
	if err != nil {
		return nil, err
	}
	request := escrowEffectRequest{SchemaVersion: 1, TransitionKind: "fund", AgreementDigest: purchase.AgreementDigest,
		ObligationID: purchase.PaymentObligationID, EscrowAddress: purchase.Escrow.Address,
		QuoteCommitment: purchase.QuoteCommitment, ExpectedStatus: nativecore.EscrowStatusAwaitingFundingV2,
		BodyHash: cellDigestText(body), AmountNanoTOS: buyer.actionNanoTOS, Target: purchase.BuyerWalletAddress}
	if err := buyer.submitEffect(ctx, purchase, request, body, resolved.State.FundingDeadline); err != nil {
		if current, resolveErr := buyer.waitForStatus(ctx, purchase, nativecore.EscrowStatusFundedV2); resolveErr == nil {
			return current, nil
		}
		return nil, err
	}
	return buyer.waitForStatus(ctx, purchase, nativecore.EscrowStatusFundedV2)
}

// BuyerAcceptEvidence converts an independently finalized accepted escrow into
// the Agreement profile evidence that may be sent to the Provider. The
// Provider still re-queries its own finalized quorum when verifying it.
func (buyer *PaidDemandBuyer) BuyerAcceptEvidence(purchase *PreparedPaidDemandPurchase,
	accepted *toschain.FinalizedEscrowV2) (commerce.AgreementAuthorizationEvidence, error) {
	if buyer == nil || purchase == nil || accepted == nil {
		return commerce.AgreementAuthorizationEvidence{}, errors.New("Paid Demand buyer evidence input is incomplete")
	}
	nativeEvidence, reference, err := paiddemand.BuildBuyerAcceptNativeEvidence(purchase.ProviderOffer.Binding,
		accepted, buyer.base.network, buyer.offerResolver)
	if err != nil {
		return commerce.AgreementAuthorizationEvidence{}, err
	}
	finalizedAt := accepted.FinalizedAt.UTC()
	if finalizedAt.IsZero() {
		finalizedAt = buyer.now().UTC()
	}
	subject := commerce.AgreementAuthoritySubject{SubjectKind: "wallet", SubjectNamespace: "tos.wallet",
		SubjectIdentifier: buyer.base.buyerAddress, RepresentedAgentID: buyer.agentID}
	return commerce.PaidDemandEvidenceFromBinding(purchase.Agreement, subject, purchase.ProviderOffer.Binding,
		"buyer_accept", nativeEvidence, uint64(finalizedAt.Unix()), reference)
}

type escrowEffectRequest struct {
	SchemaVersion   uint16 `json:"schema_version"`
	TransitionKind  string `json:"transition_kind"`
	AgreementDigest string `json:"agreement_digest"`
	ObligationID    string `json:"obligation_id"`
	EscrowAddress   string `json:"escrow_address"`
	QuoteCommitment string `json:"quote_commitment"`
	ExpectedStatus  uint8  `json:"expected_status"`
	BodyHash        string `json:"body_hash"`
	AmountNanoTOS   uint64 `json:"amount_nanotos"`
	Target          string `json:"target,omitempty"`
}

func (buyer *PaidDemandBuyer) submitEffect(ctx context.Context, purchase *PreparedPaidDemandPurchase,
	request escrowEffectRequest, body *cell.Cell, expires uint64) error {
	canonical, err := codec.Marshal(request)
	if err != nil {
		return err
	}
	expectedState, err := sha256Structured("tos.escrow.expected-state.v1", struct {
		Quote  string `json:"quote"`
		Status uint8  `json:"status"`
	}{purchase.QuoteCommitment, request.ExpectedStatus})
	if err != nil {
		return err
	}
	quoteSemantic := "sha256:" + strings.TrimPrefix(purchase.QuoteCommitment, "tvm-cell-sha256:")
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(buyer.ownerID), "agent_id": commerce.ID(buyer.agentID),
		"quote_commitment": commerce.Digest32(quoteSemantic), "escrow_account_id": commerce.ID(purchase.Escrow.Address),
		"transition_kind": commerce.Kind(request.TransitionKind), "expected_state_digest": commerce.Digest32(expectedState)}
	stableID, _, err := commerce.DeriveStableActionID("escrow.transition", fields)
	if err != nil {
		return err
	}
	target := purchase.Escrow.Address
	if request.Target != "" {
		target = request.Target
	}
	actionExpiry := minU64(expires, uint64(buyer.now().Add(buyer.actionAuthorizationTTL).Unix()))
	authorization, err := buyer.authorizer.AuthorizeCustodyEffect(ctx, CustodyEffectRequest{ActionKind: "escrow." + request.TransitionKind,
		SemanticFields: fields, CanonicalRequest: canonical, AgreementDigest: purchase.AgreementDigest,
		ObligationID: purchase.PaymentObligationID, SourceAccount: buyer.base.buyerAddress,
		NetworkID: buyer.base.network.NetworkId, NetworkGlobalID: buyer.networkGlobalID,
		Destination: target, AmountNanoTOS: request.AmountNanoTOS, BodyHash: request.BodyHash,
		StateInitHashOrZero: "sha256:" + strings.Repeat("0", 64), ExpiresAtUnix: actionExpiry})
	if err != nil || authorization.StableActionID != stableID {
		return errors.New("economic authority did not authorize the exact escrow transition")
	}
	intent := WalletActionIntent{StableActionID: stableID, NetworkID: buyer.base.network.NetworkId,
		TransitionKind: authorization.ActionKind, Destination: target, AmountNanoTOS: request.AmountNanoTOS,
		BodyBOCBase64: base64.StdEncoding.EncodeToString(body.ToBOCWithOptions(cell.BOCSerializeOptions{})), BodyHash: request.BodyHash,
		ValidUntilUnix: uint32(minU64(actionExpiry, uint64(^uint32(0)))), Authorization: authorization}
	prepared, err := buyer.actionSender.PrepareWalletAction(ctx, intent)
	if err != nil {
		return err
	}
	if err := buyer.actionSender.BroadcastWalletAction(ctx, prepared); err != nil {
		return err
	}
	if resolver, ok := buyer.actionSender.(WalletActionResolver); ok {
		return resolver.ResolveWalletAction(ctx, prepared)
	}
	return nil
}

func (buyer *PaidDemandBuyer) resolveExact(ctx context.Context,
	purchase *PreparedPaidDemandPurchase) (*toschain.FinalizedEscrowV2, error) {
	if purchase == nil || purchase.Proposal == nil || purchase.Escrow.Data == nil {
		return nil, errors.New("Paid Demand purchase is incomplete")
	}
	manifest := sha256.Sum256(purchase.ManifestCBOR)
	if "sha256:"+hex.EncodeToString(manifest[:]) != purchase.ManifestDigest ||
		purchase.Proposal.ManifestDigest != purchase.ManifestDigest || purchase.QuoteCommitment != purchase.Escrow.QuoteCommitment {
		return nil, errors.New("Paid Demand purchase changed after review")
	}
	resolved, found, err := buyer.escrowResolver.ResolveFinalizedV2(ctx, purchase.Escrow.Address)
	if err != nil {
		return nil, err
	}
	if !found || resolved == nil || resolved.State == nil || resolved.Reference == nil ||
		resolved.Reference.FinalizedCheckpoint == 0 || resolved.Reference.ContractCodeHash != nativecore.EscrowV2CodeHash ||
		resolved.Reference.ContractCodeHash != purchase.Escrow.CodeHash ||
		resolved.State.QuoteCommitment != purchase.QuoteCommitment || resolved.State.BuyerAddress != buyer.base.buyerAddress ||
		resolved.State.AssetMasterAddress != purchase.AssetMasterAddress ||
		resolved.State.AssetWalletCodeHash != purchase.Proposal.MaximumPrice.Asset.WalletCodeHash {
		return nil, errors.New("finalized Paid Demand escrow differs from reviewed purchase")
	}
	agreementDigest, err := commerce.AgreementBodyDigest(purchase.Agreement)
	if err != nil || agreementDigest != purchase.AgreementDigest {
		return nil, errors.New("Paid Demand Agreement changed after review")
	}
	verificationTime := buyer.now().UTC()
	if resolved.State.Status != nativecore.EscrowStatusPendingAcceptanceV2 {
		if resolved.State.AcceptedAtUnix == 0 || resolved.State.AcceptedAtUnix > resolved.State.AcceptByUnix {
			return nil, errors.New("Paid Demand acceptance time is invalid")
		}
		verificationTime = time.Unix(int64(resolved.State.AcceptedAtUnix), 0).UTC()
	}
	terms := nativecore.EscrowTermsV1{BuyerAddress: resolved.State.BuyerAddress,
		ProviderAddress: resolved.State.ProviderAddress, FundingDeadline: resolved.State.FundingDeadline,
		RefundAvailableAt: resolved.State.RefundAvailableAt}
	_, recoveredOffer, err := paiddemand.VerifyAcceptedQuote(resolved.State.AcceptedQuote, purchase.Agreement,
		buyer.base.network, terms, buyer.offerResolver, verificationTime)
	if err != nil {
		return nil, errors.New("finalized Paid Demand Quote no longer verifies against Agreement")
	}
	recoveredOfferDigest, err := commerce.ProviderOfferDigest(recoveredOffer)
	purchaseOfferDigest, purchaseErr := commerce.ProviderOfferDigest(purchase.ProviderOffer)
	if err != nil || purchaseErr != nil || recoveredOfferDigest != purchaseOfferDigest {
		return nil, errors.New("finalized Paid Demand Provider Offer differs from reviewed purchase")
	}
	if resolved.State.Status == nativecore.EscrowStatusFundedV2 && resolved.State.FundedAtomicAmount != purchase.AmountAtomic {
		return nil, errors.New("Paid Demand funding differs from Agreement")
	}
	return resolved, nil
}

func (buyer *PaidDemandBuyer) waitForStatus(ctx context.Context, purchase *PreparedPaidDemandPurchase,
	minimum uint8) (*toschain.FinalizedEscrowV2, error) {
	wait, cancel := context.WithTimeout(ctx, buyer.finalityTimeout)
	defer cancel()
	ticker := time.NewTicker(buyer.pollInterval)
	defer ticker.Stop()
	for {
		resolved, err := buyer.resolveExact(wait, purchase)
		if err == nil && paidDemandStatusSatisfies(resolved.State.Status, minimum) {
			return resolved, nil
		}
		select {
		case <-wait.Done():
			if err != nil {
				return nil, err
			}
			return nil, wait.Err()
		case <-ticker.C:
		}
	}
}

func cellDigestText(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}

func deterministicQueryID(kind, quote string) uint64 {
	digest := sha256.Sum256([]byte("tos.paid-demand." + kind + ".query.v1\x00" + quote))
	value := uint64(0)
	for _, octet := range digest[:8] {
		value = value<<8 | uint64(octet)
	}
	if value == 0 {
		return 1
	}
	return value
}

func sha256Structured(domain string, value any) (string, error) {
	canonical, err := codec.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(append([]byte(nil), []byte(domain+"\x00")...), canonical...))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func paidDemandStatusSatisfies(actual, expected uint8) bool {
	switch expected {
	case nativecore.EscrowStatusPendingAcceptanceV2:
		return actual == nativecore.EscrowStatusPendingAcceptanceV2
	case nativecore.EscrowStatusAwaitingFundingV2:
		return actual == nativecore.EscrowStatusAwaitingFundingV2 || actual == nativecore.EscrowStatusFundedV2 ||
			actual == nativecore.EscrowStatusReleasePendingV2 || actual == nativecore.EscrowStatusRefundPendingV2
	case nativecore.EscrowStatusFundedV2:
		return actual == nativecore.EscrowStatusFundedV2 || actual == nativecore.EscrowStatusReleasePendingV2 ||
			actual == nativecore.EscrowStatusRefundPendingV2
	default:
		return false
	}
}

func minU64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}
