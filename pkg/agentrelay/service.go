package agentrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type QuotePolicy interface {
	Quote(context.Context, RelayServiceProfile, SignedRelayQuoteRequest, time.Time) (ProviderRelayQuoteBody, error)
}

// SponsorshipRecoveryHandle binds the exact provider-funded payment action to
// an opaque processor journal token. The two digests are safe to expose in
// evidence; OpaqueToken is provider-private protected state.
type SponsorshipRecoveryHandle struct {
	AgreementPaymentRequestDigest string
	StableActionID                string
	ExactRequestDigest            string
	// ValidUntilUnix is the expiry embedded in the exact provider-funded
	// transaction. A different provider cannot sponsor again until finalized
	// evidence proves this transaction expired without inclusion.
	ValidUntilUnix uint64
	OpaqueToken    []byte
}

type SponsorshipResolutionStatus string

const (
	SponsorshipResolutionUnknown          SponsorshipResolutionStatus = "unknown"
	SponsorshipResolutionObservedUnproven SponsorshipResolutionStatus = "observed_unproven"
	// SponsorshipResolutionCorroboratedTerminal is terminal only under the
	// exact lower-assurance evidence predicate selected by the owner. It makes
	// no validator-finality or decentralized-resilience claim.
	SponsorshipResolutionCorroboratedTerminal SponsorshipResolutionStatus = "corroborated_terminal"
	// SponsorshipResolutionCorroboratedAbsent is terminal only under the
	// explicitly selected lower-assurance absence predicates. It must never be
	// consumed as validator finality.
	SponsorshipResolutionCorroboratedAbsent SponsorshipResolutionStatus = "corroborated_absent"
	SponsorshipResolutionFinalized          SponsorshipResolutionStatus = "finalized"
	SponsorshipResolutionFinalizedAbsent    SponsorshipResolutionStatus = "finalized_absent"
)

func sponsorshipResolutionHasTransfer(status SponsorshipResolutionStatus) bool {
	return status == SponsorshipResolutionCorroboratedTerminal ||
		status == SponsorshipResolutionFinalized
}

func sponsorshipOnlyOutcomeForEvidence(evidence *RelaySponsorshipTransactionEvidence) TerminalOutcome {
	if evidence != nil && evidence.TerminalEvidenceClass == SponsorshipTerminalClientCorroborated {
		return OutcomeCorroboratedSponsorshipOnly
	}
	return OutcomeFinalizedSponsorshipOnly
}

func relayOutcomeForSelectedEvidence(outcome TerminalOutcome, relayClass TerminalEvidenceClass,
	evidence *RelaySponsorshipTransactionEvidence) TerminalOutcome {
	lower := relayClass == RelayTerminalProviderCorroborated || evidence != nil &&
		evidence.TerminalEvidenceClass == SponsorshipTerminalClientCorroborated
	if !lower {
		return outcome
	}
	switch outcome {
	case OutcomeFinalizedSuccess:
		return OutcomeCorroboratedSuccess
	case OutcomeFinalizedExpired:
		return OutcomeCorroboratedExpired
	case OutcomeFinalizedAbsent:
		return OutcomeCorroboratedAbsent
	case OutcomeFinalizedInvalidated:
		return OutcomeCorroboratedInvalidated
	case OutcomeFinalizedRelayOnly:
		return OutcomeCorroboratedRelayOnly
	default:
		return outcome
	}
}

func relayOnlyOutcomeForAbsence(request RelayExecutionRequest) TerminalOutcome {
	if validRelayAbsenceOutcomeAssurance(request, OutcomeFinalizedRelayOnly, true, false, nil) {
		return OutcomeFinalizedRelayOnly
	}
	return OutcomeCorroboratedRelayOnly
}

func sponsorshipOnlyOutcomeForTransactionAbsence(request RelayExecutionRequest,
	evidence *RelaySponsorshipTransactionEvidence) TerminalOutcome {
	if validRelayAbsenceOutcomeAssurance(request, OutcomeFinalizedSponsorshipOnly, false, true, evidence) {
		return OutcomeFinalizedSponsorshipOnly
	}
	return OutcomeCorroboratedSponsorshipOnly
}

// SponsorshipResolution is closed and profile-qualified. FinalizedAbsent uses
// two explicitly typed proof sets so absence of the provider top-up can never
// be confused with absence of the client transaction.
type SponsorshipResolution struct {
	Status                         SponsorshipResolutionStatus
	TransferReference              string
	EvidenceRefs                   []string
	AbsenceOutcome                 TerminalOutcome
	SponsorshipAbsenceObservations []RelayAbsenceObservationReference
	TransactionAbsenceObservations []RelayAbsenceObservationReference
	AbsenceProofBundleDigest       string
	AbsenceProofBundle             []byte
	CreditObservation              *RelaySponsorshipCreditObservation
	TransactionEvidence            *RelaySponsorshipTransactionEvidence
}

// SponsorshipProcessor executes the provider's separate, Agreement-bound
// payment.direct obligation. PrepareRecovery must create no economic side
// effect; it returns an opaque token that durably identifies the exact payment
// journal entry. ResolveFinalized is strictly read-only and is therefore safe
// after the signed execution windows expire. Despite its legacy method name,
// EnsureFinalized may return ObservedUnproven only when the exact signed release
// profile selected that nonterminal threshold. It must be idempotent and query
// an ambiguous prior attempt before doing any new transfer. Before
// returning FinalizedAbsent, the processor must independently verify every
// referenced proof under the selected finality profile, including observer and
// operator-domain authority; the protocol layer then verifies that the typed
// references bind the exact actions, conclusions, profile, and checkpoint.
type SponsorshipProcessor interface {
	PrepareRecovery(context.Context, RelayExecutionRequest, agentcommerce.AgentAgreement,
		agentcommerce.AgreementObligation) (SponsorshipRecoveryHandle, error)
	EnsureFinalized(context.Context, RelayExecutionRequest, agentcommerce.AgentAgreement,
		agentcommerce.AgreementObligation, SponsorshipRecoveryHandle) (SponsorshipResolution, error)
	ResolveFinalized(context.Context, RelayExecutionRequest, SponsorshipRecoveryHandle) (SponsorshipResolution, error)
}

// CombinedRelayDualAbsenceResolver is an optional, no-chain-write aggregation
// seam used after a sponsorship-component tombstone already exists and the
// client transaction later becomes terminal-negative. It must re-query the
// exact frozen actions, preserve every sponsorship reference byte-for-byte,
// and return one dual proof bundle. It cannot create or replace sponsorship.
type CombinedRelayDualAbsenceResolver interface {
	ResolveRelayDualAbsence(context.Context, RelayExecutionRequest, SponsorshipRecoveryHandle,
		[]RelayAbsenceObservationReference, string, []byte) (SponsorshipResolution, error)
}

// CombinedRelayTransactionAbsenceResolver is the optional snapshot-bound
// producer used after the sponsorship transfer is durable but the client
// transaction reaches a terminal-negative checkpoint. The protected recovery
// handle identifies the immutable Provider snapshot and payment context; it
// cannot authorize another top-up because the journal already contains the
// successful sponsorship effect. The returned ChainResolution must contain a
// transaction-only proof bundle and no chain write or replacement transfer.
type CombinedRelayTransactionAbsenceResolver interface {
	ResolveRelayTransactionAbsence(context.Context, RelayExecutionRequest,
		SponsorshipRecoveryHandle, TerminalOutcome) (ChainResolution, error)
}

// SponsorshipCreditObservationVerifier enforces the exact owner-pinned RPC
// corroboration descriptor selected in the signed quote pair. Its threshold,
// members, operator domains, network, and history bounds are independent of
// validator FinalityProfile settings and can never produce terminal revenue.
type SponsorshipCreditObservationVerifier interface {
	VerifySponsorshipCreditObservation(context.Context, RelaySponsorshipCreditObservation,
		SponsorshipReleaseProfile) error
}

type BroadcastStatus string

const (
	BroadcastUnknown  BroadcastStatus = "unknown"
	BroadcastAccepted BroadcastStatus = "accepted"
)

type BroadcastResult struct {
	Status               BroadcastStatus
	TransactionReference string
}

type ChainResolution struct {
	State                  agentcommerce.ActionResolutionState
	TransactionReference   string
	EvidenceRefs           []string
	TerminalOutcome        TerminalOutcome
	SafeToRebroadcastExact bool
	// Component transaction absence is distinct from an ordinary negative
	// relay outcome. It is used only after sponsorship succeeded, and carries
	// the exact generic proof bundle independently re-queried by the client.
	TransactionAbsenceObservations []RelayAbsenceObservationReference
	AbsenceProofBundleDigest       string
	AbsenceProofBundle             []byte
}

// ExactTransactionBroadcaster never receives a signing key. SubmitExact must
// perform one write attempt only. A timeout or EOF after the attempt is
// BroadcastUnknown, not a reason to fail over implicitly.
type ExactTransactionBroadcaster interface {
	SubmitExact(context.Context, RelayExecutionRequest) (BroadcastResult, error)
	Resolve(context.Context, Record) (ChainResolution, error)
}

type FinalityEvidenceSource interface {
	Evidence(context.Context, Record) (RelayFinalityEvidenceBody, error)
}

// IndependentFinalityEvidenceSource advertises concrete proof capabilities
// for one selected mode/assurance readiness decision. It is deliberately not
// a global "production" certificate: readiness is recomputed from current
// owner-pinned capabilities for each exact pair.
type IndependentFinalityEvidenceSource interface {
	FinalityEvidenceSource
	SupportsRelayEvidenceCapability(RelayEvidenceCapability) bool
	// SupportsRelayDualAbsenceEvidence is required only for combined mode. A
	// source is not ready merely because it can prove the happy path: combined
	// mode must also distinguish expiry/non-inclusion of the provider-funded
	// action from expiry/non-inclusion of the client transaction. Sponsor-only
	// readiness requires only the sponsorship-component predicate below.
	SupportsRelayDualAbsenceEvidence(RelayEvidenceCapability) bool
	// Component support is separate from whole-negative support. Combined
	// execution has four reachable terminal quadrants and readiness must prove
	// both partial-negative paths before a quote is signed.
	SupportsRelaySponsorshipComponentAbsenceEvidence(RelayEvidenceCapability) bool
	SupportsRelayTransactionComponentAbsenceEvidence(RelayEvidenceCapability) bool
	HasRetrievableIndependentProofs() bool
	HasRollbackResistantCheckpoint() bool
	// HasRollbackResistantTerminalCommitment asserts that the exact evidence
	// digest and Provider signing-authority epoch are committed atomically with
	// terminal state in an append-only/monotonic authority domain. A bare
	// signer-supplied timestamp is backdatable after key compromise.
	HasRollbackResistantTerminalCommitment() bool
}

type ProviderService struct {
	Profile           RelayServiceProfile
	SigningKey        ed25519.PrivateKey
	AgentResolver     AgentKeyResolver
	FenceResolver     agentcommerce.CurrentWriterFenceResolver
	Inspector         TransactionInspector
	ActionBinder      ActionTransactionBinder
	AgreementVerifier agentcommerce.AgreementEvidenceVerifier
	// AdmissionAuthority is the owner-side authoritative receipt registry.
	// A locally valid signature is not enough for a first Provider admission:
	// the exact receipt must still be the Authority's current persisted answer
	// for this lookup. Already-admitted byte-identical retries drain exclusively
	// from the Provider journal and deliberately do not depend on this service.
	AdmissionAuthority             RelaySideEffectAdmissionAuthority
	QuotePolicy                    QuotePolicy
	Journal                        Journal
	Sponsorship                    SponsorshipProcessor
	SponsorshipObservationVerifier SponsorshipCreditObservationVerifier
	Broadcaster                    ExactTransactionBroadcaster
	EvidenceSource                 FinalityEvidenceSource
	Now                            func() time.Time
}

func (service ProviderService) Evidence(ctx context.Context, stableActionID, exactRequestDigest string) (SignedRelayFinalityEvidence, error) {
	if service.Journal == nil || len(service.SigningKey) != ed25519.PrivateKeySize {
		return SignedRelayFinalityEvidence{}, errors.New("relay evidence service is unavailable")
	}
	record, err := service.Journal.Resolve(stableActionID, exactRequestDigest)
	if err != nil {
		return SignedRelayFinalityEvidence{}, err
	}
	if record.State != agentcommerce.ActionTerminal || service.EvidenceSource == nil {
		return SignedRelayFinalityEvidence{}, errors.New("terminal relay evidence is unavailable")
	}
	body, err := service.EvidenceSource.Evidence(ctx, record)
	if err != nil {
		return SignedRelayFinalityEvidence{}, err
	}
	// The evidence source owns chain observation time. The Provider service owns
	// the signing-key epoch and overwrites it so a source cannot backdate key
	// authorization or accidentally couple it to historical chain time.
	body.SigningAuthorityAtUnix = uint64(service.now().Unix())
	if err := validateRelayFinalityEvidenceBody(body); err != nil {
		return SignedRelayFinalityEvidence{}, err
	}
	request := record.ExecutionRequest()
	quoted := request.QuoteRequest.Body
	if body.ProviderAgentID != service.Profile.ProviderAgentID || body.Network != quoted.Network ||
		body.AssuranceLevel != quoted.AssuranceLevel ||
		body.StableActionID != record.StableActionID ||
		body.ExactRequestDigest != record.ExactRequestDigest || body.RelayExecutionDigest != record.RelayExecutionDigest ||
		body.SignedTransactionDigest != quoted.SignedTransactionDigest ||
		body.SignedTransactionCellHash != quoted.SignedTransactionCellHash || body.SourceAccount != quoted.SourceAccount ||
		body.SourceSequence != quoted.SourceSequence ||
		!equalFinalityProfilePointers(body.RelayFinalityProfile, request.ProviderQuote.Body.RelayFinalityProfile) ||
		!equalFinalityProfilePointers(body.SponsorshipTerminalProfile,
			request.ProviderQuote.Body.SponsorshipTerminalProfile) ||
		body.Outcome != record.TerminalOutcome || body.SponsorshipTransferReference != record.SponsorshipTransferReference ||
		body.SponsorshipStableActionID != record.SponsorshipStableActionID ||
		body.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest ||
		body.SponsorshipValidUntilUnix != record.SponsorshipValidUntilUnix ||
		!equalStrings(relayAbsenceObservationReferenceDigests(body.SponsorshipAbsenceObservations),
			record.SponsorshipAbsenceObservationDigests) ||
		!equalStrings(relayAbsenceObservationReferenceDigests(body.TransactionAbsenceObservations),
			record.TransactionAbsenceObservationDigests) ||
		body.AbsenceProofBundleDigest != record.AbsenceProofBundleDigest ||
		!bytes.Equal(body.AbsenceProofBundle, record.AbsenceProofBundle) {
		return SignedRelayFinalityEvidence{}, errors.New("relay evidence source conflicts with the durable terminal record")
	}
	if body.SubmittedTransactionHash != "" && body.SubmittedTransactionHash != record.TransactionReference ||
		body.Outcome == OutcomeFinalizedSuccess && body.SubmittedTransactionHash != record.TransactionReference {
		return SignedRelayFinalityEvidence{}, errors.New("relay evidence substituted the durable submitted transaction reference")
	}
	hasSponsorshipAbsence := len(body.SponsorshipAbsenceObservations) != 0 ||
		len(body.TransactionAbsenceObservations) != 0
	if hasSponsorshipAbsence && !validSponsorshipAbsenceRecord(record) {
		return SignedRelayFinalityEvidence{}, errors.New("relay evidence source substituted sponsorship absence proof")
	}
	if quoted.Mode == ModeRelayExact && (body.SponsorshipStableActionID != "" ||
		body.SponsorshipExactRequestDigest != "" || body.SponsorshipValidUntilUnix != 0 ||
		body.SponsorshipTransferReference != "" ||
		hasSponsorshipAbsence || body.Outcome == OutcomeFinalizedSponsorshipOnly ||
		body.Outcome == OutcomeCorroboratedSponsorshipOnly) ||
		quoted.Mode == ModeSponsorAndRelay && body.SponsorshipTransferReference == "" && !hasSponsorshipAbsence ||
		quoted.Mode == ModeSponsorOnly && (body.SponsorshipTransferReference != "" &&
			body.Outcome != OutcomeFinalizedSponsorshipOnly &&
			body.Outcome != OutcomeCorroboratedSponsorshipOnly ||
			body.SponsorshipTransferReference == "" && !hasSponsorshipAbsence) {
		return SignedRelayFinalityEvidence{}, errors.New("relay evidence outcome conflicts with the selected service mode")
	}
	if body.SponsorshipTransactionEvidence != nil {
		sponsorship := *body.SponsorshipTransactionEvidence
		reserved := request.ProviderQuote.Body.ReservedSponsorship
		networkDigest, networkErr := NetworkDomainDigest(quoted.Network)
		if reserved == nil || networkErr != nil || sponsorship.AgreementPaymentRequestDigest != record.SponsorshipAgreementPaymentRequestDigest ||
			sponsorship.SponsorshipStableActionID != record.SponsorshipStableActionID ||
			sponsorship.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest ||
			sponsorship.ProviderSponsorValidUntilUnix != record.SponsorshipValidUntilUnix ||
			sponsorship.DestinationSourceAccount != quoted.SourceAccount || !sameAmount(sponsorship.Amount, *reserved) ||
			sponsorship.SubmittedTransactionHash != record.SponsorshipTransferReference ||
			!digestSetContainsAll(record.EvidenceRefs, sponsorship.ObservationDigests) ||
			quoted.AssuranceLevel == AssuranceAutonomousDecentralized &&
				(sponsorship.PortableProofLocator == "" ||
					sponsorship.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality ||
					!sponsorship.ValidatorAuthenticatedPortableProof) ||
			quoted.SponsorshipReleaseEvidenceClass == SponsorshipReleaseObservedUnproven &&
				(sponsorship.TerminalEvidenceClass != SponsorshipTerminalClientCorroborated ||
					sponsorship.ValidatorAuthenticatedPortableProof ||
					request.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
					request.ProviderQuote.Body.SponsorshipTerminalProfile.ProfileURI != ClientCorroboratedTerminalProfileURI) ||
			quoted.SponsorshipReleaseEvidenceClass == SponsorshipReleaseValidatorFinality &&
				(sponsorship.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality ||
					!sponsorship.ValidatorAuthenticatedPortableProof) {
			return SignedRelayFinalityEvidence{}, errors.New("relay sponsorship evidence conflicts with the exact payment, quote, or assurance level")
		}
		expected := RelaySponsorshipEvidenceContext{AgreementBodyDigest: request.AgreementBodyDigest,
			AgreementObligationID: request.SponsorshipObligationID,
			PayerAgentID:          quoted.ProviderAgentID, PayeeAgentID: quoted.RequesterAgentID,
			NetworkID: quoted.Network.NetworkID, NetworkDomainDigest: networkDigest,
			DestinationSourceAccount: quoted.SourceAccount, Amount: *reserved,
			MaximumExpiresAtUnix:          request.ExpiresAtUnix,
			SponsorshipStableActionID:     record.SponsorshipStableActionID,
			SponsorshipExactRequestDigest: record.SponsorshipExactRequestDigest}
		if err := VerifySponsorshipPaymentRequestForEvidence(sponsorship.AgreementPaymentRequest,
			sponsorship, expected); err != nil {
			return SignedRelayFinalityEvidence{}, err
		}
		bodyDigest, bodyDigestErr := RelaySponsorshipTransactionEvidenceDigest(sponsorship)
		if record.SponsorshipTransactionEvidence == nil {
			return SignedRelayFinalityEvidence{}, errors.New("durable sponsorship transaction evidence is unavailable")
		}
		recordDigest, recordDigestErr := RelaySponsorshipTransactionEvidenceDigest(*record.SponsorshipTransactionEvidence)
		if bodyDigestErr != nil || recordDigestErr != nil || bodyDigest != recordDigest {
			return SignedRelayFinalityEvidence{}, errors.New("relay evidence source substituted durable sponsorship transaction evidence")
		}
	}
	return SignRelayFinalityEvidence(body, service.SigningKey)
}

func (service ProviderService) Quote(ctx context.Context, request SignedRelayQuoteRequest) (SignedProviderRelayQuote, error) {
	now := service.now()
	if service.QuotePolicy == nil || service.Journal == nil || len(service.SigningKey) != ed25519.PrivateKeySize {
		return SignedProviderRelayQuote{}, errors.New("relay quote service is unavailable")
	}
	if err := VerifyRelayQuoteRequest(request, service.Profile, service.AgentResolver, now); err != nil {
		return SignedProviderRelayQuote{}, err
	}
	if err := service.verifyEvidenceCapability(request.Body); err != nil {
		return SignedProviderRelayQuote{}, err
	}
	body, err := service.QuotePolicy.Quote(ctx, service.Profile, request, now)
	if err != nil {
		return SignedProviderRelayQuote{}, err
	}
	signed, err := SignProviderRelayQuote(body, service.SigningKey)
	if err != nil {
		return SignedProviderRelayQuote{}, err
	}
	if err := VerifyProviderRelayQuote(signed, request, service.Profile, service.AgentResolver, now); err != nil {
		return SignedProviderRelayQuote{}, errors.New("relay quote policy produced an invalid quote: " + err.Error())
	}
	reserved, _, err := service.Journal.ReserveQuote(service.Profile, request, signed, now)
	if err != nil {
		return SignedProviderRelayQuote{}, err
	}
	// A concurrent or repeated request may return the first durably signed
	// quote rather than this invocation's proposal. Reverify the stored object
	// so corruption in a durable implementation fails closed.
	if err := VerifyProviderRelayQuote(reserved, request, service.Profile, service.AgentResolver, now); err != nil {
		return SignedProviderRelayQuote{}, errors.New("reserved relay quote is invalid: " + err.Error())
	}
	return reserved, nil
}

// Submit admits the exact execution envelope once. An exact retry can resume
// the same idempotent sponsorship journal entry, but it can never create a new
// payment identity or broadcast bytes after a durable non-PREPARED state.
func (service ProviderService) Submit(ctx context.Context, request RelayExecutionRequest,
	agreement agentcommerce.AgentAgreement) (Record, error) {
	now := service.now()
	if service.Journal == nil {
		return Record{}, errors.New("relay provider journal is unavailable")
	}
	// Resolve the Provider record before applying the receipt's one-time start
	// boundary. Once this exact receipt was durably consumed in time, exact
	// retries and its already-admitted stages use the immutable journal record;
	// they must not be cancelled by a later writer takeover or by expiration of
	// StartNotAfterUnix itself.
	existing, existingErr := service.Journal.Resolve(request.AuthorizedAction.StableActionID,
		request.AuthorizedAction.ExactRequestDigest)
	alreadyAdmitted := existingErr == nil
	if alreadyAdmitted {
		if err := exactRelayAdmissionMatches(existing, request); err != nil {
			return existing, err
		}
		if existing.State != agentcommerce.ActionPrepared {
			return existing, nil
		}
	} else if !errors.Is(existingErr, ErrRelayUnknown) && !errors.Is(existingErr, ErrRelayConflict) {
		return Record{}, existingErr
	} else if errors.Is(existingErr, ErrRelayConflict) {
		return existing, ErrRelayConflict
	}

	// An exact recovery after expiry may not pass live authorization checks, but
	// it still must be able to query an already attempted payment. Match the
	// complete frozen execution digest and use only the protected journal token;
	// this branch can never create a new transfer or broadcast.
	if alreadyAdmitted && existing.State == agentcommerce.ActionPrepared &&
		existing.SponsorshipAttempted && relaySignedWindowExpired(existing.ExecutionRequest(), now) {
		return service.resolveAttemptedSponsorship(ctx, existing, now)
	}
	var verified VerifiedRelayAdmissionReceipt
	if alreadyAdmitted {
		if err := VerifyRelaySideEffectAdmissionReceiptIntegrity(request.AdmissionReceipt, request); err != nil {
			return existing, err
		}
	} else {
		// The only resolver/helper work of a first admission. It reads no clock
		// and runs before inspection, Agreement checks and any journal lock.
		authorityVerified, err := VerifyRelaySideEffectAdmissionReceiptAuthority(request.AdmissionReceipt,
			service.FenceResolver)
		if err != nil {
			return Record{}, err
		}
		verified = authorityVerified
		if err := CheckRelaySideEffectAdmissionReceipt(request.AdmissionReceipt, verified, request, now); err != nil {
			return Record{}, err
		}
	}
	actionAuthorityAt := time.Unix(int64(request.AdmissionReceipt.Body.IssuedAtUnix), 0).UTC()
	if err := verifyRelayExecutionRequestCoreAtAuthorityTime(ctx, request, service.Profile, service.AgentResolver,
		service.FenceResolver, service.Inspector, now, actionAuthorityAt, false); err != nil {
		return Record{}, err
	}
	if err := VerifyActionTransactionBinding(ctx, request, service.Profile, service.Inspector, service.ActionBinder); err != nil {
		return Record{}, err
	}
	if err := VerifyRelayExecutionAgreement(request, agreement, service.AgreementVerifier, now); err != nil {
		return Record{}, err
	}
	if err := service.verifyEvidenceCapability(request.QuoteRequest.Body); err != nil {
		return Record{}, err
	}
	initialStage := SideEffectBroadcast
	if request.QuoteRequest.Body.Mode != ModeRelayExact {
		initialStage = SideEffectSponsorship
	}
	if !alreadyAdmitted {
		if service.AdmissionAuthority == nil {
			return Record{}, errors.New("relay side-effect admission authority is unavailable")
		}
		descriptor, descriptorErr := buildRelaySideEffectAdmissionDescriptorForRoute(request,
			request.AdmissionReceipt.Body.AuthenticatedPrincipal, request.AdmissionReceipt.Body.RouteAttempt,
			request.AdmissionReceipt.Body.PredecessorReceiptDigest)
		if descriptorErr != nil {
			return Record{}, descriptorErr
		}
		authoritative, resolveErr := service.AdmissionAuthority.ResolveRelaySideEffectAdmission(ctx,
			descriptor.Lookup())
		if resolveErr != nil {
			return Record{}, errors.New("resolve authoritative relay side-effect admission: " + resolveErr.Error())
		}
		equal, equalErr := equalCanonicalRelayAdmissionReceipts(authoritative, request.AdmissionReceipt)
		if equalErr != nil || !equal {
			return Record{}, errors.New("authoritative relay side-effect admission conflicts with the submitted receipt")
		}
	}
	// Agreement checks, chain inspection and the authoritative lookup may have
	// consumed most of the short receipt window. The owner Action Authority
	// already linearized the exact stage mask atomically with its
	// current-writer high water; consuming that same receipt is therefore the
	// admission boundary, judged at a fresh time with no blocking call between
	// this check and the journal insertion.
	now = service.now()
	if !alreadyAdmitted {
		if err := CheckRelaySideEffectAdmissionReceipt(request.AdmissionReceipt, verified, request, now); err != nil {
			return Record{}, err
		}
	}
	if err := VerifyRelayRemainingValidity(request, now, initialStage); err != nil {
		return Record{}, err
	}
	record, created, err := service.Journal.Admit(request, verified, now)
	if err != nil {
		return record, err
	}
	if !created && record.State != agentcommerce.ActionPrepared {
		return record, nil
	}
	if request.QuoteRequest.Body.Mode != ModeRelayExact {
		reference, evidence := record.SponsorshipTransferReference, record.EvidenceRefs
		if reference == "" && record.SponsorshipCreditObservation != nil {
			// The exact top-up is already durably observed under the signed
			// lower-assurance release profile. Re-resolving here would create a
			// different observed_at/checkpoint artifact and turn safe crash
			// recovery into a journal conflict. Sponsor-only remains nonterminal;
			// combined mode continues only through the fresh chain-state checks
			// below and can never create another top-up.
			if request.QuoteRequest.Body.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven {
				return record, errors.New("durable unproven sponsorship conflicts with the signed release profile")
			}
			if request.QuoteRequest.Body.Mode == ModeSponsorOnly {
				return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest,
					record.StateRevision, agentcommerce.ActionSubmitted, "", nil, "", service.now())
			}
		} else if reference == "" && len(record.SponsorshipAbsenceObservations) == 0 {
			if service.Sponsorship == nil {
				return record, errors.New("gas sponsorship processor is unavailable")
			}
			sponsorshipObligation, found := agreementObligation(agreement, request.SponsorshipObligationID)
			if !found {
				return record, errors.New("gas sponsorship Agreement obligation is unavailable")
			}
			now = service.now()
			if validityErr := VerifyRelayRemainingValidity(request, now, SideEffectSponsorship); validityErr != nil {
				return service.rejectPrepared(record, validityErr, now)
			}
			recovery := record.SponsorshipRecoveryHandle()
			if !record.SponsorshipAttempted {
				recovery, err = service.Sponsorship.PrepareRecovery(ctx, request, agreement, sponsorshipObligation)
				if err != nil {
					return record, err
				}
				if err := validateSponsorshipRecoveryHandle(recovery); err != nil {
					return record, err
				}
				now = service.now()
				if validityErr := VerifyRelayRemainingValidity(request, now, SideEffectSponsorship); validityErr != nil {
					return service.rejectPrepared(record, validityErr, now)
				}
				record, err = service.Journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest,
					record.StateRevision, recovery, now)
				if err != nil {
					return record, err
				}
			} else if err := validateSponsorshipRecoveryHandle(recovery); err != nil {
				return record, err
			}
			resolution, sponsorErr := service.Sponsorship.EnsureFinalized(ctx, request,
				agreement, sponsorshipObligation, recovery)
			if sponsorErr != nil {
				// The sponsorship implementation owns its exact payment action and
				// ambiguity journal. Keeping the relay PREPARED prevents premature
				// transaction broadcast while still making exact retry safe.
				return record, sponsorErr
			}
			if err := validateSponsorshipResolution(resolution, request, recovery, service.now()); err != nil {
				return record, err
			}
			switch resolution.Status {
			case SponsorshipResolutionUnknown:
				return record, nil
			case SponsorshipResolutionObservedUnproven:
				if service.SponsorshipObservationVerifier == nil {
					return record, errors.New("independent sponsorship credit observation verifier is unavailable")
				}
				if err := service.SponsorshipObservationVerifier.VerifySponsorshipCreditObservation(ctx,
					*resolution.CreditObservation, request.QuoteRequest.Body.SelectedSponsorshipReleaseProfile()); err != nil {
					return record, errors.New("verify sponsorship credit observation: " + err.Error())
				}
				record, err = service.Journal.RecordSponsorshipObservation(record.StableActionID,
					record.ExactRequestDigest, record.StateRevision, *resolution.CreditObservation, service.now())
				if err != nil {
					return record, err
				}
				if request.QuoteRequest.Body.Mode == ModeSponsorOnly {
					return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest,
						record.StateRevision, agentcommerce.ActionSubmitted, "", nil, "", service.now())
				}
			case SponsorshipResolutionCorroboratedAbsent, SponsorshipResolutionFinalizedAbsent:
				journalOutcome := resolution.AbsenceOutcome
				if request.QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
					len(resolution.SponsorshipAbsenceObservations) != 0 &&
					len(resolution.TransactionAbsenceObservations) == 0 {
					journalOutcome = ""
				}
				return service.Journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
					record.StateRevision, journalOutcome,
					resolution.SponsorshipAbsenceObservations,
					resolution.TransactionAbsenceObservations,
					resolution.AbsenceProofBundleDigest, resolution.AbsenceProofBundle, service.now())
			case SponsorshipResolutionCorroboratedTerminal, SponsorshipResolutionFinalized:
				// Continue below.
			default:
				return record, errors.New("gas sponsorship returned an unknown resolution status")
			}
			if sponsorshipResolutionHasTransfer(resolution.Status) {
				record, err = service.Journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
					record.StateRevision, *resolution.TransactionEvidence, service.now())
				if err != nil {
					return record, err
				}
			}
			reference, evidence = record.SponsorshipTransferReference, record.EvidenceRefs
		}
		if request.QuoteRequest.Body.Mode == ModeSponsorOnly {
			now = service.now()
			return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
				agentcommerce.ActionTerminal, reference, evidence,
				sponsorshipOnlyOutcomeForEvidence(record.SponsorshipTransactionEvidence), now)
		}
		// Sponsorship can take most of the signed validity window. Recheck all
		// expiring authorization and profile inputs, then require the credited
		// balance and exact source sequence to be present in a fresh chain-state
		// read before broadcasting. This does not relabel RPC corroboration as
		// validator finality; the overall action remains nonterminal until both
		// exact transfers have their selected terminal evidence.
		now = service.now()
		if validityErr := VerifyRelayRemainingValidity(request, now, SideEffectBroadcast); validityErr != nil {
			return service.terminalizeSponsorshipOnly(record, validityErr, now)
		}
		if err := VerifyRelaySideEffectAdmissionReceiptIntegrity(request.AdmissionReceipt, request); err != nil {
			return service.terminalizeSponsorshipOnly(record, err, now)
		}
		if err := verifyRelayExecutionRequestCoreAtAuthorityTime(ctx, request, service.Profile, service.AgentResolver,
			service.FenceResolver, service.Inspector, now, actionAuthorityAt, false); err != nil {
			return service.terminalizeSponsorshipOnly(record, err, now)
		}
		if err := VerifyRelayReadyToBroadcast(ctx, request, service.Profile, service.Inspector, service.ActionBinder); err != nil {
			return service.terminalizeSponsorshipOnly(record, err, now)
		}
	}
	if service.Broadcaster == nil {
		return record, errors.New("exact transaction broadcaster is unavailable")
	}
	now = service.now()
	if validityErr := VerifyRelayRemainingValidity(request, now, SideEffectBroadcast); validityErr != nil {
		if record.SponsorshipTransferReference != "" {
			return service.terminalizeSponsorshipOnly(record, validityErr, now)
		}
		if record.SponsorshipCreditObservation != nil {
			return record, validityErr
		}
		return service.rejectPrepared(record, validityErr, now)
	}
	// Persist SUBMITTED before the first network write. A crash or ambiguous
	// response therefore enters Resolve and can never create new bytes.
	record, err = service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionSubmitted, "", record.EvidenceRefs, "", now)
	if err != nil {
		return record, err
	}
	// The signed admission receipt is passed to the sink. Its prior atomic
	// issuance—not a racy lease lookup at this line—is what permits this exact
	// already-admitted stage to drain after a writer takeover.
	result, submitErr := service.Broadcaster.SubmitExact(ctx, request)
	if submitErr != nil || result.Status == BroadcastUnknown {
		return record, submitErr
	}
	if result.Status != BroadcastAccepted {
		return record, errors.New("relay broadcaster returned an unauthenticated rejection; write outcome remains ambiguous")
	}
	return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionAccepted, result.TransactionReference, record.EvidenceRefs, "", service.now())
}

func (service ProviderService) verifyEvidenceCapability(request RelayQuoteRequestBody) error {
	source, ok := service.EvidenceSource.(IndependentFinalityEvidenceSource)
	if !ok {
		return errors.New("relay terminal evidence source has no exact capability contract")
	}
	capability := RelayEvidenceCapability{Mode: request.Mode, AssuranceLevel: request.AssuranceLevel,
		Network: request.Network, TransactionProfileURI: request.TransactionProfileURI,
		TransactionProfileDigest:         request.TransactionProfileDigest,
		UnderlyingActionKind:             request.UnderlyingActionKind,
		RelayTerminalEvidenceClass:       request.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: request.SponsorshipTerminalEvidenceClass,
		SponsorshipReleaseProfile:        request.SelectedSponsorshipReleaseProfile()}
	if request.Mode != ModeRelayExact && request.AssuranceLevel != AssuranceAutonomousDecentralized {
		capability.AbsenceProofProfileURI = RelayAbsenceTOSRPCProofProfileURI
		capability.AbsenceProofProfileDigest, _ = RelayAbsenceTOSRPCProofProfileDigest()
	}
	if request.Mode != ModeSponsorOnly {
		profile, found := findFinalityProfile(service.Profile.FinalityProfiles,
			request.RelayFinalityProfileURI, request.RelayFinalityProfileDigest)
		if !found {
			return errors.New("selected relay terminal profile is unavailable")
		}
		capability.RelayFinalityProfile = &profile
	}
	if request.Mode != ModeRelayExact {
		profile, found := findFinalityProfile(service.Profile.FinalityProfiles,
			request.SponsorshipTerminalProfileURI, request.SponsorshipTerminalProfileDigest)
		if !found {
			return errors.New("selected sponsorship terminal profile is unavailable")
		}
		capability.SponsorshipTerminalProfile = &profile
	}
	if !source.SupportsRelayEvidenceCapability(capability) {
		return errors.New("relay terminal evidence source is not ready for the exact signed capability")
	}
	if request.Mode == ModeSponsorAndRelay && !source.SupportsRelayDualAbsenceEvidence(capability) {
		return errors.New("relay terminal evidence source cannot prove both sponsorship absence domains")
	}
	if request.Mode != ModeRelayExact &&
		!source.SupportsRelaySponsorshipComponentAbsenceEvidence(capability) {
		return errors.New("relay terminal evidence source cannot prove component sponsorship absence")
	}
	if request.Mode == ModeSponsorAndRelay &&
		!source.SupportsRelayTransactionComponentAbsenceEvidence(capability) {
		return errors.New("relay terminal evidence source cannot prove component transaction absence")
	}
	if request.AssuranceLevel == AssuranceAutonomousDecentralized &&
		(!source.HasRetrievableIndependentProofs() || !source.HasRollbackResistantCheckpoint() ||
			!source.HasRollbackResistantTerminalCommitment()) {
		return errors.New("relay terminal evidence source lacks autonomous assurance capabilities")
	}
	return nil
}

// Resolve is the only recovery path after SUBMITTED or tentative ACCEPTED. It
// may rebroadcast only the frozen bytes and only when the chain resolver has
// established that an exact rebroadcast is safe while the same request remains
// live.
func (service ProviderService) Resolve(ctx context.Context, stableActionID, exactRequestDigest string) (Record, error) {
	if service.Journal == nil {
		return Record{}, errors.New("relay provider journal is unavailable")
	}
	record, err := service.Journal.Resolve(stableActionID, exactRequestDigest)
	if err != nil {
		return record, err
	}
	if record.State == agentcommerce.ActionTerminal || record.State == agentcommerce.ActionRejected ||
		record.State == agentcommerce.ActionConflict {
		return record, nil
	}
	pendingSponsorshipAbsence := record.ExecutionRequest().QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
		record.SponsorshipTransferReference == "" && len(record.SponsorshipAbsenceObservations) != 0 &&
		len(record.TransactionAbsenceObservations) == 0 && record.TerminalOutcome == ""
	if record.State == agentcommerce.ActionPrepared && !pendingSponsorshipAbsence {
		now := service.now()
		if !relaySignedWindowExpired(record.ExecutionRequest(), now) {
			return record, nil
		}
		if record.SponsorshipTransferReference != "" {
			return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
				agentcommerce.ActionTerminal, record.SponsorshipTransferReference, record.EvidenceRefs,
				sponsorshipOnlyOutcomeForEvidence(record.SponsorshipTransactionEvidence), now)
		}
		// Once BeginSponsorship has been durably checkpointed, an absent final
		// transfer reference does not prove that no payment was made. Query only
		// through the processor's protected recovery token; this path cannot make
		// a new transfer after the signed execution windows expire.
		if record.SponsorshipAttempted {
			return service.resolveAttemptedSponsorship(ctx, record, now)
		}
		return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
			agentcommerce.ActionRejected, "", nil, "", now)
	}
	if record.SponsorshipAttempted && record.SponsorshipCreditObservation != nil {
		record, err = service.resolveObservedSponsorship(ctx, record, service.now())
		if err != nil {
			return record, err
		}
		if record.ExecutionRequest().QuoteRequest.Body.Mode == ModeSponsorOnly &&
			record.SponsorshipTransferReference == "" {
			return record, nil
		}
		if record.ExecutionRequest().QuoteRequest.Body.Mode == ModeSponsorOnly &&
			record.SponsorshipTransferReference != "" {
			return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest,
				record.StateRevision, agentcommerce.ActionTerminal, record.SponsorshipTransferReference,
				record.EvidenceRefs, sponsorshipOnlyOutcomeForEvidence(record.SponsorshipTransactionEvidence), service.now())
		}
		pendingSponsorshipAbsence = record.ExecutionRequest().QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
			record.SponsorshipTransferReference == "" && len(record.SponsorshipAbsenceObservations) != 0 &&
			len(record.TransactionAbsenceObservations) == 0 && record.TerminalOutcome == ""
	}
	if service.Broadcaster == nil {
		return record, errors.New("relay resolver is unavailable")
	}
	resolved, err := service.Broadcaster.Resolve(ctx, record)
	if err != nil {
		return record, err
	}
	if (record.State == agentcommerce.ActionSubmitted || record.State == agentcommerce.ActionAccepted) &&
		(resolved.State == agentcommerce.ActionRejected || resolved.State == agentcommerce.ActionConflict) {
		// The first-write boundary was crossed before SUBMITTED was persisted.
		// A later Adapter rejection cannot prove non-execution and must not release
		// an obligation or collapse a combined action to sponsorship-only. Only
		// exact success or typed, independently verified absence can terminalize it.
		return record, errors.New("post-submit relay rejection is not proof of non-execution; outcome remains unresolved")
	}
	if pendingSponsorshipAbsence && resolved.State == agentcommerce.ActionTerminal &&
		safeTerminalAbsenceOutcome(resolved.TerminalOutcome) {
		aggregator, ok := service.Sponsorship.(CombinedRelayDualAbsenceResolver)
		if !ok {
			return record, errors.New("combined relay dual-absence aggregator is unavailable")
		}
		resolution, aggregateErr := aggregator.ResolveRelayDualAbsence(ctx, record.ExecutionRequest(),
			record.SponsorshipRecoveryHandle(), record.SponsorshipAbsenceObservations,
			record.AbsenceProofBundleDigest, record.AbsenceProofBundle)
		if aggregateErr != nil {
			return record, aggregateErr
		}
		if resolution.Status == SponsorshipResolutionUnknown {
			return record, nil
		}
		if err := validateSponsorshipResolution(resolution, record.ExecutionRequest(),
			record.SponsorshipRecoveryHandle(), service.now()); err != nil {
			return record, err
		}
		if (resolution.Status != SponsorshipResolutionCorroboratedAbsent &&
			resolution.Status != SponsorshipResolutionFinalizedAbsent) ||
			len(resolution.TransactionAbsenceObservations) == 0 ||
			!equalStrings(relayAbsenceObservationReferenceDigests(record.SponsorshipAbsenceObservations),
				relayAbsenceObservationReferenceDigests(resolution.SponsorshipAbsenceObservations)) ||
			transactionConclusion(resolution.AbsenceOutcome) != transactionConclusion(resolved.TerminalOutcome) {
			return record, errors.New("dual-absence aggregation substituted a component or conclusion")
		}
		return service.Journal.RecordSponsorshipAbsence(record.StableActionID,
			record.ExactRequestDigest, record.StateRevision, resolution.AbsenceOutcome,
			resolution.SponsorshipAbsenceObservations, resolution.TransactionAbsenceObservations,
			resolution.AbsenceProofBundleDigest, resolution.AbsenceProofBundle, service.now())
	}
	if record.ExecutionRequest().QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
		record.SponsorshipTransferReference != "" && record.SponsorshipTransactionEvidence != nil &&
		resolved.State == agentcommerce.ActionTerminal && safeTerminalAbsenceOutcome(resolved.TerminalOutcome) &&
		len(resolved.TransactionAbsenceObservations) == 0 && resolved.AbsenceProofBundleDigest == "" &&
		len(resolved.AbsenceProofBundle) == 0 {
		componentResolver, ok := service.Sponsorship.(CombinedRelayTransactionAbsenceResolver)
		if !ok {
			return record, errors.New("combined relay transaction-component absence resolver is unavailable")
		}
		component, componentErr := componentResolver.ResolveRelayTransactionAbsence(ctx,
			record.ExecutionRequest(), record.SponsorshipRecoveryHandle(), resolved.TerminalOutcome)
		if componentErr != nil {
			return record, componentErr
		}
		if component.State == "" {
			return record, nil
		}
		if component.State != agentcommerce.ActionTerminal || component.TransactionReference != "" ||
			!safeTerminalAbsenceOutcome(component.TerminalOutcome) ||
			transactionConclusion(component.TerminalOutcome) != transactionConclusion(resolved.TerminalOutcome) ||
			len(component.TransactionAbsenceObservations) == 0 ||
			component.AbsenceProofBundleDigest == "" || len(component.AbsenceProofBundle) == 0 {
			return record, errors.New("transaction-component resolver substituted the exact relay conclusion or scope")
		}
		resolved = component
	}
	if len(resolved.TransactionAbsenceObservations) != 0 || resolved.AbsenceProofBundleDigest != "" ||
		len(resolved.AbsenceProofBundle) != 0 {
		if record.ExecutionRequest().QuoteRequest.Body.Mode != ModeSponsorAndRelay ||
			record.SponsorshipTransferReference == "" || record.SponsorshipTransactionEvidence == nil ||
			resolved.State != agentcommerce.ActionTerminal || !safeTerminalAbsenceOutcome(resolved.TerminalOutcome) ||
			resolved.TransactionReference != "" || len(resolved.TransactionAbsenceObservations) == 0 {
			return record, errors.New("relay transaction-component absence conflicts with the durable sponsorship state")
		}
		outcome := sponsorshipOnlyOutcomeForTransactionAbsence(record.ExecutionRequest(),
			record.SponsorshipTransactionEvidence)
		return service.Journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, outcome, nil, resolved.TransactionAbsenceObservations,
			resolved.AbsenceProofBundleDigest, resolved.AbsenceProofBundle, service.now())
	}
	if resolved.SafeToRebroadcastExact {
		request := record.ExecutionRequest()
		// Recovery queries and terminal bookkeeping must remain available when an
		// evidence backend is temporarily unavailable. Re-check the exact current
		// capability only at the branch that can create a new external side effect.
		if err := service.verifyEvidenceCapability(request.QuoteRequest.Body); err != nil {
			return record, err
		}
		now := service.now()
		if err := VerifyRelaySideEffectAdmissionReceiptIntegrity(request.AdmissionReceipt, request); err != nil {
			return record, err
		}
		actionAuthorityAt := time.Unix(int64(request.AdmissionReceipt.Body.IssuedAtUnix), 0).UTC()
		if err := verifyRelayExecutionRequestCoreAtAuthorityTime(ctx, request, service.Profile, service.AgentResolver,
			service.FenceResolver, service.Inspector, now, actionAuthorityAt, false); err != nil {
			return record, err
		}
		if err := VerifyRelayReadyToBroadcast(ctx, request, service.Profile, service.Inspector, service.ActionBinder); err != nil {
			return record, err
		}
		if err := VerifyRelayRemainingValidity(request, now, SideEffectBroadcast); err != nil {
			return record, err
		}
		result, submitErr := service.Broadcaster.SubmitExact(ctx, request)
		if submitErr != nil || result.Status == BroadcastUnknown {
			return record, submitErr
		}
		resolved.TransactionReference = result.TransactionReference
		if result.Status != BroadcastAccepted {
			return record, errors.New("exact relay rebroadcast returned no authenticated acceptance; original outcome remains unresolved")
		}
		resolved.State = agentcommerce.ActionAccepted
	}
	if resolved.State == "" || resolved.State == record.State && resolved.TransactionReference == record.TransactionReference &&
		resolved.TerminalOutcome == "" && len(resolved.EvidenceRefs) == 0 {
		return record, nil
	}
	if record.SponsorshipTransferReference != "" &&
		(resolved.State == agentcommerce.ActionRejected || resolved.State == agentcommerce.ActionConflict) {
		resolved.State = agentcommerce.ActionTerminal
		resolved.TerminalOutcome = sponsorshipOnlyOutcomeForEvidence(record.SponsorshipTransactionEvidence)
		resolved.TransactionReference = record.SponsorshipTransferReference
	}
	if len(record.SponsorshipAbsenceObservations) != 0 && record.SponsorshipTransferReference == "" &&
		resolved.State == agentcommerce.ActionTerminal &&
		(resolved.TerminalOutcome == OutcomeFinalizedSuccess ||
			resolved.TerminalOutcome == OutcomeCorroboratedSuccess) {
		resolved.TerminalOutcome = relayOnlyOutcomeForAbsence(record.ExecutionRequest())
	} else if record.SponsorshipTransferReference != "" && resolved.State == agentcommerce.ActionTerminal {
		if resolved.TerminalOutcome == OutcomeFinalizedSuccess {
			resolved.TerminalOutcome = relayOutcomeForSelectedEvidence(resolved.TerminalOutcome,
				record.ExecutionRequest().QuoteRequest.Body.RelayTerminalEvidenceClass,
				record.SponsorshipTransactionEvidence)
		} else if resolved.TerminalOutcome != OutcomeCorroboratedSuccess {
			return record, errors.New("combined post-submit relay result lacks success or typed transaction absence")
		}
	}
	if resolved.State == agentcommerce.ActionTerminal && record.SponsorshipTransferReference == "" &&
		len(record.SponsorshipAbsenceObservations) == 0 {
		resolved.TerminalOutcome = relayOutcomeForSelectedEvidence(resolved.TerminalOutcome,
			record.ExecutionRequest().QuoteRequest.Body.RelayTerminalEvidenceClass, nil)
	}
	evidence := mergeEvidenceRefs(record.EvidenceRefs, resolved.EvidenceRefs)
	if record.SponsorshipAttempted && record.SponsorshipCreditObservation != nil &&
		(resolved.State == agentcommerce.ActionTerminal || resolved.State == agentcommerce.ActionRejected ||
			resolved.State == agentcommerce.ActionConflict) {
		// The client transaction may already be visible, but the combined
		// economic action cannot become terminal until the exact top-up gains
		// independently verified finality. Keep querying both frozen actions.
		return record, nil
	}
	return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		resolved.State, resolved.TransactionReference, evidence, resolved.TerminalOutcome, service.now())
}

func (service ProviderService) resolveObservedSponsorship(ctx context.Context, record Record,
	at time.Time) (Record, error) {
	if service.Sponsorship == nil || !record.SponsorshipAttempted || record.SponsorshipCreditObservation == nil {
		return record, errors.New("observed sponsorship recovery processor or token is unavailable")
	}
	recovery := record.SponsorshipRecoveryHandle()
	resolution, err := service.Sponsorship.ResolveFinalized(ctx, record.ExecutionRequest(), recovery)
	if err != nil {
		return record, err
	}
	if err := validateSponsorshipResolution(resolution, record.ExecutionRequest(), recovery, at); err != nil {
		return record, err
	}
	switch resolution.Status {
	case SponsorshipResolutionUnknown:
		return record, nil
	case SponsorshipResolutionObservedUnproven:
		if service.SponsorshipObservationVerifier == nil {
			return record, errors.New("independent sponsorship credit observation verifier is unavailable")
		}
		if err := service.SponsorshipObservationVerifier.VerifySponsorshipCreditObservation(ctx,
			*resolution.CreditObservation,
			record.ExecutionRequest().QuoteRequest.Body.SelectedSponsorshipReleaseProfile()); err != nil {
			return record, errors.New("verify sponsorship credit observation: " + err.Error())
		}
		return service.Journal.RecordSponsorshipObservation(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, *resolution.CreditObservation, at)
	case SponsorshipResolutionCorroboratedTerminal, SponsorshipResolutionFinalized:
		return service.Journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, *resolution.TransactionEvidence, at)
	case SponsorshipResolutionCorroboratedAbsent, SponsorshipResolutionFinalizedAbsent:
		// An observed_unproven credit is deliberately nonterminal. A reorg may
		// remove it; exact profile-qualified proof that both the top-up and client
		// transaction are absent supersedes that observation and closes the
		// exposure without pretending that the earlier observation never existed.
		journalOutcome := resolution.AbsenceOutcome
		if record.ExecutionRequest().QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
			len(resolution.SponsorshipAbsenceObservations) != 0 &&
			len(resolution.TransactionAbsenceObservations) == 0 {
			journalOutcome = ""
		}
		return service.Journal.RecordSponsorshipAbsence(record.StableActionID,
			record.ExactRequestDigest, record.StateRevision, journalOutcome,
			resolution.SponsorshipAbsenceObservations,
			resolution.TransactionAbsenceObservations,
			resolution.AbsenceProofBundleDigest, resolution.AbsenceProofBundle, at)
	default:
		return record, errors.New("observed sponsorship recovery returned an unknown status")
	}
}

func (service ProviderService) SignedResolution(record Record) (SignedRelayResolution, error) {
	now := service.now()
	body := RelayResolutionBody{SchemaVersion: 1, ProviderAgentID: service.Profile.ProviderAgentID,
		Network:        record.ExecutionRequest().QuoteRequest.Body.Network,
		AssuranceLevel: record.ExecutionRequest().QuoteRequest.Body.AssuranceLevel,
		StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		RelayExecutionDigest: record.RelayExecutionDigest, State: record.State, StateRevision: record.StateRevision,
		TerminalOutcome: record.TerminalOutcome, TransactionReference: record.TransactionReference,
		SponsorshipStableActionID:     record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: record.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:     record.SponsorshipValidUntilUnix,
		SponsorshipTransferReference:  record.SponsorshipTransferReference,
		ObservedAtUnix:                uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(15 * time.Minute).Unix())}
	switch {
	case record.SponsorshipCreditObservation != nil && record.SponsorshipAttempted:
		body.SponsorshipStatus = SponsorshipResolutionObservedUnproven
		var err error
		body.SponsorshipObservationDigest, err = RelaySponsorshipCreditObservationDigest(*record.SponsorshipCreditObservation)
		if err != nil {
			return SignedRelayResolution{}, err
		}
	}
	if record.State == agentcommerce.ActionTerminal {
		var err error
		body.EvidenceSetDigest, err = RelayEvidenceSetDigest(record.EvidenceRefs)
		if err != nil {
			return SignedRelayResolution{}, err
		}
	}
	return SignRelayResolution(body, service.SigningKey)
}

func (service ProviderService) now() time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func exactRelayAdmissionMatches(record Record, request RelayExecutionRequest) error {
	executionDigest, err := RelayExecutionRequestDigest(request)
	if err != nil || executionDigest != record.RelayExecutionDigest {
		return ErrRelayConflict
	}
	receiptDigest, err := RelaySideEffectAdmissionReceiptDigest(request.AdmissionReceipt)
	if err != nil || receiptDigest != record.AdmissionReceiptDigest ||
		request.QuoteRequest.Body.SignedTransactionDigest != record.SignedTransactionDigest {
		return ErrRelayConflict
	}
	equal, err := equalCanonicalRelayAdmissionReceipts(record.ExecutionRequest().AdmissionReceipt,
		request.AdmissionReceipt)
	if err != nil || !equal {
		return ErrRelayConflict
	}
	return nil
}

func (service ProviderService) rejectPrepared(record Record, cause error, at time.Time) (Record, error) {
	rejected, err := service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionRejected, "", record.EvidenceRefs, "", at)
	if err != nil {
		return record, errors.Join(cause, err)
	}
	return rejected, cause
}

func (service ProviderService) terminalizeSponsorshipOnly(record Record, cause error, at time.Time) (Record, error) {
	if record.SponsorshipTransferReference == "" || len(record.EvidenceRefs) == 0 {
		return record, errors.Join(cause, errors.New("finalized sponsorship checkpoint is unavailable"))
	}
	terminal, err := service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionTerminal, record.SponsorshipTransferReference, record.EvidenceRefs,
		sponsorshipOnlyOutcomeForEvidence(record.SponsorshipTransactionEvidence), at)
	if err != nil {
		return record, errors.Join(cause, err)
	}
	return terminal, cause
}

func (service ProviderService) resolveAttemptedSponsorship(ctx context.Context, record Record, at time.Time) (Record, error) {
	recovery := record.SponsorshipRecoveryHandle()
	if service.Sponsorship == nil || !record.SponsorshipAttempted {
		return record, errors.New("sponsorship recovery processor or token is unavailable")
	}
	if err := validateSponsorshipRecoveryHandle(recovery); err != nil {
		return record, err
	}
	resolution, err := service.Sponsorship.ResolveFinalized(ctx, record.ExecutionRequest(), recovery)
	if err != nil {
		return record, err
	}
	if err := validateSponsorshipResolution(resolution, record.ExecutionRequest(), recovery, at); err != nil {
		return record, err
	}
	switch resolution.Status {
	case SponsorshipResolutionUnknown:
		return record, nil
	case SponsorshipResolutionObservedUnproven:
		if service.SponsorshipObservationVerifier == nil {
			return record, errors.New("independent sponsorship credit observation verifier is unavailable")
		}
		if err := service.SponsorshipObservationVerifier.VerifySponsorshipCreditObservation(ctx,
			*resolution.CreditObservation,
			record.ExecutionRequest().QuoteRequest.Body.SelectedSponsorshipReleaseProfile()); err != nil {
			return record, errors.New("verify sponsorship credit observation: " + err.Error())
		}
		return service.Journal.RecordSponsorshipObservation(record.StableActionID,
			record.ExactRequestDigest, record.StateRevision, *resolution.CreditObservation, at)
	case SponsorshipResolutionCorroboratedAbsent, SponsorshipResolutionFinalizedAbsent:
		journalOutcome := resolution.AbsenceOutcome
		if record.ExecutionRequest().QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
			len(resolution.SponsorshipAbsenceObservations) != 0 &&
			len(resolution.TransactionAbsenceObservations) == 0 {
			journalOutcome = ""
		}
		return service.Journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, journalOutcome,
			resolution.SponsorshipAbsenceObservations,
			resolution.TransactionAbsenceObservations,
			resolution.AbsenceProofBundleDigest, resolution.AbsenceProofBundle, at)
	case SponsorshipResolutionCorroboratedTerminal, SponsorshipResolutionFinalized:
		// A top-up recovered after the relay window expired is the only side
		// effect that may be declared finalized.
	default:
		return record, errors.New("sponsorship recovery returned an unknown resolution status")
	}
	record, err = service.Journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, *resolution.TransactionEvidence, at)
	if err != nil {
		return record, err
	}
	return service.Journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionTerminal, resolution.TransferReference, resolution.EvidenceRefs,
		sponsorshipOnlyOutcomeForEvidence(resolution.TransactionEvidence), at)
}

func validateSponsorshipRecoveryHandle(recovery SponsorshipRecoveryHandle) error {
	if !digestPattern.MatchString(recovery.AgreementPaymentRequestDigest) ||
		!validSponsorshipIdentity(recovery.StableActionID, recovery.ExactRequestDigest) || recovery.ValidUntilUnix == 0 {
		return errors.New("gas sponsorship recovery identity is invalid")
	}
	if _, err := sponsorshipRecoveryTokenDigest(recovery.OpaqueToken); err != nil {
		return errors.New("gas sponsorship recovery token is invalid")
	}
	return nil
}

func validateSponsorshipResolution(resolution SponsorshipResolution, request RelayExecutionRequest,
	recovery SponsorshipRecoveryHandle, at time.Time) error {
	switch resolution.Status {
	case SponsorshipResolutionUnknown:
		if resolution.TransferReference != "" || len(resolution.EvidenceRefs) != 0 || resolution.AbsenceOutcome != "" ||
			len(resolution.SponsorshipAbsenceObservations) != 0 ||
			len(resolution.TransactionAbsenceObservations) != 0 || resolution.CreditObservation != nil ||
			resolution.TransactionEvidence != nil || resolution.AbsenceProofBundleDigest != "" ||
			len(resolution.AbsenceProofBundle) != 0 {
			return errors.New("unresolved sponsorship query returned terminal data")
		}
	case SponsorshipResolutionObservedUnproven:
		if request.QuoteRequest.Body.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven ||
			resolution.TransferReference != "" || len(resolution.EvidenceRefs) != 0 || resolution.AbsenceOutcome != "" ||
			len(resolution.SponsorshipAbsenceObservations) != 0 || len(resolution.TransactionAbsenceObservations) != 0 ||
			resolution.CreditObservation == nil || resolution.TransactionEvidence != nil ||
			resolution.AbsenceProofBundleDigest != "" || len(resolution.AbsenceProofBundle) != 0 ||
			validateRelaySponsorshipCreditObservationShape(*resolution.CreditObservation) != nil ||
			validateSponsorshipCreditObservationForRequest(*resolution.CreditObservation, request, recovery, at) != nil {
			return errors.New("gas sponsorship unproven credit observation is incomplete or not permitted")
		}
	case SponsorshipResolutionCorroboratedTerminal, SponsorshipResolutionFinalized:
		if len(resolution.TransferReference) == 0 || len(resolution.TransferReference) > 1024 ||
			len(resolution.EvidenceRefs) == 0 || !sortedOptionalDigests(resolution.EvidenceRefs) ||
			resolution.AbsenceOutcome != "" || len(resolution.SponsorshipAbsenceObservations) != 0 ||
			len(resolution.TransactionAbsenceObservations) != 0 || resolution.CreditObservation != nil ||
			resolution.AbsenceProofBundleDigest != "" || len(resolution.AbsenceProofBundle) != 0 ||
			resolution.TransactionEvidence == nil ||
			validateRelaySponsorshipTransactionEvidenceShape(*resolution.TransactionEvidence) != nil ||
			validateSponsorshipTransactionEvidenceForRequest(*resolution.TransactionEvidence, request, recovery, at) != nil ||
			resolution.TransactionEvidence.SubmittedTransactionHash != resolution.TransferReference ||
			!equalStrings(resolution.TransactionEvidence.ObservationDigests, resolution.EvidenceRefs) {
			return errors.New("gas sponsorship finality evidence is incomplete")
		}
		if resolution.Status == SponsorshipResolutionCorroboratedTerminal {
			if request.QuoteRequest.Body.AssuranceLevel == AssuranceAutonomousDecentralized ||
				request.QuoteRequest.Body.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven ||
				request.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
				request.ProviderQuote.Body.SponsorshipTerminalProfile.ProfileURI != ClientCorroboratedTerminalProfileURI ||
				resolution.TransactionEvidence.TerminalEvidenceClass != SponsorshipTerminalClientCorroborated ||
				resolution.TransactionEvidence.ValidatorAuthenticatedPortableProof {
				return errors.New("corroborated sponsorship terminal evidence is not permitted for this assurance")
			}
		} else if request.QuoteRequest.Body.SponsorshipReleaseEvidenceClass != SponsorshipReleaseValidatorFinality ||
			resolution.TransactionEvidence.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality ||
			!resolution.TransactionEvidence.ValidatorAuthenticatedPortableProof {
			return errors.New("finalized sponsorship lacks validator-authenticated evidence")
		}
	case SponsorshipResolutionCorroboratedAbsent, SponsorshipResolutionFinalizedAbsent:
		if resolution.TransferReference != "" || len(resolution.EvidenceRefs) != 0 ||
			resolution.CreditObservation != nil || resolution.TransactionEvidence != nil ||
			!safeTerminalAbsenceOutcome(resolution.AbsenceOutcome) {
			return errors.New("gas sponsorship finalized-absence evidence is incomplete")
		}
		hasSponsorshipAbsence := len(resolution.SponsorshipAbsenceObservations) != 0
		hasTransactionAbsence := len(resolution.TransactionAbsenceObservations) != 0
		if request.QuoteRequest.Body.Mode == ModeSponsorOnly &&
			(!hasSponsorshipAbsence || hasTransactionAbsence) ||
			request.QuoteRequest.Body.Mode == ModeSponsorAndRelay && !hasSponsorshipAbsence ||
			request.QuoteRequest.Body.Mode == ModeRelayExact {
			return errors.New("gas sponsorship absence scope conflicts with the selected mode")
		}
		absenceContext, err := relayAbsenceContextForRequest(request, recovery, resolution.AbsenceOutcome, at)
		if err != nil {
			return errors.New("gas sponsorship finalized-absence context is invalid")
		}
		if _, err := validateRelayAbsenceObservationComponents(resolution.SponsorshipAbsenceObservations,
			resolution.TransactionAbsenceObservations, absenceContext); err != nil {
			return errors.New("gas sponsorship finalized-absence evidence is incomplete: " + err.Error())
		}
		if err := validateRelayAbsenceProofBundleForBody(RelayFinalityEvidenceBody{
			SponsorshipAbsenceObservations: resolution.SponsorshipAbsenceObservations,
			TransactionAbsenceObservations: resolution.TransactionAbsenceObservations,
			AbsenceProofBundleDigest:       resolution.AbsenceProofBundleDigest,
			AbsenceProofBundle:             resolution.AbsenceProofBundle,
		}); err != nil {
			return errors.New("gas sponsorship absence proof bundle is incomplete: " + err.Error())
		}
		corroborated := resolution.AbsenceOutcome == OutcomeCorroboratedExpired ||
			resolution.AbsenceOutcome == OutcomeCorroboratedAbsent ||
			resolution.AbsenceOutcome == OutcomeCorroboratedInvalidated
		allValidator := request.ProviderQuote.Body.SponsorshipTerminalProfile != nil &&
			request.ProviderQuote.Body.SponsorshipTerminalProfile.TerminalEvidenceClass ==
				SponsorshipTerminalValidatorFinality
		if hasTransactionAbsence {
			allValidator = allValidator && request.ProviderQuote.Body.RelayFinalityProfile != nil &&
				request.ProviderQuote.Body.RelayFinalityProfile.TerminalEvidenceClass == RelayTerminalValidatorFinality
		}
		if resolution.Status == SponsorshipResolutionCorroboratedAbsent && (!corroborated || allValidator) ||
			resolution.Status == SponsorshipResolutionFinalizedAbsent && (corroborated || !allValidator) {
			return errors.New("gas sponsorship absence status overstates or understates its selected evidence class")
		}
	default:
		return errors.New("gas sponsorship resolution status is invalid")
	}
	return nil
}

func validateSponsorshipCreditObservationForRequest(observation RelaySponsorshipCreditObservation,
	request RelayExecutionRequest, recovery SponsorshipRecoveryHandle, at time.Time) error {
	quoted := request.QuoteRequest.Body
	if quoted.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven ||
		observation.EvidenceProfileURI != quoted.SponsorshipReleaseProfileURI ||
		observation.EvidenceProfileDigest != quoted.SponsorshipReleaseProfileDigest {
		return errors.New("sponsorship credit observation conflicts with the selected release profile")
	}
	return validateSponsorshipPaymentForRequest(observation.AgreementPaymentRequest,
		observation.AgreementPaymentRequestDigest, observation.SponsorshipStableActionID,
		observation.SponsorshipExactRequestDigest, observation.ProviderSponsorValidUntilUnix,
		observation.NetworkDigest, observation.DestinationSourceAccount, observation.Amount,
		observation.ObservedAtUnix, request, recovery, at)
}

func validateSponsorshipTransactionEvidenceForRequest(evidence RelaySponsorshipTransactionEvidence,
	request RelayExecutionRequest, recovery SponsorshipRecoveryHandle, at time.Time) error {
	profile := request.ProviderQuote.Body.SponsorshipTerminalProfile
	if profile == nil || evidence.SponsorshipTerminalProfileDigest != profile.ProfileDigest ||
		evidence.TerminalEvidenceClass != profile.TerminalEvidenceClass ||
		len(evidence.ObservationDigests) < int(profile.MinimumObservers) ||
		evidence.ConfirmationDepth < profile.MinimumConfirmationDepth ||
		request.QuoteRequest.Body.AssuranceLevel == AssuranceAutonomousDecentralized && evidence.PortableProofLocator == "" ||
		evidence.TerminalEvidenceClass == SponsorshipTerminalClientCorroborated &&
			profile.ProfileURI != ClientCorroboratedTerminalProfileURI {
		return errors.New("autonomous sponsorship evidence has no portable proof locator")
	}
	return validateSponsorshipPaymentForRequest(evidence.AgreementPaymentRequest,
		evidence.AgreementPaymentRequestDigest, evidence.SponsorshipStableActionID,
		evidence.SponsorshipExactRequestDigest, evidence.ProviderSponsorValidUntilUnix,
		evidence.NetworkDigest, evidence.DestinationSourceAccount, evidence.Amount,
		evidence.ObservedAtUnix, request, recovery, at)
}

func validateSponsorshipPaymentForRequest(payment agentcommerce.AgreementPaymentRequest, paymentDigest,
	stableActionID, exactRequestDigest string, validUntilUnix uint64, networkDigest,
	destinationSourceAccount string, amount AssetAmount, observedAtUnix uint64,
	request RelayExecutionRequest, recovery SponsorshipRecoveryHandle, at time.Time) error {
	quoted := request.QuoteRequest.Body
	reserved := request.ProviderQuote.Body.ReservedSponsorship
	wantNetworkDigest, err := NetworkDomainDigest(quoted.Network)
	if err != nil || reserved == nil || paymentDigest != recovery.AgreementPaymentRequestDigest ||
		stableActionID != recovery.StableActionID || exactRequestDigest != recovery.ExactRequestDigest ||
		validUntilUnix != recovery.ValidUntilUnix || networkDigest != wantNetworkDigest ||
		destinationSourceAccount != quoted.SourceAccount || !sameAmount(amount, *reserved) ||
		payment.AgreementBodyDigest != request.AgreementBodyDigest ||
		payment.AgreementObligationID != request.SponsorshipObligationID ||
		payment.AgentID != quoted.ProviderAgentID || payment.PayerAgentID != quoted.ProviderAgentID ||
		payment.PayeeAgentID != quoted.RequesterAgentID ||
		payment.NetworkID != quoted.Network.NetworkID || payment.NetworkDomainDigest != wantNetworkDigest ||
		payment.SettlementAdapterURI != DirectPaymentAdapterURI || string(payment.Destination) != quoted.SourceAccount ||
		payment.ExpiresAtUnix != recovery.ValidUntilUnix || payment.ExpiresAtUnix > request.ExpiresAtUnix ||
		observedAtUnix > uint64(at.UTC().Add(5*time.Minute).Unix()) {
		return errors.New("sponsorship payment evidence conflicts with the exact execution")
	}
	return nil
}

func relaySignedWindowExpired(request RelayExecutionRequest, now time.Time) bool {
	nowSeconds := now.UTC().Unix()
	if nowSeconds < 0 {
		return true
	}
	for _, deadline := range []uint64{
		request.ExpiresAtUnix,
		request.AgreementExpiresAtUnix,
		request.QuoteRequest.Body.ExpiresAtUnix,
		request.ProviderQuote.Body.ExpiresAtUnix,
		request.QuoteRequest.Body.TransactionValidUntilUnix,
		request.AuthorizedAction.ExpiresAtUnix,
		request.WriterFence.Body.ExpiresAtUnix,
	} {
		if deadline == 0 || uint64(nowSeconds) >= deadline {
			return true
		}
	}
	return false
}

// RelayEvidenceSetDigest commits a terminal resolution to the same sorted,
// duplicate-free observation digest set carried by its independently
// verifiable finality evidence. Callers must not pair a signed resolution with
// evidence unless this digest matches exactly.
func RelayEvidenceSetDigest(values []string) (string, error) {
	if !sortedDigests(values, MaxRelayEvidenceRefs) {
		return "", errors.New("relay evidence digest set is invalid")
	}
	// Evidence references are already canonical sorted digests. Reusing the
	// action request digest framing gives a bounded, deterministic set digest.
	encoded := []byte{}
	for _, value := range values {
		encoded = append(encoded, []byte(value)...)
		encoded = append(encoded, 0)
	}
	digest, err := agentcommerce.ExactRequestDigest(encoded)
	if err != nil {
		return "", err
	}
	return digest, nil
}

func mergeEvidenceRefs(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	for _, value := range right {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func digestSetContainsAll(container, required []string) bool {
	if !sortedOptionalDigests(container) || !sortedOptionalDigests(required) {
		return false
	}
	index := 0
	for _, value := range required {
		for index < len(container) && container[index] < value {
			index++
		}
		if index == len(container) || container[index] != value {
			return false
		}
		index++
	}
	return true
}

func agreementObligation(agreement agentcommerce.AgentAgreement, obligationID string) (agentcommerce.AgreementObligation, bool) {
	for _, obligation := range agreement.Body.Obligations {
		if obligation.ObligationID == obligationID {
			return obligation, true
		}
	}
	return agentcommerce.AgreementObligation{}, false
}
