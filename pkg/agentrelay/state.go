package agentrelay

import (
	"bytes"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

var (
	ErrRelayConflict        = errors.New("relay action identity conflicts with the frozen request")
	ErrRelayStaleWriter     = errors.New("relay action uses a stale writer generation")
	ErrRelayInvalidState    = errors.New("relay state transition is invalid")
	ErrRelayUnknown         = errors.New("relay action is unknown")
	ErrRelayExposure        = errors.New("relay provider sponsorship exposure is exhausted")
	ErrRelayAdmissionLimit  = errors.New("relay provider admission limit is exhausted")
	ErrRelayQuoteUnreserved = errors.New("relay provider quote is not reserved")
	ErrRelayQuoteConsumed   = errors.New("relay provider quote reservation was already consumed")
)

// Record is provider-private durable state. SignedTransactionBytes must never
// be emitted through ordinary logs or status APIs.
type Record struct {
	ProviderAgentID                              string
	NetworkDigest                                string
	StableActionID                               string
	ExactRequestDigest                           string
	RelayExecutionDigest                         string
	ProviderQuoteDigest                          string
	AdmissionReceiptDigest                       string
	SignedTransactionDigest                      string
	State                                        agentcommerce.ActionResolutionState
	StateRevision                                uint64
	TransactionReference                         string
	SponsorshipAttempted                         bool
	SponsorshipAgreementPaymentRequestDigest     string
	SponsorshipStableActionID                    string
	SponsorshipExactRequestDigest                string
	SponsorshipValidUntilUnix                    uint64
	SponsorshipRecoveryTokenDigest               string
	SponsorshipTransferReference                 string
	SponsorshipCreditObservation                 *RelaySponsorshipCreditObservation
	SupersededSponsorshipCreditObservationDigest string
	SponsorshipTransactionEvidence               *RelaySponsorshipTransactionEvidence
	SponsorshipAbsenceObservations               []RelayAbsenceObservationReference
	TransactionAbsenceObservations               []RelayAbsenceObservationReference
	SponsorshipAbsenceObservationDigests         []string
	TransactionAbsenceObservationDigests         []string
	AbsenceProofBundleDigest                     string
	AbsenceProofBundle                           []byte
	SupersededAbsenceProofBundleDigest           string
	SponsorshipExposureReleaseEvidenceRefs       []string
	SponsorshipExposureReleasedAtUnix            uint64
	EvidenceRefs                                 []string
	TerminalOutcome                              TerminalOutcome
	CreatedAtUnix                                uint64
	UpdatedAtUnix                                uint64
	request                                      RelayExecutionRequest
	sponsorshipRecoveryToken                     []byte
}

func (record Record) ExecutionRequest() RelayExecutionRequest {
	return cloneExecutionRequest(record.request)
}

// SponsorshipRecoveryToken returns the protected processor-created token used
// only for query-only recovery of an ambiguous top-up. It must never be placed
// in an ordinary status response or log.
func (record Record) SponsorshipRecoveryToken() []byte {
	return append([]byte(nil), record.sponsorshipRecoveryToken...)
}

// SponsorshipRecoveryHandle returns the exact public payment identity and its
// protected processor token. Callers must keep OpaqueToken out of status,
// evidence, and logs.
func (record Record) SponsorshipRecoveryHandle() SponsorshipRecoveryHandle {
	return SponsorshipRecoveryHandle{
		AgreementPaymentRequestDigest: record.SponsorshipAgreementPaymentRequestDigest,
		StableActionID:                record.SponsorshipStableActionID,
		ExactRequestDigest:            record.SponsorshipExactRequestDigest,
		ValidUntilUnix:                record.SponsorshipValidUntilUnix,
		OpaqueToken:                   append([]byte(nil), record.sponsorshipRecoveryToken...),
	}
}

// RecordSnapshot is the durable, non-secret index portion of a provider
// journal record. The exact execution request (including the BOC) is stored in
// the provider's protected payload area and restored through RestoreRecord.
type RecordSnapshot struct {
	ProviderAgentID                              string                               `json:"provider_agent_id"`
	NetworkDigest                                string                               `json:"network_digest"`
	StableActionID                               string                               `json:"stable_action_id"`
	ExactRequestDigest                           string                               `json:"exact_request_digest"`
	RelayExecutionDigest                         string                               `json:"relay_execution_request_digest"`
	ProviderQuoteDigest                          string                               `json:"provider_quote_digest"`
	AdmissionReceiptDigest                       string                               `json:"admission_receipt_digest"`
	SignedTransactionDigest                      string                               `json:"signed_transaction_digest"`
	State                                        agentcommerce.ActionResolutionState  `json:"state"`
	StateRevision                                uint64                               `json:"state_revision"`
	TransactionReference                         string                               `json:"transaction_reference,omitempty"`
	SponsorshipAttempted                         bool                                 `json:"sponsorship_attempted,omitempty"`
	SponsorshipAgreementPaymentRequestDigest     string                               `json:"sponsorship_agreement_payment_request_digest,omitempty"`
	SponsorshipStableActionID                    string                               `json:"sponsorship_stable_action_id,omitempty"`
	SponsorshipExactRequestDigest                string                               `json:"sponsorship_exact_request_digest,omitempty"`
	SponsorshipValidUntilUnix                    uint64                               `json:"sponsorship_valid_until_unix,omitempty"`
	SponsorshipRecoveryTokenDigest               string                               `json:"sponsorship_recovery_token_digest,omitempty"`
	SponsorshipTransferReference                 string                               `json:"sponsorship_transfer_reference,omitempty"`
	SponsorshipCreditObservation                 *RelaySponsorshipCreditObservation   `json:"sponsorship_credit_observation,omitempty"`
	SupersededSponsorshipCreditObservationDigest string                               `json:"superseded_sponsorship_credit_observation_digest,omitempty"`
	SponsorshipTransactionEvidence               *RelaySponsorshipTransactionEvidence `json:"sponsorship_transaction_evidence,omitempty"`
	SponsorshipAbsenceObservations               []RelayAbsenceObservationReference   `json:"sponsorship_absence_observations,omitempty"`
	TransactionAbsenceObservations               []RelayAbsenceObservationReference   `json:"transaction_absence_observations,omitempty"`
	SponsorshipAbsenceObservationDigests         []string                             `json:"sponsorship_absence_observation_digests,omitempty"`
	TransactionAbsenceObservationDigests         []string                             `json:"transaction_absence_observation_digests,omitempty"`
	AbsenceProofBundleDigest                     string                               `json:"absence_proof_bundle_digest,omitempty"`
	AbsenceProofBundle                           []byte                               `json:"absence_proof_bundle,omitempty"`
	SupersededAbsenceProofBundleDigest           string                               `json:"superseded_absence_proof_bundle_digest,omitempty"`
	SponsorshipExposureReleaseEvidenceRefs       []string                             `json:"sponsorship_exposure_release_evidence_refs,omitempty"`
	SponsorshipExposureReleasedAtUnix            uint64                               `json:"sponsorship_exposure_released_at_unix,omitempty"`
	EvidenceRefs                                 []string                             `json:"evidence_refs,omitempty"`
	TerminalOutcome                              TerminalOutcome                      `json:"terminal_outcome,omitempty"`
	CreatedAtUnix                                uint64                               `json:"created_at_unix"`
	UpdatedAtUnix                                uint64                               `json:"updated_at_unix"`
}

func (record Record) Snapshot() RecordSnapshot {
	return RecordSnapshot{ProviderAgentID: record.ProviderAgentID, NetworkDigest: record.NetworkDigest,
		StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		RelayExecutionDigest: record.RelayExecutionDigest, ProviderQuoteDigest: record.ProviderQuoteDigest,
		AdmissionReceiptDigest:  record.AdmissionReceiptDigest,
		SignedTransactionDigest: record.SignedTransactionDigest, State: record.State, StateRevision: record.StateRevision,
		TransactionReference: record.TransactionReference, SponsorshipAttempted: record.SponsorshipAttempted,
		SponsorshipAgreementPaymentRequestDigest:     record.SponsorshipAgreementPaymentRequestDigest,
		SponsorshipStableActionID:                    record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest:                record.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:                    record.SponsorshipValidUntilUnix,
		SponsorshipRecoveryTokenDigest:               record.SponsorshipRecoveryTokenDigest,
		SponsorshipTransferReference:                 record.SponsorshipTransferReference,
		SponsorshipCreditObservation:                 cloneSponsorshipCreditObservation(record.SponsorshipCreditObservation),
		SupersededSponsorshipCreditObservationDigest: record.SupersededSponsorshipCreditObservationDigest,
		SponsorshipTransactionEvidence:               cloneSponsorshipTransactionEvidence(record.SponsorshipTransactionEvidence),
		SponsorshipAbsenceObservations:               append([]RelayAbsenceObservationReference(nil), record.SponsorshipAbsenceObservations...),
		TransactionAbsenceObservations:               append([]RelayAbsenceObservationReference(nil), record.TransactionAbsenceObservations...),
		SponsorshipAbsenceObservationDigests:         append([]string(nil), record.SponsorshipAbsenceObservationDigests...),
		TransactionAbsenceObservationDigests:         append([]string(nil), record.TransactionAbsenceObservationDigests...),
		AbsenceProofBundleDigest:                     record.AbsenceProofBundleDigest,
		AbsenceProofBundle:                           append([]byte(nil), record.AbsenceProofBundle...),
		SupersededAbsenceProofBundleDigest:           record.SupersededAbsenceProofBundleDigest,
		SponsorshipExposureReleaseEvidenceRefs:       append([]string(nil), record.SponsorshipExposureReleaseEvidenceRefs...),
		SponsorshipExposureReleasedAtUnix:            record.SponsorshipExposureReleasedAtUnix,
		EvidenceRefs:                                 append([]string(nil), record.EvidenceRefs...),
		TerminalOutcome:                              record.TerminalOutcome, CreatedAtUnix: record.CreatedAtUnix, UpdatedAtUnix: record.UpdatedAtUnix}
}

// RestoreRecord verifies that a protected exact request is the one committed
// by the public snapshot. It is the only supported way for an external durable
// Journal implementation to construct a recoverable Record.
func RestoreRecord(snapshot RecordSnapshot, request RelayExecutionRequest, protectedRecoveryToken ...[]byte) (Record, error) {
	executionDigest, err := RelayExecutionRequestDigest(request)
	if err != nil {
		return Record{}, err
	}
	networkDigest, err := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	if err != nil {
		return Record{}, err
	}
	quoteDigest, err := ProviderRelayQuoteDigest(request.ProviderQuote.Body)
	if err != nil {
		return Record{}, err
	}
	receiptDigest, err := RelaySideEffectAdmissionReceiptDigest(request.AdmissionReceipt)
	if err != nil {
		return Record{}, err
	}
	if snapshot.ProviderAgentID != request.ProviderQuote.Body.ProviderAgentID || snapshot.NetworkDigest != networkDigest ||
		snapshot.StableActionID != request.AuthorizedAction.StableActionID || snapshot.ExactRequestDigest != request.AuthorizedAction.ExactRequestDigest ||
		snapshot.RelayExecutionDigest != executionDigest || snapshot.ProviderQuoteDigest != quoteDigest ||
		snapshot.AdmissionReceiptDigest != receiptDigest ||
		snapshot.SignedTransactionDigest != request.QuoteRequest.Body.SignedTransactionDigest || snapshot.StateRevision == 0 ||
		snapshot.CreatedAtUnix == 0 || snapshot.UpdatedAtUnix < snapshot.CreatedAtUnix || !sortedOptionalDigests(snapshot.EvidenceRefs) {
		return Record{}, errors.New("relay journal snapshot conflicts with its protected request")
	}
	mode := request.QuoteRequest.Body.Mode
	hasSponsorshipIdentity, validSponsorshipIdentity := validSponsorshipIdentityPair(
		snapshot.SponsorshipStableActionID, snapshot.SponsorshipExactRequestDigest)
	hasSponsorshipPaymentRequest := digestPattern.MatchString(snapshot.SponsorshipAgreementPaymentRequestDigest)
	hasCreditObservation := snapshot.SponsorshipCreditObservation != nil
	hasSupersededCreditObservation := snapshot.SupersededSponsorshipCreditObservationDigest != ""
	hasTransactionEvidence := snapshot.SponsorshipTransactionEvidence != nil
	hasSponsorshipAbsence := len(snapshot.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(snapshot.TransactionAbsenceObservations) != 0
	pendingSponsorshipAbsence := mode == ModeSponsorAndRelay && hasSponsorshipAbsence &&
		!hasTransactionAbsence && snapshot.TerminalOutcome == "" && snapshot.SponsorshipTransferReference == ""
	pendingTransactionResolution := mode == ModeSponsorAndRelay && snapshot.SponsorshipTransferReference != "" &&
		hasTransactionEvidence && !hasSponsorshipAbsence && !hasTransactionAbsence &&
		snapshot.TerminalOutcome == "" && snapshot.State != agentcommerce.ActionTerminal
	hasAnyAbsence := hasSponsorshipAbsence || hasTransactionAbsence ||
		len(snapshot.SponsorshipAbsenceObservationDigests) != 0 ||
		len(snapshot.TransactionAbsenceObservationDigests) != 0 ||
		snapshot.AbsenceProofBundleDigest != "" || len(snapshot.AbsenceProofBundle) != 0 ||
		snapshot.SupersededAbsenceProofBundleDigest != ""
	if !validSponsorshipIdentity ||
		mode == ModeRelayExact && (snapshot.SponsorshipTransferReference != "" || snapshot.SponsorshipAttempted ||
			hasCreditObservation || hasTransactionEvidence ||
			hasSponsorshipIdentity || hasAnyAbsence) ||
		pendingSponsorshipAbsence && !snapshot.SponsorshipAttempted ||
		pendingTransactionResolution && !snapshot.SponsorshipAttempted ||
		snapshot.SponsorshipAttempted && snapshot.SponsorshipTransferReference != "" &&
			!pendingTransactionResolution ||
		snapshot.SponsorshipAttempted && !hasCreditObservation && !pendingSponsorshipAbsence &&
			!pendingTransactionResolution &&
			snapshot.State != agentcommerce.ActionPrepared ||
		hasCreditObservation && (!snapshot.SponsorshipAttempted || hasTransactionEvidence ||
			request.QuoteRequest.Body.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven ||
			(snapshot.State != agentcommerce.ActionPrepared && snapshot.State != agentcommerce.ActionSubmitted &&
				snapshot.State != agentcommerce.ActionAccepted)) ||
		hasTransactionEvidence != (snapshot.SponsorshipTransferReference != "") ||
		snapshot.SponsorshipTransferReference != "" && hasSponsorshipAbsence ||
		hasSupersededCreditObservation && (!hasSponsorshipAbsence ||
			!digestPattern.MatchString(snapshot.SupersededSponsorshipCreditObservationDigest)) ||
		(snapshot.SponsorshipAttempted || snapshot.SponsorshipTransferReference != "" || hasAnyAbsence) != hasSponsorshipIdentity ||
		hasSponsorshipIdentity != hasSponsorshipPaymentRequest ||
		hasSponsorshipIdentity != (snapshot.SponsorshipValidUntilUnix != 0) ||
		snapshot.SponsorshipValidUntilUnix > request.ExpiresAtUnix ||
		snapshot.SponsorshipTransferReference != "" && len(snapshot.EvidenceRefs) == 0 ||
		len(snapshot.SponsorshipTransferReference) > 1024 {
		return Record{}, errors.New("relay journal snapshot carries invalid sponsorship state")
	}
	if hasCreditObservation {
		observation := *snapshot.SponsorshipCreditObservation
		if validateRelaySponsorshipCreditObservationShape(observation) != nil ||
			observation.EvidenceProfileURI != request.QuoteRequest.Body.SponsorshipReleaseProfileURI ||
			observation.EvidenceProfileDigest != request.QuoteRequest.Body.SponsorshipReleaseProfileDigest ||
			observation.AgreementPaymentRequestDigest != snapshot.SponsorshipAgreementPaymentRequestDigest ||
			observation.SponsorshipStableActionID != snapshot.SponsorshipStableActionID ||
			observation.SponsorshipExactRequestDigest != snapshot.SponsorshipExactRequestDigest ||
			observation.ProviderSponsorValidUntilUnix != snapshot.SponsorshipValidUntilUnix {
			return Record{}, errors.New("relay journal snapshot carries invalid sponsorship observation")
		}
	}
	if hasTransactionEvidence {
		evidence := *snapshot.SponsorshipTransactionEvidence
		if validateRelaySponsorshipTransactionEvidenceShape(evidence) != nil ||
			evidence.AgreementPaymentRequestDigest != snapshot.SponsorshipAgreementPaymentRequestDigest ||
			evidence.SponsorshipStableActionID != snapshot.SponsorshipStableActionID ||
			evidence.SponsorshipExactRequestDigest != snapshot.SponsorshipExactRequestDigest ||
			evidence.ProviderSponsorValidUntilUnix != snapshot.SponsorshipValidUntilUnix ||
			evidence.SubmittedTransactionHash != snapshot.SponsorshipTransferReference {
			return Record{}, errors.New("relay journal snapshot carries invalid sponsorship transaction evidence")
		}
	}
	if hasAnyAbsence {
		sponsorshipProfile := request.ProviderQuote.Body.SponsorshipTerminalProfile
		if sponsorshipProfile == nil {
			return Record{}, errors.New("relay journal sponsorship absence lacks its terminal profile")
		}
		transactionProfile := sponsorshipProfile
		if request.ProviderQuote.Body.RelayFinalityProfile != nil {
			transactionProfile = request.ProviderQuote.Body.RelayFinalityProfile
		}
		sponsorshipDigests := relayAbsenceObservationReferenceDigests(snapshot.SponsorshipAbsenceObservations)
		transactionDigests := relayAbsenceObservationReferenceDigests(snapshot.TransactionAbsenceObservations)
		context, contextErr := relayAbsenceContextForRequest(request, SponsorshipRecoveryHandle{
			StableActionID:     snapshot.SponsorshipStableActionID,
			ExactRequestDigest: snapshot.SponsorshipExactRequestDigest,
			ValidUntilUnix:     snapshot.SponsorshipValidUntilUnix,
		}, snapshot.TerminalOutcome, time.Unix(int64(snapshot.UpdatedAtUnix), 0).UTC())
		validated, validationErr := validateRelayAbsenceObservationComponents(snapshot.SponsorshipAbsenceObservations,
			snapshot.TransactionAbsenceObservations, context)
		bundleErr := validateRelayAbsenceProofBundleForBody(RelayFinalityEvidenceBody{
			SponsorshipAbsenceObservations: snapshot.SponsorshipAbsenceObservations,
			TransactionAbsenceObservations: snapshot.TransactionAbsenceObservations,
			AbsenceProofBundleDigest:       snapshot.AbsenceProofBundleDigest,
			AbsenceProofBundle:             snapshot.AbsenceProofBundle,
		})
		merged := mergeSortedDigestSets(sponsorshipDigests, transactionDigests)
		promoted := snapshot.SupersededAbsenceProofBundleDigest != ""
		if promoted && (!digestPattern.MatchString(snapshot.SupersededAbsenceProofBundleDigest) ||
			mode != ModeSponsorAndRelay || !hasSponsorshipAbsence || !hasTransactionAbsence ||
			snapshot.SupersededAbsenceProofBundleDigest == snapshot.AbsenceProofBundleDigest) ||
			!validRelayAbsenceStateShape(mode, snapshot.State, snapshot.TerminalOutcome,
				snapshot.SponsorshipTransferReference, snapshot.TransactionReference,
				hasSponsorshipAbsence, hasTransactionAbsence) ||
			(snapshot.SponsorshipAttempted && !pendingSponsorshipAbsence) ||
			contextErr != nil || validationErr != nil || bundleErr != nil || !equalStrings(validated, merged) ||
			!equalStrings(snapshot.SponsorshipAbsenceObservationDigests, sponsorshipDigests) ||
			!equalStrings(snapshot.TransactionAbsenceObservationDigests, transactionDigests) ||
			hasSponsorshipAbsence && !sortedRequiredDigests(sponsorshipDigests,
				int(sponsorshipProfile.MinimumObservers)) ||
			hasTransactionAbsence && !sortedRequiredDigests(transactionDigests,
				int(transactionProfile.MinimumObservers)) ||
			!digestSetsDisjoint(sponsorshipDigests, transactionDigests) ||
			!sortedOptionalDigests(merged) || !digestSetContainsAll(snapshot.EvidenceRefs, merged) ||
			!validRelayAbsenceOutcomeAssurance(request, snapshot.TerminalOutcome,
				hasSponsorshipAbsence, hasTransactionAbsence, snapshot.SponsorshipTransactionEvidence) {
			return Record{}, errors.New("relay journal snapshot carries invalid sponsorship absence evidence")
		}
	}
	if len(protectedRecoveryToken) > 1 {
		return Record{}, errors.New("relay journal snapshot has multiple protected recovery tokens")
	}
	var recoveryToken []byte
	if len(protectedRecoveryToken) == 1 {
		recoveryToken = protectedRecoveryToken[0]
	}
	recoveryDigest, recoveryErr := sponsorshipRecoveryTokenDigest(recoveryToken)
	if snapshot.SponsorshipAttempted {
		if recoveryErr != nil || recoveryDigest != snapshot.SponsorshipRecoveryTokenDigest {
			return Record{}, errors.New("relay journal sponsorship recovery token conflicts with its digest")
		}
	} else if snapshot.SponsorshipRecoveryTokenDigest != "" || len(recoveryToken) != 0 {
		return Record{}, errors.New("relay journal carries an unexpected sponsorship recovery token")
	}
	released := len(snapshot.SponsorshipExposureReleaseEvidenceRefs) > 0
	if !sortedOptionalDigests(snapshot.SponsorshipExposureReleaseEvidenceRefs) ||
		released != (snapshot.SponsorshipExposureReleasedAtUnix != 0) ||
		released && (snapshot.State != agentcommerce.ActionTerminal || snapshot.SponsorshipTransferReference == "") {
		return Record{}, errors.New("relay journal snapshot carries invalid sponsorship exposure release")
	}
	switch snapshot.State {
	case agentcommerce.ActionPrepared, agentcommerce.ActionSubmitted, agentcommerce.ActionAccepted,
		agentcommerce.ActionRejected, agentcommerce.ActionConflict:
		if snapshot.TerminalOutcome != "" {
			return Record{}, errors.New("nonterminal relay journal snapshot carries a terminal outcome")
		}
	case agentcommerce.ActionTerminal:
		if !validOutcome(snapshot.TerminalOutcome) || len(snapshot.EvidenceRefs) == 0 {
			return Record{}, errors.New("terminal relay journal snapshot lacks evidence")
		}
		if (snapshot.TerminalOutcome == OutcomeFinalizedSponsorshipOnly ||
			snapshot.TerminalOutcome == OutcomeCorroboratedSponsorshipOnly) &&
			(mode == ModeRelayExact || snapshot.SponsorshipTransferReference == "") {
			return Record{}, errors.New("terminal sponsorship outcome conflicts with the relay mode")
		}
		if snapshot.TerminalOutcome == OutcomeCorroboratedSponsorshipOnly &&
			(request.QuoteRequest.Body.AssuranceLevel == AssuranceAutonomousDecentralized ||
				request.ProviderQuote.Body.SponsorshipTerminalProfile == nil ||
				request.ProviderQuote.Body.SponsorshipTerminalProfile.ProfileURI != ClientCorroboratedTerminalProfileURI ||
				snapshot.SponsorshipTransactionEvidence == nil ||
				snapshot.SponsorshipTransactionEvidence.TerminalEvidenceClass != SponsorshipTerminalClientCorroborated ||
				snapshot.SponsorshipTransactionEvidence.ValidatorAuthenticatedPortableProof) {
			return Record{}, errors.New("corroborated sponsorship outcome overstates its assurance")
		}
		if snapshot.TerminalOutcome == OutcomeCorroboratedSuccess &&
			(mode == ModeSponsorOnly || request.QuoteRequest.Body.AssuranceLevel == AssuranceAutonomousDecentralized ||
				!selectedTerminalUsesCorroboration(request, snapshot.SponsorshipTransactionEvidence)) {
			return Record{}, errors.New("corroborated success conflicts with its selected evidence classes")
		}
		if snapshot.TerminalOutcome == OutcomeFinalizedSuccess &&
			selectedTerminalUsesCorroboration(request, snapshot.SponsorshipTransactionEvidence) {
			return Record{}, errors.New("client-corroborated sponsorship was mislabeled as wholly finalized")
		}
	default:
		return Record{}, errors.New("relay journal snapshot state is invalid")
	}
	if !validRelayModeState(mode, snapshot.State, snapshot.TerminalOutcome,
		snapshot.SponsorshipTransferReference, hasCreditObservation,
		hasSponsorshipAbsence, hasTransactionAbsence) {
		return Record{}, errors.New("relay journal snapshot mode and side-effect state conflict")
	}
	return Record{ProviderAgentID: snapshot.ProviderAgentID, NetworkDigest: snapshot.NetworkDigest,
		StableActionID: snapshot.StableActionID, ExactRequestDigest: snapshot.ExactRequestDigest,
		RelayExecutionDigest: snapshot.RelayExecutionDigest, ProviderQuoteDigest: snapshot.ProviderQuoteDigest,
		AdmissionReceiptDigest:  snapshot.AdmissionReceiptDigest,
		SignedTransactionDigest: snapshot.SignedTransactionDigest, State: snapshot.State, StateRevision: snapshot.StateRevision,
		TransactionReference: snapshot.TransactionReference, SponsorshipAttempted: snapshot.SponsorshipAttempted,
		SponsorshipAgreementPaymentRequestDigest:     snapshot.SponsorshipAgreementPaymentRequestDigest,
		SponsorshipStableActionID:                    snapshot.SponsorshipStableActionID,
		SponsorshipExactRequestDigest:                snapshot.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:                    snapshot.SponsorshipValidUntilUnix,
		SponsorshipRecoveryTokenDigest:               snapshot.SponsorshipRecoveryTokenDigest,
		SponsorshipTransferReference:                 snapshot.SponsorshipTransferReference,
		SponsorshipCreditObservation:                 cloneSponsorshipCreditObservation(snapshot.SponsorshipCreditObservation),
		SupersededSponsorshipCreditObservationDigest: snapshot.SupersededSponsorshipCreditObservationDigest,
		SponsorshipTransactionEvidence:               cloneSponsorshipTransactionEvidence(snapshot.SponsorshipTransactionEvidence),
		SponsorshipAbsenceObservations:               append([]RelayAbsenceObservationReference(nil), snapshot.SponsorshipAbsenceObservations...),
		TransactionAbsenceObservations:               append([]RelayAbsenceObservationReference(nil), snapshot.TransactionAbsenceObservations...),
		SponsorshipAbsenceObservationDigests:         append([]string(nil), snapshot.SponsorshipAbsenceObservationDigests...),
		TransactionAbsenceObservationDigests:         append([]string(nil), snapshot.TransactionAbsenceObservationDigests...),
		AbsenceProofBundleDigest:                     snapshot.AbsenceProofBundleDigest,
		AbsenceProofBundle:                           append([]byte(nil), snapshot.AbsenceProofBundle...),
		SupersededAbsenceProofBundleDigest:           snapshot.SupersededAbsenceProofBundleDigest,
		SponsorshipExposureReleaseEvidenceRefs:       append([]string(nil), snapshot.SponsorshipExposureReleaseEvidenceRefs...),
		SponsorshipExposureReleasedAtUnix:            snapshot.SponsorshipExposureReleasedAtUnix,
		EvidenceRefs:                                 append([]string(nil), snapshot.EvidenceRefs...),
		TerminalOutcome:                              snapshot.TerminalOutcome, CreatedAtUnix: snapshot.CreatedAtUnix, UpdatedAtUnix: snapshot.UpdatedAtUnix,
		request: cloneExecutionRequest(request), sponsorshipRecoveryToken: append([]byte(nil), recoveryToken...)}, nil
}

// NewPreparedRecord constructs the exact first durable state for external
// Journal implementations before they atomically publish it. now must be the
// journal's clock at the insertion transaction: the receipt's exclusive start
// boundary is checked against it.
func NewPreparedRecord(request RelayExecutionRequest, verified VerifiedRelayAdmissionReceipt, now time.Time) (Record, error) {
	if err := CheckRelaySideEffectAdmissionReceipt(request.AdmissionReceipt, verified, request, now); err != nil {
		return Record{}, err
	}
	return newPreparedRecordChecked(request, now)
}

// newPreparedRecordChecked builds the prepared record of a request whose
// receipt the caller has just checked at now.
func newPreparedRecordChecked(request RelayExecutionRequest, now time.Time) (Record, error) {
	executionDigest, err := RelayExecutionRequestDigest(request)
	if err != nil {
		return Record{}, err
	}
	networkDigest, err := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	if err != nil {
		return Record{}, err
	}
	quoteDigest, err := ProviderRelayQuoteDigest(request.ProviderQuote.Body)
	if err != nil {
		return Record{}, err
	}
	receiptDigest, err := RelaySideEffectAdmissionReceiptDigest(request.AdmissionReceipt)
	if err != nil {
		return Record{}, err
	}
	return Record{ProviderAgentID: request.ProviderQuote.Body.ProviderAgentID, NetworkDigest: networkDigest,
		StableActionID: request.AuthorizedAction.StableActionID, ExactRequestDigest: request.AuthorizedAction.ExactRequestDigest,
		RelayExecutionDigest: executionDigest, ProviderQuoteDigest: quoteDigest,
		AdmissionReceiptDigest:  receiptDigest,
		SignedTransactionDigest: request.QuoteRequest.Body.SignedTransactionDigest,
		State:                   agentcommerce.ActionPrepared, StateRevision: 1, CreatedAtUnix: uint64(now.UTC().Unix()),
		UpdatedAtUnix: uint64(now.UTC().Unix()), request: cloneExecutionRequest(request)}, nil
}

func (record Record) Resolution() agentcommerce.ActionResolution {
	return agentcommerce.ActionResolution{StableActionID: record.StableActionID, ExactRequestDigest: record.ExactRequestDigest,
		State: record.State, SinkReference: record.TransactionReference, EvidenceRefs: append([]string(nil), record.EvidenceRefs...),
		StateRevision: record.StateRevision}
}

type Journal interface {
	// ReserveQuote atomically creates the provider-wide reservation behind a
	// signed quote. An exact, unconsumed re-quote returns the originally signed
	// quote. Implementations must release expired unconsumed reservations before
	// evaluating MaximumOutstandingAtomic and must never replace a consumed
	// reservation.
	ReserveQuote(RelayServiceProfile, SignedRelayQuoteRequest, SignedProviderRelayQuote, time.Time) (SignedProviderRelayQuote, bool, error)
	// Admit atomically consumes the matching quote reservation while creating
	// the first PREPARED record. No execution can be admitted from a quote that
	// was not reserved by ReserveQuote. The receipt's Action Authority was
	// verified before the call (VerifiedRelayAdmissionReceipt); Admit performs
	// no resolver, helper or network work. It must check the receipt's
	// exclusive start boundary inside the insertion transaction with its
	// current time, measured after any lock wait and never earlier than the
	// supplied time.
	Admit(RelayExecutionRequest, VerifiedRelayAdmissionReceipt, time.Time) (Record, bool, error)
	// BeginSponsorship durably marks that the exact Agreement-bound payment may
	// have been attempted. An expired PREPARED record with this marker cannot be
	// treated as side-effect-free; Submit recovery must query the same payment
	// identity through SponsorshipProcessor. The public payment action identity
	// is retained for evidence; the opaque token is stored only in the protected
	// payload area and Snapshot exposes only its digest.
	BeginSponsorship(stableActionID, exactRequestDigest string, expectedRevision uint64,
		recovery SponsorshipRecoveryHandle, at time.Time) (Record, error)
	// RecordSponsorshipObservation durably records explicit nonterminal RPC
	// corroboration while retaining the protected recovery token. It never
	// permits a second top-up or releases exposure.
	RecordSponsorshipObservation(stableActionID, exactRequestDigest string, expectedRevision uint64,
		observation RelaySponsorshipCreditObservation, at time.Time) (Record, error)
	// RecordSponsorship durably checkpoints independently verified transaction
	// evidence. An exact retry is idempotent; any changed transaction/proof is a
	// conflict. In combined mode it MUST retain the protected recovery token and
	// its digest until the combined action becomes terminal: that token is the
	// only immutable handle to the Provider snapshot needed for S+/R- component
	// verification. The durable transfer reference is the no-successor fence and
	// prevents the retained query token from authorizing another top-up.
	RecordSponsorship(stableActionID, exactRequestDigest string, expectedRevision uint64,
		evidence RelaySponsorshipTransactionEvidence, at time.Time) (Record, error)
	// RecordSponsorshipAbsence records exactly one released absence scope. A
	// sponsor_only action needs only sponsorship absence; combined mode may
	// persist sponsorship-component absence while the client transaction is
	// still resolving, terminalize on dual absence, or retain an already proven
	// sponsorship transfer while transaction-only absence closes the relay leg.
	// A pending sponsorship-only component may be promoted once to a dual bundle
	// only at the expected revision, with byte-identical sponsorship references;
	// the predecessor bundle digest remains in the audit record.
	RecordSponsorshipAbsence(stableActionID, exactRequestDigest string, expectedRevision uint64,
		outcome TerminalOutcome, sponsorshipObservations, transactionObservations []RelayAbsenceObservationReference,
		absenceProofBundleDigest string, absenceProofBundle []byte,
		at time.Time) (Record, error)
	// ReleaseSponsorshipExposure is provider-private accounting admission. It is
	// called only after independently verified reimbursement or an authorized
	// write-off. Relay finality alone never releases actual sponsored value.
	ReleaseSponsorshipExposure(stableActionID, exactRequestDigest string, expectedRevision uint64,
		settlementEvidenceRefs []string, at time.Time) (Record, error)
	Resolve(stableActionID, exactRequestDigest string) (Record, error)
	Transition(stableActionID, exactRequestDigest string, expectedRevision uint64,
		target agentcommerce.ActionResolutionState, transactionReference string, evidenceRefs []string,
		outcome TerminalOutcome, at time.Time) (Record, error)
}

// MemoryJournal is the conformance implementation of atomic relay admission.
// Production providers use the same rules with a rollback-resistant durable
// store and a process/host writer lease.
type MemoryJournal struct {
	mu                  sync.Mutex
	providerAgentID     string
	records             map[string]Record
	quoteReservations   map[string]quoteReservation
	quoteDigestBindings map[string]string
	quoteAdmissions     map[string][]uint64
}

func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{records: make(map[string]Record), quoteReservations: make(map[string]quoteReservation),
		quoteDigestBindings: make(map[string]string),
		quoteAdmissions:     make(map[string][]uint64)}
}

type quoteReservation struct {
	requestDigest       string
	quoteDigest         string
	quote               SignedProviderRelayQuote
	reservedSponsorship *AssetAmount
	expiresAtUnix       uint64
	consumed            bool
	exposureReleased    bool
	stableActionID      string
	executionDigest     string
	admissionLimits     AdmissionLimits
}

func (journal *MemoryJournal) ReserveQuote(profile RelayServiceProfile, request SignedRelayQuoteRequest,
	proposal SignedProviderRelayQuote, now time.Time) (SignedProviderRelayQuote, bool, error) {
	if journal == nil {
		return SignedProviderRelayQuote{}, false, errors.New("relay journal is unavailable")
	}
	requestDigest, err := RelayQuoteRequestDigest(request.Body)
	if err != nil {
		return SignedProviderRelayQuote{}, false, err
	}
	quoteDigest, err := ProviderRelayQuoteDigest(proposal.Body)
	if err != nil {
		return SignedProviderRelayQuote{}, false, err
	}
	profileDigest, err := RelayServiceProfileDigest(profile)
	if err != nil {
		return SignedProviderRelayQuote{}, false, err
	}
	nowSeconds := now.UTC().Unix()
	if nowSeconds < 0 {
		return SignedProviderRelayQuote{}, false, ErrRelayInvalidState
	}
	nowUnix := uint64(nowSeconds)
	if request.Body.ProviderAgentID != profile.ProviderAgentID || proposal.Body.ProviderAgentID != profile.ProviderAgentID ||
		proposal.Body.QuoteRequestDigest != requestDigest || proposal.Body.ServiceProfileDigest != profileDigest ||
		proposal.Body.ExpiresAtUnix <= nowUnix ||
		(request.Body.RequestedSponsorship == nil) != (proposal.Body.ReservedSponsorship == nil) ||
		request.Body.RequestedSponsorship != nil && !sameAmount(*request.Body.RequestedSponsorship, *proposal.Body.ReservedSponsorship) {
		return SignedProviderRelayQuote{}, false, ErrRelayConflict
	}
	key := relayQuoteReservationKey(profile.ProviderAgentID, requestDigest)
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := journal.bindProviderLocked(profile.ProviderAgentID); err != nil {
		return SignedProviderRelayQuote{}, false, err
	}
	journal.releaseExpiredUnconsumedLocked(nowUnix)
	if existing, found := journal.quoteReservations[key]; found {
		if existing.expiresAtUnix > nowUnix {
			return cloneSignedProviderQuote(existing.quote), false, nil
		}
		// Consumed reservations remain immutable even after their quote expires;
		// Resolve, rather than a replacement quote, owns their lifecycle.
		return SignedProviderRelayQuote{}, false, ErrRelayQuoteConsumed
	}
	if bound, found := journal.quoteDigestBindings[quoteDigest]; found && bound != key {
		return SignedProviderRelayQuote{}, false, ErrRelayConflict
	}
	if journal.activeQuoteReservationsLocked() >= uint64(profile.AdmissionLimits.MaximumQuoteReservations) {
		return SignedProviderRelayQuote{}, false, ErrRelayAdmissionLimit
	}
	if proposal.Body.ReservedSponsorship != nil && !journal.canReserveExposureLocked(profile,
		*proposal.Body.ReservedSponsorship) {
		return SignedProviderRelayQuote{}, false, ErrRelayExposure
	}
	if !journal.admitQuoteRateLocked(request.Body.RequesterAgentID, profile.AdmissionLimits, nowUnix) {
		return SignedProviderRelayQuote{}, false, ErrRelayAdmissionLimit
	}
	reservation := quoteReservation{requestDigest: requestDigest, quoteDigest: quoteDigest,
		quote: cloneSignedProviderQuote(proposal), expiresAtUnix: proposal.Body.ExpiresAtUnix,
		admissionLimits: profile.AdmissionLimits}
	if proposal.Body.ReservedSponsorship != nil {
		amount := *proposal.Body.ReservedSponsorship
		reservation.reservedSponsorship = &amount
	}
	journal.quoteReservations[key] = reservation
	journal.quoteDigestBindings[quoteDigest] = key
	return cloneSignedProviderQuote(proposal), true, nil
}

func (journal *MemoryJournal) Admit(request RelayExecutionRequest, verified VerifiedRelayAdmissionReceipt,
	now time.Time) (Record, bool, error) {
	entered := time.Now()
	if journal == nil {
		return Record{}, false, errors.New("relay journal is unavailable")
	}
	if now.UTC().Unix() < 0 {
		return Record{}, false, ErrRelayInvalidState
	}
	executionDigest, err := RelayExecutionRequestDigest(request)
	if err != nil {
		return Record{}, false, err
	}
	quoteDigest, err := ProviderRelayQuoteDigest(request.ProviderQuote.Body)
	if err != nil {
		return Record{}, false, err
	}
	receiptDigest, err := RelaySideEffectAdmissionReceiptDigest(request.AdmissionReceipt)
	if err != nil {
		return Record{}, false, err
	}
	action := request.AuthorizedAction
	key := relayRecordKey(action.StableActionID)
	requestDigest, err := RelayQuoteRequestDigest(request.QuoteRequest.Body)
	if err != nil {
		return Record{}, false, err
	}
	reservationKey := relayQuoteReservationKey(request.ProviderQuote.Body.ProviderAgentID, requestDigest)
	journal.mu.Lock()
	defer journal.mu.Unlock()
	// The start boundary is judged at the insertion instant: the caller's time
	// advanced by everything spent since entry, including the lock wait.
	now = now.Add(time.Since(entered))
	nowUnix := uint64(now.UTC().Unix())
	if err := journal.bindProviderLocked(request.ProviderQuote.Body.ProviderAgentID); err != nil {
		return Record{}, false, err
	}
	if existing, found := journal.records[key]; found {
		if existing.ExactRequestDigest != action.ExactRequestDigest || existing.RelayExecutionDigest != executionDigest ||
			existing.AdmissionReceiptDigest != receiptDigest ||
			existing.SignedTransactionDigest != request.QuoteRequest.Body.SignedTransactionDigest {
			return existing, false, ErrRelayConflict
		}
		return cloneRecord(existing), false, nil
	}
	// The admission receipt is a first-consumption capability. Journal
	// implementations must enforce its exclusive start boundary in the same
	// transaction that creates the durable record, not rely on an earlier
	// coordinator check that may race with inspection or Agreement validation.
	if err := CheckRelaySideEffectAdmissionReceipt(request.AdmissionReceipt, verified, request, now); err != nil {
		return Record{}, false, err
	}
	reservation, found := journal.quoteReservations[reservationKey]
	if !found {
		return Record{}, false, ErrRelayQuoteUnreserved
	}
	if reservation.quoteDigest != quoteDigest || reservation.quote.PublicKey != request.ProviderQuote.PublicKey ||
		reservation.quote.Signature != request.ProviderQuote.Signature {
		return Record{}, false, ErrRelayConflict
	}
	if reservation.expiresAtUnix <= nowUnix {
		if !reservation.consumed {
			journal.deleteQuoteReservationLocked(reservationKey, reservation)
		}
		return Record{}, false, ErrRelayQuoteUnreserved
	}
	if reservation.consumed {
		return Record{}, false, ErrRelayQuoteConsumed
	}
	limits := reservation.admissionLimits
	if limits.MaximumActiveExecutions == 0 ||
		journal.activeExecutionsLocked("") >= uint64(limits.MaximumActiveExecutions) ||
		journal.activeExecutionsLocked(request.QuoteRequest.Body.RequesterAgentID) >=
			uint64(limits.MaximumActivePerRequester) {
		return Record{}, false, ErrRelayAdmissionLimit
	}
	record, err := newPreparedRecordChecked(request, now)
	if err != nil {
		return Record{}, false, err
	}
	journal.records[key] = record
	reservation.consumed = true
	reservation.stableActionID = action.StableActionID
	reservation.executionDigest = executionDigest
	journal.quoteReservations[reservationKey] = reservation
	return cloneRecord(record), true, nil
}

func (journal *MemoryJournal) Resolve(stableActionID, exactRequestDigest string) (Record, error) {
	if journal == nil || !digestPattern.MatchString(stableActionID) || !digestPattern.MatchString(exactRequestDigest) {
		return Record{}, ErrRelayUnknown
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, found := journal.records[relayRecordKey(stableActionID)]
	if !found {
		return Record{}, ErrRelayUnknown
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRecord(record), ErrRelayConflict
	}
	return cloneRecord(record), nil
}

func (journal *MemoryJournal) BeginSponsorship(stableActionID, exactRequestDigest string, expectedRevision uint64,
	recovery SponsorshipRecoveryHandle, at time.Time) (Record, error) {
	recoveryDigest, digestErr := sponsorshipRecoveryTokenDigest(recovery.OpaqueToken)
	hasIdentity, validIdentity := validSponsorshipIdentityPair(recovery.StableActionID, recovery.ExactRequestDigest)
	atSeconds := at.UTC().Unix()
	var recoveryBudget uint64
	if journal != nil {
		// The exact sponsor transaction needs its own inclusion and complete
		// resolution window; the outer relay request having time left is not
		// sufficient if this inner transaction expires immediately.
		recoveryBudget = MinimumRelayInclusionMarginSeconds
	}
	if journal == nil || expectedRevision == 0 || digestErr != nil || !hasIdentity || !validIdentity ||
		!digestPattern.MatchString(recovery.AgreementPaymentRequestDigest) ||
		atSeconds < 0 || recovery.ValidUntilUnix <= uint64(atSeconds) {
		return Record{}, ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, found := journal.records[relayRecordKey(stableActionID)]
	if !found {
		return Record{}, ErrRelayUnknown
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRecord(record), ErrRelayConflict
	}
	if record.State != agentcommerce.ActionPrepared || record.request.QuoteRequest.Body.Mode == ModeRelayExact ||
		record.SponsorshipTransferReference != "" || len(record.SponsorshipAbsenceObservations) != 0 ||
		len(record.TransactionAbsenceObservations) != 0 || record.AbsenceProofBundleDigest != "" ||
		len(record.AbsenceProofBundle) != 0 || recovery.ValidUntilUnix > record.request.ExpiresAtUnix {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if record.request.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		return cloneRecord(record), ErrRelayInvalidState
	}
	recoveryBudget += uint64(record.request.ProviderQuote.Body.SponsorshipTerminalProfile.MaximumResolutionSeconds)
	if !hasStrictRemainingWindow(uint64(atSeconds), recovery.ValidUntilUnix, recoveryBudget) {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if record.SponsorshipAttempted {
		if record.SponsorshipAgreementPaymentRequestDigest != recovery.AgreementPaymentRequestDigest ||
			record.SponsorshipStableActionID != recovery.StableActionID ||
			record.SponsorshipExactRequestDigest != recovery.ExactRequestDigest ||
			record.SponsorshipValidUntilUnix != recovery.ValidUntilUnix ||
			record.SponsorshipRecoveryTokenDigest != recoveryDigest ||
			!bytes.Equal(record.sponsorshipRecoveryToken, recovery.OpaqueToken) {
			return cloneRecord(record), ErrRelayConflict
		}
		return cloneRecord(record), nil
	}
	if record.StateRevision != expectedRevision {
		return cloneRecord(record), ErrRelayInvalidState
	}
	record.SponsorshipAttempted = true
	record.SponsorshipAgreementPaymentRequestDigest = recovery.AgreementPaymentRequestDigest
	record.SponsorshipStableActionID = recovery.StableActionID
	record.SponsorshipExactRequestDigest = recovery.ExactRequestDigest
	record.SponsorshipValidUntilUnix = recovery.ValidUntilUnix
	record.SponsorshipRecoveryTokenDigest = recoveryDigest
	record.sponsorshipRecoveryToken = append([]byte(nil), recovery.OpaqueToken...)
	record.StateRevision++
	record.UpdatedAtUnix = uint64(at.UTC().Unix())
	journal.records[relayRecordKey(stableActionID)] = record
	return cloneRecord(record), nil
}

func (journal *MemoryJournal) RecordSponsorshipObservation(stableActionID, exactRequestDigest string,
	expectedRevision uint64, observation RelaySponsorshipCreditObservation, at time.Time) (Record, error) {
	observationDigest, observationErr := RelaySponsorshipCreditObservationDigest(observation)
	if journal == nil || expectedRevision == 0 || observationErr != nil {
		return Record{}, ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, found := journal.records[relayRecordKey(stableActionID)]
	if !found {
		return Record{}, ErrRelayUnknown
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRecord(record), ErrRelayConflict
	}
	if record.request.QuoteRequest.Body.Mode == ModeRelayExact ||
		record.request.QuoteRequest.Body.AssuranceLevel == AssuranceAutonomousDecentralized ||
		(record.State != agentcommerce.ActionPrepared && record.State != agentcommerce.ActionSubmitted &&
			record.State != agentcommerce.ActionAccepted) || record.SponsorshipTransferReference != "" {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if record.SponsorshipCreditObservation != nil {
		existingDigest, err := RelaySponsorshipCreditObservationDigest(*record.SponsorshipCreditObservation)
		if err == nil && existingDigest == observationDigest {
			return cloneRecord(record), nil
		}
		if err != nil || !sameObservedSponsorshipCredit(*record.SponsorshipCreditObservation, observation) ||
			observation.ObservedAtUnix < record.SponsorshipCreditObservation.ObservedAtUnix ||
			observation.ObservedCheckpointSequence < record.SponsorshipCreditObservation.ObservedCheckpointSequence ||
			record.StateRevision != expectedRevision {
			return cloneRecord(record), ErrRelayConflict
		}
		record.SponsorshipCreditObservation = cloneSponsorshipCreditObservation(&observation)
		record.StateRevision++
		record.UpdatedAtUnix = uint64(at.UTC().Unix())
		journal.records[relayRecordKey(stableActionID)] = record
		return cloneRecord(record), nil
	}
	if !record.SponsorshipAttempted || !validSponsorshipIdentity(record.SponsorshipStableActionID,
		record.SponsorshipExactRequestDigest) ||
		observation.AgreementPaymentRequestDigest != record.SponsorshipAgreementPaymentRequestDigest ||
		observation.SponsorshipStableActionID != record.SponsorshipStableActionID ||
		observation.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest ||
		observation.ProviderSponsorValidUntilUnix != record.SponsorshipValidUntilUnix {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if record.StateRevision != expectedRevision {
		return cloneRecord(record), ErrRelayInvalidState
	}
	record.SponsorshipCreditObservation = cloneSponsorshipCreditObservation(&observation)
	record.StateRevision++
	record.UpdatedAtUnix = uint64(at.UTC().Unix())
	journal.records[relayRecordKey(stableActionID)] = record
	return cloneRecord(record), nil
}

func (journal *MemoryJournal) RecordSponsorship(stableActionID, exactRequestDigest string, expectedRevision uint64,
	evidence RelaySponsorshipTransactionEvidence, at time.Time) (Record, error) {
	evidenceDigest, evidenceErr := RelaySponsorshipTransactionEvidenceDigest(evidence)
	if journal == nil || expectedRevision == 0 || evidenceErr != nil {
		return Record{}, ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, found := journal.records[relayRecordKey(stableActionID)]
	if !found {
		return Record{}, ErrRelayUnknown
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRecord(record), ErrRelayConflict
	}
	if record.request.QuoteRequest.Body.Mode == ModeRelayExact ||
		(record.State != agentcommerce.ActionPrepared && record.State != agentcommerce.ActionSubmitted &&
			record.State != agentcommerce.ActionAccepted) {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if record.SponsorshipTransactionEvidence != nil {
		existingDigest, err := RelaySponsorshipTransactionEvidenceDigest(*record.SponsorshipTransactionEvidence)
		if err != nil || existingDigest != evidenceDigest {
			return cloneRecord(record), ErrRelayConflict
		}
		return cloneRecord(record), nil
	}
	if !record.SponsorshipAttempted || !validSponsorshipIdentity(record.SponsorshipStableActionID,
		record.SponsorshipExactRequestDigest) ||
		evidence.AgreementPaymentRequestDigest != record.SponsorshipAgreementPaymentRequestDigest ||
		evidence.SponsorshipStableActionID != record.SponsorshipStableActionID ||
		evidence.SponsorshipExactRequestDigest != record.SponsorshipExactRequestDigest ||
		evidence.ProviderSponsorValidUntilUnix != record.SponsorshipValidUntilUnix ||
		(record.SponsorshipCreditObservation != nil &&
			!sameObservedSponsorshipTransaction(*record.SponsorshipCreditObservation, evidence)) {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if record.StateRevision != expectedRevision {
		return cloneRecord(record), ErrRelayInvalidState
	}
	record.SponsorshipTransferReference = evidence.SubmittedTransactionHash
	record.SponsorshipTransactionEvidence = cloneSponsorshipTransactionEvidence(&evidence)
	record.SponsorshipCreditObservation = nil
	if record.request.QuoteRequest.Body.Mode != ModeSponsorAndRelay {
		record.SponsorshipAttempted = false
		record.SponsorshipRecoveryTokenDigest = ""
		record.sponsorshipRecoveryToken = nil
	}
	record.EvidenceRefs = append([]string(nil), evidence.ObservationDigests...)
	record.StateRevision++
	record.UpdatedAtUnix = uint64(at.UTC().Unix())
	journal.records[relayRecordKey(stableActionID)] = record
	return cloneRecord(record), nil
}

func (journal *MemoryJournal) RecordSponsorshipAbsence(stableActionID, exactRequestDigest string,
	expectedRevision uint64, outcome TerminalOutcome, sponsorshipObservations,
	transactionObservations []RelayAbsenceObservationReference, absenceProofBundleDigest string,
	absenceProofBundle []byte, at time.Time) (Record, error) {
	if journal == nil || expectedRevision == 0 || outcome != "" && !validOutcome(outcome) {
		return Record{}, ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	key := relayRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return Record{}, ErrRelayUnknown
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRecord(record), ErrRelayConflict
	}
	sponsorshipObservationDigests := relayAbsenceObservationReferenceDigests(sponsorshipObservations)
	transactionObservationDigests := relayAbsenceObservationReferenceDigests(transactionObservations)
	promotingComponentToDual := false
	if len(record.SponsorshipAbsenceObservations)+len(record.TransactionAbsenceObservations) != 0 &&
		validSponsorshipAbsenceRecord(record) {
		exactReplay := record.TerminalOutcome == outcome &&
			equalStrings(record.SponsorshipAbsenceObservationDigests, sponsorshipObservationDigests) &&
			equalStrings(record.TransactionAbsenceObservationDigests, transactionObservationDigests) &&
			record.AbsenceProofBundleDigest == absenceProofBundleDigest &&
			bytes.Equal(record.AbsenceProofBundle, absenceProofBundle)
		if exactReplay {
			return cloneRecord(record), nil
		}
		promotingComponentToDual = record.request.QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
			record.State != agentcommerce.ActionTerminal && record.TerminalOutcome == "" &&
			len(record.SponsorshipAbsenceObservations) != 0 &&
			len(record.TransactionAbsenceObservations) == 0 && len(transactionObservations) != 0 &&
			equalStrings(record.SponsorshipAbsenceObservationDigests, sponsorshipObservationDigests) &&
			safeTerminalAbsenceOutcome(outcome)
		if !promotingComponentToDual {
			return cloneRecord(record), ErrRelayConflict
		}
	}
	absenceContext, contextErr := relayAbsenceContextForRequest(record.request,
		record.SponsorshipRecoveryHandle(), outcome, at)
	if contextErr != nil {
		return cloneRecord(record), ErrRelayInvalidState
	}
	merged, observationsErr := validateRelayAbsenceObservationComponents(sponsorshipObservations,
		transactionObservations, absenceContext)
	bundleErr := validateRelayAbsenceProofBundleForBody(RelayFinalityEvidenceBody{
		SponsorshipAbsenceObservations: sponsorshipObservations,
		TransactionAbsenceObservations: transactionObservations,
		AbsenceProofBundleDigest:       absenceProofBundleDigest,
		AbsenceProofBundle:             absenceProofBundle,
	})
	if observationsErr != nil || bundleErr != nil {
		return cloneRecord(record), ErrRelayInvalidState
	}
	hasSponsorshipAbsence := len(sponsorshipObservations) != 0
	hasTransactionAbsence := len(transactionObservations) != 0
	mode := record.request.QuoteRequest.Body.Mode
	validScope := mode == ModeSponsorOnly && hasSponsorshipAbsence && !hasTransactionAbsence &&
		record.SponsorshipTransferReference == "" && record.SponsorshipAttempted && safeTerminalAbsenceOutcome(outcome) ||
		mode == ModeSponsorAndRelay && hasSponsorshipAbsence && hasTransactionAbsence &&
			record.SponsorshipTransferReference == "" && record.SponsorshipAttempted && safeTerminalAbsenceOutcome(outcome) ||
		mode == ModeSponsorAndRelay && hasSponsorshipAbsence && !hasTransactionAbsence &&
			record.SponsorshipTransferReference == "" && record.SponsorshipAttempted && outcome == "" ||
		mode == ModeSponsorAndRelay && !hasSponsorshipAbsence && hasTransactionAbsence &&
			record.SponsorshipTransferReference != "" && record.SponsorshipAttempted &&
			record.SponsorshipTransactionEvidence != nil &&
			(outcome == OutcomeFinalizedSponsorshipOnly || outcome == OutcomeCorroboratedSponsorshipOnly)
	validScope = validScope || promotingComponentToDual && hasSponsorshipAbsence && hasTransactionAbsence &&
		record.SponsorshipTransferReference == "" && safeTerminalAbsenceOutcome(outcome)
	if (record.State != agentcommerce.ActionPrepared && record.State != agentcommerce.ActionSubmitted &&
		record.State != agentcommerce.ActionAccepted) || !validScope ||
		!validSponsorshipIdentity(record.SponsorshipStableActionID, record.SponsorshipExactRequestDigest) ||
		record.StateRevision != expectedRevision ||
		!sortedOptionalDigests(merged) || !validRelayAbsenceOutcomeAssurance(record.request, outcome,
		hasSponsorshipAbsence, hasTransactionAbsence, record.SponsorshipTransactionEvidence) {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if hasSponsorshipAbsence && record.SponsorshipCreditObservation != nil {
		observationDigest, err := RelaySponsorshipCreditObservationDigest(*record.SponsorshipCreditObservation)
		if err != nil {
			return cloneRecord(record), ErrRelayInvalidState
		}
		record.SupersededSponsorshipCreditObservationDigest = observationDigest
		record.SponsorshipCreditObservation = nil
	}
	pendingSponsorshipComponent := mode == ModeSponsorAndRelay && hasSponsorshipAbsence &&
		!hasTransactionAbsence && outcome == ""
	if hasSponsorshipAbsence && !pendingSponsorshipComponent {
		record.SponsorshipAttempted = false
		record.SponsorshipRecoveryTokenDigest = ""
		record.sponsorshipRecoveryToken = nil
	}
	record.SponsorshipAbsenceObservations = append([]RelayAbsenceObservationReference(nil),
		sponsorshipObservations...)
	record.TransactionAbsenceObservations = append([]RelayAbsenceObservationReference(nil),
		transactionObservations...)
	record.SponsorshipAbsenceObservationDigests = append([]string(nil), sponsorshipObservationDigests...)
	record.TransactionAbsenceObservationDigests = append([]string(nil), transactionObservationDigests...)
	if promotingComponentToDual {
		record.SupersededAbsenceProofBundleDigest = record.AbsenceProofBundleDigest
	}
	record.AbsenceProofBundleDigest = absenceProofBundleDigest
	record.AbsenceProofBundle = append([]byte(nil), absenceProofBundle...)
	terminal := mode == ModeSponsorOnly || hasTransactionAbsence
	if terminal {
		record.State = agentcommerce.ActionTerminal
		record.SponsorshipAttempted = false
		record.SponsorshipRecoveryTokenDigest = ""
		record.sponsorshipRecoveryToken = nil
	}
	record.StateRevision++
	if terminal {
		if record.SponsorshipTransferReference != "" {
			record.TransactionReference = record.SponsorshipTransferReference
		} else {
			record.TransactionReference = ""
		}
	}
	record.EvidenceRefs = mergeEvidenceRefs(record.EvidenceRefs, merged)
	record.TerminalOutcome = outcome
	record.UpdatedAtUnix = uint64(at.UTC().Unix())
	journal.records[key] = record
	if terminal {
		journal.releaseRecordExposureLocked(record)
	}
	return cloneRecord(record), nil
}

func (journal *MemoryJournal) ReleaseSponsorshipExposure(stableActionID, exactRequestDigest string,
	expectedRevision uint64, settlementEvidenceRefs []string, at time.Time) (Record, error) {
	if journal == nil || expectedRevision == 0 || len(settlementEvidenceRefs) == 0 ||
		!sortedOptionalDigests(settlementEvidenceRefs) {
		return Record{}, ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, found := journal.records[relayRecordKey(stableActionID)]
	if !found {
		return Record{}, ErrRelayUnknown
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRecord(record), ErrRelayConflict
	}
	if len(record.SponsorshipExposureReleaseEvidenceRefs) > 0 {
		if !equalStrings(record.SponsorshipExposureReleaseEvidenceRefs, settlementEvidenceRefs) {
			return cloneRecord(record), ErrRelayConflict
		}
		return cloneRecord(record), nil
	}
	if record.StateRevision != expectedRevision || record.State != agentcommerce.ActionTerminal ||
		record.SponsorshipTransferReference == "" {
		return cloneRecord(record), ErrRelayInvalidState
	}
	record.SponsorshipExposureReleaseEvidenceRefs = append([]string(nil), settlementEvidenceRefs...)
	record.SponsorshipExposureReleasedAtUnix = uint64(at.UTC().Unix())
	record.StateRevision++
	record.UpdatedAtUnix = uint64(at.UTC().Unix())
	journal.records[relayRecordKey(stableActionID)] = record
	journal.releaseRecordExposureLocked(record)
	return cloneRecord(record), nil
}

func (journal *MemoryJournal) Transition(stableActionID, exactRequestDigest string, expectedRevision uint64,
	target agentcommerce.ActionResolutionState, transactionReference string, evidenceRefs []string,
	outcome TerminalOutcome, at time.Time) (Record, error) {
	if journal == nil || expectedRevision == 0 || !sortedOptionalDigests(evidenceRefs) || len(transactionReference) > 1024 {
		return Record{}, ErrRelayInvalidState
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	key := relayRecordKey(stableActionID)
	record, found := journal.records[key]
	if !found {
		return Record{}, ErrRelayUnknown
	}
	if record.ExactRequestDigest != exactRequestDigest {
		return cloneRecord(record), ErrRelayConflict
	}
	if record.StateRevision != expectedRevision || !validRelayTransition(record.State, target) {
		return cloneRecord(record), ErrRelayInvalidState
	}
	pendingSponsorshipAbsence := len(record.SponsorshipAbsenceObservations) != 0 &&
		len(record.TransactionAbsenceObservations) == 0 && record.SponsorshipTransferReference == "" &&
		record.SponsorshipCreditObservation == nil && record.TerminalOutcome == ""
	terminalRelayOnly := target == agentcommerce.ActionTerminal && pendingSponsorshipAbsence &&
		(outcome == OutcomeFinalizedRelayOnly || outcome == OutcomeCorroboratedRelayOnly)
	retainedSuccessfulSponsorship := record.SponsorshipAttempted &&
		record.request.QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
		record.SponsorshipTransferReference != "" && record.SponsorshipTransactionEvidence != nil
	if record.SponsorshipAttempted && !terminalRelayOnly && !retainedSuccessfulSponsorship &&
		(record.SponsorshipCreditObservation == nil ||
			(target != agentcommerce.ActionSubmitted && target != agentcommerce.ActionAccepted)) {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if target == agentcommerce.ActionTerminal {
		if !validOutcome(outcome) || len(evidenceRefs) == 0 {
			return cloneRecord(record), ErrRelayInvalidState
		}
	} else if outcome != "" {
		return cloneRecord(record), ErrRelayInvalidState
	}
	if !validRelayModeState(record.request.QuoteRequest.Body.Mode, target, outcome,
		record.SponsorshipTransferReference, record.SponsorshipCreditObservation != nil,
		len(record.SponsorshipAbsenceObservations) != 0,
		len(record.TransactionAbsenceObservations) != 0) {
		return cloneRecord(record), ErrRelayInvalidState
	}
	record.State = target
	record.StateRevision++
	record.TransactionReference = transactionReference
	record.EvidenceRefs = append([]string(nil), evidenceRefs...)
	record.TerminalOutcome = outcome
	if target == agentcommerce.ActionTerminal {
		record.SponsorshipAttempted = false
		record.SponsorshipRecoveryTokenDigest = ""
		record.sponsorshipRecoveryToken = nil
	}
	record.UpdatedAtUnix = uint64(at.UTC().Unix())
	journal.records[key] = record
	if target == agentcommerce.ActionRejected || target == agentcommerce.ActionConflict || target == agentcommerce.ActionTerminal {
		journal.releaseRecordExposureLocked(record)
	}
	return cloneRecord(record), nil
}

func (journal *MemoryJournal) bindProviderLocked(providerAgentID string) error {
	if journal.providerAgentID == "" {
		journal.providerAgentID = providerAgentID
	}
	if journal.providerAgentID != providerAgentID {
		return errors.New("relay journal is scoped to a different provider")
	}
	return nil
}

func (journal *MemoryJournal) releaseExpiredUnconsumedLocked(nowUnix uint64) {
	for key, reservation := range journal.quoteReservations {
		if !reservation.consumed && reservation.expiresAtUnix <= nowUnix {
			journal.deleteQuoteReservationLocked(key, reservation)
		}
	}
}

func (journal *MemoryJournal) deleteQuoteReservationLocked(key string, reservation quoteReservation) {
	delete(journal.quoteReservations, key)
	if journal.quoteDigestBindings[reservation.quoteDigest] == key {
		delete(journal.quoteDigestBindings, reservation.quoteDigest)
	}
}

func (journal *MemoryJournal) canReserveExposureLocked(profile RelayServiceProfile, requested AssetAmount) bool {
	limit, found := findExposureLimit(profile.ExposureLimits, requested.Asset)
	if !found || compareAtomic(requested.AmountAtomic, limit.MaximumPerRequestAtomic) > 0 {
		return false
	}
	total := "0"
	for _, reservation := range journal.quoteReservations {
		if reservation.exposureReleased || reservation.reservedSponsorship == nil ||
			!sameAsset(reservation.reservedSponsorship.Asset, requested.Asset) {
			continue
		}
		total = addAtomic(total, reservation.reservedSponsorship.AmountAtomic)
	}
	total = addAtomic(total, requested.AmountAtomic)
	return compareAtomic(total, limit.MaximumOutstandingAtomic) <= 0
}

func (journal *MemoryJournal) activeQuoteReservationsLocked() uint64 {
	var count uint64
	for _, reservation := range journal.quoteReservations {
		if !reservation.consumed {
			count++
		}
	}
	return count
}

func (journal *MemoryJournal) activeExecutionsLocked(requesterAgentID string) uint64 {
	var count uint64
	for _, record := range journal.records {
		if record.State == agentcommerce.ActionTerminal || record.State == agentcommerce.ActionRejected ||
			record.State == agentcommerce.ActionConflict {
			continue
		}
		if requesterAgentID == "" || record.request.QuoteRequest.Body.RequesterAgentID == requesterAgentID {
			count++
		}
	}
	return count
}

func (journal *MemoryJournal) admitQuoteRateLocked(requesterAgentID string, limits AdmissionLimits,
	nowUnix uint64) bool {
	window := uint64(limits.QuoteRequestWindowSeconds)
	cutoff := uint64(0)
	if nowUnix > window {
		cutoff = nowUnix - window
	}
	const globalBucket = "\x00provider-global"
	global := pruneRelayAdmissionTimes(journal.quoteAdmissions[globalBucket], cutoff)
	requester := pruneRelayAdmissionTimes(journal.quoteAdmissions[requesterAgentID], cutoff)
	journal.quoteAdmissions[globalBucket] = global
	journal.quoteAdmissions[requesterAgentID] = requester
	if len(global) >= int(limits.MaximumQuoteRequestsPerWindow) ||
		len(requester) >= int(limits.MaximumQuoteRequestsPerRequesterWindow) {
		return false
	}
	journal.quoteAdmissions[globalBucket] = append(global, nowUnix)
	journal.quoteAdmissions[requesterAgentID] = append(requester, nowUnix)
	return true
}

func pruneRelayAdmissionTimes(admissions []uint64, cutoff uint64) []uint64 {
	first := 0
	for first < len(admissions) && admissions[first] <= cutoff {
		first++
	}
	if first == len(admissions) {
		return nil
	}
	return append([]uint64(nil), admissions[first:]...)
}

func (journal *MemoryJournal) releaseRecordExposureLocked(record Record) {
	requestDigest, err := RelayQuoteRequestDigest(record.request.QuoteRequest.Body)
	if err != nil {
		return
	}
	key := relayQuoteReservationKey(record.ProviderAgentID, requestDigest)
	reservation, found := journal.quoteReservations[key]
	if !found || !reservation.consumed || reservation.stableActionID != record.StableActionID ||
		reservation.executionDigest != record.RelayExecutionDigest {
		return
	}
	if record.SponsorshipTransferReference != "" && len(record.SponsorshipExposureReleaseEvidenceRefs) == 0 {
		return
	}
	reservation.exposureReleased = true
	journal.quoteReservations[key] = reservation
}

func validRelayTransition(from, to agentcommerce.ActionResolutionState) bool {
	switch from {
	case agentcommerce.ActionPrepared:
		return to == agentcommerce.ActionSubmitted || to == agentcommerce.ActionRejected || to == agentcommerce.ActionConflict || to == agentcommerce.ActionTerminal
	case agentcommerce.ActionSubmitted:
		return to == agentcommerce.ActionAccepted || to == agentcommerce.ActionRejected || to == agentcommerce.ActionConflict || to == agentcommerce.ActionTerminal
	case agentcommerce.ActionAccepted:
		// accepted is tentative. A reorg may return it to submitted while the
		// exact bytes and action identity remain frozen.
		return to == agentcommerce.ActionSubmitted || to == agentcommerce.ActionTerminal
	default:
		return false
	}
}

func validRelayModeState(mode Mode, state agentcommerce.ActionResolutionState, outcome TerminalOutcome,
	sponsorshipReference string, sponsorshipObserved, sponsorshipAbsent, transactionAbsent bool) bool {
	sponsored := sponsorshipReference != ""
	sponsorshipPresent := sponsored || sponsorshipObserved
	switch mode {
	case ModeRelayExact:
		return !sponsorshipPresent && !sponsorshipAbsent && !transactionAbsent &&
			outcome != OutcomeFinalizedSponsorshipOnly && outcome != OutcomeCorroboratedSponsorshipOnly
	case ModeSponsorOnly:
		if transactionAbsent {
			return false
		}
		if sponsorshipObserved {
			return (state == agentcommerce.ActionPrepared || state == agentcommerce.ActionSubmitted) &&
				outcome == "" && !sponsorshipAbsent
		}
		if state == agentcommerce.ActionSubmitted || state == agentcommerce.ActionAccepted ||
			sponsorshipPresent && (state == agentcommerce.ActionRejected || state == agentcommerce.ActionConflict) {
			return false
		}
		return state != agentcommerce.ActionTerminal ||
			sponsored && !sponsorshipAbsent &&
				(outcome == OutcomeFinalizedSponsorshipOnly || outcome == OutcomeCorroboratedSponsorshipOnly) ||
			!sponsored && sponsorshipAbsent && safeTerminalAbsenceOutcome(outcome)
	case ModeSponsorAndRelay:
		if sponsorshipPresent && (state == agentcommerce.ActionRejected || state == agentcommerce.ActionConflict) {
			return false
		}
		if state == agentcommerce.ActionSubmitted || state == agentcommerce.ActionAccepted {
			return sponsorshipPresent && !sponsorshipAbsent && !transactionAbsent ||
				!sponsorshipPresent && sponsorshipAbsent && !transactionAbsent && outcome == ""
		}
		if state == agentcommerce.ActionTerminal {
			return sponsored && !sponsorshipAbsent && !transactionAbsent &&
				(outcome == OutcomeFinalizedSuccess || outcome == OutcomeFinalizedSponsorshipOnly ||
					outcome == OutcomeCorroboratedSponsorshipOnly ||
					outcome == OutcomeCorroboratedSuccess) ||
				sponsored && !sponsorshipAbsent && transactionAbsent &&
					(outcome == OutcomeFinalizedSponsorshipOnly ||
						outcome == OutcomeCorroboratedSponsorshipOnly) ||
				!sponsorshipPresent && sponsorshipAbsent && !transactionAbsent &&
					(outcome == OutcomeFinalizedRelayOnly || outcome == OutcomeCorroboratedRelayOnly) ||
				!sponsorshipPresent && sponsorshipAbsent && transactionAbsent &&
					safeTerminalAbsenceOutcome(outcome)
		}
		if state == agentcommerce.ActionPrepared && sponsorshipAbsent && !transactionAbsent &&
			!sponsorshipPresent && outcome == "" {
			return true
		}
		return !sponsorshipAbsent && !transactionAbsent
	default:
		return false
	}
}

func relayRecordKey(stableActionID string) string {
	return stableActionID
}

func relayQuoteReservationKey(providerAgentID, requestDigest string) string {
	return providerAgentID + "\x00" + requestDigest
}

func sortedOptionalDigests(values []string) bool {
	if len(values) > MaxRelayEvidenceRefs {
		return false
	}
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	for index, value := range values {
		if !digestPattern.MatchString(value) || value != copyValues[index] || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func sortedRequiredDigests(values []string, minimum int) bool {
	return minimum > 0 && len(values) >= minimum && sortedOptionalDigests(values)
}

func mergeSortedDigestSets(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	for _, value := range right {
		seen[value] = struct{}{}
	}
	merged := make([]string, 0, len(seen))
	for value := range seen {
		merged = append(merged, value)
	}
	sort.Strings(merged)
	return merged
}

func digestSetsDisjoint(left, right []string) bool {
	rightValues := make(map[string]struct{}, len(right))
	for _, value := range right {
		rightValues[value] = struct{}{}
	}
	for _, value := range left {
		if _, found := rightValues[value]; found {
			return false
		}
	}
	return true
}

func validSponsorshipIdentity(stableActionID, exactRequestDigest string) bool {
	return digestPattern.MatchString(stableActionID) && digestPattern.MatchString(exactRequestDigest)
}

func validSponsorshipIdentityPair(stableActionID, exactRequestDigest string) (bool, bool) {
	if stableActionID == "" && exactRequestDigest == "" {
		return false, true
	}
	return true, validSponsorshipIdentity(stableActionID, exactRequestDigest)
}

func safeTerminalAbsenceOutcome(outcome TerminalOutcome) bool {
	return outcome == OutcomeFinalizedExpired || outcome == OutcomeFinalizedAbsent ||
		outcome == OutcomeFinalizedInvalidated || outcome == OutcomeCorroboratedExpired ||
		outcome == OutcomeCorroboratedAbsent || outcome == OutcomeCorroboratedInvalidated
}

func selectedTerminalUsesCorroboration(request RelayExecutionRequest,
	sponsorship *RelaySponsorshipTransactionEvidence) bool {
	if request.QuoteRequest.Body.RelayTerminalEvidenceClass == RelayTerminalProviderCorroborated {
		return true
	}
	return sponsorship != nil && sponsorship.TerminalEvidenceClass == SponsorshipTerminalClientCorroborated
}

func validRelayAbsenceStateShape(mode Mode, state agentcommerce.ActionResolutionState, outcome TerminalOutcome,
	sponsorshipReference, transactionReference string, sponsorshipAbsent, transactionAbsent bool) bool {
	if !sponsorshipAbsent && !transactionAbsent {
		return false
	}
	if state != agentcommerce.ActionTerminal {
		return mode == ModeSponsorAndRelay && sponsorshipAbsent && !transactionAbsent &&
			sponsorshipReference == "" && outcome == "" &&
			(state == agentcommerce.ActionPrepared || state == agentcommerce.ActionSubmitted ||
				state == agentcommerce.ActionAccepted)
	}
	switch mode {
	case ModeSponsorOnly:
		return sponsorshipAbsent && !transactionAbsent && sponsorshipReference == "" &&
			transactionReference == "" && safeTerminalAbsenceOutcome(outcome)
	case ModeSponsorAndRelay:
		switch {
		case sponsorshipAbsent && transactionAbsent:
			return sponsorshipReference == "" && transactionReference == "" && safeTerminalAbsenceOutcome(outcome)
		case sponsorshipAbsent:
			return sponsorshipReference == "" && transactionReference != "" &&
				(outcome == OutcomeFinalizedRelayOnly || outcome == OutcomeCorroboratedRelayOnly)
		case transactionAbsent:
			return sponsorshipReference != "" && transactionReference == sponsorshipReference &&
				(outcome == OutcomeFinalizedSponsorshipOnly || outcome == OutcomeCorroboratedSponsorshipOnly)
		}
	}
	return false
}

func validRelayAbsenceOutcomeAssurance(request RelayExecutionRequest, outcome TerminalOutcome,
	sponsorshipAbsent, transactionAbsent bool,
	sponsorshipEvidence *RelaySponsorshipTransactionEvidence) bool {
	// A pending sponsorship-component observation has no terminal label yet.
	if outcome == "" {
		return request.QuoteRequest.Body.Mode == ModeSponsorAndRelay && sponsorshipAbsent && !transactionAbsent
	}
	allValidator := true
	if sponsorshipAbsent {
		profile := request.ProviderQuote.Body.SponsorshipTerminalProfile
		allValidator = profile != nil &&
			profile.TerminalEvidenceClass == SponsorshipTerminalValidatorFinality
	} else {
		allValidator = sponsorshipEvidence != nil &&
			sponsorshipEvidence.TerminalEvidenceClass == SponsorshipTerminalValidatorFinality &&
			sponsorshipEvidence.ValidatorAuthenticatedPortableProof
	}
	if request.QuoteRequest.Body.Mode == ModeSponsorAndRelay &&
		(transactionAbsent || outcome == OutcomeFinalizedRelayOnly || outcome == OutcomeCorroboratedRelayOnly) {
		profile := request.ProviderQuote.Body.RelayFinalityProfile
		allValidator = allValidator && profile != nil &&
			profile.TerminalEvidenceClass == RelayTerminalValidatorFinality
	}
	finalized := outcome == OutcomeFinalizedExpired || outcome == OutcomeFinalizedAbsent ||
		outcome == OutcomeFinalizedInvalidated || outcome == OutcomeFinalizedRelayOnly ||
		outcome == OutcomeFinalizedSponsorshipOnly
	corroborated := outcome == OutcomeCorroboratedExpired || outcome == OutcomeCorroboratedAbsent ||
		outcome == OutcomeCorroboratedInvalidated || outcome == OutcomeCorroboratedRelayOnly ||
		outcome == OutcomeCorroboratedSponsorshipOnly
	return allValidator && finalized || !allValidator && corroborated &&
		request.QuoteRequest.Body.AssuranceLevel != AssuranceAutonomousDecentralized
}

func validSponsorshipAbsenceRecord(record Record) bool {
	sponsorshipProfile := record.request.ProviderQuote.Body.SponsorshipTerminalProfile
	if sponsorshipProfile == nil {
		return false
	}
	transactionProfile := sponsorshipProfile
	if record.request.ProviderQuote.Body.RelayFinalityProfile != nil {
		transactionProfile = record.request.ProviderQuote.Body.RelayFinalityProfile
	}
	sponsorshipDigests := relayAbsenceObservationReferenceDigests(record.SponsorshipAbsenceObservations)
	transactionDigests := relayAbsenceObservationReferenceDigests(record.TransactionAbsenceObservations)
	context, contextErr := relayAbsenceContextForRequest(record.request, SponsorshipRecoveryHandle{
		StableActionID:     record.SponsorshipStableActionID,
		ExactRequestDigest: record.SponsorshipExactRequestDigest,
		ValidUntilUnix:     record.SponsorshipValidUntilUnix,
	}, record.TerminalOutcome, time.Unix(int64(record.UpdatedAtUnix), 0).UTC())
	validated, validationErr := validateRelayAbsenceObservationComponents(record.SponsorshipAbsenceObservations,
		record.TransactionAbsenceObservations, context)
	bundleErr := validateRelayAbsenceProofBundleForBody(RelayFinalityEvidenceBody{
		SponsorshipAbsenceObservations: record.SponsorshipAbsenceObservations,
		TransactionAbsenceObservations: record.TransactionAbsenceObservations,
		AbsenceProofBundleDigest:       record.AbsenceProofBundleDigest,
		AbsenceProofBundle:             record.AbsenceProofBundle,
	})
	merged := mergeSortedDigestSets(sponsorshipDigests, transactionDigests)
	hasSponsorshipAbsence := len(record.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(record.TransactionAbsenceObservations) != 0
	return validRelayAbsenceStateShape(record.request.QuoteRequest.Body.Mode, record.State,
		record.TerminalOutcome, record.SponsorshipTransferReference, record.TransactionReference,
		hasSponsorshipAbsence, hasTransactionAbsence) &&
		validSponsorshipIdentity(record.SponsorshipStableActionID, record.SponsorshipExactRequestDigest) &&
		contextErr == nil && validationErr == nil && bundleErr == nil && equalStrings(validated, merged) &&
		equalStrings(record.SponsorshipAbsenceObservationDigests, sponsorshipDigests) &&
		equalStrings(record.TransactionAbsenceObservationDigests, transactionDigests) &&
		(!hasSponsorshipAbsence || sortedRequiredDigests(sponsorshipDigests,
			int(sponsorshipProfile.MinimumObservers))) &&
		(!hasTransactionAbsence || sortedRequiredDigests(transactionDigests,
			int(transactionProfile.MinimumObservers))) &&
		digestSetsDisjoint(sponsorshipDigests, transactionDigests) &&
		sortedOptionalDigests(merged) && digestSetContainsAll(record.EvidenceRefs, merged) &&
		validRelayAbsenceOutcomeAssurance(record.request, record.TerminalOutcome,
			hasSponsorshipAbsence, hasTransactionAbsence, record.SponsorshipTransactionEvidence)
}

func cloneRecord(record Record) Record {
	record.EvidenceRefs = append([]string(nil), record.EvidenceRefs...)
	record.SponsorshipAbsenceObservationDigests = append([]string(nil), record.SponsorshipAbsenceObservationDigests...)
	record.TransactionAbsenceObservationDigests = append([]string(nil), record.TransactionAbsenceObservationDigests...)
	record.SponsorshipAbsenceObservations = append([]RelayAbsenceObservationReference(nil), record.SponsorshipAbsenceObservations...)
	record.TransactionAbsenceObservations = append([]RelayAbsenceObservationReference(nil), record.TransactionAbsenceObservations...)
	record.AbsenceProofBundle = append([]byte(nil), record.AbsenceProofBundle...)
	record.SponsorshipExposureReleaseEvidenceRefs = append([]string(nil), record.SponsorshipExposureReleaseEvidenceRefs...)
	record.SponsorshipCreditObservation = cloneSponsorshipCreditObservation(record.SponsorshipCreditObservation)
	record.SponsorshipTransactionEvidence = cloneSponsorshipTransactionEvidence(record.SponsorshipTransactionEvidence)
	record.sponsorshipRecoveryToken = append([]byte(nil), record.sponsorshipRecoveryToken...)
	record.request = cloneExecutionRequest(record.request)
	return record
}

func cloneSponsorshipCreditObservation(value *RelaySponsorshipCreditObservation) *RelaySponsorshipCreditObservation {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.AgreementPaymentRequest.Destination = append([]byte(nil), value.AgreementPaymentRequest.Destination...)
	copyValue.DestinationCreditReferences = append([]string(nil), value.DestinationCreditReferences...)
	copyValue.ObservationDigests = append([]string(nil), value.ObservationDigests...)
	return &copyValue
}

func cloneSponsorshipTransactionEvidence(value *RelaySponsorshipTransactionEvidence) *RelaySponsorshipTransactionEvidence {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.AgreementPaymentRequest.Destination = append([]byte(nil), value.AgreementPaymentRequest.Destination...)
	copyValue.DestinationCreditReferences = append([]string(nil), value.DestinationCreditReferences...)
	copyValue.ObservationDigests = append([]string(nil), value.ObservationDigests...)
	copyValue.ProofBundle = append([]byte(nil), value.ProofBundle...)
	return &copyValue
}

func sameObservedSponsorshipTransaction(observation RelaySponsorshipCreditObservation,
	evidence RelaySponsorshipTransactionEvidence) bool {
	return observation.NetworkDigest == evidence.NetworkDigest &&
		observation.AgreementPaymentRequestDigest == evidence.AgreementPaymentRequestDigest &&
		observation.SponsorshipStableActionID == evidence.SponsorshipStableActionID &&
		observation.SponsorshipExactRequestDigest == evidence.SponsorshipExactRequestDigest &&
		observation.ProviderSponsorSourceAccount == evidence.ProviderSponsorSourceAccount &&
		observation.ProviderSponsorSourceSequence == evidence.ProviderSponsorSourceSequence &&
		observation.ProviderSponsorValidUntilUnix == evidence.ProviderSponsorValidUntilUnix &&
		observation.SignedTopUpTransactionDigest == evidence.SignedTopUpTransactionDigest &&
		observation.SignedTopUpTransactionCellHash == evidence.SignedTopUpTransactionCellHash &&
		observation.SponsorshipPaymentCommitmentCellHash == evidence.SponsorshipPaymentCommitmentCellHash &&
		observation.DestinationSourceAccount == evidence.DestinationSourceAccount &&
		sameAmount(observation.Amount, evidence.Amount) &&
		observation.SubmittedTransactionHash == evidence.SubmittedTransactionHash &&
		observation.SourceExecutionReference == evidence.SourceExecutionReference &&
		equalStrings(observation.DestinationCreditReferences, evidence.DestinationCreditReferences)
}

func sameObservedSponsorshipCredit(left, right RelaySponsorshipCreditObservation) bool {
	return left.NetworkDigest == right.NetworkDigest &&
		left.AgreementPaymentRequestDigest == right.AgreementPaymentRequestDigest &&
		left.SponsorshipStableActionID == right.SponsorshipStableActionID &&
		left.SponsorshipExactRequestDigest == right.SponsorshipExactRequestDigest &&
		left.ProviderSponsorSourceAccount == right.ProviderSponsorSourceAccount &&
		left.ProviderSponsorSourceSequence == right.ProviderSponsorSourceSequence &&
		left.ProviderSponsorValidUntilUnix == right.ProviderSponsorValidUntilUnix &&
		left.SignedTopUpTransactionDigest == right.SignedTopUpTransactionDigest &&
		left.SignedTopUpTransactionCellHash == right.SignedTopUpTransactionCellHash &&
		left.SponsorshipPaymentCommitmentCellHash == right.SponsorshipPaymentCommitmentCellHash &&
		left.DestinationSourceAccount == right.DestinationSourceAccount && sameAmount(left.Amount, right.Amount) &&
		left.SubmittedTransactionHash == right.SubmittedTransactionHash &&
		left.SourceExecutionReference == right.SourceExecutionReference &&
		equalStrings(left.DestinationCreditReferences, right.DestinationCreditReferences) &&
		left.EvidenceProfileURI == right.EvidenceProfileURI &&
		left.EvidenceProfileDigest == right.EvidenceProfileDigest
}

func cloneExecutionRequest(request RelayExecutionRequest) RelayExecutionRequest {
	request.SignedTransactionBytes = append([]byte(nil), request.SignedTransactionBytes...)
	request.FeeObligationIDs = append([]string(nil), request.FeeObligationIDs...)
	request.UnderlyingActionRequest = append([]byte(nil), request.UnderlyingActionRequest...)
	request.SemanticFields = append([]agentcommerce.SemanticFieldValue(nil), request.SemanticFields...)
	request.WriterFence.Body.Scope = append([]string(nil), request.WriterFence.Body.Scope...)
	request.AdmissionReceipt.Body.StageMask = append([]SideEffectStage(nil), request.AdmissionReceipt.Body.StageMask...)
	return request
}

func cloneSignedProviderQuote(quote SignedProviderRelayQuote) SignedProviderRelayQuote {
	quote.Body.FeeLines = append([]FeeLine(nil), quote.Body.FeeLines...)
	if quote.Body.ReservedSponsorship != nil {
		amount := *quote.Body.ReservedSponsorship
		quote.Body.ReservedSponsorship = &amount
	}
	return quote
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sponsorshipRecoveryTokenDigest(token []byte) (string, error) {
	if len(token) == 0 || len(token) > MaxSignedTransactionBytes {
		return "", errors.New("sponsorship recovery token is invalid")
	}
	return agentcommerce.ExactRequestDigest(token)
}
