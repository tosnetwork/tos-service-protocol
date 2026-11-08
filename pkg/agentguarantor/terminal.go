package agentguarantor

import (
	"bytes"
	"errors"
	"math/big"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	ClaimFilingCloseDomain   = "tos.service.agent-guarantor-claim-filing-close-envelope.v1"
	TerminalClaimSetDomain   = "tos.service.agent-guarantor-terminal-claim-set-evidence.v1"
	ExposureReleaseDomain    = "tos.service.agent-guarantor-exposure-release-receipt-envelope.v1"
	CoverageResolutionDomain = "tos.service.agent-guarantor-resolution-envelope.v1"
)

type ClaimFilingCloseActionBodyV1 struct {
	SchemaVersion                       uint16                          `json:"schema_version"`
	CoverageAgreementBodyDigest         string                          `json:"coverage_agreement_body_digest"`
	CoverageObligationID                string                          `json:"coverage_obligation_id"`
	ClaimAdmissionLogID                 string                          `json:"claim_admission_log_id"`
	ClaimIngressAdmissionCutProof       ClaimIngressAdmissionCutProofV1 `json:"claim_ingress_admission_cut_proof"`
	FilingCloseReason                   string                          `json:"filing_close_reason"`
	FilingCutoffUnix                    uint64                          `json:"filing_cutoff_unix"`
	ExpectedCoverageState               string                          `json:"expected_coverage_state"`
	ExpectedCoverageEndCommitmentDigest string                          `json:"expected_coverage_end_commitment_digest"`
	CoverageEndReason                   string                          `json:"coverage_end_reason"`
	ActivationEvidenceDigest            string                          `json:"activation_evidence_digest,omitempty"`
	CoverageCancellationReceiptDigest   string                          `json:"coverage_cancellation_receipt_digest,omitempty"`
	NonActivationEvidenceDigest         string                          `json:"non_activation_evidence_digest,omitempty"`
	ExpectedCoverageRevision            uint64                          `json:"expected_coverage_revision"`
	TargetCoverageRevision              uint64                          `json:"target_coverage_revision"`
	ExpectedClaimFilingStateRevision    uint64                          `json:"expected_claim_filing_state_revision"`
	TargetClaimFilingState              string                          `json:"target_claim_filing_state"`
	ExpectedClaimAdmissionHighWater     uint64                          `json:"expected_claim_admission_high_water"`
	ExpectedClaimAdmissionLogRoot       string                          `json:"expected_claim_admission_log_root"`
	TransitionEvidenceProjection        TransitionEvidenceProjectionV1  `json:"transition_evidence_projection"`
}

type CoverageClosureActionBodyV1 struct {
	SchemaVersion                           uint16                            `json:"schema_version"`
	CoverageAgreementBodyDigest             string                            `json:"coverage_agreement_body_digest"`
	CoverageObligationID                    string                            `json:"coverage_obligation_id"`
	ClaimFilingCloseReceiptDigest           string                            `json:"claim_filing_close_receipt_digest"`
	ExpectedCoverageEndCommitmentDigest     string                            `json:"expected_coverage_end_commitment_digest"`
	ClaimResolutionBundles                  []ClaimTerminalResolutionBundleV1 `json:"claim_resolution_bundles"`
	ClaimResolutionRefSet                   ClaimTerminalResolutionRefSetV1   `json:"claim_resolution_ref_set"`
	ClosureReason                           string                            `json:"closure_reason"`
	ExpectedCoverageRevision                uint64                            `json:"expected_coverage_revision"`
	TargetCoverageRevision                  uint64                            `json:"target_coverage_revision"`
	TargetCoverageState                     string                            `json:"target_coverage_state"`
	ExpectedClaimSetRevision                uint64                            `json:"expected_claim_set_revision"`
	TargetClaimSetRevision                  uint64                            `json:"target_claim_set_revision"`
	CoverageClosureEvidenceContext          CoverageClosureEvidenceContextV1  `json:"coverage_closure_evidence_context"`
	TerminalPrerequisiteEvidenceSet         CanonicalGuarantorEvidenceSetV1   `json:"terminal_prerequisite_evidence_set"`
	FeeResolutionEvidenceSet                *CanonicalGuarantorEvidenceSetV1  `json:"fee_resolution_evidence_set,omitempty"`
	CollateralReleaseEligibilityEvidenceSet *CanonicalGuarantorEvidenceSetV1  `json:"collateral_release_eligibility_evidence_set,omitempty"`
	TransitionEvidenceProjection            TransitionEvidenceProjectionV1    `json:"transition_evidence_projection"`
}

type ExposureReleaseActionBodyV1 struct {
	ReservationID             string `json:"reservation_id"`
	AgreementDigest           string `json:"agreement_digest"`
	TargetPortfolioRevision   uint64 `json:"target_portfolio_revision"`
	TerminalEvidenceSetDigest string `json:"terminal_evidence_set_digest"`
}

type CoverageResolutionActionBodyV1 struct {
	SchemaVersion                uint16 `json:"schema_version"`
	ExposureReleaseReceiptDigest string `json:"authorized_exposure_release_receipt_digest"`
	ExpectedRevision             uint64 `json:"expected_coverage_revision"`
	TargetRevision               uint64 `json:"target_coverage_revision"`
}

type ClaimFilingCloseReceiptBodyV1 struct {
	SchemaVersion                       uint16 `json:"schema_version"`
	AuthorityID                         string `json:"authority_id"`
	CoverageAgreementBodyDigest         string `json:"coverage_agreement_body_digest"`
	CoverageObligationID                string `json:"coverage_obligation_id"`
	CoverageStateDomainDigest           string `json:"coverage_state_domain_digest"`
	CoverageEndCommitmentDigest         string `json:"coverage_end_commitment_digest"`
	ClaimAdmissionLogID                 string `json:"claim_admission_log_id"`
	ClaimIngressAdmissionCutProofDigest string `json:"claim_ingress_admission_cut_proof_digest"`
	FrozenClaimIngressHighWater         uint64 `json:"frozen_claim_ingress_high_water"`
	FrozenClaimIngressLogRoot           string `json:"frozen_claim_ingress_log_root"`
	FrozenClaimAdmissionHighWater       uint64 `json:"frozen_claim_admission_high_water"`
	FrozenClaimAdmissionLogRoot         string `json:"frozen_claim_admission_log_root"`
	FilingCloseReason                   string `json:"filing_close_reason"`
	FilingCutoffUnix                    uint64 `json:"filing_cutoff_unix"`
	PriorCoverageState                  string `json:"prior_coverage_state"`
	CoverageEndReason                   string `json:"coverage_end_reason"`
	IncidentEligibilityEndsAtUnix       uint64 `json:"incident_eligibility_ends_at_unix"`
	CoverageEndEvidenceDigest           string `json:"coverage_end_evidence_digest,omitempty"`
	ActivationEvidenceDigest            string `json:"activation_evidence_digest"`
	CoverageCancellationReceiptDigest   string `json:"coverage_cancellation_receipt_digest,omitempty"`
	NonActivationEvidenceDigest         string `json:"non_activation_evidence_digest,omitempty"`
	PriorCoverageRevision               uint64 `json:"prior_coverage_revision"`
	ClosedCoverageRevision              uint64 `json:"closed_coverage_revision"`
	PriorClaimFilingState               string `json:"prior_claim_filing_state"`
	ResultingClaimFilingState           string `json:"resulting_claim_filing_state"`
	PriorClaimFilingStateRevision       uint64 `json:"prior_claim_filing_state_revision"`
	ResultingClaimFilingStateRevision   uint64 `json:"resulting_claim_filing_state_revision"`
	TransitionEvidenceProjectionDigest  string `json:"transition_evidence_projection_digest"`
	AuthorizedActionDigest              string `json:"authorized_action_digest"`
	StableActionID                      string `json:"stable_action_id"`
	ExactRequestDigest                  string `json:"exact_request_digest"`
	WriterGeneration                    uint64 `json:"writer_generation"`
	WriterFenceDigest                   string `json:"writer_fence_digest"`
	ClosedAtUnix                        uint64 `json:"closed_at_unix"`
}

type AuthorizedClaimFilingCloseReceiptV1 struct {
	Body                            ClaimFilingCloseReceiptBodyV1              `json:"body"`
	StageActionAdmissionEvidence    PortableStageActionAdmissionEvidenceV1     `json:"stage_action_admission_evidence"`
	CoverageEndCommitment           CoverageEndCommitmentV1                    `json:"coverage_end_commitment"`
	ClaimIngressAdmissionCutProof   ClaimIngressAdmissionCutProofV1            `json:"claim_ingress_admission_cut_proof"`
	AuthorizedActivationEvidence    *AuthorizedCoverageActivationEvidenceV1    `json:"authorized_activation_evidence,omitempty"`
	AuthorizedCancellationReceipt   *AuthorizedCoverageCancellationReceiptV1   `json:"authorized_cancellation_receipt,omitempty"`
	AuthorizedNonActivationEvidence *AuthorizedCoverageNonActivationEvidenceV1 `json:"authorized_non_activation_evidence,omitempty"`
	TransitionEvidenceProjection    TransitionEvidenceProjectionV1             `json:"transition_evidence_projection"`
	Authorizations                  []ProfileQualifiedObjectAuthorizationV1    `json:"authorizations"`
}

type ClaimTerminalResolutionRefV1 struct {
	ClaimAdmissionSequence                    uint64      `json:"claim_admission_sequence"`
	ClaimID                                   string      `json:"claim_id"`
	InitialClaimAdmissionReceiptDigest        string      `json:"initial_claim_admission_receipt_digest"`
	FinalClaimRevision                        uint64      `json:"final_claim_revision"`
	FinalClaimRevisionAdmissionReceiptDigest  string      `json:"final_claim_revision_admission_receipt_digest"`
	ClaimRevisionAdmissionHighWater           uint64      `json:"claim_revision_admission_high_water"`
	ClaimRevisionAdmissionLogRoot             string      `json:"claim_revision_admission_log_root"`
	ClaimRevisionIngressHighWater             uint64      `json:"claim_revision_ingress_high_water"`
	ClaimRevisionIngressLogRoot               string      `json:"claim_revision_ingress_log_root"`
	TerminalAuthorizedClaimEnvelopeDigest     string      `json:"terminal_authorized_claim_envelope_digest"`
	TerminalDecisionDigest                    string      `json:"terminal_decision_digest"`
	TerminalDecisionAdmissionReceiptDigest    string      `json:"terminal_decision_admission_receipt_digest"`
	DecisionApplicationReceiptDigest          string      `json:"decision_application_receipt_digest"`
	TerminalClaimState                        ClaimStatus `json:"terminal_claim_state"`
	ClaimStateRevision                        uint64      `json:"claim_state_revision"`
	TerminalClaimStateTransitionReceiptDigest string      `json:"terminal_claim_state_transition_receipt_digest"`
	MaterializedPayoutObligationSetDigest     string      `json:"materialized_payout_obligation_set_digest"`
	TerminalPayoutEvidenceSetDigest           string      `json:"terminal_payout_evidence_set_digest"`
}

type ClaimTerminalResolutionBundleV1 struct {
	ResolutionRef                     ClaimTerminalResolutionRefV1              `json:"resolution_ref"`
	InitialClaimAdmissionReceiptProof ClaimAdmissionReceiptProofV1              `json:"initial_claim_admission_receipt_proof"`
	RevisionAdmissionReceiptProofs    []ClaimAdmissionReceiptProofV1            `json:"revision_admission_receipt_proofs"`
	TerminalAuthorizedDecision        AuthorizedClaimDecisionV1                 `json:"terminal_authorized_decision"`
	DecisionAdmissionReceiptProofs    []ClaimDecisionAdmissionReceiptProofV1    `json:"decision_admission_receipt_proofs"`
	DecisionApplicationReceiptProof   DecisionApplicationReceiptProofV1         `json:"decision_application_receipt_proof"`
	ClaimStateTransitionReceipts      []AuthorizedClaimStateTransitionReceiptV1 `json:"claim_state_transition_receipts"`
	MaterializedPayoutObligationSet   MaterializedPayoutObligationSetV1         `json:"materialized_payout_obligation_set"`
	TerminalPayoutEvidenceSet         TerminalPayoutEvidenceSetV1               `json:"terminal_payout_evidence_set"`
}

// DecisionApplicationReceiptProofV1 is the signed, compact projection of a
// previously verified application receipt. It avoids recursively copying the
// full decision history into every terminal recovery wrapper.
type DecisionApplicationReceiptProofV1 struct {
	SchemaVersion         uint16                                  `json:"schema_version"`
	ReceiptEnvelopeDigest string                                  `json:"receipt_envelope_digest"`
	ReceiptDescriptor     ImmutableEvidenceDescriptorV1           `json:"receipt_descriptor"`
	Body                  ClaimDecisionApplicationReceiptBodyV1   `json:"body"`
	Authorizations        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
	SealBody              DecisionApplicationReceiptSealBodyV1    `json:"seal_body"`
	SealAuthorization     ProfileQualifiedObjectAuthorizationV1   `json:"seal_authorization"`
}

type DecisionApplicationReceiptSealBodyV1 struct {
	SchemaVersion                             uint16 `json:"schema_version"`
	ReceiptEnvelopeDigest                     string `json:"receipt_envelope_digest"`
	ReceiptBodyDigest                         string `json:"receipt_body_digest"`
	AuthorizedActionDigest                    string `json:"authorized_action_digest"`
	TerminalClaimStateTransitionReceiptDigest string `json:"terminal_claim_state_transition_receipt_digest"`
	MaterializedPayoutObligationSetDigest     string `json:"materialized_payout_obligation_set_digest"`
	DecisionApplicationTokenDigest            string `json:"decision_application_token_digest"`
	CoverageTermsDigest                       string `json:"coverage_terms_digest"`
	SealedAtUnix                              uint64 `json:"sealed_at_unix"`
}

type TerminalClaimSetBodyV1 struct {
	SchemaVersion                      uint16                         `json:"schema_version"`
	CoverageAgreementBodyDigest        string                         `json:"coverage_agreement_body_digest"`
	CoverageObligationID               string                         `json:"coverage_obligation_id"`
	ClaimAdmissionProfileDigest        string                         `json:"claim_admission_profile_digest"`
	ClaimAdmissionAuthoritySubjects    []string                       `json:"claim_admission_authority_subjects"`
	ClaimAdmissionLogID                string                         `json:"claim_admission_log_id"`
	ClaimFilingCloseReceiptDigest      string                         `json:"claim_filing_close_receipt_digest"`
	CoverageCancellationReceiptDigest  string                         `json:"coverage_cancellation_receipt_digest,omitempty"`
	CoverageEndCommitmentDigest        string                         `json:"coverage_end_commitment_digest"`
	FilingCloseReason                  string                         `json:"filing_close_reason"`
	CoverageEndReason                  string                         `json:"coverage_end_reason"`
	IncidentEligibilityEndsAtUnix      uint64                         `json:"incident_eligibility_ends_at_unix,omitempty"`
	CoverageEndEvidenceDigest          string                         `json:"coverage_end_evidence_digest,omitempty"`
	ActivationEvidenceDigest           string                         `json:"activation_evidence_digest,omitempty"`
	CoverageClosureReason              string                         `json:"coverage_closure_reason"`
	ResolutionTargetTerminalState      string                         `json:"resolution_target_terminal_state"`
	CoverageClosureContextDigest       string                         `json:"coverage_closure_context_digest"`
	CoverageClosureEvidenceSetDigest   string                         `json:"coverage_closure_evidence_set_digest"`
	TransitionEvidenceProjectionDigest string                         `json:"transition_evidence_projection_digest"`
	NonActivationEvidenceDigest        string                         `json:"non_activation_evidence_digest,omitempty"`
	FilingCloseCoverageRevision        uint64                         `json:"filing_close_coverage_revision"`
	PriorCoverageRevision              uint64                         `json:"prior_coverage_revision"`
	ReleasePendingCoverageRevision     uint64                         `json:"release_pending_coverage_revision"`
	AdmissionHighWater                 uint64                         `json:"admission_high_water"`
	ClaimAdmissionLogRoot              string                         `json:"claim_admission_log_root"`
	ClaimResolutions                   []ClaimTerminalResolutionRefV1 `json:"claim_resolutions"`
	OpenClaimCount                     uint64                         `json:"open_claim_count"`
	AmbiguousActionCount               uint64                         `json:"ambiguous_action_count"`
	CumulativeApprovedAmount           AtomicAmountV1                 `json:"cumulative_approved_amount"`
	CumulativePaidAmount               AtomicAmountV1                 `json:"cumulative_paid_amount"`
	CumulativeDefaultedAmount          AtomicAmountV1                 `json:"cumulative_defaulted_amount"`
	OutstandingApprovedAmount          AtomicAmountV1                 `json:"outstanding_approved_amount"`
	ClaimSetRevision                   uint64                         `json:"claim_set_revision"`
	FilingClosedAtUnix                 uint64                         `json:"filing_closed_at_unix"`
	AllClaimsTerminalAtUnix            uint64                         `json:"all_claims_terminal_at_unix"`
	ReleaseNotBeforeUnix               uint64                         `json:"release_not_before_unix"`
	AuthorizedActionDigest             string                         `json:"authorized_action_digest"`
	StableActionID                     string                         `json:"stable_action_id"`
	ExactRequestDigest                 string                         `json:"exact_request_digest"`
	WriterGeneration                   uint64                         `json:"writer_generation"`
	WriterFenceDigest                  string                         `json:"writer_fence_digest"`
	CreatedAtUnix                      uint64                         `json:"created_at_unix"`
	RequiredExtensions                 []ProfileRefV1                 `json:"required_extensions"`
	OptionalExtensions                 []ProfileRefV1                 `json:"optional_extensions"`
}

type AuthorizedTerminalClaimSetEvidenceV1 struct {
	Body                                    TerminalClaimSetBodyV1                  `json:"body"`
	StageActionAdmissionEvidence            PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	AuthorizedClaimFilingCloseReceipt       AuthorizedClaimFilingCloseReceiptV1     `json:"authorized_claim_filing_close_receipt"`
	ClaimResolutionBundles                  []ClaimTerminalResolutionBundleV1       `json:"claim_resolution_bundles"`
	ClaimResolutionRefSet                   ClaimTerminalResolutionRefSetV1         `json:"claim_resolution_ref_set"`
	CoverageClosureEvidenceContext          CoverageClosureEvidenceContextV1        `json:"coverage_closure_evidence_context"`
	CoverageClosureEvidenceSet              CanonicalGuarantorEvidenceSetV1         `json:"coverage_closure_evidence_set"`
	FeeResolutionEvidenceSet                *CanonicalGuarantorEvidenceSetV1        `json:"fee_resolution_evidence_set,omitempty"`
	CollateralReleaseEligibilityEvidenceSet *CanonicalGuarantorEvidenceSetV1        `json:"collateral_release_eligibility_evidence_set,omitempty"`
	TransitionEvidenceProjection            TransitionEvidenceProjectionV1          `json:"transition_evidence_projection"`
	Authorizations                          []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type ExposureReleaseReceiptBodyV1 struct {
	SchemaVersion                        uint16         `json:"schema_version"`
	AuthorityID                          string         `json:"authority_id"`
	GuarantorAgentID                     string         `json:"guarantor_agent_id"`
	CoverageAgreementBodyDigest          string         `json:"coverage_agreement_body_digest"`
	CoverageObligationID                 string         `json:"coverage_obligation_id"`
	ReservationID                        string         `json:"reservation_id"`
	ExposureAdmissionReceiptDigest       string         `json:"exposure_admission_receipt_digest"`
	TerminalClaimSetEvidenceDigest       string         `json:"terminal_claim_set_evidence_digest"`
	ExposureDispositionComputationDigest string         `json:"exposure_disposition_computation_digest"`
	AuthorizedActionDigest               string         `json:"authorized_action_digest"`
	StableActionID                       string         `json:"stable_action_id"`
	ExactRequestDigest                   string         `json:"exact_request_digest"`
	WriterGeneration                     uint64         `json:"writer_generation"`
	WriterFenceDigest                    string         `json:"writer_fence_digest"`
	BaseReleaseStateRevision             uint64         `json:"base_release_state_revision"`
	ReleasedReleaseStateRevision         uint64         `json:"released_release_state_revision"`
	ReleasedExposure                     AtomicAmountV1 `json:"released_exposure"`
	RemainingReservedExposure            AtomicAmountV1 `json:"remaining_reserved_exposure"`
	PortfolioDisposition                 string         `json:"portfolio_disposition"`
	ReturnedToAvailableExposure          AtomicAmountV1 `json:"returned_to_available_exposure"`
	RealizedLoss                         AtomicAmountV1 `json:"realized_loss"`
	RetainedDefaultedLiability           AtomicAmountV1 `json:"retained_defaulted_liability"`
	State                                string         `json:"state"`
	ReleasedAtUnix                       uint64         `json:"released_at_unix"`
}

type AuthorizedExposureReleaseReceiptV1 struct {
	Body                               ExposureReleaseReceiptBodyV1                 `json:"body"`
	StageActionAdmissionEvidence       PortableStageActionAdmissionEvidenceV1       `json:"stage_action_admission_evidence"`
	AuthorizedExposureAdmissionReceipt AuthorizedProviderExposureAdmissionReceiptV1 `json:"authorized_exposure_admission_receipt"`
	AuthorizedTerminalClaimSetEvidence AuthorizedTerminalClaimSetEvidenceV1         `json:"authorized_terminal_claim_set_evidence"`
	ExposureDispositionComputation     ExposureDispositionComputationV1             `json:"exposure_disposition_computation"`
	Authorizations                     []ProfileQualifiedObjectAuthorizationV1      `json:"authorizations"`
}

type CoverageResolutionBodyV1 struct {
	SchemaVersion                  uint16 `json:"schema_version"`
	AuthorityID                    string `json:"authority_id"`
	CoverageAgreementBodyDigest    string `json:"coverage_agreement_body_digest"`
	CoverageObligationID           string `json:"coverage_obligation_id"`
	CoverageEndCommitmentDigest    string `json:"coverage_end_commitment_digest"`
	ActivationEvidenceDigest       string `json:"activation_evidence_digest"`
	TerminalClaimSetEvidenceDigest string `json:"terminal_claim_set_evidence_digest"`
	ExposureReleaseReceiptDigest   string `json:"exposure_release_receipt_digest"`
	PriorCoverageRevision          uint64 `json:"prior_coverage_revision"`
	ResolvedCoverageRevision       uint64 `json:"resolved_coverage_revision"`
	TerminalState                  string `json:"terminal_state"`
	AuthorizedActionDigest         string `json:"authorized_action_digest"`
	StableActionID                 string `json:"stable_action_id"`
	ExactRequestDigest             string `json:"exact_request_digest"`
	WriterGeneration               uint64 `json:"writer_generation"`
	WriterFenceDigest              string `json:"writer_fence_digest"`
	ResolvedAtUnix                 uint64 `json:"resolved_at_unix"`
}

type AuthorizedCoverageResolutionV1 struct {
	Body                             CoverageResolutionBodyV1                `json:"body"`
	StageActionAdmissionEvidence     PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	AuthorizedExposureReleaseReceipt AuthorizedExposureReleaseReceiptV1      `json:"authorized_exposure_release_receipt"`
	Authorizations                   []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

func ClaimFilingCloseReceiptDigestV1(value AuthorizedClaimFilingCloseReceiptV1) (string, error) {
	if value.Body.SchemaVersion != 1 || !validDigest(value.Body.CoverageAgreementBodyDigest) || !validDigest(value.Body.FrozenClaimAdmissionLogRoot) || len(value.Authorizations) == 0 {
		return "", errors.New("claim filing close receipt is invalid")
	}
	return codec.Digest(ClaimFilingCloseDomain, value)
}
func TerminalClaimSetDigestV1(value AuthorizedTerminalClaimSetEvidenceV1) (string, error) {
	if err := ValidateTerminalClaimSetV1(value); err != nil {
		return "", err
	}
	return codec.Digest(TerminalClaimSetDomain, value)
}
func ExposureReleaseReceiptDigestV1(value AuthorizedExposureReleaseReceiptV1) (string, error) {
	if value.Body.SchemaVersion != 1 || value.Body.State != "released" || !validDigest(value.Body.TerminalClaimSetEvidenceDigest) || len(value.Authorizations) == 0 {
		return "", errors.New("exposure release receipt is invalid")
	}
	return codec.Digest(ExposureReleaseDomain, value)
}
func CoverageResolutionDigestV1(value AuthorizedCoverageResolutionV1) (string, error) {
	if value.Body.SchemaVersion != 1 || value.Body.TerminalState == "" || !validDigest(value.Body.ExposureReleaseReceiptDigest) || len(value.Authorizations) == 0 {
		return "", errors.New("coverage resolution is invalid")
	}
	return codec.Digest(CoverageResolutionDomain, value)
}

func ExposureDispositionComputationDigestV1(value ExposureDispositionComputationV1) (string, error) {
	if value.SchemaVersion != 1 || !validDigest(value.CoverageAgreementBodyDigest) ||
		!validToken(value.CoverageObligationID, 128) || !validDigest(value.ReservationID) ||
		!validDigest(value.ExposureAdmissionReceiptDigest) || !validDigest(value.ReservationScopeDigest) {
		return "", errors.New("exposure disposition computation is invalid")
	}
	return codec.Digest("tos.service.agent-guarantor-exposure-disposition.v1", value)
}

// ComputeExposureDispositionV1 derives the only permitted underwriting split
// from the immutable reservation scope and terminal claim arithmetic.  It is
// deliberately output-only: a caller cannot choose which bucket restores
// capacity.
func ComputeExposureDispositionV1(admission AuthorizedProviderExposureAdmissionReceiptV1,
	terminal TerminalClaimSetBodyV1) (ExposureDispositionComputationV1, error) {
	exposureDigest, err := ExposureAdmissionReceiptDigestV1(admission)
	scopeDigest, scopeErr := ExposureReservationScopeDigestV1(admission.Descriptor.ReservationScope)
	reserved, reservedOK := new(big.Int).SetString(admission.Body.ReservedExposure.AmountAtomic, 10)
	approved, approvedOK := new(big.Int).SetString(terminal.CumulativeApprovedAmount.AmountAtomic, 10)
	paid, paidOK := new(big.Int).SetString(terminal.CumulativePaidAmount.AmountAtomic, 10)
	defaulted, defaultedOK := new(big.Int).SetString(terminal.CumulativeDefaultedAmount.AmountAtomic, 10)
	outstanding, outstandingOK := new(big.Int).SetString(terminal.OutstandingApprovedAmount.AmountAtomic, 10)
	asset := admission.Body.ReservedExposure.Asset
	if err != nil || scopeErr != nil || reservedOK == false || approvedOK == false || paidOK == false ||
		defaultedOK == false || outstandingOK == false || reserved.Sign() <= 0 || approved.Sign() < 0 ||
		paid.Sign() < 0 || defaulted.Sign() < 0 || outstanding.Sign() != 0 ||
		asset != terminal.CumulativeApprovedAmount.Asset || asset != terminal.CumulativePaidAmount.Asset ||
		asset != terminal.CumulativeDefaultedAmount.Asset || asset != terminal.OutstandingApprovedAmount.Asset ||
		new(big.Int).Add(new(big.Int).Set(paid), defaulted).Cmp(approved) != 0 || approved.Cmp(reserved) > 0 {
		return ExposureDispositionComputationV1{}, errors.New("terminal amounts cannot be dispositioned against the reserved exposure")
	}
	realized := new(big.Int).Set(paid)
	retained := new(big.Int)
	if admission.Descriptor.ReservationScope.DefaultLiabilityDisposition == "charge_off" {
		realized.Add(realized, defaulted)
	} else if admission.Descriptor.ReservationScope.DefaultLiabilityDisposition == "retain" {
		retained.Set(defaulted)
	} else {
		return ExposureDispositionComputationV1{}, errors.New("reservation has no released default-liability disposition")
	}
	returned := new(big.Int).Sub(new(big.Int).Set(reserved), realized)
	returned.Sub(returned, retained)
	if returned.Sign() < 0 {
		return ExposureDispositionComputationV1{}, errors.New("exposure disposition underflows the reservation")
	}
	nonzero := 0
	label := ""
	for _, candidate := range []struct {
		name  string
		value *big.Int
	}{{"residual_release", returned}, {"realized_loss", realized}, {"retained_defaulted_liability", retained}} {
		if candidate.value.Sign() > 0 {
			nonzero++
			label = candidate.name
		}
	}
	if nonzero > 1 {
		label = "mixed"
	}
	amount := func(value *big.Int) AtomicAmountV1 { return AtomicAmountV1{Asset: asset, AmountAtomic: value.String()} }
	return ExposureDispositionComputationV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: terminal.CoverageAgreementBodyDigest,
		CoverageObligationID:        terminal.CoverageObligationID, ReservationID: admission.Body.ReservationID,
		ExposureAdmissionReceiptDigest: exposureDigest, ReservationScopeDigest: scopeDigest,
		ReleasedExposure: amount(reserved), CumulativeApprovedAmount: terminal.CumulativeApprovedAmount,
		CumulativePaidAmount: terminal.CumulativePaidAmount, CumulativeDefaultedAmount: terminal.CumulativeDefaultedAmount,
		OutstandingApprovedAmount:   terminal.OutstandingApprovedAmount,
		DefaultLiabilityDisposition: admission.Descriptor.ReservationScope.DefaultLiabilityDisposition,
		ReturnedToAvailableExposure: amount(returned), RealizedLoss: amount(realized),
		RetainedDefaultedLiability: amount(retained), PortfolioDisposition: label}, nil
}

func VerifyClaimFilingCloseReceiptV1(value AuthorizedClaimFilingCloseReceiptV1,
	offer AuthorizedFirmCoverageOfferV1, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if _, err := ClaimFilingCloseReceiptDigestV1(value); err != nil {
		return err
	}
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "filing_close")
	if err != nil {
		return err
	}
	if value.AuthorizedActivationEvidence == nil || value.AuthorizedNonActivationEvidence != nil {
		return errors.New("normal claim filing close lacks its exclusive activation predecessor")
	}
	activation := *value.AuthorizedActivationEvidence
	if err := VerifyCoverageActivationEvidenceV1(activation, offer, agreementVerifier,
		authorityResolver, fenceResolver, collateralFinalityVerifierFromResolverV1(authorityResolver), now); err != nil {
		return err
	}
	body := value.Body
	activationDigest, _ := CoverageActivationEvidenceDigestV1(activation)
	endDigest, _ := CoverageEndCommitmentDigestV1(value.CoverageEndCommitment)
	cutDigest, cutErr := ClaimIngressAdmissionCutProofDigestV1(value.ClaimIngressAdmissionCutProof)
	projectionDigest, projectionErr := TransitionEvidenceProjectionDigestV1(value.TransitionEvidenceProjection)
	wantFilingReason, wantEndReason, wantPriorState := "normal", "normal_expiry", "active"
	wantFilingCutoff := offer.CoverageTerms.ClaimFilingEndsAtUnix
	wantIncidentEnd := offer.CoverageTerms.CoverageEndsAtUnix
	wantPriorRevision := activation.Body.ActivatedCoverageRevision
	wantCancellationDigest := ""
	if value.AuthorizedCancellationReceipt != nil {
		cancellation := *value.AuthorizedCancellationReceipt
		if err := VerifyCoverageCancellationReceiptV1(cancellation, activation,
			agreementVerifier, authorityResolver, fenceResolver, now); err != nil {
			return err
		}
		cancellationDigest, _ := CoverageCancellationReceiptDigestV1(cancellation)
		wantCancellationDigest = cancellationDigest
		wantCommitment := CoverageEndCommitmentV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: body.CoverageAgreementBodyDigest, CoverageObligationID: body.CoverageObligationID,
			CoverageStateDomainDigest: offer.CoverageTerms.CoverageStateDomainDigest, EndBranch: "accepted_cancellation",
			IncidentEligibilityEndsAtUnix: cancellation.Body.IncidentEligibilityEndsAtUnix,
			CoverageEndEvidenceDigest:     cancellationDigest}
		if !equalCanonical(wantCommitment, value.CoverageEndCommitment) {
			return errors.New("cancelled claim filing close has a substituted coverage end commitment")
		}
		wantFilingReason, wantEndReason, wantPriorState = "accepted_cancellation", "accepted_cancellation", "coverage_ended"
		wantFilingCutoff = cancellation.Body.ClaimFilingEndsAtUnix
		wantIncidentEnd = cancellation.Body.IncidentEligibilityEndsAtUnix
		wantPriorRevision = cancellation.Body.EndedCoverageRevision
	} else if value.CoverageEndCommitment != activation.CoverageEndCommitment {
		return errors.New("normal claim filing close has a substituted scheduled end commitment")
	}
	claimLogID := "claim-log:" + body.CoverageAgreementBodyDigest[len("sha256:"):]
	cut := value.ClaimIngressAdmissionCutProof
	if cutErr != nil || projectionErr != nil || body.ActivationEvidenceDigest != activationDigest ||
		body.CoverageEndCommitmentDigest != endDigest || body.CoverageEndEvidenceDigest != value.CoverageEndCommitment.CoverageEndEvidenceDigest ||
		body.CoverageCancellationReceiptDigest != wantCancellationDigest || body.NonActivationEvidenceDigest != "" ||
		body.ClaimAdmissionLogID != claimLogID || body.ClaimIngressAdmissionCutProofDigest != cutDigest ||
		body.FrozenClaimIngressHighWater != cut.AdmissionHighWater || body.FrozenClaimIngressLogRoot != cut.AdmissionLogRoot ||
		cut.CutKind != "initial_claims" || cut.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
		cut.CoverageObligationID != body.CoverageObligationID || cut.IngressCutoffUnix != body.FilingCutoffUnix ||
		cut.PendingOrAmbiguousCount != 0 || cut.AdmittedClaimCount != body.FrozenClaimAdmissionHighWater ||
		body.TransitionEvidenceProjectionDigest != projectionDigest ||
		value.TransitionEvidenceProjection.Purpose != "claim-filing-close" || value.TransitionEvidenceProjection.TargetState != "frozen" ||
		body.CoverageAgreementBodyDigest != activation.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != activation.Body.CoverageObligationID ||
		body.FilingCloseReason != wantFilingReason || body.CoverageEndReason != wantEndReason || body.PriorCoverageState != wantPriorState ||
		body.PriorClaimFilingState != "open" || body.ResultingClaimFilingState != "frozen" ||
		body.FilingCutoffUnix != wantFilingCutoff || body.PriorCoverageRevision < wantPriorRevision ||
		body.ClosedCoverageRevision != body.PriorCoverageRevision+1 ||
		body.ResultingClaimFilingStateRevision != body.PriorClaimFilingStateRevision+1 ||
		body.ClosedAtUnix < body.FilingCutoffUnix || body.IncidentEligibilityEndsAtUnix != wantIncidentEnd {
		return errors.New("claim filing close receipt binding is invalid")
	}
	request := ClaimFilingCloseActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: body.CoverageAgreementBodyDigest,
		CoverageObligationID: body.CoverageObligationID, ClaimAdmissionLogID: claimLogID,
		ClaimIngressAdmissionCutProof: cut, FilingCloseReason: body.FilingCloseReason, FilingCutoffUnix: body.FilingCutoffUnix,
		ExpectedCoverageState: body.PriorCoverageState, ExpectedCoverageEndCommitmentDigest: endDigest,
		CoverageEndReason: body.CoverageEndReason, ActivationEvidenceDigest: activationDigest,
		CoverageCancellationReceiptDigest: wantCancellationDigest,
		ExpectedCoverageRevision:          body.PriorCoverageRevision, TargetCoverageRevision: body.ClosedCoverageRevision,
		ExpectedClaimFilingStateRevision: body.PriorClaimFilingStateRevision, TargetClaimFilingState: "frozen",
		ExpectedClaimAdmissionHighWater: body.FrozenClaimAdmissionHighWater,
		ExpectedClaimAdmissionLogRoot:   body.FrozenClaimAdmissionLogRoot,
		TransitionEvidenceProjection:    value.TransitionEvidenceProjection}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.OwnerID),
		"agent_id":              agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.AgentID),
		"agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest), "obligation_id": agentcommerce.ID(body.CoverageObligationID),
		"claim_admission_log_id": agentcommerce.ID(claimLogID), "expected_coverage_revision": agentcommerce.U64(body.PriorCoverageRevision),
		"expected_claim_filing_state_revision": agentcommerce.U64(body.PriorClaimFilingStateRevision),
		"filing_cutoff_unix":                   agentcommerce.U64(body.FilingCutoffUnix), "target_state": agentcommerce.State("frozen")}
	if err := verifyPortableStage(value.StageActionAdmissionEvidence, &bound, request, fields, "filing_close", body.AuthorizedActionDigest,
		body.StableActionID, body.ExactRequestDigest, body.WriterGeneration, body.WriterFenceDigest,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-claim-filing-close-receipt-body.v1", body)
	return ValidateAuthorizationSet(value.Authorizations, "claim-filing-close-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-filing-close-signature.v1", []string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}

func VerifyTerminalClaimSetV1(value AuthorizedTerminalClaimSetEvidenceV1, offer AuthorizedFirmCoverageOfferV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, paymentVerifier agentcommerce.PaymentEvidenceVerifier, now time.Time) error {
	if err := ValidateTerminalClaimSetV1(value); err != nil || paymentVerifier == nil {
		return errors.New("terminal claim set is invalid")
	}
	if err := enforceCanonicalSize(value, offer.CoverageTerms.ClaimClosureCapacity.MaximumTerminalClaimSetEnvelopeBytes,
		"terminal claim set"); err != nil {
		return err
	}
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "coverage_closure")
	if err != nil {
		return err
	}
	if err := VerifyClaimFilingCloseReceiptV1(value.AuthorizedClaimFilingCloseReceipt, offer, agreementVerifier,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	body := value.Body
	filingDigest, _ := ClaimFilingCloseReceiptDigestV1(value.AuthorizedClaimFilingCloseReceipt)
	bundleDigest, _ := CanonicalGuarantorEvidenceSetDigestV1(value.CoverageClosureEvidenceSet)
	filingEndReason := value.AuthorizedClaimFilingCloseReceipt.Body.CoverageEndReason
	closureMatchesEnd := body.CoverageClosureReason == filingEndReason ||
		body.CoverageClosureReason == "aggregate_exhaustion" || body.CoverageClosureReason == "terminal_default"
	if body.ClaimFilingCloseReceiptDigest != filingDigest || body.AdmissionHighWater != value.AuthorizedClaimFilingCloseReceipt.Body.FrozenClaimAdmissionHighWater ||
		body.ClaimAdmissionLogRoot != value.AuthorizedClaimFilingCloseReceipt.Body.FrozenClaimAdmissionLogRoot ||
		!closureMatchesEnd ||
		body.CoverageEndCommitmentDigest != value.AuthorizedClaimFilingCloseReceipt.Body.CoverageEndCommitmentDigest ||
		body.ActivationEvidenceDigest != value.AuthorizedClaimFilingCloseReceipt.Body.ActivationEvidenceDigest {
		return errors.New("terminal claim set differs from the frozen filing cut")
	}
	for _, bundle := range value.ClaimResolutionBundles {
		admissions := append([]ClaimAdmissionReceiptProofV1{bundle.InitialClaimAdmissionReceiptProof},
			bundle.RevisionAdmissionReceiptProofs...)
		var predecessorDigest string
		for index, admission := range admissions {
			if err := ValidateClaimAdmissionReceiptProofV1(admission, offer.CoverageTerms,
				authorityResolver, fenceResolver, now, true); err != nil {
				return err
			}
			if index > 0 && admission.ReceiptBody.PredecessorRevisionAdmissionReceiptDigest != predecessorDigest {
				return errors.New("terminal claim revision admission chain is broken")
			}
			predecessorDigest = admission.ReceiptEnvelopeDigest
		}
		claim := admissions[len(admissions)-1].AuthorizedClaimIngressReceipt.AuthorizedClaim
		for _, admission := range bundle.DecisionAdmissionReceiptProofs {
			if err := VerifyClaimDecisionAdmissionReceiptProofV1(admission, offer.CoverageTerms,
				authorityResolver, now); err != nil {
				return err
			}
		}
		for _, transition := range bundle.ClaimStateTransitionReceipts {
			if err := VerifyClaimStateTransitionReceiptV1(transition, offer.CoverageTerms, agreementVerifier,
				authorityResolver, fenceResolver, now); err != nil {
				return err
			}
		}
		if err := ValidateDecisionApplicationReceiptProofV1(bundle.DecisionApplicationReceiptProof,
			offer.CoverageTerms, authorityResolver, now, true); err != nil {
			return err
		}
		decisionAt := time.Unix(int64(bundle.TerminalAuthorizedDecision.Body.DecidedAtUnix), 0).UTC()
		if err := ValidateClaimDecision(bundle.TerminalAuthorizedDecision, claim, offer.CoverageTerms,
			authorityResolver, offer.CoverageTerms.DecisionAuthoritySubjects, decisionAt); err != nil {
			return err
		}
		payouts := bundle.MaterializedPayoutObligationSet
		decisionDigest, _ := ClaimDecisionDigestV1(bundle.TerminalAuthorizedDecision)
		payoutDigest, _ := codec.Digest(PayoutSetDomain, payouts)
		application := bundle.DecisionApplicationReceiptProof
		if application.Body.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
			application.Body.CoverageObligationID != body.CoverageObligationID || application.Body.ClaimID != claim.Body.ClaimID ||
			application.Body.AuthorizedClaimDecisionDigest != decisionDigest ||
			application.Body.MaterializedPayoutObligationSetDigest != payoutDigest {
			return errors.New("terminal claim has no exact authorized decision application proof")
		}
		terminalPayout := bundle.TerminalPayoutEvidenceSet
		if terminalPayout.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest || terminalPayout.ClaimID != claim.Body.ClaimID ||
			terminalPayout.AuthorizedClaimDecisionDigest != decisionDigest || terminalPayout.MaterializedPayoutObligationSetDigest != payoutDigest ||
			len(terminalPayout.PayoutExecutionEvidence) != len(payouts.Obligations) {
			return errors.New("terminal payment evidence cardinality is invalid")
		}
		if err := VerifyTerminalPayoutEvidenceSetV1(terminalPayout, payouts, offer.CoverageTerms,
			authorityResolver, fenceResolver, paymentVerifier, now); err != nil {
			return err
		}
		for index, execution := range terminalPayout.PayoutExecutionEvidence {
			obligation := payouts.Obligations[index]
			var actionBody GuarantorAgreementPaymentActionBodyV1
			if codec.Unmarshal(execution.StageActionAdmissionEvidence.CanonicalRequest, &actionBody) != nil ||
				!equalCanonical(actionBody.SettlementObligation, obligation) ||
				!equalCanonical(actionBody.MaterializedPayoutObligationSet, payouts) {
				return errors.New("terminal payout execution request cannot be reconstructed")
			}
			if err := VerifyGuarantorPayoutExecutionEvidenceV1(execution, actionBody.PaymentRequest, obligation,
				payouts, offer.CoverageTerms, authorityResolver, fenceResolver, paymentVerifier, now); err != nil {
				return err
			}
		}
	}
	if comparison, err := compareAmount(body.CumulativeApprovedAmount, offer.CoverageTerms.MaximumAggregatePayout); err != nil || comparison > 0 {
		return errors.New("terminal claim set exceeds the Agreement aggregate payout cap")
	}
	paidVsMaximum, paidComparisonErr := compareAmount(body.CumulativePaidAmount, offer.CoverageTerms.MaximumAggregatePayout)
	if paidComparisonErr != nil || body.CoverageClosureReason == "aggregate_exhaustion" && paidVsMaximum != 0 ||
		body.CoverageClosureReason != "aggregate_exhaustion" && body.CoverageClosureReason != "terminal_default" && paidVsMaximum == 0 {
		return errors.New("aggregate exhaustion outcome does not match the finalized paid amount")
	}
	request := CoverageClosureActionBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: body.CoverageAgreementBodyDigest, CoverageObligationID: body.CoverageObligationID,
		ClaimFilingCloseReceiptDigest:       body.ClaimFilingCloseReceiptDigest,
		ExpectedCoverageEndCommitmentDigest: body.CoverageEndCommitmentDigest,
		ClaimResolutionBundles:              value.ClaimResolutionBundles, ClaimResolutionRefSet: value.ClaimResolutionRefSet,
		ClosureReason: body.CoverageClosureReason, ExpectedCoverageRevision: body.PriorCoverageRevision,
		TargetCoverageRevision: body.ReleasePendingCoverageRevision, TargetCoverageState: "release_pending",
		ExpectedClaimSetRevision: 0, TargetClaimSetRevision: 1,
		CoverageClosureEvidenceContext:          value.CoverageClosureEvidenceContext,
		TerminalPrerequisiteEvidenceSet:         value.CoverageClosureEvidenceSet,
		FeeResolutionEvidenceSet:                value.FeeResolutionEvidenceSet,
		CollateralReleaseEligibilityEvidenceSet: value.CollateralReleaseEligibilityEvidenceSet,
		TransitionEvidenceProjection:            value.TransitionEvidenceProjection}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.OwnerID),
		"agent_id":              agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.AgentID),
		"agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest), "obligation_id": agentcommerce.ID(body.CoverageObligationID),
		"expected_state_revision": agentcommerce.U64(body.PriorCoverageRevision), "target_state": agentcommerce.State("release_pending"),
		"evidence_set_digest": agentcommerce.Digest32(bundleDigest)}
	if err := verifyPortableStage(value.StageActionAdmissionEvidence, &bound, request, fields, "coverage_closure", body.AuthorizedActionDigest,
		body.StableActionID, body.ExactRequestDigest, body.WriterGeneration, body.WriterFenceDigest,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-terminal-claim-set-body.v1", body)
	return ValidateAuthorizationSet(value.Authorizations, "terminal-claim-set", bodyDigest,
		"tos.service.agent-guarantor-terminal-claim-set-signature.v1", []string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}

func verifyTerminalPaymentRequestBindingV1(request agentcommerce.AgreementPaymentRequest,
	obligation agentcommerce.SettlementObligation, line MaterializedPayoutLineV1, terms CoverageTermsV1) error {
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "payout_execution")
	if err != nil {
		return err
	}
	operation, err := StageOperationBindingForAuthorityV1(bound)
	if err != nil {
		return err
	}
	destination := terms.PayoutTemplate.PayoutDestinationBinding.PayoutDestination
	destinationDigest, digestErr := agentcommerce.PayoutDestinationDigestV1(destination)
	validVariant := request.SchemaVersion == 1 && operation.ActionKind == "payment.direct" &&
		request.NetworkDomainDigest == "" && request.SemanticActionKind == "" ||
		request.SchemaVersion == 3 && operation.ActionKind == "payment.domain-bound" &&
			request.NetworkDomainDigest == destination.NetworkOrSystemDigest && request.SemanticActionKind == "" ||
		request.SchemaVersion == 2 && operation.ActionKind == "settlement.external" &&
			request.SemanticActionKind == "settlement.external" &&
			request.AdapterProfileDigest == terms.SelectedPayoutAdapterProfile.ProfileDigest &&
			request.ExternalSystemID == destination.NetworkOrSystemDigest
	if digestErr != nil || destinationDigest != line.ClaimPayoutLine.PayoutDestinationDigest ||
		!validVariant || request.OwnerID != bound.ActionOwnerID || request.AgentID != bound.ActionAgentID ||
		request.AgreementBodyDigest != obligation.AgreementBodyDigest ||
		request.AgreementObligationID != obligation.AgreementObligationID ||
		request.ObligationInstanceID != obligation.ObligationInstanceID ||
		request.PayerAgentID != obligation.PayerAgentID || request.PayeeAgentID != obligation.PayeeAgentID ||
		request.Amount != obligation.Amount || !bytes.Equal(request.Destination, destination.DestinationBytes) ||
		len(destination.RoutingParameters) != 0 ||
		request.SettlementAdapterURI != obligation.SettlementAdapterURI ||
		request.SettlementAdapterURI != terms.SelectedPayoutAdapterProfile.ProfileURI ||
		request.ExpiresAtUnix != obligation.ExpiresAtUnix || agentcommerce.PaymentActionKind(request) != operation.ActionKind {
		return errors.New("terminal payment request differs from the Agreement-bound payout")
	}
	canonical, fields, err := agentcommerce.PaymentAuthorizationMaterial(request)
	if err != nil || len(canonical) == 0 {
		return errors.New("terminal payment request is not canonical")
	}
	wantStable, _, err := agentcommerce.DeriveStableActionID(operation.ActionKind, fields)
	if err != nil || wantStable != request.StableActionID {
		return errors.New("terminal payment request has a substituted semantic identity")
	}
	return nil
}

func VerifyExposureReleaseReceiptV1(value AuthorizedExposureReleaseReceiptV1, offer AuthorizedFirmCoverageOfferV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, paymentVerifier agentcommerce.PaymentEvidenceVerifier, now time.Time) error {
	if _, err := ExposureReleaseReceiptDigestV1(value); err != nil {
		return err
	}
	if err := enforceCanonicalSize(value, offer.CoverageTerms.ClaimClosureCapacity.MaximumExposureReleaseReceiptBytes,
		"exposure release receipt"); err != nil {
		return err
	}
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "post_acceptance_exposure_release")
	if err != nil {
		return err
	}
	if err := VerifyTerminalClaimSetV1(value.AuthorizedTerminalClaimSetEvidence, offer, agreementVerifier,
		authorityResolver, fenceResolver, paymentVerifier, now); err != nil {
		return err
	}
	body := value.Body
	terminalDigest, _ := TerminalClaimSetDigestV1(value.AuthorizedTerminalClaimSetEvidence)
	exposureDigest, _ := ExposureAdmissionReceiptDigestV1(value.AuthorizedExposureAdmissionReceipt)
	computed, computationErr := ComputeExposureDispositionV1(value.AuthorizedExposureAdmissionReceipt,
		value.AuthorizedTerminalClaimSetEvidence.Body)
	computationDigest, digestErr := ExposureDispositionComputationDigestV1(value.ExposureDispositionComputation)
	if body.TerminalClaimSetEvidenceDigest != terminalDigest || body.ExposureAdmissionReceiptDigest != exposureDigest ||
		body.ReservationID != offer.Body.ReservationID || body.CoverageAgreementBodyDigest != offer.Body.CoverageAgreementBodyDigest ||
		body.ReleasedExposure != offer.ExposureAdmissionReceipt.Body.ReservedExposure || body.RemainingReservedExposure.AmountAtomic != "0" ||
		computationErr != nil || digestErr != nil || !equalCanonical(computed, value.ExposureDispositionComputation) ||
		body.ExposureDispositionComputationDigest != computationDigest ||
		body.PortfolioDisposition != computed.PortfolioDisposition ||
		body.ReturnedToAvailableExposure != computed.ReturnedToAvailableExposure || body.RealizedLoss != computed.RealizedLoss ||
		body.RetainedDefaultedLiability != computed.RetainedDefaultedLiability ||
		body.ReleasedReleaseStateRevision != body.BaseReleaseStateRevision+1 {
		return errors.New("exposure release receipt binding is invalid")
	}
	request := ExposureReleaseActionBodyV1{ReservationID: body.ReservationID, AgreementDigest: body.CoverageAgreementBodyDigest,
		TargetPortfolioRevision: body.ReleasedReleaseStateRevision, TerminalEvidenceSetDigest: terminalDigest}
	if err := enforceCanonicalSize(request, offer.CoverageTerms.ClaimClosureCapacity.MaximumExposureReleaseRequestBytes,
		"exposure release request"); err != nil {
		return err
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.OwnerID),
		"agent_id": agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.AgentID), "reservation_id": agentcommerce.Digest32(body.ReservationID),
		"target_revision": agentcommerce.U64(body.ReleasedReleaseStateRevision), "terminal_evidence_set_digest": agentcommerce.Digest32(terminalDigest)}
	if err := verifyPortableStage(value.StageActionAdmissionEvidence, &bound, request, fields, "post_acceptance_exposure_release",
		body.AuthorizedActionDigest, body.StableActionID, body.ExactRequestDigest, body.WriterGeneration, body.WriterFenceDigest,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-exposure-release-receipt-body.v1", body)
	return ValidateAuthorizationSet(value.Authorizations, "exposure-release-receipt", bodyDigest,
		"tos.service.agent-guarantor-exposure-release-receipt-signature.v1", []string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}

func VerifyCoverageResolutionV1(value AuthorizedCoverageResolutionV1, offer AuthorizedFirmCoverageOfferV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, paymentVerifier agentcommerce.PaymentEvidenceVerifier, now time.Time) error {
	if _, err := CoverageResolutionDigestV1(value); err != nil {
		return err
	}
	if err := enforceCanonicalSize(value, offer.CoverageTerms.ClaimClosureCapacity.MaximumCoverageResolutionEnvelopeBytes,
		"coverage resolution"); err != nil {
		return err
	}
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "coverage_resolution")
	if err != nil {
		return err
	}
	if err := VerifyExposureReleaseReceiptV1(value.AuthorizedExposureReleaseReceipt, offer, agreementVerifier,
		authorityResolver, fenceResolver, paymentVerifier, now); err != nil {
		return err
	}
	body := value.Body
	releaseDigest, _ := ExposureReleaseReceiptDigestV1(value.AuthorizedExposureReleaseReceipt)
	terminal := value.AuthorizedExposureReleaseReceipt.AuthorizedTerminalClaimSetEvidence.Body
	if body.ExposureReleaseReceiptDigest != releaseDigest || body.TerminalClaimSetEvidenceDigest != value.AuthorizedExposureReleaseReceipt.Body.TerminalClaimSetEvidenceDigest ||
		body.CoverageEndCommitmentDigest != terminal.CoverageEndCommitmentDigest || body.ActivationEvidenceDigest != terminal.ActivationEvidenceDigest ||
		body.TerminalState != terminal.ResolutionTargetTerminalState || body.ResolvedCoverageRevision != body.PriorCoverageRevision+1 {
		return errors.New("coverage resolution binding is invalid")
	}
	request := CoverageResolutionActionBodyV1{SchemaVersion: 1, ExposureReleaseReceiptDigest: releaseDigest,
		ExpectedRevision: body.PriorCoverageRevision, TargetRevision: body.ResolvedCoverageRevision}
	if err := enforceCanonicalSize(request, offer.CoverageTerms.ClaimClosureCapacity.MaximumCoverageResolutionRequestBytes,
		"coverage resolution request"); err != nil {
		return err
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.OwnerID),
		"agent_id":              agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.AgentID),
		"agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest), "obligation_id": agentcommerce.ID(body.CoverageObligationID),
		"expected_state_revision": agentcommerce.U64(body.PriorCoverageRevision), "target_state": agentcommerce.State(body.TerminalState),
		"evidence_set_digest": agentcommerce.Digest32(releaseDigest)}
	if err := verifyPortableStage(value.StageActionAdmissionEvidence, &bound, request, fields, "coverage_resolution", body.AuthorizedActionDigest,
		body.StableActionID, body.ExactRequestDigest, body.WriterGeneration, body.WriterFenceDigest,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-resolution-body.v1", body)
	return ValidateAuthorizationSet(value.Authorizations, "coverage-resolution", bodyDigest,
		"tos.service.agent-guarantor-resolution-signature.v1", []string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}

func verifyPortableStage(stage PortableStageActionAdmissionEvidenceV1, bound *GuarantorStageActionAuthorityV1, request interface{}, fields map[string]agentcommerce.SemanticValue,
	expectedStage, actionDigest, stableID, exactRequestDigest string, generation uint64, fenceDigest string,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	canonical, err := codec.Marshal(request)
	if bound != nil {
		if bound.Stage != expectedStage || VerifyPortableStageActionAdmissionEvidenceV1(stage, *bound, canonical, fields,
			authorityResolver, fenceResolver, now) != nil {
			return errors.New("portable Guarantor stage does not match the Agreement-selected authority")
		}
	}
	computedActionDigest, actionErr := agentcommerce.AuthorizedActionDigest(stage.AuthorizedAction)
	if err != nil || actionErr != nil || !bytes.Equal(canonical, stage.CanonicalRequest) || stage.Body.Stage != expectedStage ||
		stage.Body.AuthorizedActionDigest != computedActionDigest || computedActionDigest != actionDigest ||
		stage.Body.CanonicalRequestDigest != exactRequestDigest || stage.AuthorizedAction.StableActionID != stableID ||
		stage.AuthorizedAction.ExactRequestDigest != exactRequestDigest || stage.AuthorizedAction.WriterGeneration != generation ||
		stage.AuthorizedAction.WriterFenceDigest != fenceDigest || stage.ActionResolution.State != agentcommerce.ActionTerminal ||
		stage.ActionResolution.StableActionID != stableID || stage.ActionResolution.ExactRequestDigest != exactRequestDigest {
		return errors.New("portable Guarantor stage evidence is invalid")
	}
	admittedAt := time.Unix(int64(stage.Body.AdmittedAtUnix), 0).UTC()
	if admittedAt.After(now.UTC().Add(5*time.Minute)) || agentcommerce.VerifyAuthorizedActionAtAuthorityTime(stage.AuthorizedAction,
		fields, canonical, stage.WriterFence, fenceResolver, admittedAt, now) != nil {
		return errors.New("portable Guarantor stage action does not verify")
	}
	if stage.ActionAdmissionAuthorization.AuthoritySubject != stage.AuthorizedAction.AuthorityID ||
		stage.ActionAdmissionAuthorization.ValidationTimeUnix != stage.Body.AdmittedAtUnix {
		return errors.New("portable Guarantor stage admission is signed by the wrong authority or at the wrong time")
	}
	stageBodyDigest, _ := codec.Digest("tos.service.agent-guarantor-stage-action-admission.v1", stage.Body)
	return verifyStageActionAdmissionAuthorizationV1(stage.ActionAdmissionAuthorization, stage.AuthorizedAction,
		stageBodyDigest, authorityResolver, fenceResolver, now)
}

func ValidateTerminalClaimSetV1(value AuthorizedTerminalClaimSetEvidenceV1) error {
	body := value.Body
	validOutcome := body.CoverageClosureReason == "normal_expiry" && body.ResolutionTargetTerminalState == "closed" ||
		body.CoverageClosureReason == "accepted_cancellation" && body.ResolutionTargetTerminalState == "cancelled" ||
		body.CoverageClosureReason == "aggregate_exhaustion" && body.ResolutionTargetTerminalState == "exhausted" ||
		body.CoverageClosureReason == "terminal_default" && body.ResolutionTargetTerminalState == "defaulted"
	if body.SchemaVersion != 1 || !validDigest(body.CoverageAgreementBodyDigest) || !validToken(body.CoverageObligationID, 128) ||
		!validDigest(body.ClaimAdmissionProfileDigest) || !sortedUnique(body.ClaimAdmissionAuthoritySubjects, MaxAuthorizations, validID) ||
		!validID(body.ClaimAdmissionLogID) || !validDigest(body.ClaimFilingCloseReceiptDigest) ||
		!validDigest(body.CoverageEndCommitmentDigest) || body.ActivationEvidenceDigest != "" && !validDigest(body.ActivationEvidenceDigest) ||
		!validDigest(body.CoverageClosureContextDigest) || !validDigest(body.CoverageClosureEvidenceSetDigest) ||
		!validDigest(body.TransitionEvidenceProjectionDigest) ||
		!validOutcome || body.OpenClaimCount != 0 ||
		body.AmbiguousActionCount != 0 || body.ClaimSetRevision != 1 || body.AdmissionHighWater != uint64(len(value.ClaimResolutionBundles)) ||
		len(value.ClaimResolutionBundles) != len(body.ClaimResolutions) || len(value.Authorizations) == 0 ||
		value.ClaimResolutionRefSet.SchemaVersion != 1 || value.ClaimResolutionRefSet.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
		value.ClaimResolutionRefSet.CoverageObligationID != body.CoverageObligationID ||
		value.ClaimResolutionRefSet.AdmissionHighWater != body.AdmissionHighWater ||
		!equalCanonical(value.ClaimResolutionRefSet.Refs, body.ClaimResolutions) {
		return errors.New("terminal claim set shape is invalid")
	}
	refSetDigest, refSetErr := ClaimTerminalResolutionRefSetDigestV1(value.ClaimResolutionRefSet)
	contextDigest, contextErr := CoverageClosureEvidenceContextDigestV1(value.CoverageClosureEvidenceContext)
	evidenceSetDigest, evidenceSetErr := CanonicalGuarantorEvidenceSetDigestV1(value.CoverageClosureEvidenceSet)
	projectionDigest, projectionErr := TransitionEvidenceProjectionDigestV1(value.TransitionEvidenceProjection)
	if refSetErr != nil || contextErr != nil || evidenceSetErr != nil || projectionErr != nil ||
		refSetDigest != value.CoverageClosureEvidenceContext.ClaimResolutionSetDigest ||
		contextDigest != body.CoverageClosureContextDigest || evidenceSetDigest != body.CoverageClosureEvidenceSetDigest ||
		projectionDigest != body.TransitionEvidenceProjectionDigest || value.CoverageClosureEvidenceSet.Purpose != "coverage-closure" ||
		value.CoverageClosureEvidenceSet.ContextDigest != contextDigest {
		return errors.New("terminal claim-set context or evidence projection is invalid")
	}
	contextValue := value.CoverageClosureEvidenceContext
	if contextValue.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
		contextValue.CoverageObligationID != body.CoverageObligationID ||
		contextValue.ClaimFilingCloseReceiptDigest != body.ClaimFilingCloseReceiptDigest ||
		contextValue.CoverageCancellationReceiptDigest != body.CoverageCancellationReceiptDigest ||
		contextValue.CoverageEndCommitmentDigest != body.CoverageEndCommitmentDigest ||
		contextValue.FilingCloseReason != body.FilingCloseReason || contextValue.CoverageEndReason != body.CoverageEndReason ||
		contextValue.IncidentEligibilityEndsAtUnix != body.IncidentEligibilityEndsAtUnix ||
		contextValue.CoverageEndEvidenceDigest != body.CoverageEndEvidenceDigest ||
		contextValue.ActivationEvidenceDigest != body.ActivationEvidenceDigest ||
		contextValue.CoverageClosureReason != body.CoverageClosureReason ||
		contextValue.ResolutionTargetTerminalState != body.ResolutionTargetTerminalState ||
		contextValue.AdmissionHighWater != body.AdmissionHighWater ||
		contextValue.ClaimAdmissionLogRoot != body.ClaimAdmissionLogRoot ||
		contextValue.CumulativeApprovedAmount != body.CumulativeApprovedAmount ||
		contextValue.CumulativePaidAmount != body.CumulativePaidAmount ||
		contextValue.CumulativeDefaultedAmount != body.CumulativeDefaultedAmount ||
		contextValue.OutstandingApprovedAmount != body.OutstandingApprovedAmount ||
		contextValue.ReleaseNotBeforeUnix != body.ReleaseNotBeforeUnix {
		return errors.New("terminal claim-set body differs from its closure context")
	}
	expectedClosureObjects := make(map[string]struct {
		contentType string
		wire        []byte
	}, len(value.ClaimResolutionBundles)+1)
	filingWire, filingWireErr := codec.Marshal(value.AuthorizedClaimFilingCloseReceipt)
	filingEnvelopeDigest, filingEnvelopeErr := ClaimFilingCloseReceiptDigestV1(value.AuthorizedClaimFilingCloseReceipt)
	if filingWireErr != nil || filingEnvelopeErr != nil {
		return errors.New("terminal filing-close evidence cannot be encoded")
	}
	expectedClosureObjects[filingEnvelopeDigest] = struct {
		contentType string
		wire        []byte
	}{"application/vnd.tos.service.agent-guarantor-claim-filing-close-envelope.v1+cbor", filingWire}
	for _, bundle := range value.ClaimResolutionBundles {
		wire, wireErr := codec.Marshal(bundle)
		digest, digestErr := codec.Digest("tos.service.agent-guarantor-claim-terminal-resolution-bundle.v1", bundle)
		if wireErr != nil || digestErr != nil {
			return errors.New("terminal claim-resolution bundle cannot be encoded")
		}
		expectedClosureObjects[digest] = struct {
			contentType string
			wire        []byte
		}{"application/vnd.tos.service.agent-guarantor-claim-terminal-resolution-bundle.v1+cbor", wire}
	}
	if len(value.CoverageClosureEvidenceSet.Items) != len(expectedClosureObjects) {
		return errors.New("terminal closure evidence cardinality is invalid")
	}
	for _, item := range value.CoverageClosureEvidenceSet.Items {
		expected, found := expectedClosureObjects[item.EvidenceEnvelopeDigest]
		if !found || item.ContentType != expected.contentType ||
			item.EvidenceProfileDigest != body.ClaimAdmissionProfileDigest {
			return errors.New("terminal closure evidence contains a substituted object")
		}
		if item.Representation == "inline" {
			if item.ImmutableDescriptor != nil || !bytes.Equal(item.CanonicalEnvelopeBytes, expected.wire) {
				return errors.New("terminal inline closure evidence differs from its carried object")
			}
		} else if item.ImmutableDescriptor == nil || len(item.CanonicalEnvelopeBytes) != 0 ||
			item.ImmutableDescriptor.ContentType != expected.contentType ||
			item.ImmutableDescriptor.ContentDigest != item.EvidenceEnvelopeDigest ||
			item.ImmutableDescriptor.ContentSize != uint64(len(expected.wire)) ||
			item.ImmutableDescriptor.RetrievalPolicyDigest != body.ClaimAdmissionProfileDigest {
			return errors.New("terminal content-addressed closure descriptor differs from its carried object")
		}
		delete(expectedClosureObjects, item.EvidenceEnvelopeDigest)
	}
	if len(expectedClosureObjects) != 0 {
		return errors.New("terminal closure evidence omits a carried object")
	}
	approved, paid, defaulted := new(big.Int), new(big.Int), new(big.Int)
	for index, bundle := range value.ClaimResolutionBundles {
		initial := bundle.InitialClaimAdmissionReceiptProof
		finalAdmission := initial
		for _, revision := range bundle.RevisionAdmissionReceiptProofs {
			finalAdmission = revision
		}
		claim := finalAdmission.AuthorizedClaimIngressReceipt.AuthorizedClaim
		decision := bundle.TerminalAuthorizedDecision
		payouts := bundle.MaterializedPayoutObligationSet
		ref := bundle.ResolutionRef
		if ref != body.ClaimResolutions[index] || ref.ClaimAdmissionSequence != uint64(index+1) || ref.ClaimID != claim.Body.ClaimID ||
			(ref.TerminalClaimState != ClaimFinalApproved && ref.TerminalClaimState != ClaimFinalPartiallyApproved && ref.TerminalClaimState != ClaimFinalDenied) ||
			initial.ReceiptBody.AdmittedClaimRevision != 1 || initial.ReceiptBody.ClaimAdmissionSequence != ref.ClaimAdmissionSequence ||
			finalAdmission.ReceiptBody.AdmittedClaimRevision != ref.FinalClaimRevision || ref.ClaimStateRevision == 0 {
			return errors.New("terminal claim bundle is nonterminal or reordered")
		}
		claimDigest, _ := ClaimEnvelopeDigest(claim)
		decisionDigest, _ := ClaimDecisionDigestV1(decision)
		payoutDigest, _ := codec.Digest(PayoutSetDomain, payouts)
		paymentDigest, _ := TerminalPayoutEvidenceSetDigestV1(bundle.TerminalPayoutEvidenceSet)
		initialDigest := initial.ReceiptEnvelopeDigest
		finalAdmissionDigest := finalAdmission.ReceiptEnvelopeDigest
		decisionApplicationDigest := bundle.DecisionApplicationReceiptProof.ReceiptEnvelopeDigest
		if len(bundle.DecisionAdmissionReceiptProofs) == 0 || len(bundle.ClaimStateTransitionReceipts) == 0 {
			return errors.New("terminal claim omits its decision or state-transition history")
		}
		terminalDecisionAdmissionDigest := bundle.DecisionAdmissionReceiptProofs[len(bundle.DecisionAdmissionReceiptProofs)-1].ReceiptEnvelopeDigest
		terminalTransitionDigest, _ := ClaimStateTransitionReceiptDigestV1(bundle.ClaimStateTransitionReceipts[len(bundle.ClaimStateTransitionReceipts)-1])
		if claimDigest != ref.TerminalAuthorizedClaimEnvelopeDigest || decisionDigest != ref.TerminalDecisionDigest ||
			payoutDigest != ref.MaterializedPayoutObligationSetDigest || paymentDigest != ref.TerminalPayoutEvidenceSetDigest ||
			initialDigest != ref.InitialClaimAdmissionReceiptDigest || finalAdmissionDigest != ref.FinalClaimRevisionAdmissionReceiptDigest ||
			terminalDecisionAdmissionDigest != ref.TerminalDecisionAdmissionReceiptDigest ||
			decisionApplicationDigest != ref.DecisionApplicationReceiptDigest ||
			terminalTransitionDigest != ref.TerminalClaimStateTransitionReceiptDigest ||
			ref.ClaimRevisionAdmissionHighWater != finalAdmission.ReceiptBody.ClaimRevisionAdmissionSequence ||
			ref.ClaimRevisionAdmissionLogRoot != finalAdmission.ReceiptBody.AdmittedClaimRevisionLogRoot ||
			ref.ClaimRevisionIngressHighWater != finalAdmission.AuthorizedClaimIngressReceipt.Body.ClaimIngressSequence ||
			ref.ClaimRevisionIngressLogRoot != finalAdmission.AuthorizedClaimIngressReceipt.Body.AdmittedClaimIngressLogRoot {
			return errors.New("terminal claim bundle digest mismatch")
		}
		amount, _ := new(big.Int).SetString(decision.Body.ApprovedAmount.AmountAtomic, 10)
		approved.Add(approved, amount)
		terminalState := "final_" + string(decision.Body.Result)
		if string(ref.TerminalClaimState) != terminalState ||
			bundle.DecisionApplicationReceiptProof.Body.MaterializedPayoutObligationSetDigest != payoutDigest ||
			payouts.AuthorizedClaimDecisionDigest != decisionDigest {
			return errors.New("terminal claim state or payout materialization is substituted")
		}
		if decision.Body.Result == DecisionDenied {
			if bundle.TerminalPayoutEvidenceSet.Disposition != "not_applicable" || payouts.MaterializationState != "not_applicable" ||
				len(payouts.Obligations) != 0 || len(bundle.TerminalPayoutEvidenceSet.PayoutExecutionEvidence) != 0 || amount.Sign() != 0 {
				return errors.New("denied claim carries payout value")
			}
		} else if (bundle.TerminalPayoutEvidenceSet.Disposition != "resolved" && bundle.TerminalPayoutEvidenceSet.Disposition != "defaulted") ||
			payouts.MaterializationState != "materialized" || len(payouts.Obligations) == 0 ||
			len(bundle.TerminalPayoutEvidenceSet.PayoutExecutionEvidence) != len(payouts.Obligations) {
			return errors.New("approved claim lacks a complete terminal payout set")
		}
		if decision.Body.Result != DecisionDenied {
			claimPaid, claimDefaulted := new(big.Int), new(big.Int)
			for paymentIndex, execution := range bundle.TerminalPayoutEvidenceSet.PayoutExecutionEvidence {
				paymentAmount, ok := new(big.Int).SetString(payouts.Obligations[paymentIndex].Amount.AmountAtomic, 10)
				if !ok || paymentAmount.Sign() <= 0 || paymentIndex >= len(payouts.Obligations) ||
					execution.ObligationInstanceID != payouts.Obligations[paymentIndex].ObligationInstanceID {
					return errors.New("terminal payout amount is invalid")
				}
				switch execution.AgreementPaymentEvidence.ResolvedState {
				case "finalized":
					claimPaid.Add(claimPaid, paymentAmount)
				case "defaulted":
					claimDefaulted.Add(claimDefaulted, paymentAmount)
				default:
					return errors.New("terminal payout carries a nonterminal Adapter state")
				}
			}
			if new(big.Int).Add(new(big.Int).Set(claimPaid), claimDefaulted).Cmp(amount) != 0 ||
				(bundle.TerminalPayoutEvidenceSet.Disposition == "resolved" && claimDefaulted.Sign() != 0) ||
				(bundle.TerminalPayoutEvidenceSet.Disposition == "defaulted" && claimDefaulted.Sign() == 0) {
				return errors.New("terminal payout disposition does not match its claim state")
			}
			paid.Add(paid, claimPaid)
			defaulted.Add(defaulted, claimDefaulted)
		}
	}
	if new(big.Int).Add(new(big.Int).Set(paid), defaulted).Cmp(approved) != 0 ||
		body.CumulativeApprovedAmount.AmountAtomic != approved.String() || body.CumulativePaidAmount.AmountAtomic != paid.String() ||
		body.CumulativeDefaultedAmount.AmountAtomic != defaulted.String() || body.OutstandingApprovedAmount.AmountAtomic != "0" ||
		body.CumulativeApprovedAmount.Asset != body.CumulativePaidAmount.Asset || body.CumulativeApprovedAmount.Asset != body.CumulativeDefaultedAmount.Asset ||
		body.CumulativeApprovedAmount.Asset != body.OutstandingApprovedAmount.Asset {
		return errors.New("terminal claim arithmetic is invalid")
	}
	if body.CoverageClosureReason == "terminal_default" && defaulted.Sign() == 0 ||
		body.CoverageClosureReason != "terminal_default" && defaulted.Sign() != 0 {
		return errors.New("terminal default outcome does not match the verified defaulted amount")
	}
	return nil
}

func sortTerminalBundles(bundles []ClaimTerminalResolutionBundleV1) bool {
	for index := 1; index < len(bundles); index++ {
		left, _ := codec.Marshal(bundles[index-1].ResolutionRef)
		right, _ := codec.Marshal(bundles[index].ResolutionRef)
		if bytes.Compare(left, right) >= 0 {
			return false
		}
	}
	return true
}
