// Package agentguarantor implements the bounded, Carrier-neutral Agent
// Guarantor Service V1 profile. It deliberately contains no discovery index,
// private underwriting policy, AI authority, custody key, or chain consensus.
package agentguarantor

import (
	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	SchemaVersionV1         uint16 = 1
	RegistryVersionV1       uint16 = 1
	MaxCanonicalObjectBytes        = 1 << 20
	MaxProfileArtifactBytes        = 512 << 10
	MaxProfileRevisions            = 64
	MaxCoverageCapabilities        = 64
	MaxClaimProfiles               = 64
	MaxCollateralProfiles          = 64
	MaxPayoutAdapters              = 32
	MaxClaims                      = 1024
	MaxClaimRevisions              = 64
	MaxEvidenceItems               = 256
	MaxPayoutLines                 = 256
	MaxAuthorizations              = 512
	MaxExtensions                  = 64
	MaxObjectIDBytes               = 256
	MaxPolicyBytes                 = 64 << 10
)

const (
	ProfileURI = "tos.agent-service.guarantor.v1"

	ServiceProfileDomain = "tos.service.agent-guarantor-service-profile.v1"
	RequestedTermsDomain = "tos.service.agent-guarantor-requested-coverage-terms.v1"
	QuoteRequestDomain   = "tos.service.agent-guarantor-quote-request-envelope.v1"
	CoverageTermsDomain  = "tos.service.agent-guarantor-coverage-terms.v1"
	FirmOfferDomain      = "tos.service.agent-guarantor-firm-offer-envelope.v1"
	ClaimDomain          = "tos.service.agent-guarantor-claim-envelope.v1"
	ClaimBodyDomain      = "tos.service.agent-guarantor-claim.v1"
	ClaimDecisionDomain  = "tos.service.agent-guarantor-claim-decision-envelope.v1"
	PayoutSetDomain      = "tos.service.agent-guarantor-payout-obligation-set.v1"
	CollateralDomain     = "tos.service.agent-guarantor-collateral-evidence-envelope.v1"
)

type AssuranceLevel string

const (
	AssuranceUnsecuredSigned       AssuranceLevel = "unsecured-signed"
	AssuranceCollateralAttested    AssuranceLevel = "collateral-attested"
	AssuranceIndependentlyEnforced AssuranceLevel = "independently-enforceable"
)

type BenefitKind string

const (
	BenefitFixed     BenefitKind = "fixed_benefit"
	BenefitIndemnity BenefitKind = "indemnity"
)

type AuthorizationStatementV1 struct {
	SchemaVersion        uint16 `json:"schema_version"`
	AuthoritySubject     string `json:"authority_subject"`
	ProfileURI           string `json:"profile_uri"`
	ProfileVersion       uint64 `json:"profile_version"`
	ProfileDigest        string `json:"profile_digest"`
	AuthorizedObjectKind string `json:"authorized_object_kind"`
	AuthorizedBodyDigest string `json:"authorized_body_digest"`
	ValidationTimeUnix   uint64 `json:"validation_time_unix"`
}

// NativeMLDSA44AgentAuthorizationEvidenceV1 is native Agent authorization
// evidence: a Pure ML-DSA-44 signature under TOS-AGENT-GUARANTOR-V1 by one of
// the subject's Native Registry controllers. It carries no public key; the
// verifier takes the key stored for KeyID in the Agent state that
// HistoricalAuthorityProof locates.
type NativeMLDSA44AgentAuthorizationEvidenceV1 struct {
	// KeyID is mldsa44:<64 lowercase hex>.
	KeyID string `json:"key_id"`
	// Signature is mldsa44:<unpadded URL-safe Base64 of 2,420 bytes>.
	Signature string `json:"signature"`
	// HistoricalAuthorityProof is the canonical CBOR of
	// NativeAgentHistoricalAuthorityProofV1.
	HistoricalAuthorityProof []byte `json:"historical_authority_proof"`
}

type ProfileQualifiedObjectAuthorizationV1 struct {
	AuthoritySubject     string                                    `json:"authority_subject"`
	ProfileURI           string                                    `json:"profile_uri"`
	ProfileVersion       uint64                                    `json:"profile_version"`
	ProfileDigest        string                                    `json:"profile_digest"`
	AuthorizedObjectKind string                                    `json:"authorized_object_kind"`
	AuthorizedBodyDigest string                                    `json:"authorized_body_digest"`
	ValidationTimeUnix   uint64                                    `json:"validation_time_unix"`
	EvidenceContentType  string                                    `json:"evidence_content_type"`
	Evidence             NativeMLDSA44AgentAuthorizationEvidenceV1 `json:"evidence"`
}

func (authorization ProfileQualifiedObjectAuthorizationV1) AuthorizationStatement() AuthorizationStatementV1 {
	return AuthorizationStatementV1{SchemaVersion: SchemaVersionV1,
		AuthoritySubject: authorization.AuthoritySubject, ProfileURI: authorization.ProfileURI,
		ProfileVersion: authorization.ProfileVersion, ProfileDigest: authorization.ProfileDigest,
		AuthorizedObjectKind: authorization.AuthorizedObjectKind,
		AuthorizedBodyDigest: authorization.AuthorizedBodyDigest,
		ValidationTimeUnix:   authorization.ValidationTimeUnix}
}

// ActionAuthorityMLDSA44EvidenceV1 is the stage-admission evidence of a
// scalar Action Authority under its Semantic Action Identity scheme: a Pure
// ML-DSA-44 signature under TOS-ACTION-AUTHORITY-V1. It is never native Agent
// evidence.
type ActionAuthorityMLDSA44EvidenceV1 struct {
	// KeyID is mldsa44:<64 lowercase hex>, the admitted action's
	// authority_key_id.
	KeyID string `json:"key_id"`
	// Signature is mldsa44:<unpadded URL-safe Base64 of 2,420 bytes>.
	Signature                string `json:"signature"`
	HistoricalAuthorityProof []byte `json:"historical_authority_proof"`
}

// StageActionAdmissionAuthorizationV1 authorizes a portable stage admission.
// Its wire fields are those of a profile-qualified authorization, but its
// evidence is the Action Authority's, so native Agent evidence cannot be
// placed here.
type StageActionAdmissionAuthorizationV1 struct {
	AuthoritySubject     string                           `json:"authority_subject"`
	ProfileURI           string                           `json:"profile_uri"`
	ProfileVersion       uint64                           `json:"profile_version"`
	ProfileDigest        string                           `json:"profile_digest"`
	AuthorizedObjectKind string                           `json:"authorized_object_kind"`
	AuthorizedBodyDigest string                           `json:"authorized_body_digest"`
	ValidationTimeUnix   uint64                           `json:"validation_time_unix"`
	EvidenceContentType  string                           `json:"evidence_content_type"`
	Evidence             ActionAuthorityMLDSA44EvidenceV1 `json:"evidence"`
}

func (authorization StageActionAdmissionAuthorizationV1) AuthorizationStatement() AuthorizationStatementV1 {
	return AuthorizationStatementV1{SchemaVersion: SchemaVersionV1,
		AuthoritySubject: authorization.AuthoritySubject, ProfileURI: authorization.ProfileURI,
		ProfileVersion: authorization.ProfileVersion, ProfileDigest: authorization.ProfileDigest,
		AuthorizedObjectKind: authorization.AuthorizedObjectKind,
		AuthorizedBodyDigest: authorization.AuthorizedBodyDigest,
		ValidationTimeUnix:   authorization.ValidationTimeUnix}
}

type AtomicRangeV1 = agentcommerce.AtomicAmountRangeV1
type AtomicAmountV1 = agentcommerce.AtomicAmountV1
type AssetIdentityV1 = agentcommerce.AssetIdentityV1
type ProfileRefV1 = agentcommerce.ProfileRefV1
type PolicyRefV1 = agentcommerce.PolicyRefV1
type PayoutDestinationBindingV1 = agentcommerce.PayoutDestinationBindingV1

type CoverageCapabilityV1 struct {
	Category                    string            `json:"category"`
	BenefitKinds                []BenefitKind     `json:"benefit_kinds"`
	SupportedUnderlyingProfiles []ProfileRefV1    `json:"supported_underlying_profiles"`
	SupportedClaimProfiles      []ProfileRefV1    `json:"supported_claim_profiles"`
	SupportedAssets             []AssetIdentityV1 `json:"supported_assets"`
	CoverageRanges              []AtomicRangeV1   `json:"coverage_ranges"`
	FeeRanges                   []AtomicRangeV1   `json:"fee_ranges"`
	MaximumCoverageSeconds      uint64            `json:"maximum_coverage_seconds"`
	MaximumClaimWindowSeconds   uint64            `json:"maximum_claim_window_seconds"`
	JurisdictionPolicy          PolicyRefV1       `json:"jurisdiction_policy"`
}

type ClaimProfileV1 struct {
	ProfileID                                   string                                 `json:"profile_id"`
	ProfileVersion                              uint64                                 `json:"profile_version"`
	PredecessorProfileDigest                    string                                 `json:"predecessor_profile_digest,omitempty"`
	TriggerProfile                              ProfileRefV1                           `json:"trigger_profile"`
	EvidenceProfile                             ProfileRefV1                           `json:"evidence_profile"`
	ClaimantAuthorizationProfiles               []ProfileRefV1                         `json:"claimant_authorization_profiles"`
	IngressProfile                              ProfileRefV1                           `json:"ingress_profile"`
	IngressAuthoritySubjects                    []string                               `json:"ingress_authority_subjects"`
	IngressAuthorityQuorumRule                  string                                 `json:"ingress_authority_quorum_rule"`
	AdmissionProfile                            ProfileRefV1                           `json:"admission_profile"`
	AdmissionAuthoritySubjects                  []string                               `json:"admission_authority_subjects"`
	AdmissionQuorumRule                         string                                 `json:"admission_quorum_rule"`
	DecisionAdmissionProfile                    ProfileRefV1                           `json:"decision_admission_profile"`
	DecisionAdmissionAuthoritySubjects          []string                               `json:"decision_admission_authority_subjects"`
	DecisionAdmissionQuorumRule                 string                                 `json:"decision_admission_quorum_rule"`
	DecisionProfile                             ProfileRefV1                           `json:"decision_profile"`
	DisputeProfile                              *ProfileRefV1                          `json:"dispute_profile,omitempty"`
	IndependentClaimOperationProfile            *ProfileRefV1                          `json:"independent_claim_operation_profile,omitempty"`
	MaximumClaims                               uint64                                 `json:"maximum_claims"`
	MaximumClaimIngressActions                  uint64                                 `json:"maximum_claim_ingress_actions"`
	MaximumClaimRevisionsPerClaim               uint64                                 `json:"maximum_claim_revisions_per_claim"`
	MaximumDecisionAdmissionsPerClaim           uint64                                 `json:"maximum_decision_admissions_per_claim"`
	MaximumClaimStateTransitionsPerClaim        uint64                                 `json:"maximum_claim_state_transitions_per_claim"`
	MaximumChallengeRoundsPerClaim              uint64                                 `json:"maximum_challenge_rounds_per_claim"`
	MaximumNonterminalRoundsPerClaim            uint64                                 `json:"maximum_nonterminal_rounds_per_claim"`
	MaximumPayoutLinesPerClaim                  uint64                                 `json:"maximum_payout_lines_per_claim"`
	MaximumAdmittedClaimEnvelopeBytes           uint64                                 `json:"maximum_admitted_claim_envelope_bytes"`
	MaximumClaimIngressReceiptEnvelopeBytes     uint64                                 `json:"maximum_claim_ingress_receipt_envelope_bytes"`
	MaximumClaimIngressCutProofBytes            uint64                                 `json:"maximum_claim_ingress_cut_proof_bytes"`
	MaximumAcceptanceRequestEnvelopeBytes       uint64                                 `json:"maximum_acceptance_request_envelope_bytes"`
	MaximumAcceptanceReceiptEnvelopeBytes       uint64                                 `json:"maximum_acceptance_receipt_envelope_bytes"`
	MaximumActivationEvidenceEnvelopeBytes      uint64                                 `json:"maximum_activation_evidence_envelope_bytes"`
	MaximumNonActivationEvidenceEnvelopeBytes   uint64                                 `json:"maximum_non_activation_evidence_envelope_bytes"`
	MaximumCancellationReceiptEnvelopeBytes     uint64                                 `json:"maximum_cancellation_receipt_envelope_bytes"`
	MaximumClaimFilingCloseReceiptEnvelopeBytes uint64                                 `json:"maximum_claim_filing_close_receipt_envelope_bytes"`
	MaximumTerminalClaimSetEnvelopeBytes        uint64                                 `json:"maximum_terminal_claim_set_envelope_bytes"`
	MaximumExposureReleaseRequestBytes          uint64                                 `json:"maximum_exposure_release_request_bytes"`
	MaximumExposureReleaseReceiptBytes          uint64                                 `json:"maximum_exposure_release_receipt_bytes"`
	MaximumCoverageResolutionRequestBytes       uint64                                 `json:"maximum_coverage_resolution_request_bytes"`
	MaximumCoverageResolutionEnvelopeBytes      uint64                                 `json:"maximum_coverage_resolution_envelope_bytes"`
	ContinuationBudgetProfile                   ProfileRefV1                           `json:"continuation_budget_profile"`
	PermittedTerminalFallbacks                  []DeterministicClaimTerminalFallbackV1 `json:"permitted_terminal_fallbacks"`
	MaximumEvidenceItems                        uint64                                 `json:"maximum_evidence_items"`
	MaximumEvidenceBytes                        uint64                                 `json:"maximum_evidence_bytes"`
	ReviewDeadlineSeconds                       uint64                                 `json:"review_deadline_seconds"`
	MaximumNonterminalResolutionWindowSeconds   uint64                                 `json:"maximum_nonterminal_resolution_window_seconds"`
	MaximumSuccessorDecisionWindowSeconds       uint64                                 `json:"maximum_successor_decision_window_seconds"`
	MaximumClaimIngressResolutionGraceSeconds   uint64                                 `json:"maximum_claim_ingress_resolution_grace_seconds"`
	MaximumLateIngressRecoveryWindowSeconds     uint64                                 `json:"maximum_late_ingress_recovery_window_seconds"`
	PayoutDeadlineSeconds                       uint64                                 `json:"payout_deadline_seconds"`
}

type CollateralProfileV1 struct {
	ProfileID                             string                          `json:"profile_id"`
	ProfileVersion                        uint64                          `json:"profile_version"`
	PredecessorProfileDigest              string                          `json:"predecessor_profile_digest,omitempty"`
	AssuranceLevel                        AssuranceLevel                  `json:"assurance_level"`
	Asset                                 AssetIdentityV1                 `json:"asset"`
	CustodyAdapterProfile                 ProfileRefV1                    `json:"custody_adapter_profile"`
	CollateralControlDisclosure           CollateralControlDisclosureV1   `json:"collateral_control_disclosure"`
	TransitionProfiles                    []CollateralTransitionProfileV1 `json:"transition_profiles"`
	IndependentExecutionProfile           *ProfileRefV1                   `json:"independent_execution_profile,omitempty"`
	IndependentExecutionAuthoritySubjects []string                        `json:"independent_execution_authority_subjects,omitempty"`
	IndependentExecutionQuorumRule        string                          `json:"independent_execution_quorum_rule,omitempty"`
	CompatibleClaimProfileDigests         []string                        `json:"compatible_claim_profile_digests"`
	ExclusiveAllocationRequired           bool                            `json:"exclusive_allocation_required"`
	MinimumCollateralizationPPM           uint64                          `json:"minimum_collateralization_ppm"`
	MaximumEvidenceAgeSeconds             uint64                          `json:"maximum_evidence_age_seconds"`
}

type AdmissionLimitsV1 struct {
	MaximumQuoteReservations                uint64 `json:"maximum_quote_reservations"`
	MaximumActiveCoverages                  uint64 `json:"maximum_active_coverages"`
	MaximumActiveClaims                     uint64 `json:"maximum_active_claims"`
	MaximumActivePerCoveredParty            uint64 `json:"maximum_active_per_covered_party"`
	MaximumActivationAttemptsPerCoverage    uint64 `json:"maximum_activation_attempts_per_coverage"`
	MaximumQuoteRequestsPerWindow           uint64 `json:"maximum_quote_requests_per_window"`
	QuoteRequestWindowSeconds               uint64 `json:"quote_request_window_seconds"`
	MaximumAcceptanceProcessingGraceSeconds uint64 `json:"maximum_acceptance_processing_grace_seconds"`
}

type ServiceEndpointsV1 struct {
	QuoteRoute      string `json:"quote_route"`
	AcceptanceRoute string `json:"acceptance_route"`
	ClaimRoute      string `json:"claim_route"`
	ResolveRoute    string `json:"resolve_route"`
	EvidenceRoute   string `json:"evidence_route"`
}

type ServiceProfileV1 struct {
	SchemaVersion                 uint16                 `json:"schema_version"`
	ProfileID                     string                 `json:"profile_id"`
	Revision                      uint64                 `json:"revision"`
	PredecessorProfileDigest      string                 `json:"predecessor_profile_digest,omitempty"`
	ProviderAgentID               string                 `json:"provider_agent_id"`
	AuthorityDomainDigest         string                 `json:"authority_domain_digest"`
	CoverageCapabilities          []CoverageCapabilityV1 `json:"coverage_capabilities"`
	CollateralProfiles            []CollateralProfileV1  `json:"collateral_profiles,omitempty"`
	ClaimProfiles                 []ClaimProfileV1       `json:"claim_profiles"`
	PayoutAdapterProfiles         []ProfileRefV1         `json:"payout_adapter_profiles"`
	AdmissionLimits               AdmissionLimitsV1      `json:"admission_limits"`
	Endpoints                     ServiceEndpointsV1     `json:"endpoints"`
	ExposureAuthorityID           string                 `json:"exposure_authority_id"`
	ExposureAuthorizationProfile  ProfileRefV1           `json:"exposure_authorization_profile"`
	LifecycleAuthorityID          string                 `json:"lifecycle_authority_id"`
	LifecycleAuthorizationProfile ProfileRefV1           `json:"lifecycle_authorization_profile"`
	PolicyRevision                uint64                 `json:"policy_revision"`
	CreatedAtUnix                 uint64                 `json:"created_at_unix"`
	ExpiresAtUnix                 uint64                 `json:"expires_at_unix"`
	RequiredExtensions            []ProfileRefV1         `json:"required_extensions,omitempty"`
	OptionalExtensions            []ProfileRefV1         `json:"optional_extensions,omitempty"`
}

type ClaimClosureCapacityV1 struct {
	MaximumClaims                                         uint64                               `json:"maximum_claims"`
	MaximumClaimIngressActions                            uint64                               `json:"maximum_claim_ingress_actions"`
	MaximumClaimRevisionsPerClaim                         uint64                               `json:"maximum_claim_revisions_per_claim"`
	MaximumDecisionAdmissionsPerClaim                     uint64                               `json:"maximum_decision_admissions_per_claim"`
	MaximumClaimStateTransitionsPerClaim                  uint64                               `json:"maximum_claim_state_transitions_per_claim"`
	MaximumChallengeRoundsPerClaim                        uint64                               `json:"maximum_challenge_rounds_per_claim"`
	MaximumNonterminalRoundsPerClaim                      uint64                               `json:"maximum_nonterminal_rounds_per_claim"`
	MaximumPayoutLinesPerClaim                            uint64                               `json:"maximum_payout_lines_per_claim"`
	MaximumAdmittedClaimEnvelopeBytes                     uint64                               `json:"maximum_admitted_claim_envelope_bytes"`
	MaximumClaimIngressReceiptEnvelopeBytes               uint64                               `json:"maximum_claim_ingress_receipt_envelope_bytes"`
	MaximumClaimIngressCutProofBytes                      uint64                               `json:"maximum_claim_ingress_cut_proof_bytes"`
	MaximumAcceptanceRequestEnvelopeBytes                 uint64                               `json:"maximum_acceptance_request_envelope_bytes"`
	MaximumAcceptanceReceiptEnvelopeBytes                 uint64                               `json:"maximum_acceptance_receipt_envelope_bytes"`
	MaximumActivationEvidenceEnvelopeBytes                uint64                               `json:"maximum_activation_evidence_envelope_bytes"`
	MaximumNonActivationEvidenceEnvelopeBytes             uint64                               `json:"maximum_non_activation_evidence_envelope_bytes"`
	MaximumCancellationReceiptEnvelopeBytes               uint64                               `json:"maximum_cancellation_receipt_envelope_bytes"`
	MaximumClaimFilingCloseReceiptEnvelopeBytes           uint64                               `json:"maximum_claim_filing_close_receipt_envelope_bytes"`
	MaximumTerminalClaimSetEnvelopeBytes                  uint64                               `json:"maximum_terminal_claim_set_envelope_bytes"`
	MaximumExposureReleaseRequestBytes                    uint64                               `json:"maximum_exposure_release_request_bytes"`
	MaximumExposureReleaseReceiptBytes                    uint64                               `json:"maximum_exposure_release_receipt_bytes"`
	MaximumCoverageResolutionRequestBytes                 uint64                               `json:"maximum_coverage_resolution_request_bytes"`
	MaximumCoverageResolutionEnvelopeBytes                uint64                               `json:"maximum_coverage_resolution_envelope_bytes"`
	ComputedWorstCaseAcceptanceRequestEnvelopeBytes       uint64                               `json:"computed_worst_case_acceptance_request_envelope_bytes"`
	ComputedWorstCaseAcceptanceReceiptEnvelopeBytes       uint64                               `json:"computed_worst_case_acceptance_receipt_envelope_bytes"`
	ComputedWorstCaseActivationEvidenceEnvelopeBytes      uint64                               `json:"computed_worst_case_activation_evidence_envelope_bytes"`
	ComputedWorstCaseNonActivationEvidenceEnvelopeBytes   uint64                               `json:"computed_worst_case_non_activation_evidence_envelope_bytes"`
	ComputedWorstCaseCancellationReceiptEnvelopeBytes     uint64                               `json:"computed_worst_case_cancellation_receipt_envelope_bytes"`
	ComputedWorstCaseClaimFilingCloseReceiptEnvelopeBytes uint64                               `json:"computed_worst_case_claim_filing_close_receipt_envelope_bytes"`
	ComputedWorstCaseTerminalClaimSetBytes                uint64                               `json:"computed_worst_case_terminal_claim_set_bytes"`
	ComputedWorstCaseExposureReleaseRequestBytes          uint64                               `json:"computed_worst_case_exposure_release_request_bytes"`
	ComputedWorstCaseExposureReleaseReceiptBytes          uint64                               `json:"computed_worst_case_exposure_release_receipt_bytes"`
	ComputedWorstCaseCoverageResolutionRequestBytes       uint64                               `json:"computed_worst_case_coverage_resolution_request_bytes"`
	ComputedWorstCaseCoverageResolutionEnvelopeBytes      uint64                               `json:"computed_worst_case_coverage_resolution_envelope_bytes"`
	ContinuationBudgetProfile                             ProfileRefV1                         `json:"continuation_budget_profile"`
	ContinuationBudgetEntries                             []ClaimContinuationBudgetEntryV1     `json:"continuation_budget_entries"`
	TerminalFallback                                      DeterministicClaimTerminalFallbackV1 `json:"terminal_fallback"`
}

type RequestedCoverageTermsV1 struct {
	SchemaVersion                             uint16                 `json:"schema_version"`
	CoverageCategory                          string                 `json:"coverage_category"`
	BenefitKind                               BenefitKind            `json:"benefit_kind"`
	CoverageAsset                             AssetIdentityV1        `json:"coverage_asset"`
	RequestedAggregatePayout                  AtomicAmountV1         `json:"requested_aggregate_payout"`
	RequestedPerClaim                         AtomicAmountV1         `json:"requested_per_claim"`
	MaximumClaims                             uint64                 `json:"maximum_claims"`
	RequestedClosureCapacity                  ClaimClosureCapacityV1 `json:"requested_closure_capacity"`
	RequestedCoverageStartsAtUnix             uint64                 `json:"requested_coverage_starts_at_unix"`
	RequestedCoverageEndsAtUnix               uint64                 `json:"requested_coverage_ends_at_unix"`
	RequestedClaimFilingEndsAtUnix            uint64                 `json:"requested_claim_filing_ends_at_unix"`
	MaximumReviewDeadlineSeconds              uint64                 `json:"maximum_review_deadline_seconds"`
	MaximumChallengeWindowSeconds             uint64                 `json:"maximum_challenge_window_seconds"`
	MaximumNonterminalResolutionWindowSeconds uint64                 `json:"maximum_nonterminal_resolution_window_seconds"`
	MaximumSuccessorDecisionWindowSeconds     uint64                 `json:"maximum_successor_decision_window_seconds"`
	MaximumPayoutDeadlineSeconds              uint64                 `json:"maximum_payout_deadline_seconds"`
	MaximumAdapterRecoveryWindowSeconds       uint64                 `json:"maximum_adapter_recovery_window_seconds"`
	ClaimTriggerProfile                       ProfileRefV1           `json:"claim_trigger_profile"`
	ClaimEvidenceProfile                      ProfileRefV1           `json:"claim_evidence_profile"`
	SelectedAssuranceLevel                    AssuranceLevel         `json:"selected_assurance_level"`
	SelectedClaimProfileDigest                string                 `json:"selected_claim_profile_digest"`
	SelectedCollateralProfileDigest           string                 `json:"selected_collateral_profile_digest,omitempty"`
	SelectedPayoutAdapterProfile              ProfileRefV1           `json:"selected_payout_adapter_profile"`
	RequiredExtensions                        []ProfileRefV1         `json:"required_extensions,omitempty"`
	OptionalExtensions                        []ProfileRefV1         `json:"optional_extensions,omitempty"`
}

type CoverageQuoteRequestBodyV1 struct {
	SchemaVersion                   uint16         `json:"schema_version"`
	RequestID                       string         `json:"request_id"`
	ServiceIntentDigest             string         `json:"service_intent_digest"`
	ServiceProfileDigest            string         `json:"service_profile_digest"`
	RequesterAgentID                string         `json:"requester_agent_id"`
	GuarantorAgentID                string         `json:"guarantor_agent_id"`
	CoveredPartyAgentID             string         `json:"covered_party_agent_id"`
	BeneficiaryAgentID              string         `json:"beneficiary_agent_id"`
	ClaimantSubjects                []string       `json:"claimant_subjects"`
	UnderlyingAgreementBodyDigest   string         `json:"underlying_agreement_body_digest"`
	CoveredObligationIDs            []string       `json:"covered_obligation_ids"`
	RequestedTermsDigest            string         `json:"requested_terms_digest"`
	MaximumFee                      AtomicAmountV1 `json:"maximum_fee"`
	SelectedAssuranceLevel          AssuranceLevel `json:"selected_assurance_level"`
	SelectedClaimProfileDigest      string         `json:"selected_claim_profile_digest"`
	SelectedDecisionProfile         ProfileRefV1   `json:"selected_decision_profile"`
	SelectedCollateralProfileDigest string         `json:"selected_collateral_profile_digest,omitempty"`
	SelectedPayoutAdapterProfile    ProfileRefV1   `json:"selected_payout_adapter_profile"`
	PrivateInputManifestDigest      string         `json:"private_input_manifest_digest,omitempty"`
	CreatedAtUnix                   uint64         `json:"created_at_unix"`
	ExpiresAtUnix                   uint64         `json:"expires_at_unix"`
}

type AuthorizedCoverageQuoteRequestV1 struct {
	Body           CoverageQuoteRequestBodyV1              `json:"body"`
	RequestedTerms RequestedCoverageTermsV1                `json:"requested_terms"`
	Authorizations []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type CoverageTermsV1 struct {
	SchemaVersion                      uint16                                        `json:"schema_version"`
	CoverageID                         string                                        `json:"coverage_id"`
	CoverageVersion                    uint64                                        `json:"coverage_version"`
	PredecessorTermsDigest             string                                        `json:"predecessor_terms_digest,omitempty"`
	ServiceProfileDigest               string                                        `json:"service_profile_digest"`
	QuoteRequestDigest                 string                                        `json:"quote_request_digest"`
	GuarantorAgentID                   string                                        `json:"guarantor_agent_id"`
	CoveredPartyAgentID                string                                        `json:"covered_party_agent_id"`
	BeneficiaryAgentID                 string                                        `json:"beneficiary_agent_id"`
	PermittedClaimantSubjects          []string                                      `json:"permitted_claimant_subjects"`
	UnderlyingAgreementBodyDigest      string                                        `json:"underlying_agreement_body_digest"`
	CoveredObligationIDs               []string                                      `json:"covered_obligation_ids"`
	CoverageCategory                   string                                        `json:"coverage_category"`
	BenefitKind                        BenefitKind                                   `json:"benefit_kind"`
	SelectedAssuranceLevel             AssuranceLevel                                `json:"selected_assurance_level"`
	CoverageAsset                      AssetIdentityV1                               `json:"coverage_asset"`
	MaximumAggregatePayout             AtomicAmountV1                                `json:"maximum_aggregate_payout"`
	MaximumPerClaim                    AtomicAmountV1                                `json:"maximum_per_claim"`
	Deductible                         *AtomicAmountV1                               `json:"deductible,omitempty"`
	CoinsurancePPM                     *uint64                                       `json:"coinsurance_ppm,omitempty"`
	BenefitCalculationProfile          ProfileRefV1                                  `json:"benefit_calculation_profile"`
	MaximumClaims                      uint64                                        `json:"maximum_claims"`
	ClaimClosureCapacity               ClaimClosureCapacityV1                        `json:"claim_closure_capacity"`
	CoverageStartsAtUnix               uint64                                        `json:"coverage_starts_at_unix"`
	CoverageEndsAtUnix                 uint64                                        `json:"coverage_ends_at_unix"`
	ClaimFilingEndsAtUnix              uint64                                        `json:"claim_filing_ends_at_unix"`
	ClaimIngressResolutionGraceSeconds uint64                                        `json:"claim_ingress_resolution_grace_seconds"`
	LateIngressRecoveryWindowSeconds   uint64                                        `json:"late_ingress_recovery_window_seconds"`
	ReviewDeadlineSeconds              uint64                                        `json:"review_deadline_seconds"`
	ChallengeWindowSeconds             uint64                                        `json:"challenge_window_seconds"`
	NonterminalResolutionWindowSeconds uint64                                        `json:"nonterminal_resolution_window_seconds"`
	SuccessorDecisionWindowSeconds     uint64                                        `json:"successor_decision_window_seconds"`
	PayoutDeadlineSeconds              uint64                                        `json:"payout_deadline_seconds"`
	AdapterRecoveryWindowSeconds       uint64                                        `json:"adapter_recovery_window_seconds"`
	TerminalResolutionDeadlineUnix     uint64                                        `json:"terminal_resolution_deadline_unix"`
	LateIngressRecoveryDeadlineUnix    uint64                                        `json:"late_ingress_recovery_deadline_unix"`
	LateRecoveryTerminalDeadlineUnix   uint64                                        `json:"late_recovery_terminal_deadline_unix"`
	AcceptanceProcessingGraceSeconds   uint64                                        `json:"acceptance_processing_grace_seconds"`
	ExclusionsPolicy                   PolicyRefV1                                   `json:"exclusions_policy"`
	CancellationPolicy                 CoverageCancellationPolicyV1                  `json:"cancellation_policy"`
	NonActivationReasonRules           []CoverageNonActivationReasonRuleV1           `json:"non_activation_reason_rules"`
	DisputePolicy                      PolicyRefV1                                   `json:"dispute_policy"`
	DefaultPolicy                      PolicyRefV1                                   `json:"default_policy"`
	OtherCoveragePolicy                PolicyRefV1                                   `json:"other_coverage_policy"`
	PayoutDestinationBinding           PayoutDestinationBindingV1                    `json:"payout_destination_binding"`
	CoverageLayerID                    string                                        `json:"coverage_layer_id"`
	LayerPriority                      uint64                                        `json:"layer_priority"`
	LayerSharePPM                      uint64                                        `json:"layer_share_ppm"`
	CoverageStateDomainDigest          string                                        `json:"coverage_state_domain_digest"`
	SelectedClaimProfileDigest         string                                        `json:"selected_claim_profile_digest"`
	SelectedCollateralProfileDigest    string                                        `json:"selected_collateral_profile_digest,omitempty"`
	SelectedPayoutAdapterProfile       ProfileRefV1                                  `json:"selected_payout_adapter_profile"`
	CoverageOperationAdapterProfile    ProfileRefV1                                  `json:"coverage_operation_adapter_profile"`
	ClaimOperationAdapterProfile       ProfileRefV1                                  `json:"claim_operation_adapter_profile"`
	ExposureOperationAdapterProfile    ProfileRefV1                                  `json:"exposure_operation_adapter_profile"`
	StageActionAuthorityBinding        GuarantorStageActionAuthorityBindingV1        `json:"stage_action_authority_binding"`
	OperationalIndependenceTerms       *GuarantorOperationalIndependenceTermsV1      `json:"operational_independence_terms,omitempty"`
	ClaimTriggerProfile                ProfileRefV1                                  `json:"claim_trigger_profile"`
	ClaimEvidenceProfile               ProfileRefV1                                  `json:"claim_evidence_profile"`
	ClaimantAuthorizationProfiles      []ProfileRefV1                                `json:"claimant_authorization_profiles"`
	ClaimIngressProfile                ProfileRefV1                                  `json:"claim_ingress_profile"`
	ClaimIngressAuthoritySubjects      []string                                      `json:"claim_ingress_authority_subjects"`
	ClaimIngressAuthorityQuorumRule    string                                        `json:"claim_ingress_authority_quorum_rule"`
	ClaimAdmissionProfile              ProfileRefV1                                  `json:"claim_admission_profile"`
	ClaimAdmissionAuthoritySubjects    []string                                      `json:"claim_admission_authority_subjects"`
	ClaimAdmissionQuorumRule           string                                        `json:"claim_admission_quorum_rule"`
	AcceptanceAuthorityProfile         ProfileRefV1                                  `json:"acceptance_authority_profile"`
	LifecycleAuthorizationProfile      ProfileRefV1                                  `json:"lifecycle_authorization_profile"`
	DecisionAdmissionProfile           ProfileRefV1                                  `json:"decision_admission_profile"`
	DecisionAdmissionAuthoritySubjects []string                                      `json:"decision_admission_authority_subjects"`
	DecisionAdmissionQuorumRule        string                                        `json:"decision_admission_quorum_rule"`
	DecisionProfile                    ProfileRefV1                                  `json:"decision_profile"`
	DecisionAuthoritySubjects          []string                                      `json:"decision_authority_subjects"`
	DecisionQuorumRule                 string                                        `json:"decision_quorum_rule"`
	PayoutTemplate                     agentcommerce.ConditionalSettlementTemplateV1 `json:"payout_template"`
	PremiumObligationIDs               []string                                      `json:"premium_obligation_ids"`
	CollateralObligationID             string                                        `json:"collateral_obligation_id,omitempty"`
	CollateralTerms                    *CollateralTermsV1                            `json:"collateral_terms,omitempty"`
	RequiredExtensions                 []ProfileRefV1                                `json:"required_extensions,omitempty"`
	OptionalExtensions                 []ProfileRefV1                                `json:"optional_extensions,omitempty"`
}

type FirmCoverageOfferBodyV1 struct {
	SchemaVersion                    uint16                                `json:"schema_version"`
	OfferID                          string                                `json:"offer_id"`
	OfferVersion                     uint64                                `json:"offer_version"`
	PredecessorOfferDigest           string                                `json:"predecessor_offer_digest,omitempty"`
	QuoteRequestDigest               string                                `json:"quote_request_digest"`
	ServiceIntentDigest              string                                `json:"service_intent_digest"`
	ServiceProfileDigest             string                                `json:"service_profile_digest"`
	CoverageID                       string                                `json:"coverage_id"`
	CoverageVersion                  uint64                                `json:"coverage_version"`
	GuarantorAgentID                 string                                `json:"guarantor_agent_id"`
	CoveredPartyAgentID              string                                `json:"covered_party_agent_id"`
	BeneficiaryAgentID               string                                `json:"beneficiary_agent_id"`
	UnderlyingAgreementBodyDigest    string                                `json:"underlying_agreement_body_digest"`
	CoveredObligationIDs             []string                              `json:"covered_obligation_ids"`
	CoverageTermsDigest              string                                `json:"coverage_terms_digest"`
	CoverageAgreementBodyDigest      string                                `json:"coverage_agreement_body_digest"`
	CoverageObligationID             string                                `json:"coverage_obligation_id"`
	PremiumObligationIDs             []string                              `json:"premium_obligation_ids"`
	CollateralObligationID           string                                `json:"collateral_obligation_id,omitempty"`
	PayoutTemplateObligationID       string                                `json:"payout_template_obligation_id"`
	GuarantorPredicateTargets        []GuarantorSatisfiedPredicateTargetV1 `json:"guarantor_predicate_targets"`
	GuarantorEvidenceProfile         ProfileRefV1                          `json:"guarantor_evidence_profile"`
	ExposureAdmissionReceiptDigest   string                                `json:"exposure_receipt_digest"`
	ReservationID                    string                                `json:"reservation_id"`
	MaxAcceptances                   uint64                                `json:"max_acceptances"`
	ValidFromUnix                    uint64                                `json:"valid_from_unix"`
	AcceptByUnix                     uint64                                `json:"accept_by_unix"`
	AcceptanceProcessingGraceSeconds uint64                                `json:"acceptance_processing_grace_seconds"`
	WithdrawalPolicy                 string                                `json:"withdrawal_policy"`
	ExpiresAtUnix                    uint64                                `json:"expires_at_unix"`
	RequiredExtensions               []ProfileRefV1                        `json:"required_extensions,omitempty"`
	OptionalExtensions               []ProfileRefV1                        `json:"optional_extensions,omitempty"`
}

type AuthorizedFirmCoverageOfferV1 struct {
	Body                     FirmCoverageOfferBodyV1                      `json:"body"`
	CoverageTerms            CoverageTermsV1                              `json:"coverage_terms"`
	ExposureAdmissionReceipt AuthorizedProviderExposureAdmissionReceiptV1 `json:"exposure_admission_receipt"`
	AuthorizedQuoteRequest   AuthorizedCoverageQuoteRequestV1             `json:"authorized_quote_request"`
	ServiceProfileArtifact   GuarantorServiceProfileArtifactV1            `json:"service_profile_artifact"`
	Authorizations           []ProfileQualifiedObjectAuthorizationV1      `json:"authorizations"`
}

type CoverageAcceptanceRequestBodyV1 struct {
	SchemaVersion                          uint16       `json:"schema_version"`
	CoverageAgreementBodyDigest            string       `json:"coverage_agreement_body_digest"`
	AuthorizedFirmOfferEnvelopeDigest      string       `json:"authorized_firm_offer_envelope_digest"`
	CompleteAuthorizationEvidenceSetDigest string       `json:"complete_authorization_evidence_set_digest"`
	AcceptingSubject                       string       `json:"accepting_subject"`
	SubmissionAuthorizationProfile         ProfileRefV1 `json:"submission_authorization_profile"`
	CreatedAtUnix                          uint64       `json:"created_at_unix"`
	ExpiresAtUnix                          uint64       `json:"expires_at_unix"`
}

type AuthorizedCoverageAcceptanceRequestV1 struct {
	Body                     CoverageAcceptanceRequestBodyV1              `json:"body"`
	CoverageAgreementBody    agentcommerce.AgentAgreementBody             `json:"coverage_agreement_body"`
	AuthorizationEvidenceSet GuarantorAgreementAuthorizationEvidenceSetV1 `json:"authorization_evidence_set"`
	Authorizations           []ProfileQualifiedObjectAuthorizationV1      `json:"authorizations"`
}

type CoverageAcceptanceReceiptBodyV1 struct {
	SchemaVersion                               uint16 `json:"schema_version"`
	AuthorityID                                 string `json:"authority_id"`
	CoverageAgreementBodyDigest                 string `json:"coverage_agreement_body_digest"`
	AuthorizedFirmOfferEnvelopeDigest           string `json:"authorized_firm_offer_envelope_digest"`
	AuthorizedAcceptanceRequestEnvelopeDigest   string `json:"authorized_acceptance_request_envelope_digest"`
	ExposureAdmissionReceiptDigest              string `json:"exposure_admission_receipt_digest"`
	ReservationID                               string `json:"reservation_id"`
	TransitionEvidenceProjectionDigest          string `json:"transition_evidence_projection_digest"`
	AuthorizedActionDigest                      string `json:"authorized_action_digest"`
	StableActionID                              string `json:"stable_action_id"`
	ExactRequestDigest                          string `json:"exact_request_digest"`
	WriterGeneration                            uint64 `json:"writer_generation"`
	WriterFenceDigest                           string `json:"writer_fence_digest"`
	PriorOfferStateRevision                     uint64 `json:"prior_offer_state_revision"`
	AcceptedOfferStateRevision                  uint64 `json:"accepted_offer_state_revision"`
	PriorCoverageRevision                       uint64 `json:"prior_coverage_revision"`
	AcceptedCoverageRevision                    uint64 `json:"accepted_coverage_revision"`
	PriorClaimFilingState                       string `json:"prior_claim_filing_state"`
	AcceptedClaimFilingState                    string `json:"accepted_claim_filing_state"`
	PriorClaimFilingStateRevision               uint64 `json:"prior_claim_filing_state_revision"`
	AcceptedClaimFilingStateRevision            uint64 `json:"accepted_claim_filing_state_revision"`
	ReceivedAtUnix                              uint64 `json:"received_at_unix"`
	AcceptedAtUnix                              uint64 `json:"accepted_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedCoverageAcceptanceReceiptV1 struct {
	Body                                  CoverageAcceptanceReceiptBodyV1         `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	AuthorizedAcceptanceRequest           AuthorizedCoverageAcceptanceRequestV1   `json:"authorized_acceptance_request"`
	TransitionEvidenceProjection          TransitionEvidenceProjectionV1          `json:"transition_evidence_projection"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1 `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type ClaimEvidenceDescriptorV1 struct {
	PredicateID            string       `json:"predicate_id"`
	EvidenceProfile        ProfileRefV1 `json:"evidence_profile"`
	ContentType            string       `json:"content_type"`
	ContentDigest          string       `json:"content_digest"`
	ContentSize            uint64       `json:"content_size"`
	DisclosurePolicyDigest string       `json:"disclosure_policy_digest"`
}

type ClaimEvidenceManifestV1 struct {
	SchemaVersion      uint16                      `json:"schema_version"`
	Items              []ClaimEvidenceDescriptorV1 `json:"items"`
	TotalDeclaredBytes uint64                      `json:"total_declared_bytes"`
}

type TriggeredObligationSetV1 struct {
	SchemaVersion                 uint16   `json:"schema_version"`
	UnderlyingAgreementBodyDigest string   `json:"underlying_agreement_body_digest"`
	ObligationIDs                 []string `json:"obligation_ids"`
}

type OtherRecoveryItemV1 struct {
	RecoveryItemID          string         `json:"recovery_item_id"`
	SourceKind              string         `json:"source_kind"`
	SourceSubject           string         `json:"source_subject"`
	RelatedInstrumentDigest string         `json:"related_instrument_digest,omitempty"`
	RecoveryStatus          string         `json:"recovery_status"`
	AmountReceived          AtomicAmountV1 `json:"amount_received"`
	AmountReceivable        AtomicAmountV1 `json:"amount_receivable"`
	EvidencePredicateIDs    []string       `json:"evidence_predicate_ids,omitempty"`
}

type OtherRecoveryDeclarationV1 struct {
	SchemaVersion                 uint16                `json:"schema_version"`
	CoverageAgreementBodyDigest   string                `json:"coverage_agreement_body_digest"`
	CoverageObligationID          string                `json:"coverage_obligation_id"`
	UnderlyingAgreementBodyDigest string                `json:"underlying_agreement_body_digest"`
	ClaimRevision                 uint64                `json:"claim_revision"`
	BeneficiaryAgentID            string                `json:"beneficiary_agent_id"`
	IncidentKeyDigest             string                `json:"incident_key_digest"`
	CoverageAsset                 AssetIdentityV1       `json:"coverage_asset"`
	RecoveryItems                 []OtherRecoveryItemV1 `json:"recovery_items"`
	DeclaredAtUnix                uint64                `json:"declared_at_unix"`
}

type CoverageClaimBodyV1 struct {
	SchemaVersion                  uint16                   `json:"schema_version"`
	ClaimID                        string                   `json:"claim_id"`
	ClaimRevision                  uint64                   `json:"claim_revision"`
	PredecessorClaimDigest         string                   `json:"predecessor_claim_digest,omitempty"`
	CoverageAgreementBodyDigest    string                   `json:"coverage_agreement_body_digest"`
	CoverageObligationID           string                   `json:"coverage_obligation_id"`
	UnderlyingAgreementBodyDigest  string                   `json:"underlying_agreement_body_digest"`
	TriggeredObligationSet         TriggeredObligationSetV1 `json:"triggered_obligation_set"`
	ClaimantSubject                string                   `json:"claimant_subject"`
	ClaimantAuthorizationProfile   ProfileRefV1             `json:"claimant_authorization_profile"`
	BeneficiaryAgentID             string                   `json:"beneficiary_agent_id"`
	IncidentKeyDigest              string                   `json:"incident_key_digest"`
	OccurredAtUnix                 uint64                   `json:"occurred_at_unix"`
	ClaimedAmount                  AtomicAmountV1           `json:"claimed_amount"`
	EvidenceManifestDigest         string                   `json:"evidence_manifest_digest"`
	OtherRecoveryDeclarationDigest string                   `json:"other_recovery_declaration_digest"`
	PayoutDestinationDigest        string                   `json:"payout_destination_digest"`
	CreatedAtUnix                  uint64                   `json:"created_at_unix"`
	ExpiresAtUnix                  uint64                   `json:"expires_at_unix"`
}

type AuthorizedCoverageClaimV1 struct {
	Body                     CoverageClaimBodyV1                     `json:"body"`
	EvidenceManifest         ClaimEvidenceManifestV1                 `json:"evidence_manifest"`
	OtherRecoveryDeclaration OtherRecoveryDeclarationV1              `json:"other_recovery_declaration"`
	Authorizations           []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type ClaimDecisionResult string

const (
	DecisionApproved          ClaimDecisionResult = "approved"
	DecisionPartiallyApproved ClaimDecisionResult = "partially_approved"
	DecisionDenied            ClaimDecisionResult = "denied"
	DecisionEvidenceRequired  ClaimDecisionResult = "evidence_required"
	DecisionDisputed          ClaimDecisionResult = "disputed"
)

type ClaimPayoutLineV1 struct {
	DecisionLineIndex                  uint64         `json:"decision_line_index"`
	Amount                             AtomicAmountV1 `json:"amount"`
	PayoutDestinationDigest            string         `json:"payout_destination_digest"`
	NotBeforeAfterTerminalCloseSeconds uint64         `json:"not_before_after_terminal_close_seconds"`
	DueAfterTerminalCloseSeconds       uint64         `json:"due_after_terminal_close_seconds"`
	ExpiresAfterTerminalCloseSeconds   uint64         `json:"expires_after_terminal_close_seconds"`
}

type DeterministicFallbackAggregateProjectionV1 struct {
	SchemaVersion                         uint16         `json:"schema_version"`
	FallbackProfileDigest                 string         `json:"fallback_profile_digest"`
	GrossFallbackAmount                   AtomicAmountV1 `json:"gross_fallback_amount"`
	CumulativeAppliedApprovedAmount       AtomicAmountV1 `json:"cumulative_applied_approved_amount"`
	AggregatePendingDecisionReserveBefore AtomicAmountV1 `json:"aggregate_pending_decision_reserve_before"`
	ReclaimablePriorAmount                AtomicAmountV1 `json:"reclaimable_prior_amount"`
	RemainingAggregateCapacity            AtomicAmountV1 `json:"remaining_aggregate_capacity"`
	ProjectedApprovedAmount               AtomicAmountV1 `json:"projected_approved_amount"`
}

type ClaimDecisionPolicyApplicationV1 struct {
	SchemaVersion                  uint16                                      `json:"schema_version"`
	CoverageAgreementBodyDigest    string                                      `json:"coverage_agreement_body_digest"`
	CoverageObligationID           string                                      `json:"coverage_obligation_id"`
	AuthorizedClaimEnvelopeDigest  string                                      `json:"authorized_claim_envelope_digest"`
	DecisionPath                   string                                      `json:"decision_path"`
	BenefitCalculationProfile      ProfileRefV1                                `json:"benefit_calculation_profile"`
	TriggeredObligationSetDigest   string                                      `json:"triggered_obligation_set_digest"`
	EvidenceSetDigest              string                                      `json:"evidence_set_digest"`
	OtherRecoveryDeclarationDigest string                                      `json:"other_recovery_declaration_digest"`
	ApplicablePolicyClauseIDs      []string                                    `json:"applicable_policy_clause_ids"`
	PolicyInputProjection          []byte                                      `json:"policy_input_projection"`
	FullEligibleBenefitAmount      AtomicAmountV1                              `json:"full_eligible_benefit_amount"`
	FallbackAggregateProjection    *DeterministicFallbackAggregateProjectionV1 `json:"fallback_aggregate_projection,omitempty"`
}

type ClaimDecisionReasonV1 struct {
	SchemaVersion             uint16              `json:"schema_version"`
	DecisionProfile           ProfileRefV1        `json:"decision_profile"`
	Result                    ClaimDecisionResult `json:"result"`
	ReasonCode                string              `json:"reason_code"`
	ApplicablePolicyClauseIDs []string            `json:"applicable_policy_clause_ids"`
	EvidencePredicateIDs      []string            `json:"evidence_predicate_ids"`
}

type ClaimDecisionBodyV1 struct {
	SchemaVersion                            uint16              `json:"schema_version"`
	CoverageAgreementBodyDigest              string              `json:"coverage_agreement_body_digest"`
	CoverageObligationID                     string              `json:"coverage_obligation_id"`
	ClaimID                                  string              `json:"claim_id"`
	AuthorizedClaimEnvelopeDigest            string              `json:"authorized_claim_envelope_digest"`
	DecisionSequence                         uint64              `json:"decision_sequence"`
	DecisionRevision                         uint64              `json:"decision_revision"`
	PredecessorAuthorizedClaimDecisionDigest string              `json:"predecessor_authorized_claim_decision_digest,omitempty"`
	DecisionPath                             string              `json:"decision_path"`
	ExpectedClaimRevision                    uint64              `json:"expected_claim_revision"`
	DecisionProfile                          ProfileRefV1        `json:"decision_profile"`
	DecisionAuthoritySubjects                []string            `json:"decision_authority_subjects"`
	DecisionQuorumRule                       string              `json:"decision_quorum_rule"`
	Result                                   ClaimDecisionResult `json:"result"`
	ApprovedAmount                           AtomicAmountV1      `json:"approved_amount"`
	EvidenceSetDigest                        string              `json:"evidence_set_digest"`
	PolicyApplicationDigest                  string              `json:"policy_application_digest"`
	ReasonDigest                             string              `json:"reason_digest"`
	PayoutLines                              []ClaimPayoutLineV1 `json:"payout_lines,omitempty"`
	ChallengeWindowSeconds                   uint64              `json:"challenge_window_seconds,omitempty"`
	ResolutionWindowSeconds                  uint64              `json:"resolution_window_seconds,omitempty"`
	DecidedAtUnix                            uint64              `json:"decided_at_unix"`
	ExpiresAtUnix                            uint64              `json:"expires_at_unix"`
	RequiredExtensions                       []ProfileRefV1      `json:"required_extensions,omitempty"`
	OptionalExtensions                       []ProfileRefV1      `json:"optional_extensions,omitempty"`
}

type AuthorizedClaimDecisionV1 struct {
	Body                ClaimDecisionBodyV1                     `json:"body"`
	PolicyApplication   ClaimDecisionPolicyApplicationV1        `json:"policy_application"`
	DecisionReason      ClaimDecisionReasonV1                   `json:"decision_reason"`
	DecisionEvidenceSet CanonicalGuarantorEvidenceSetV1         `json:"decision_evidence_set"`
	Authorizations      []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type MaterializedPayoutLineV1 struct {
	PayoutSequence                            uint64            `json:"payout_sequence"`
	PredecessorMaterializedPayoutLineDigest   string            `json:"predecessor_materialized_payout_line_digest,omitempty"`
	ClaimDecisionBodyDigest                   string            `json:"claim_decision_body_digest"`
	TerminalClaimStateTransitionReceiptDigest string            `json:"terminal_claim_state_transition_receipt_digest"`
	DecisionLineIndex                         uint64            `json:"decision_line_index"`
	ClaimPayoutLine                           ClaimPayoutLineV1 `json:"claim_payout_line"`
	NotBeforeUnix                             uint64            `json:"not_before_unix"`
	DueAtUnix                                 uint64            `json:"due_at_unix"`
	ExpiresAtUnix                             uint64            `json:"expires_at_unix"`
	ObligationInstanceID                      string            `json:"obligation_instance_id"`
}

type MaterializedPayoutObligationSetV1 struct {
	SchemaVersion                             uint16                               `json:"schema_version"`
	CoverageAgreementBodyDigest               string                               `json:"coverage_agreement_body_digest"`
	PayoutTemplateObligationID                string                               `json:"payout_template_obligation_id"`
	AuthorizedClaimDecisionDigest             string                               `json:"authorized_claim_decision_digest"`
	TerminalClaimStateTransitionReceiptDigest string                               `json:"terminal_claim_state_transition_receipt_digest"`
	MaterializationState                      string                               `json:"materialization_state"`
	FirstPayoutSequence                       uint64                               `json:"first_payout_sequence,omitempty"`
	LastPayoutSequence                        uint64                               `json:"last_payout_sequence,omitempty"`
	MaterializedLines                         []MaterializedPayoutLineV1           `json:"materialized_lines"`
	Obligations                               []agentcommerce.SettlementObligation `json:"obligations"`
}

type CollateralStatus string

const (
	CollateralUnproven          CollateralStatus = "unproven"
	CollateralLockPending       CollateralStatus = "lock_pending"
	CollateralLocked            CollateralStatus = "locked"
	CollateralEncumbered        CollateralStatus = "encumbered"
	CollateralPayoutPending     CollateralStatus = "payout_pending"
	CollateralPartiallyConsumed CollateralStatus = "partially_consumed"
	CollateralDepleted          CollateralStatus = "depleted"
	CollateralReleasePending    CollateralStatus = "release_pending"
	CollateralReleased          CollateralStatus = "released"
	CollateralAmbiguous         CollateralStatus = "ambiguous"
	CollateralReorged           CollateralStatus = "reorged"
	CollateralDefaulted         CollateralStatus = "defaulted"
)

type CollateralPositionStateV1 struct {
	SchemaVersion               uint16           `json:"schema_version"`
	CoverageAgreementBodyDigest string           `json:"coverage_agreement_body_digest"`
	CollateralObligationID      string           `json:"collateral_obligation_id"`
	PositionID                  string           `json:"position_id"`
	PositionDigest              string           `json:"position_digest"`
	CoverageBindingDigest       string           `json:"coverage_binding_digest"`
	StateRevision               uint64           `json:"state_revision"`
	Status                      CollateralStatus `json:"state"`
	Asset                       AssetIdentityV1  `json:"asset"`
	AllocatedAmount             AtomicAmountV1   `json:"allocated_amount"`
	CumulativeConsumed          AtomicAmountV1   `json:"cumulative_consumed"`
	CumulativeReleased          AtomicAmountV1   `json:"cumulative_released"`
	CumulativeImpaired          AtomicAmountV1   `json:"cumulative_impaired"`
	RemainingAmount             AtomicAmountV1   `json:"remaining_amount"`
}
