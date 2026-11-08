package agentguarantor

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type ImmutableEvidenceDescriptorV1 struct {
	ContentType           string `json:"content_type"`
	ContentDigest         string `json:"content_digest"`
	ContentSize           uint64 `json:"content_size"`
	RetrievalPolicyDigest string `json:"retrieval_policy_digest"`
}

type ClaimContinuationBudgetEntryV1 struct {
	ProfileStateKey                           string `json:"profile_state_key"`
	ChallengeRoundsRemaining                  uint64 `json:"challenge_rounds_remaining"`
	NonterminalRoundsRemaining                uint64 `json:"nonterminal_rounds_remaining"`
	RequiredReservedDecisionAdmissionSlots    uint64 `json:"required_reserved_decision_admission_slots"`
	RequiredReservedClaimStateTransitionSlots uint64 `json:"required_reserved_claim_state_transition_slots"`
	MaximumRemainingDecisionPathSeconds       uint64 `json:"maximum_remaining_decision_path_seconds"`
	MaximumRemainingClosureSeconds            uint64 `json:"maximum_remaining_closure_seconds"`
}

type DeterministicClaimTerminalFallbackTriggerDeadlineRuleV1 struct {
	SourceState    string `json:"source_state"`
	DeadlineSource string `json:"deadline_source"`
}

type DeterministicFallbackReasonRuleV1 struct {
	OutcomeCase                    string   `json:"outcome_case"`
	Result                         string   `json:"result"`
	ReasonCode                     string   `json:"reason_code"`
	ApplicablePolicyClauseIDs      []string `json:"applicable_policy_clause_ids"`
	EvidencePredicateSelectionRule string   `json:"evidence_predicate_selection_rule"`
}

type DeterministicClaimTerminalFallbackV1 struct {
	SchemaVersion              uint16                                                    `json:"schema_version"`
	FallbackProfile            ProfileRefV1                                              `json:"fallback_profile"`
	FallbackAuthoritySubjects  []string                                                  `json:"fallback_authority_subjects"`
	FallbackQuorumRule         string                                                    `json:"fallback_quorum_rule"`
	EligibleSourceStates       []string                                                  `json:"eligible_source_states"`
	TriggerDeadlineRules       []DeterministicClaimTerminalFallbackTriggerDeadlineRuleV1 `json:"trigger_deadline_rules"`
	EvidenceSnapshotRule       string                                                    `json:"evidence_snapshot_rule"`
	OutcomeRule                string                                                    `json:"outcome_rule"`
	AggregateCapProjectionRule string                                                    `json:"aggregate_cap_projection_rule"`
	ReasonRules                []DeterministicFallbackReasonRuleV1                       `json:"reason_rules"`
	PayoutLineDerivationRule   string                                                    `json:"payout_line_derivation_rule"`
	AuthorizationMode          string                                                    `json:"authorization_mode"`
	FinalRoundRule             string                                                    `json:"final_round_rule"`
}

type PayoutDestinationV1 = agentcommerce.PayoutDestinationV1

type CollateralControlDisclosureV1 struct {
	SchemaVersion                        uint16        `json:"schema_version"`
	CustodyAdapterProfile                ProfileRefV1  `json:"custody_adapter_profile"`
	AdapterOperatorSubjects              []string      `json:"adapter_operator_subjects"`
	CustodianControllerRootSubjects      []string      `json:"custodian_controller_root_subjects"`
	DeclaredGuarantorControlRelationship string        `json:"declared_guarantor_control_relationship"`
	ControlResolutionProfile             *ProfileRefV1 `json:"control_resolution_profile,omitempty"`
	DisclosureEvidenceProfile            *ProfileRefV1 `json:"disclosure_evidence_profile,omitempty"`
	DisclosureAuthoritySubjects          []string      `json:"disclosure_authority_subjects,omitempty"`
	DisclosureAuthorityQuorumRule        string        `json:"disclosure_authority_quorum_rule,omitempty"`
	MaximumDisclosureEvidenceAgeSeconds  uint64        `json:"maximum_disclosure_evidence_age_seconds,omitempty"`
}

type CollateralControlEvidenceBodyV1 struct {
	SchemaVersion                        uint16       `json:"schema_version"`
	CoverageAgreementBodyDigest          string       `json:"coverage_agreement_body_digest"`
	CollateralObligationID               string       `json:"collateral_obligation_id"`
	SelectedCollateralProfileDigest      string       `json:"selected_collateral_profile_digest"`
	CollateralControlDisclosureDigest    string       `json:"collateral_control_disclosure_digest"`
	CustodyAdapterProfile                ProfileRefV1 `json:"custody_adapter_profile"`
	AdapterOperatorSubjects              []string     `json:"adapter_operator_subjects"`
	CustodianControllerRootSubjects      []string     `json:"custodian_controller_root_subjects"`
	DeclaredGuarantorControlRelationship string       `json:"declared_guarantor_control_relationship"`
	ObservedAtUnix                       uint64       `json:"observed_at_unix"`
	ExpiresAtUnix                        uint64       `json:"expires_at_unix"`
}

type AuthorizedCollateralControlEvidenceV1 struct {
	Body           CollateralControlEvidenceBodyV1         `json:"body"`
	Authorizations []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type GuarantorStageOperationResultBindingV1 struct {
	Role                   string `json:"role"`
	CanonicalType          string `json:"canonical_type"`
	DigestOrEnvelopeDomain string `json:"digest_or_envelope_domain"`
	Cardinality            string `json:"cardinality"`
	PresenceRule           string `json:"presence_rule"`
}

type GuarantorStageOperationBindingV1 struct {
	SchemaVersion                    uint16                                   `json:"schema_version"`
	Stage                            string                                   `json:"stage"`
	OperationRegistryProfile         ProfileRefV1                             `json:"operation_registry_profile"`
	OperationID                      string                                   `json:"operation_id"`
	ActionKind                       string                                   `json:"action_kind"`
	OperationPurpose                 string                                   `json:"operation_purpose"`
	SemanticActionRegistryVersion    uint64                                   `json:"semantic_action_registry_version"`
	SemanticActionEntryVersion       uint64                                   `json:"semantic_action_entry_version"`
	RequestSchemaVersion             uint16                                   `json:"request_schema_version"`
	RequestType                      string                                   `json:"request_type"`
	RequestBodyProfileID             string                                   `json:"request_body_profile_id"`
	MaximumRequestBytes              uint64                                   `json:"maximum_request_bytes"`
	ResultComponents                 []GuarantorStageOperationResultBindingV1 `json:"result_components"`
	RequiredContextTypes             []string                                 `json:"required_context_types"`
	SemanticFieldDerivationProfileID string                                   `json:"semantic_field_derivation_profile_id"`
	TransitionValidatorProfileID     string                                   `json:"transition_validator_profile_id"`
	MaterializerProfileID            string                                   `json:"materializer_profile_id"`
	AdapterRouteProfileSource        string                                   `json:"adapter_route_profile_source"`
	AdapterOperation                 string                                   `json:"adapter_operation"`
	CASDomainSource                  string                                   `json:"cas_domain_source"`
	StageDerivationProfileID         string                                   `json:"stage_derivation_profile_id"`
}

type GuarantorStageActionAuthorityV1 struct {
	Stage                            string       `json:"stage"`
	OperationActionKind              string       `json:"operation_action_kind"`
	OperationPurpose                 string       `json:"operation_purpose"`
	MaximumRequestBytes              uint64       `json:"maximum_request_bytes"`
	OperationBindingDigest           string       `json:"operation_binding_digest"`
	ActionOwnerID                    string       `json:"action_owner_id"`
	ActionAgentID                    string       `json:"action_agent_id"`
	ActionAuthorityID                string       `json:"action_authority_id"`
	WriterFenceDomainID              string       `json:"writer_fence_domain_id"`
	WriterFenceAuthorityID           string       `json:"writer_fence_authority_id"`
	WriterGenerationHighWaterProfile ProfileRefV1 `json:"writer_generation_high_water_profile"`
	ActionResolutionProfile          ProfileRefV1 `json:"action_resolution_profile"`
	AdmissionStateDomainDigest       string       `json:"admission_state_domain_digest"`
}

type GuarantorStageActionAuthorityBindingV1 struct {
	SchemaVersion         uint16                            `json:"schema_version"`
	AuthorityDomainDigest string                            `json:"authority_domain_digest"`
	Stages                []GuarantorStageActionAuthorityV1 `json:"stages"`
}

type GuarantorOperationalIndependenceTermsV1 struct {
	SchemaVersion                     uint16       `json:"schema_version"`
	AuthorityControlResolutionProfile ProfileRefV1 `json:"authority_control_resolution_profile"`
	CoverageOperationAdapterProfile   ProfileRefV1 `json:"coverage_operation_adapter_profile"`
	ClaimOperationAdapterProfile      ProfileRefV1 `json:"claim_operation_adapter_profile"`
	ExposureOperationAdapterProfile   ProfileRefV1 `json:"exposure_operation_adapter_profile"`
	RequiredIndependentStages         []string     `json:"required_independent_stages"`
	GuarantorControlRootSubjects      []string     `json:"guarantor_control_root_subjects"`
	ControlEvidenceAuthoritySubjects  []string     `json:"control_evidence_authority_subjects"`
	ControlEvidenceQuorumRule         string       `json:"control_evidence_quorum_rule"`
	StageActionAuthorityBindingDigest string       `json:"stage_action_authority_binding_digest"`
	AuthorityChangePolicy             PolicyRefV1  `json:"authority_change_policy"`
	MaximumControlEvidenceAgeSeconds  uint64       `json:"maximum_control_evidence_age_seconds"`
}

type GuarantorOperationalIndependenceEvidenceBodyV1 struct {
	SchemaVersion                      uint16                                `json:"schema_version"`
	CoverageAgreementBodyDigest        string                                `json:"coverage_agreement_body_digest"`
	CollateralObligationID             string                                `json:"collateral_obligation_id"`
	OperationalIndependenceTermsDigest string                                `json:"operational_independence_terms_digest"`
	StageActionAuthorityBindingDigest  string                                `json:"stage_action_authority_binding_digest"`
	AuthorityControlResolutionProfile  ProfileRefV1                          `json:"authority_control_resolution_profile"`
	RequiredIndependentStages          []string                              `json:"required_independent_stages"`
	ResolvedStageAuthorities           []ResolvedIndependentStageAuthorityV1 `json:"resolved_stage_authorities"`
	GuarantorControlRootSubjects       []string                              `json:"guarantor_control_root_subjects"`
	GuarantorControlAbsent             bool                                  `json:"guarantor_control_absent"`
	FinalizedAuthorityStateRoot        string                                `json:"finalized_authority_state_root"`
	ObservedAtUnix                     uint64                                `json:"observed_at_unix"`
	ExpiresAtUnix                      uint64                                `json:"expires_at_unix"`
}

type ResolvedIndependentStageAuthorityV1 struct {
	Stage                           string `json:"stage"`
	AuthoritySubject                string `json:"authority_subject"`
	FinalizedAuthorityStateRevision uint64 `json:"finalized_authority_state_revision"`
	FinalizedAuthorityStateRoot     string `json:"finalized_authority_state_root"`
}

type AuthorizedGuarantorOperationalIndependenceEvidenceV1 struct {
	Body                     GuarantorOperationalIndependenceEvidenceBodyV1 `json:"body"`
	ResolverFinalityEvidence []byte                                         `json:"resolver_finality_evidence"`
	Authorizations           []ProfileQualifiedObjectAuthorizationV1        `json:"authorizations"`
}

type AuthorityAdmissionEligibilityProofV1 struct {
	SchemaVersion                   uint16       `json:"schema_version"`
	InputAuthorizedEnvelopeDigest   string       `json:"input_authorized_envelope_digest"`
	AuthoritySubject                string       `json:"authority_subject"`
	AuthorityKeyOrPrincipalDigest   string       `json:"authority_key_or_principal_digest"`
	AuthorizedObjectKind            string       `json:"authorized_object_kind"`
	AuthorizedBodyDigest            string       `json:"authorized_body_digest"`
	RequiredScopeDigest             string       `json:"required_scope_digest"`
	AuthorityResolverProfile        ProfileRefV1 `json:"authority_resolver_profile"`
	FinalizedAuthorityStateRevision uint64       `json:"finalized_authority_state_revision"`
	FinalizedAuthorityStateRoot     string       `json:"finalized_authority_state_root"`
	ResolverFinalityEvidence        []byte       `json:"resolver_finality_evidence"`
	AdmissionDomainID               string       `json:"admission_domain_id"`
	AdmissionSequence               uint64       `json:"admission_sequence"`
	AdmissionTimeUnix               uint64       `json:"admission_time_unix"`
	EligibilityState                string       `json:"eligibility_state"`
}

type AuthorityAdmissionEligibilityProofSetV1 struct {
	SchemaVersion        uint16                                 `json:"schema_version"`
	AdmittedActionDigest string                                 `json:"admitted_action_digest"`
	AdmissionDomainID    string                                 `json:"admission_domain_id"`
	AdmissionSequence    uint64                                 `json:"admission_sequence"`
	AdmissionTimeUnix    uint64                                 `json:"admission_time_unix"`
	Entries              []AuthorityAdmissionEligibilityProofV1 `json:"entries"`
}

// AuthorityAdmissionEligibilityProofSetDigestV1 validates the complete,
// portable authority snapshot before deriving its wire digest. Callers must
// never hash an opaque provider-specific proof blob: doing so would bind bytes
// without proving which subject, scope, finalized revision, or admission cut
// was actually authorized.
func AuthorityAdmissionEligibilityProofSetDigestV1(set AuthorityAdmissionEligibilityProofSetV1) (string, error) {
	if err := ValidateAuthorityAdmissionEligibilityProofSetV1(set); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-authority-admission-eligibility-proof-set.v1", set)
}

func ValidateAuthorityAdmissionEligibilityProofSetV1(set AuthorityAdmissionEligibilityProofSetV1) error {
	if set.SchemaVersion != 1 || !validDigest(set.AdmittedActionDigest) || !validDigest(set.AdmissionDomainID) ||
		set.AdmissionSequence == 0 || set.AdmissionTimeUnix == 0 || len(set.Entries) == 0 || len(set.Entries) > MaxAuthorizations {
		return errors.New("Guarantor authority-admission eligibility proof set is invalid")
	}
	var prior []byte
	for _, proof := range set.Entries {
		if proof.SchemaVersion != 1 || !validDigest(proof.InputAuthorizedEnvelopeDigest) || !validID(proof.AuthoritySubject) ||
			!validDigest(proof.AuthorityKeyOrPrincipalDigest) || !validToken(proof.AuthorizedObjectKind, 128) ||
			!validDigest(proof.AuthorizedBodyDigest) || !validDigest(proof.RequiredScopeDigest) ||
			agentcommerce.ValidateProfileRefV1(proof.AuthorityResolverProfile) != nil ||
			proof.FinalizedAuthorityStateRevision == 0 || !validDigest(proof.FinalizedAuthorityStateRoot) ||
			len(proof.ResolverFinalityEvidence) == 0 || len(proof.ResolverFinalityEvidence) > MaxPolicyBytes ||
			proof.AdmissionDomainID != set.AdmissionDomainID || proof.AdmissionSequence != set.AdmissionSequence ||
			proof.AdmissionTimeUnix != set.AdmissionTimeUnix || proof.EligibilityState != "eligible" {
			return errors.New("Guarantor authority-admission eligibility proof is invalid")
		}
		encoded, err := guarantorCodec.Marshal(proof)
		if err != nil || prior != nil && bytes.Compare(prior, encoded) >= 0 {
			return errors.New("Guarantor authority-admission eligibility proofs are unsorted or duplicated")
		}
		prior = encoded
	}
	return nil
}

type CanonicalGuarantorEvidenceItemV1 struct {
	ContentType            string                         `json:"content_type"`
	EvidenceProfileDigest  string                         `json:"evidence_profile_digest"`
	EvidenceEnvelopeDigest string                         `json:"evidence_envelope_digest"`
	Representation         string                         `json:"representation"`
	CanonicalEnvelopeBytes []byte                         `json:"canonical_envelope_bytes,omitempty"`
	ImmutableDescriptor    *ImmutableEvidenceDescriptorV1 `json:"immutable_descriptor,omitempty"`
}

type CanonicalGuarantorEvidenceSetV1 struct {
	SchemaVersion uint16                             `json:"schema_version"`
	Purpose       string                             `json:"purpose"`
	ContextDigest string                             `json:"context_digest"`
	Items         []CanonicalGuarantorEvidenceItemV1 `json:"items"`
}

type CollateralAuthorizationBindingV1 struct {
	AuthorizationProfile    ProfileRefV1 `json:"authorization_profile"`
	AuthorizationSubjects   []string     `json:"authorization_subjects"`
	AuthorizationQuorumRule string       `json:"authorization_quorum_rule"`
}

type CollateralTransitionProfileV1 struct {
	TransitionKind                 string                            `json:"transition_kind"`
	SuccessorDerivationProfile     ProfileRefV1                      `json:"successor_derivation_profile"`
	AdapterProfile                 ProfileRefV1                      `json:"adapter_profile"`
	AdapterRequestContentType      string                            `json:"adapter_request_content_type"`
	AdapterRequestProfile          ProfileRefV1                      `json:"adapter_request_profile"`
	MaximumAdapterRequestBytes     uint64                            `json:"maximum_adapter_request_bytes"`
	AdapterEvidenceContentType     string                            `json:"adapter_evidence_content_type"`
	AdapterEvidenceProfile         ProfileRefV1                      `json:"adapter_evidence_profile"`
	AuthorizationSubjectSource     string                            `json:"authorization_subject_source"`
	CustodianAuthorizationBinding  *CollateralAuthorizationBindingV1 `json:"custodian_authorization_binding,omitempty"`
	PermittedPriorStates           []string                          `json:"permitted_prior_states"`
	PermittedResultingStates       []string                          `json:"permitted_resulting_states"`
	PrerequisiteEvidenceRoles      []string                          `json:"prerequisite_evidence_roles"`
	AuthorizedClaimDecisionBinding string                            `json:"authorized_claim_decision_binding"`
	PayoutDestinationBinding       string                            `json:"payout_destination_binding"`
}

type CollateralTransitionBindingV1 struct {
	TransitionProfileDigest string                           `json:"transition_profile_digest"`
	TransitionProfile       CollateralTransitionProfileV1    `json:"transition_profile"`
	AuthorizationBinding    CollateralAuthorizationBindingV1 `json:"authorization_binding"`
}

type ActivationPrerequisiteFailureRuleV1 struct {
	PrerequisiteID                   string       `json:"prerequisite_id"`
	TerminalFailureEvidenceProfile   ProfileRefV1 `json:"terminal_failure_evidence_profile"`
	TerminalFailureAuthoritySubjects []string     `json:"terminal_failure_authority_subjects"`
	TerminalFailureQuorumRule        string       `json:"terminal_failure_quorum_rule"`
	PermittedTerminalFailureOutcomes []string     `json:"permitted_terminal_failure_outcomes"`
}

type CoverageNonActivationReasonRuleV1 struct {
	Reason                                string                                `json:"reason"`
	EvidenceMode                          string                                `json:"evidence_mode"`
	PrerequisiteFailureRules              []ActivationPrerequisiteFailureRuleV1 `json:"prerequisite_failure_rules"`
	CancellationAuthorizationPredicateIDs []string                              `json:"cancellation_authorization_predicate_ids"`
}
