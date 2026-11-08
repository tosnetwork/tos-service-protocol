package agentguarantor

import (
	"errors"
	"sort"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type MutationResultComponentV1 struct {
	Role                   string `json:"role"`
	CanonicalType          string `json:"canonical_type"`
	DigestOrEnvelopeDomain string `json:"digest_or_envelope_domain"`
	Cardinality            string `json:"cardinality"`
	PresenceRule           string `json:"presence_rule"`
}

type MutationVerifierEntryV1 struct {
	OperationID                      string                      `json:"operation_id"`
	ActionKind                       string                      `json:"action_kind"`
	OperationPurpose                 string                      `json:"operation_purpose"`
	RequestSchemaVersion             uint16                      `json:"request_schema_version"`
	RequestType                      string                      `json:"request_type"`
	RequestBodyProfileID             string                      `json:"request_body_profile_id"`
	ResultComponents                 []MutationResultComponentV1 `json:"result_components"`
	RequiredContextTypes             []string                    `json:"required_context_types"`
	SemanticFieldDerivationProfileID string                      `json:"semantic_field_derivation_profile_id"`
	TransitionValidatorProfileID     string                      `json:"transition_validator_profile_id"`
	MaterializerProfileID            string                      `json:"materializer_profile_id"`
}

type MutationVerifierRegistryV1 struct {
	SchemaVersion   uint16                    `json:"schema_version"`
	RegistryVersion uint16                    `json:"registry_version"`
	Entries         []MutationVerifierEntryV1 `json:"entries"`
}

type ObjectVerifierEntryV1 struct {
	ObjectKind              string `json:"object_kind"`
	CanonicalType           string `json:"canonical_type"`
	DigestOrEnvelopeBinding string `json:"digest_or_envelope_binding"`
	VerifierProfileID       string `json:"verifier_profile_id"`
}

type ObjectVerifierRegistryV1 struct {
	SchemaVersion   uint16                  `json:"schema_version"`
	RegistryVersion uint16                  `json:"registry_version"`
	Entries         []ObjectVerifierEntryV1 `json:"entries"`
}

func objectEntry(kind, canonicalType, binding, verifier string) ObjectVerifierEntryV1 {
	return ObjectVerifierEntryV1{ObjectKind: kind, CanonicalType: canonicalType,
		DigestOrEnvelopeBinding: binding, VerifierProfileID: verifier}
}

// ReleasedObjectVerifierRegistryV1 is the exhaustive public dispatch surface
// from section 23.1. An implementation may support only a dark subset, but it
// may never reinterpret or add an object kind while claiming V1 conformance.
func ReleasedObjectVerifierRegistryV1() ObjectVerifierRegistryV1 {
	entries := []ObjectVerifierEntryV1{
		objectEntry("service-profile-revision-artifact", "GuarantorServiceProfileRevisionArtifactV1", "embedded in GuarantorServiceProfileArtifactV1.revisions[]", "tos.service.agent-guarantor.verify.service-profile-revision.v1"),
		objectEntry("service-profile-artifact", "GuarantorServiceProfileArtifactV1", "tos.service.agent-guarantor-service-profile-artifact.v1", "tos.service.agent-guarantor.verify.service-profile-artifact.v1"),
		objectEntry("service-profile", "GuarantorServiceProfileV1", "tos.service.agent-guarantor-service-profile.v1", "tos.service.agent-guarantor.verify.service-profile.v1"),
		objectEntry("collateral-profile", "GuarantorCollateralProfileV1", "tos.service.agent-guarantor-collateral-profile.v1", "tos.service.agent-guarantor.verify.collateral-profile.v1"),
		objectEntry("collateral-transition-profile", "CollateralTransitionProfileV1", "tos.service.agent-guarantor-collateral-transition-profile.v1", "tos.service.agent-guarantor.verify.collateral-transition-profile.v1"),
		objectEntry("claim-profile", "GuarantorClaimProfileV1", "tos.service.agent-guarantor-claim-profile.v1", "tos.service.agent-guarantor.verify.claim-profile.v1"),
		objectEntry("claim-closure-capacity", "ClaimClosureCapacityV1", "embedded in requested and accepted coverage terms", "tos.service.agent-guarantor.verify.claim-closure-capacity.v1"),
		objectEntry("stage-action-admission-body", "PortableStageActionAdmissionBodyV1", "tos.service.agent-guarantor-stage-action-admission.v1; embedded in its evidence envelope", "tos.service.agent-guarantor.verify.stage-action-admission-body.v1"),
		objectEntry("stage-action-admission-evidence", "PortableStageActionAdmissionEvidenceV1", "tos.service.agent-guarantor-stage-action-admission-evidence.v1; embedded exactly once in each stage result at every assurance level", "tos.service.agent-guarantor.verify.stage-action-admission-evidence.v1"),
		objectEntry("payout-execution-evidence", "AuthorizedGuarantorPayoutExecutionEvidenceV1", "tos.service.agent-guarantor-payout-execution-evidence.v1", "tos.service.agent-guarantor.verify.payout-execution-evidence.v1"),
		objectEntry("payout-destination", "PayoutDestinationV1", "tos.service.agent-guarantor-payout-destination.v1", "tos.service.agent-guarantor.verify.payout-destination.v1"),
		objectEntry("coverage-end-commitment", "CoverageEndCommitmentV1", "tos.service.agent-guarantor-coverage-end-commitment.v1", "tos.service.agent-guarantor.verify.coverage-end-commitment.v1"),
		objectEntry("stage-operation-binding", "GuarantorStageOperationBindingV1", "tos.service.agent-guarantor-stage-operation-binding.v1", "tos.service.agent-guarantor.verify.stage-operation-binding.v1"),
		objectEntry("collateral-control-disclosure", "CollateralControlDisclosureV1", "tos.service.agent-guarantor-collateral-control-disclosure.v1", "tos.service.agent-guarantor.verify.collateral-control-disclosure.v1"),
		objectEntry("collateral-control-evidence", "AuthorizedCollateralControlEvidenceV1", "tos.service.agent-guarantor-collateral-control-evidence-envelope.v1", "tos.service.agent-guarantor.verify.collateral-control-evidence.v1"),
		objectEntry("operational-independence-terms", "GuarantorOperationalIndependenceTermsV1", OperationalIndependenceTermsDomainV1, "tos.service.agent-guarantor.verify.operational-independence-terms.v1"),
		objectEntry("operational-independence-evidence", "AuthorizedGuarantorOperationalIndependenceEvidenceV1", OperationalIndependenceEvidenceDomainV1, "tos.service.agent-guarantor.verify.operational-independence-evidence.v1"),
		objectEntry("requested-coverage-terms", "RequestedCoverageTermsV1", RequestedTermsDomain, "tos.service.agent-guarantor.verify.requested-coverage-terms.v1"),
		objectEntry("quote-request", "AuthorizedCoverageQuoteRequestV1", QuoteRequestDomain, "tos.service.agent-guarantor.verify.quote-request.v1"),
		objectEntry("coverage-terms", "GuarantorCoverageTermsV1", CoverageTermsDomain, "tos.service.agent-guarantor.verify.coverage-terms.v1"),
		objectEntry("cancellation-policy", "CoverageCancellationPolicyV1", "tos.service.agent-guarantor-cancellation-policy.v1", "tos.service.agent-guarantor.verify.cancellation-policy.v1"),
		objectEntry("coverage-agreement", "AgentAgreementBodyV1 plus profile-qualified evidence", "released generic Agreement domains", "tos.service.agent-guarantor.verify.coverage-agreement.v1"),
		objectEntry("agreement-authorization-set", "GuarantorAgreementAuthorizationEvidenceSetV1", "tos.service.agent-guarantor-agreement-authorization-evidence-set.v1", "tos.service.agent-guarantor.verify.agreement-authorization-set.v1"),
		objectEntry("authority-admission-proof", "AuthorityAdmissionEligibilityProofV1", "tos.service.agent-guarantor-authority-admission-eligibility-proof.v1", "tos.service.agent-guarantor.verify.authority-admission-proof.v1"),
		objectEntry("authority-admission-proof-set", "AuthorityAdmissionEligibilityProofSetV1", "tos.service.agent-guarantor-authority-admission-eligibility-proof-set.v1", "tos.service.agent-guarantor.verify.authority-admission-proof-set.v1"),
		objectEntry("firm-offer-agreement-evidence", "GuarantorFirmOfferAgreementEvidenceV1", "tos.service.agent-guarantor-firm-offer-agreement-evidence.v1", "tos.service.agent-guarantor.verify.firm-offer-agreement-evidence.v1"),
		objectEntry("guarantor-evidence-set", "CanonicalGuarantorEvidenceSetV1", "tos.service.agent-guarantor-evidence-set.v1", "tos.service.agent-guarantor.verify.evidence-set.v1"),
		objectEntry("exposure-admission-descriptor", "ProviderExposureAdmissionDescriptorV1", ExposureDescriptorDomain, "tos.service.agent-guarantor.verify.exposure-admission-descriptor.v1"),
		objectEntry("firm-offer-recipient-set", "FirmOfferRecipientSetV1", "tos.service.agent-guarantor-firm-offer-recipient-set.v1", "tos.service.agent-guarantor.verify.firm-offer-recipient-set.v1"),
		objectEntry("exposure-reservation-scope", "ProviderExposureReservationScopeV1", "tos.service.agent-guarantor-reservation-scope.v1", "tos.service.agent-guarantor.verify.exposure-reservation-scope.v1"),
		objectEntry("firm-offer-authority-instance-effect", "FirmOfferAuthorityInstanceEffectV1", "embedded in FirmOfferIssuanceActionBodyV1", "tos.service.agent-guarantor.verify.firm-offer-authority-effect.v1"),
		objectEntry("exposure-admission-receipt", "AuthorizedProviderExposureAdmissionReceiptV1", ExposureReceiptDomain, "tos.service.agent-guarantor.verify.exposure-admission-receipt.v1"),
		objectEntry("firm-offer", "AuthorizedFirmCoverageOfferV1", FirmOfferDomain, "tos.service.agent-guarantor.verify.firm-offer.v1"),
		objectEntry("offer-non-acceptance", "AuthorizedOfferNonAcceptanceEvidenceV1", "tos.service.agent-guarantor-offer-non-acceptance-envelope.v1", "tos.service.agent-guarantor.verify.offer-non-acceptance.v1"),
		objectEntry("pre-acceptance-exposure-release", "AuthorizedPreAcceptanceExposureReleaseReceiptV1", "tos.service.agent-guarantor-pre-acceptance-release-receipt-envelope.v1", "tos.service.agent-guarantor.verify.pre-acceptance-release.v1"),
		objectEntry("acceptance-request", "AuthorizedCoverageAcceptanceRequestV1", "tos.service.agent-guarantor-acceptance-request-envelope.v1", "tos.service.agent-guarantor.verify.acceptance-request.v1"),
		objectEntry("acceptance-receipt", "AuthorizedCoverageAcceptanceReceiptV1", "tos.service.agent-guarantor-acceptance-receipt-envelope.v1", "tos.service.agent-guarantor.verify.acceptance-receipt.v1"),
		objectEntry("activation-admission-cut", "ActivationAdmissionCutProofV1", "tos.service.agent-guarantor-activation-cut-proof.v1", "tos.service.agent-guarantor.verify.activation-admission-cut.v1"),
		objectEntry("activation-evidence", "AuthorizedCoverageActivationEvidenceV1", "tos.service.agent-guarantor-activation-evidence-envelope.v1", "tos.service.agent-guarantor.verify.activation-evidence.v1"),
		objectEntry("non-activation-evidence", "AuthorizedCoverageNonActivationEvidenceV1", "tos.service.agent-guarantor-non-activation-evidence-envelope.v1", "tos.service.agent-guarantor.verify.non-activation-evidence.v1"),
		objectEntry("non-activation-exposure-release", "AuthorizedNonActivationExposureReleaseReceiptV1", NonActivationExposureReleaseDomainV1, "tos.service.agent-guarantor.verify.non-activation-exposure-release.v1"),
		objectEntry("cancellation-request", "AuthorizedCoverageCancellationRequestV1", "tos.service.agent-guarantor-cancellation-request-envelope.v1", "tos.service.agent-guarantor.verify.cancellation-request.v1"),
		objectEntry("cancellation-receipt", "AuthorizedCoverageCancellationReceiptV1", "tos.service.agent-guarantor-cancellation-receipt-envelope.v1", "tos.service.agent-guarantor.verify.cancellation-receipt.v1"),
		objectEntry("collateral-terms", "CollateralTermsV1", "embedded in the accepted coverage Agreement", "tos.service.agent-guarantor.verify.collateral-terms.v1"),
		objectEntry("collateral-position-state", "CollateralPositionStateV1", "tos.service.agent-guarantor-collateral-position-state.v1", "tos.service.agent-guarantor.verify.collateral-position-state.v1"),
		objectEntry("collateral-adapter-request", "CollateralAdapterRequestV1", "tos.service.agent-guarantor-collateral-adapter-request.v1", "tos.service.agent-guarantor.verify.collateral-adapter-request.v1"),
		objectEntry("collateral-adapter-evidence", "CollateralAdapterEvidenceV1", "tos.service.agent-guarantor-collateral-adapter-evidence.v1", "tos.service.agent-guarantor.verify.collateral-adapter-evidence.v1"),
		objectEntry("collateral-evidence", "AuthorizedCollateralEvidenceV1", CollateralDomain, "tos.service.agent-guarantor.verify.collateral-evidence.v1"),
		objectEntry("collateral-payout-payment-evidence-projection", "CollateralPayoutPaymentEvidenceProjectionV1", "tos.service.agent-guarantor-collateral-payout-payment-evidence.v1", "tos.service.agent-guarantor.verify.collateral-payout-payment-evidence.v1"),
		objectEntry("triggered-obligation-set", "TriggeredObligationSetV1", "tos.service.agent-guarantor-triggered-obligation-set.v1", "tos.service.agent-guarantor.verify.triggered-obligation-set.v1"),
		objectEntry("claim-evidence-manifest", "ClaimEvidenceManifestV1", "tos.service.agent-guarantor-claim-evidence-manifest.v1", "tos.service.agent-guarantor.verify.claim-evidence-manifest.v1"),
		objectEntry("other-recovery-declaration", "OtherRecoveryDeclarationV1", "tos.service.agent-guarantor-other-recovery-declaration.v1", "tos.service.agent-guarantor.verify.other-recovery-declaration.v1"),
		objectEntry("claim", "AuthorizedCoverageClaimV1", ClaimDomain, "tos.service.agent-guarantor.verify.claim.v1"),
		objectEntry("claim-ingress-receipt", "AuthorizedClaimSubmissionIngressReceiptV1", "tos.service.agent-guarantor-claim-ingress-receipt-envelope.v1", "tos.service.agent-guarantor.verify.claim-ingress-receipt.v1"),
		objectEntry("claim-ingress-cut", "ClaimIngressAdmissionCutProofV1", "tos.service.agent-guarantor-claim-ingress-cut-proof.v1", "tos.service.agent-guarantor.verify.claim-ingress-cut.v1"),
		objectEntry("claim-submission-authority-instance-effect", "ClaimSubmissionAuthorityInstanceEffectV1", "tos.service.agent-guarantor-claim-submission-authority-instance-effect.v1", "tos.service.agent-guarantor.verify.claim-submission-authority-effect.v1"),
		objectEntry("claim-admission-receipt", "AuthorizedClaimAdmissionReceiptV1", "tos.service.agent-guarantor-claim-admission-envelope.v1", "tos.service.agent-guarantor.verify.claim-admission-receipt.v1"),
		objectEntry("claim-filing-close-receipt", "AuthorizedClaimFilingCloseReceiptV1", "tos.service.agent-guarantor-claim-filing-close-envelope.v1", "tos.service.agent-guarantor.verify.claim-filing-close-receipt.v1"),
		objectEntry("claim-decision", "AuthorizedClaimDecisionV1", ClaimDecisionDomain, "tos.service.agent-guarantor.verify.claim-decision.v1"),
		objectEntry("claim-revision-epoch-expectation", "ClaimRevisionEpochExpectationV1", "tos.service.agent-guarantor-claim-revision-epoch-expectation.v1", "tos.service.agent-guarantor.verify.claim-revision-epoch-expectation.v1"),
		objectEntry("claim-decision-admission-receipt", "AuthorizedClaimDecisionAdmissionReceiptV1", "tos.service.agent-guarantor-claim-decision-admission-envelope.v1", "tos.service.agent-guarantor.verify.claim-decision-admission-receipt.v1"),
		objectEntry("claim-decision-admission-receipt-seal", "ClaimDecisionAdmissionReceiptSealBodyV1 plus authorization", ClaimDecisionAdmissionReceiptSealDomainV1, "tos.service.agent-guarantor.verify.claim-decision-admission-receipt-seal.v1"),
		objectEntry("claim-decision-admission-receipt-proof", "ClaimDecisionAdmissionReceiptProofV1", "tos.service.agent-guarantor-claim-decision-admission-receipt-proof.v1", "tos.service.agent-guarantor.verify.claim-decision-admission-receipt-proof.v1"),
		objectEntry("decision-application-token", "DecisionApplicationTokenV1", "tos.service.agent-guarantor-decision-application-token.v1", "tos.service.agent-guarantor.verify.decision-application-token.v1"),
		objectEntry("claim-decision-application-receipt", "AuthorizedClaimDecisionApplicationReceiptV1", "tos.service.agent-guarantor-decision-application-envelope.v1", "tos.service.agent-guarantor.verify.claim-decision-application-receipt.v1"),
		objectEntry("decision-application-receipt-seal", "DecisionApplicationReceiptSealBodyV1 plus authorization", DecisionApplicationReceiptSealDomainV1, "tos.service.agent-guarantor.verify.decision-application-receipt-seal.v1"),
		objectEntry("decision-application-receipt-proof", "DecisionApplicationReceiptProofV1", "tos.service.agent-guarantor-decision-application-receipt-proof.v1", "tos.service.agent-guarantor.verify.decision-application-receipt-proof.v1"),
		objectEntry("claim-admission-receipt-proof", "ClaimAdmissionReceiptProofV1", "tos.service.agent-guarantor-claim-admission-receipt-proof.v1", "tos.service.agent-guarantor.verify.claim-admission-receipt-proof.v1"),
		objectEntry("claim-admission-receipt-seal", "ClaimAdmissionReceiptSealBodyV1 plus authorization", ClaimAdmissionReceiptSealDomainV1, "tos.service.agent-guarantor.verify.claim-admission-receipt-seal.v1"),
		objectEntry("claim-state-transition-receipt", "AuthorizedClaimStateTransitionReceiptV1", "tos.service.agent-guarantor-claim-state-transition-envelope.v1", "tos.service.agent-guarantor.verify.claim-state-transition-receipt.v1"),
		objectEntry("conditional-settlement-template", "ConditionalSettlementTemplateV1", "embedded in the accepted coverage Agreement", "tos.service.agent-guarantor.verify.conditional-settlement-template.v1"),
		objectEntry("settlement-parameters", "ProfileQualifiedSettlementParametersV1", "tos.service.agent-guarantor-settlement-parameters.v1", "tos.service.agent-guarantor.verify.settlement-parameters.v1"),
		objectEntry("claim-payout-line", "ClaimPayoutLineV1", "tos.service.agent-guarantor-payout-line.v1", "tos.service.agent-guarantor.verify.claim-payout-line.v1"),
		objectEntry("materialized-payout-line", "MaterializedPayoutLineV1", "tos.service.agent-guarantor-materialized-payout-line.v1", "tos.service.agent-guarantor.verify.materialized-payout-line.v1"),
		objectEntry("materialized-payout-set", "MaterializedPayoutObligationSetV1", PayoutSetDomain, "tos.service.agent-guarantor.verify.materialized-payout-set.v1"),
		objectEntry("terminal-payout-set", "TerminalPayoutEvidenceSetV1", "tos.service.agent-guarantor-terminal-payout-evidence-set.v1", "tos.service.agent-guarantor.verify.terminal-payout-set.v1"),
		objectEntry("coverage-terminal-payout-set", "CoverageTerminalPayoutEvidenceSetV1", "tos.service.agent-guarantor-coverage-terminal-payout-evidence-set.v1", "tos.service.agent-guarantor.verify.coverage-terminal-payout-set.v1"),
		objectEntry("claim-terminal-resolution-ref-set", "ClaimTerminalResolutionRefSetV1", "tos.service.agent-guarantor-claim-resolution-set.v1", "tos.service.agent-guarantor.verify.claim-resolution-ref-set.v1"),
		objectEntry("coverage-closure-context", "CoverageClosureEvidenceContextV1", "tos.service.agent-guarantor-coverage-closure-context.v1", "tos.service.agent-guarantor.verify.coverage-closure-context.v1"),
		objectEntry("terminal-claim-set", "AuthorizedTerminalClaimSetEvidenceV1", "tos.service.agent-guarantor-terminal-claim-set-evidence.v1", "tos.service.agent-guarantor.verify.terminal-claim-set.v1"),
		objectEntry("exposure-disposition", "ExposureDispositionComputationV1", "tos.service.agent-guarantor-exposure-disposition.v1", "tos.service.agent-guarantor.verify.exposure-disposition.v1"),
		objectEntry("exposure-release-receipt", "AuthorizedExposureReleaseReceiptV1", "tos.service.agent-guarantor-exposure-release-receipt-envelope.v1", "tos.service.agent-guarantor.verify.exposure-release-receipt.v1"),
		objectEntry("coverage-resolution", "AuthorizedCoverageResolutionV1", "tos.service.agent-guarantor-resolution-envelope.v1", "tos.service.agent-guarantor.verify.coverage-resolution.v1"),
		objectEntry("transition-evidence-projection", "TransitionEvidenceProjectionV1", "tos.service.agent-guarantor-transition-evidence-projection.v1", "tos.service.agent-guarantor.verify.transition-evidence-projection.v1"),
		objectEntry("pre-acceptance-release-projection", "PreAcceptanceExposureReleaseEvidenceProjectionV1", "tos.service.agent-guarantor-pre-acceptance-release-evidence-projection.v1", "tos.service.agent-guarantor.verify.pre-acceptance-release-projection.v1"),
		objectEntry("exposure-release-projection", "ExposureReleaseEvidenceProjectionV1", "tos.service.agent-guarantor-exposure-release-evidence-projection.v1", "tos.service.agent-guarantor.verify.exposure-release-projection.v1"),
		objectEntry("commerce-profile-event", "CommerceProfileEventV1", "released generic commerce-event domain", "tos.service.agent-guarantor.verify.commerce-profile-event.v1"),
		objectEntry("object-verifier-registry", "GuarantorObjectVerifierRegistryV1", "tos.service.agent-guarantor-object-verifier-registry.v1", "tos.service.agent-guarantor.verify.object-registry.v1"),
		objectEntry("mutation-verifier-registry", "GuarantorMutationVerifierRegistryV1", "tos.service.agent-guarantor-mutation-verifier-registry.v1", "tos.service.agent-guarantor.verify.mutation-registry.v1"),
	}
	return ObjectVerifierRegistryV1{SchemaVersion: 1, RegistryVersion: 1, Entries: entries}
}

func VerifyObjectVerifierRegistryV1(registry ObjectVerifierRegistryV1) error {
	released := ReleasedObjectVerifierRegistryV1()
	if registry.SchemaVersion != 1 || registry.RegistryVersion != 1 || len(registry.Entries) != len(released.Entries) {
		return errors.New("Guarantor object registry header or size is invalid")
	}
	want, wantErr := guarantorCodec.Marshal(released)
	got, gotErr := guarantorCodec.Marshal(registry)
	if wantErr != nil || gotErr != nil || string(want) != string(got) {
		return errors.New("Guarantor object registry differs from the released registry")
	}
	seen := make(map[string]struct{}, len(registry.Entries))
	for _, candidate := range registry.Entries {
		if candidate.ObjectKind == "" || candidate.CanonicalType == "" || candidate.DigestOrEnvelopeBinding == "" ||
			candidate.VerifierProfileID == "" {
			return errors.New("Guarantor object registry entry is incomplete")
		}
		if _, duplicate := seen[candidate.ObjectKind]; duplicate {
			return errors.New("Guarantor object registry kind is duplicated")
		}
		seen[candidate.ObjectKind] = struct{}{}
	}
	if factories := guarantorObjectFactoriesV1(); len(factories) != len(registry.Entries) {
		return errors.New("Guarantor object registry has no exhaustive decoder table")
	} else {
		for _, candidate := range registry.Entries {
			if factories[candidate.ObjectKind] == nil {
				return errors.New("Guarantor object registry entry has no decoder")
			}
		}
	}
	return nil
}

func ObjectVerifierRegistryDigestV1() (string, error) {
	registry := ReleasedObjectVerifierRegistryV1()
	if err := VerifyObjectVerifierRegistryV1(registry); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-object-verifier-registry.v1", registry)
}

func ReleasedMutationVerifierRegistryV1() MutationVerifierRegistryV1 {
	component := func(role, canonicalType, domain string) MutationResultComponentV1 {
		return MutationResultComponentV1{Role: role, CanonicalType: canonicalType, DigestOrEnvelopeDomain: domain,
			Cardinality: "exactly_one", PresenceRule: "accepted_effect_v1"}
	}
	entry := func(kind, purpose, requestType, profile string, components ...MutationResultComponentV1) MutationVerifierEntryV1 {
		return MutationVerifierEntryV1{OperationID: profile, ActionKind: kind, OperationPurpose: purpose,
			RequestSchemaVersion: 1, RequestType: requestType, RequestBodyProfileID: profile,
			ResultComponents: components, RequiredContextTypes: []string{}, SemanticFieldDerivationProfileID: profile,
			TransitionValidatorProfileID: profile, MaterializerProfileID: profile}
	}
	entries := []MutationVerifierEntryV1{
		entry("commercial.quote.close", "offer-non-acceptance", "OfferNonAcceptanceResolutionActionBodyV1", "tos.service.agent-guarantor.mutate.offer-non-acceptance.v1", component("non_acceptance", "AuthorizedOfferNonAcceptanceEvidenceV1", "tos.service.agent-guarantor-offer-non-acceptance-envelope.v1")),
		entry("commercial.quote.issue", "firm-offer-issuance", "FirmOfferIssuanceActionBodyV1", "tos.service.agent-guarantor.mutate.firm-offer-issuance.v1", component("exposure_receipt", "AuthorizedProviderExposureAdmissionReceiptV1", "tos.service.agent-guarantor-exposure-receipt-envelope.v1"), component("firm_offer", "AuthorizedFirmCoverageOfferV1", FirmOfferDomain)),
		entry("collateral.transition", "collateral-transition", "CollateralTransitionActionBodyV1", "tos.service.agent-guarantor.mutate.collateral-transition.v1", component("collateral_evidence", "AuthorizedCollateralEvidenceV1", CollateralDomain)),
		entry("conditional.claim-decision.admit", "claim-decision-admission", "ClaimDecisionAdmissionActionBodyV1", "tos.service.agent-guarantor.mutate.claim-decision-admission.v1", component("decision_admission_receipt", "AuthorizedClaimDecisionAdmissionReceiptV1", "tos.service.agent-guarantor-claim-decision-admission-envelope.v1")),
		entry("conditional.claim-filing.close", "claim-filing-close", "ClaimFilingCloseActionBodyV1", "tos.service.agent-guarantor.mutate.claim-filing-close.v1", component("filing_close_receipt", "AuthorizedClaimFilingCloseReceiptV1", "tos.service.agent-guarantor-claim-filing-close-envelope.v1")),
		entry("conditional.claim.decide", "claim-decision-application", "ClaimDecisionApplicationActionBodyV1", "tos.service.agent-guarantor.mutate.claim-decision-application.v1", component("materialized_payout_set", "MaterializedPayoutObligationSetV1", PayoutSetDomain), component("application_receipt", "AuthorizedClaimDecisionApplicationReceiptV1", "tos.service.agent-guarantor-decision-application-envelope.v1")),
		entry("conditional.claim.ingress", "claim-submission-ingress", "ClaimSubmissionIngressActionBodyV1", "tos.service.agent-guarantor.mutate.claim-submission-ingress.v1", component("claim_ingress_receipt", "AuthorizedClaimSubmissionIngressReceiptV1", "tos.service.agent-guarantor-claim-ingress-receipt-envelope.v1")),
		entry("conditional.claim.submit", "claim-admission", "ClaimSubmissionActionBodyV1", "tos.service.agent-guarantor.mutate.claim-admission.v1", component("claim_admission_receipt", "AuthorizedClaimAdmissionReceiptV1", "tos.service.agent-guarantor-claim-admission-envelope.v1")),
		entry("conditional.claim.transition", "claim-state-transition", "ClaimStateTransitionActionBodyV1", "tos.service.agent-guarantor.mutate.claim-state-transition.v1", component("state_transition_receipt", "AuthorizedClaimStateTransitionReceiptV1", "tos.service.agent-guarantor-claim-state-transition-envelope.v1")),
		entry("conditional.obligation.transition", "coverage-acceptance", "CoverageAcceptanceAdmissionActionBodyV1", "tos.service.agent-guarantor.mutate.coverage-acceptance.v1", component("acceptance_receipt", "AuthorizedCoverageAcceptanceReceiptV1", "tos.service.agent-guarantor-acceptance-receipt-envelope.v1")),
		entry("conditional.obligation.transition", "coverage-activation", "CoverageActivationActionBodyV1", "tos.service.agent-guarantor.mutate.coverage-activation.v1", component("activation_evidence", "AuthorizedCoverageActivationEvidenceV1", "tos.service.agent-guarantor-activation-evidence-envelope.v1")),
		entry("conditional.obligation.transition", "coverage-cancellation", "CoverageCancellationActionBodyV1", "tos.service.agent-guarantor.mutate.coverage-cancellation.v1", component("cancellation_receipt", "AuthorizedCoverageCancellationReceiptV1", "tos.service.agent-guarantor-cancellation-receipt-envelope.v1")),
		entry("conditional.obligation.transition", "coverage-closure", "CoverageClosureActionBodyV1", "tos.service.agent-guarantor.mutate.coverage-closure.v1", component("terminal_claim_set", "AuthorizedTerminalClaimSetEvidenceV1", "tos.service.agent-guarantor-terminal-claim-set-evidence.v1")),
		entry("conditional.obligation.transition", "coverage-non-activation", "CoverageNonActivationActionBodyV1", "tos.service.agent-guarantor.mutate.coverage-non-activation.v1", component("non_activation_evidence", "AuthorizedCoverageNonActivationEvidenceV1", "tos.service.agent-guarantor-non-activation-evidence-envelope.v1")),
		entry("conditional.obligation.transition", "coverage-resolution", "CoverageResolutionActionBodyV1", "tos.service.agent-guarantor.mutate.coverage-resolution.v1", component("coverage_resolution", "AuthorizedCoverageResolutionV1", "tos.service.agent-guarantor-resolution-envelope.v1")),
		entry("payment.direct", "guarantor-payout", "GuarantorAgreementPaymentActionBodyV1", "tos.service.agent-guarantor.mutate.direct-payout.v1", component("payout_execution_evidence", "AuthorizedGuarantorPayoutExecutionEvidenceV1", "tos.service.agent-guarantor-payout-execution-evidence.v1")),
		entry("payment.domain-bound", "guarantor-payout", "GuarantorAgreementPaymentActionBodyV1", "tos.service.agent-guarantor.mutate.domain-bound-payout.v1", component("payout_execution_evidence", "AuthorizedGuarantorPayoutExecutionEvidenceV1", "tos.service.agent-guarantor-payout-execution-evidence.v1")),
		entry("portfolio.release", "post-acceptance", "ExposureReleaseActionBodyV1", "tos.service.agent-guarantor.mutate.post-acceptance-release.v1", component("release_receipt", "AuthorizedExposureReleaseReceiptV1", "tos.service.agent-guarantor-exposure-release-receipt-envelope.v1")),
		entry("portfolio.release", "pre-acceptance", "PreAcceptanceExposureReleaseActionBodyV1", "tos.service.agent-guarantor.mutate.pre-acceptance-release.v1", component("release_receipt", "AuthorizedPreAcceptanceExposureReleaseReceiptV1", "tos.service.agent-guarantor-pre-acceptance-release-receipt-envelope.v1")),
		entry("settlement.external", "collateral-backed-payout", "CollateralBackedAgreementPaymentActionBodyV1", "tos.service.agent-guarantor.mutate.collateral-backed-payout.v1", component("payout_execution_evidence", "AuthorizedGuarantorPayoutExecutionEvidenceV1", "tos.service.agent-guarantor-payout-execution-evidence.v1")),
		entry("settlement.external", "guarantor-payout", "GuarantorAgreementPaymentActionBodyV1", "tos.service.agent-guarantor.mutate.external-payout.v1", component("payout_execution_evidence", "AuthorizedGuarantorPayoutExecutionEvidenceV1", "tos.service.agent-guarantor-payout-execution-evidence.v1")),
	}
	sort.Slice(entries, func(i, j int) bool {
		left := entries[i].ActionKind + "\x00" + entries[i].OperationPurpose
		right := entries[j].ActionKind + "\x00" + entries[j].OperationPurpose
		return left < right
	})
	return MutationVerifierRegistryV1{SchemaVersion: 1, RegistryVersion: 1, Entries: entries}
}

func VerifyMutationVerifierRegistryV1(registry MutationVerifierRegistryV1) error {
	released := ReleasedMutationVerifierRegistryV1()
	if registry.SchemaVersion != 1 || registry.RegistryVersion != 1 || len(registry.Entries) != len(released.Entries) {
		return errors.New("Guarantor mutation registry header or size is invalid")
	}
	releasedBytes, err := guarantorCodec.Marshal(released)
	if err != nil {
		return err
	}
	candidateBytes, err := guarantorCodec.Marshal(registry)
	if err != nil || string(candidateBytes) != string(releasedBytes) {
		return errors.New("Guarantor mutation registry differs from the released registry")
	}
	semantic := agentcommerce.SemanticActionRegistry()
	for _, entry := range registry.Entries {
		if semantic[entry.ActionKind].ActionKind == "" || entry.OperationID == "" || entry.OperationID != entry.RequestBodyProfileID ||
			entry.OperationID != entry.SemanticFieldDerivationProfileID || entry.OperationID != entry.TransitionValidatorProfileID ||
			entry.OperationID != entry.MaterializerProfileID || len(entry.RequiredContextTypes) != 0 {
			return errors.New("Guarantor mutation registry dispatch is invalid")
		}
	}
	return verifyMutationFactoriesMatchRegistryV1()
}

func MutationVerifierRegistryDigestV1() (string, error) {
	registry := ReleasedMutationVerifierRegistryV1()
	if err := VerifyMutationVerifierRegistryV1(registry); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-mutation-verifier-registry.v1", registry)
}
