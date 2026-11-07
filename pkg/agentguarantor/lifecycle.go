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
	CoverageEndCommitmentDomain = "tos.service.agent-guarantor-coverage-end-commitment.v1"
	TransitionProjectionDomain  = "tos.service.agent-guarantor-transition-evidence-projection.v1"
	StageAdmissionDomain        = "tos.service.agent-guarantor-stage-action-admission-evidence.v1"
	ActivationEvidenceDomain    = "tos.service.agent-guarantor-activation-evidence-envelope.v1"
)

// CoverageEndCommitmentV1 prevents a lifecycle coordinator from changing the
// incident cutoff while closing or resolving a coverage.
type CoverageEndCommitmentV1 struct {
	SchemaVersion                 uint16 `json:"schema_version"`
	CoverageAgreementBodyDigest   string `json:"coverage_agreement_body_digest"`
	CoverageObligationID          string `json:"coverage_obligation_id"`
	CoverageStateDomainDigest     string `json:"coverage_state_domain_digest"`
	EndBranch                     string `json:"end_branch"`
	IncidentEligibilityEndsAtUnix uint64 `json:"incident_eligibility_ends_at_unix,omitempty"`
	CoverageEndEvidenceDigest     string `json:"coverage_end_evidence_digest,omitempty"`
}

type TransitionEvidenceDigestRefV1 struct {
	EvidenceRole string `json:"evidence_role"`
	DigestKind   string `json:"digest_kind"`
	ObjectDigest string `json:"object_digest"`
}

type TransitionEvidenceProjectionV1 struct {
	SchemaVersion               uint16                          `json:"schema_version"`
	Purpose                     string                          `json:"purpose"`
	CoverageAgreementBodyDigest string                          `json:"coverage_agreement_body_digest"`
	ObligationID                string                          `json:"obligation_id"`
	ClaimID                     string                          `json:"claim_id,omitempty"`
	TargetState                 string                          `json:"target_state"`
	EvidenceDigests             []TransitionEvidenceDigestRefV1 `json:"evidence_digests"`
}

// PortableStageActionAdmissionEvidenceV1 carries enough information for a
// verifier which has never contacted the provider to reproduce the exact
// action identity, writer generation and authority result.
type PortableStageActionAdmissionBodyV1 struct {
	SchemaVersion          uint16 `json:"schema_version"`
	Stage                  string `json:"stage"`
	OperationID            string `json:"operation_id"`
	OperationBindingDigest string `json:"operation_binding_digest"`
	AdmittedAtUnix         uint64 `json:"admitted_at_unix"`
	CanonicalRequestDigest string `json:"canonical_request_digest"`
	AuthorizedActionDigest string `json:"authorized_action_digest"`
	WriterFenceDigest      string `json:"writer_fence_digest"`
	AdmissionState         string `json:"admission_state"`
	AdmissionStateRevision uint64 `json:"admission_state_revision"`
}

type PortableStageActionAdmissionEvidenceV1 struct {
	Body                         PortableStageActionAdmissionBodyV1  `json:"body"`
	CanonicalRequestContentType  string                              `json:"canonical_request_content_type"`
	CanonicalRequest             []byte                              `json:"canonical_request"`
	AuthorizedAction             agentcommerce.AuthorizedAction      `json:"authorized_action"`
	WriterFence                  agentcommerce.WriterFence           `json:"writer_fence"`
	ActionResolution             agentcommerce.ActionResolution      `json:"action_resolution"`
	ActionAdmissionAuthorization StageActionAdmissionAuthorizationV1 `json:"action_admission_authorization"`
}

type CoverageActivationActionBodyV1 struct {
	SchemaVersion                      uint16                                       `json:"schema_version"`
	UnderlyingAgreementBody            agentcommerce.AgentAgreementBody             `json:"underlying_agreement_body"`
	UnderlyingAuthorizationEvidenceSet GuarantorAgreementAuthorizationEvidenceSetV1 `json:"underlying_authorization_evidence_set"`
	AuthorizedAcceptanceReceipt        AuthorizedCoverageAcceptanceReceiptV1        `json:"authorized_acceptance_receipt"`
	PrerequisiteEvidenceSet            *CanonicalGuarantorEvidenceSetV1             `json:"prerequisite_evidence_set,omitempty"`
	TargetCoverageEndCommitment        CoverageEndCommitmentV1                      `json:"target_coverage_end_commitment"`
	TransitionEvidenceProjection       TransitionEvidenceProjectionV1               `json:"transition_evidence_projection"`
	ExpectedCoverageRevision           uint64                                       `json:"expected_coverage_revision"`
	TargetCoverageRevision             uint64                                       `json:"target_coverage_revision"`
	ExpectedClaimFilingState           string                                       `json:"expected_claim_filing_state"`
	TargetClaimFilingState             string                                       `json:"target_claim_filing_state"`
	ExpectedClaimFilingStateRevision   uint64                                       `json:"expected_claim_filing_state_revision"`
	TargetClaimFilingStateRevision     uint64                                       `json:"target_claim_filing_state_revision"`
}

type CoverageActivationEvidenceBodyV1 struct {
	SchemaVersion                               uint16         `json:"schema_version"`
	AuthorityID                                 string         `json:"authority_id"`
	CoverageAgreementBodyDigest                 string         `json:"coverage_agreement_body_digest"`
	CoverageObligationID                        string         `json:"coverage_obligation_id"`
	CoverageStateDomainDigest                   string         `json:"coverage_state_domain_digest"`
	AuthorizationEvidenceSetDigest              string         `json:"authorization_evidence_set_digest"`
	UnderlyingAgreementBodyDigest               string         `json:"underlying_agreement_body_digest"`
	UnderlyingAuthorizationEvidenceSetDigest    string         `json:"underlying_authorization_evidence_set_digest"`
	AuthorizedFirmOfferEnvelopeDigest           string         `json:"authorized_firm_offer_envelope_digest"`
	AcceptanceReceiptDigest                     string         `json:"acceptance_receipt_digest"`
	ExposureReceiptDigest                       string         `json:"exposure_receipt_digest"`
	PrerequisiteEvidenceSetDigest               string         `json:"prerequisite_evidence_set_digest,omitempty"`
	SelectedAssuranceLevel                      AssuranceLevel `json:"selected_assurance_level"`
	SelectedClaimProfileDigest                  string         `json:"selected_claim_profile_digest"`
	TransitionEvidenceProjectionDigest          string         `json:"transition_evidence_projection_digest"`
	AuthorizedActionDigest                      string         `json:"authorized_action_digest"`
	StableActionID                              string         `json:"stable_action_id"`
	ExactRequestDigest                          string         `json:"exact_request_digest"`
	WriterGeneration                            uint64         `json:"writer_generation"`
	WriterFenceDigest                           string         `json:"writer_fence_digest"`
	PriorCoverageRevision                       uint64         `json:"prior_coverage_revision"`
	ActivatedCoverageRevision                   uint64         `json:"activated_coverage_revision"`
	PriorClaimFilingState                       string         `json:"prior_claim_filing_state"`
	ActivatedClaimFilingState                   string         `json:"activated_claim_filing_state"`
	PriorClaimFilingStateRevision               uint64         `json:"prior_claim_filing_state_revision"`
	ActivatedClaimFilingStateRevision           uint64         `json:"activated_claim_filing_state_revision"`
	ResultingCoverageEndCommitmentDigest        string         `json:"resulting_coverage_end_commitment_digest"`
	ActivatedAtUnix                             uint64         `json:"activated_at_unix"`
	CoverageEndsAtUnix                          uint64         `json:"coverage_ends_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string         `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedCoverageActivationEvidenceV1 struct {
	Body                                  CoverageActivationEvidenceBodyV1             `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1       `json:"stage_action_admission_evidence"`
	UnderlyingAgreementBody               agentcommerce.AgentAgreementBody             `json:"underlying_agreement_body"`
	AuthorizedAcceptanceReceipt           AuthorizedCoverageAcceptanceReceiptV1        `json:"authorized_acceptance_receipt"`
	CoverageEndCommitment                 CoverageEndCommitmentV1                      `json:"coverage_end_commitment"`
	UnderlyingAuthorizationEvidenceSet    GuarantorAgreementAuthorizationEvidenceSetV1 `json:"underlying_authorization_evidence_set"`
	PrerequisiteEvidenceSet               *CanonicalGuarantorEvidenceSetV1             `json:"prerequisite_evidence_set,omitempty"`
	TransitionEvidenceProjection          TransitionEvidenceProjectionV1               `json:"transition_evidence_projection"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1      `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1      `json:"authorizations"`
}

func CoverageEndCommitmentDigestV1(commitment CoverageEndCommitmentV1) (string, error) {
	if err := ValidateCoverageEndCommitmentV1(commitment); err != nil {
		return "", err
	}
	return codec.Digest(CoverageEndCommitmentDomain, commitment)
}

func ValidateCoverageEndCommitmentV1(commitment CoverageEndCommitmentV1) error {
	if commitment.SchemaVersion != 1 || !validDigest(commitment.CoverageAgreementBodyDigest) ||
		!validToken(commitment.CoverageObligationID, 128) || !validDigest(commitment.CoverageStateDomainDigest) {
		return errors.New("coverage end commitment is invalid")
	}
	switch commitment.EndBranch {
	case "scheduled":
		if commitment.IncidentEligibilityEndsAtUnix == 0 || commitment.CoverageEndEvidenceDigest != "" {
			return errors.New("scheduled coverage end is invalid")
		}
	case "accepted_cancellation":
		if commitment.IncidentEligibilityEndsAtUnix == 0 || !validDigest(commitment.CoverageEndEvidenceDigest) {
			return errors.New("cancelled coverage end is invalid")
		}
	case "never_activated":
		if commitment.IncidentEligibilityEndsAtUnix != 0 || !validDigest(commitment.CoverageEndEvidenceDigest) {
			return errors.New("non-activation coverage end is invalid")
		}
	default:
		return errors.New("coverage end branch is unknown")
	}
	return nil
}

func TransitionEvidenceProjectionDigestV1(projection TransitionEvidenceProjectionV1) (string, error) {
	if err := ValidateTransitionEvidenceProjectionV1(projection); err != nil {
		return "", err
	}
	return codec.Digest(TransitionProjectionDomain, projection)
}

func ValidateTransitionEvidenceProjectionV1(projection TransitionEvidenceProjectionV1) error {
	if projection.SchemaVersion != 1 || !validToken(projection.Purpose, 128) ||
		!validDigest(projection.CoverageAgreementBodyDigest) || !validToken(projection.ObligationID, 128) ||
		!validToken(projection.TargetState, 128) || len(projection.EvidenceDigests) == 0 || len(projection.EvidenceDigests) > MaxEvidenceItems {
		return errors.New("transition evidence projection is invalid")
	}
	var prior []byte
	for _, ref := range projection.EvidenceDigests {
		if !validToken(ref.EvidenceRole, 128) || (ref.DigestKind != "authorized_envelope" && ref.DigestKind != "canonical_set" && ref.DigestKind != "canonical_object") || !validDigest(ref.ObjectDigest) {
			return errors.New("transition evidence reference is invalid")
		}
		encoded, err := codec.Marshal(ref)
		if err != nil || prior != nil && bytes.Compare(prior, encoded) >= 0 {
			return errors.New("transition evidence references are unsorted or duplicated")
		}
		prior = encoded
	}
	return nil
}

func CoverageActivationEvidenceDigestV1(evidence AuthorizedCoverageActivationEvidenceV1) (string, error) {
	if err := validateActivationEvidenceShape(evidence); err != nil {
		return "", err
	}
	return codec.Digest(ActivationEvidenceDomain, evidence)
}

func VerifyCoverageActivationEvidenceV1(evidence AuthorizedCoverageActivationEvidenceV1, offer AuthorizedFirmCoverageOfferV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, collateralFinalityVerifier CollateralAdapterFinalityVerifier,
	now time.Time) error {
	if err := validateActivationEvidenceShape(evidence); err != nil || agreementVerifier == nil || fenceResolver == nil {
		return errors.New("coverage activation evidence is invalid")
	}
	if err := enforceCanonicalSize(evidence, offer.CoverageTerms.ClaimClosureCapacity.MaximumActivationEvidenceEnvelopeBytes,
		"coverage activation evidence"); err != nil {
		return err
	}
	body := evidence.Body
	acceptance := evidence.AuthorizedAcceptanceReceipt
	agreementDigest, _ := agentcommerce.AgreementBodyDigest(acceptance.AuthorizedAcceptanceRequest.CoverageAgreementBody)
	underlyingDigest, _ := agentcommerce.AgreementBodyDigest(evidence.UnderlyingAgreementBody)
	underlyingSetDigest, _ := AgreementAuthorizationEvidenceSetDigestV1(evidence.UnderlyingAuthorizationEvidenceSet)
	coverageSetDigest, _ := AgreementAuthorizationEvidenceSetDigestV1(acceptance.AuthorizedAcceptanceRequest.AuthorizationEvidenceSet)
	offerDigest, _ := FirmOfferDigest(offer)
	acceptanceDigest, _ := CoverageAcceptanceReceiptDigestV1(acceptance)
	exposureDigest, _ := ExposureAdmissionReceiptDigestV1(offer.ExposureAdmissionReceipt)
	endDigest, _ := CoverageEndCommitmentDigestV1(evidence.CoverageEndCommitment)
	projectionDigest, _ := TransitionEvidenceProjectionDigestV1(evidence.TransitionEvidenceProjection)
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(evidence.StageActionAdmissionEvidence.AuthorizedAction)
	if actionErr != nil || body.CoverageAgreementBodyDigest != agreementDigest || body.UnderlyingAgreementBodyDigest != underlyingDigest ||
		body.UnderlyingAuthorizationEvidenceSetDigest != underlyingSetDigest || body.AuthorizationEvidenceSetDigest != coverageSetDigest ||
		body.AuthorizedFirmOfferEnvelopeDigest != offerDigest || body.AcceptanceReceiptDigest != acceptanceDigest ||
		body.ExposureReceiptDigest != exposureDigest || body.ResultingCoverageEndCommitmentDigest != endDigest ||
		body.TransitionEvidenceProjectionDigest != projectionDigest || body.AuthorizedActionDigest != actionDigest {
		return errors.New("coverage activation evidence binding is invalid")
	}
	if err := VerifyCoverageAcceptanceReceiptV1(acceptance, offer, agreementVerifier, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	underlying := agentcommerce.AgentAgreement{Body: evidence.UnderlyingAgreementBody,
		AuthorizationEvidence: evidence.UnderlyingAuthorizationEvidenceSet.Evidence}
	if err := agentcommerce.ValidateAgreementAuthorization(underlying, agreementVerifier, now); err != nil {
		return errors.New("underlying Agreement is not authorized")
	}
	if offer.CoverageTerms.UnderlyingAgreementBodyDigest != underlyingDigest || evidence.CoverageEndCommitment.CoverageAgreementBodyDigest != agreementDigest ||
		evidence.CoverageEndCommitment.CoverageObligationID != body.CoverageObligationID || evidence.CoverageEndCommitment.CoverageStateDomainDigest != body.CoverageStateDomainDigest ||
		evidence.CoverageEndCommitment.EndBranch != "scheduled" || evidence.CoverageEndCommitment.IncidentEligibilityEndsAtUnix != offer.CoverageTerms.CoverageEndsAtUnix {
		return errors.New("coverage activation end commitment is substituted")
	}
	stage := evidence.StageActionAdmissionEvidence
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "coverage_activation")
	if err != nil {
		return err
	}
	requestBytes, err := codec.Marshal(CoverageActivationActionBodyV1{SchemaVersion: 1, UnderlyingAgreementBody: evidence.UnderlyingAgreementBody,
		UnderlyingAuthorizationEvidenceSet: evidence.UnderlyingAuthorizationEvidenceSet, AuthorizedAcceptanceReceipt: acceptance,
		PrerequisiteEvidenceSet: evidence.PrerequisiteEvidenceSet, TargetCoverageEndCommitment: evidence.CoverageEndCommitment,
		TransitionEvidenceProjection: evidence.TransitionEvidenceProjection, ExpectedCoverageRevision: body.PriorCoverageRevision,
		TargetCoverageRevision: body.ActivatedCoverageRevision, ExpectedClaimFilingState: body.PriorClaimFilingState,
		TargetClaimFilingState: body.ActivatedClaimFilingState, ExpectedClaimFilingStateRevision: body.PriorClaimFilingStateRevision,
		TargetClaimFilingStateRevision: body.ActivatedClaimFilingStateRevision})
	if err != nil || !bytes.Equal(requestBytes, stage.CanonicalRequest) || stage.Body.CanonicalRequestDigest != body.ExactRequestDigest ||
		stage.AuthorizedAction.StableActionID != body.StableActionID || stage.AuthorizedAction.ExactRequestDigest != body.ExactRequestDigest ||
		stage.AuthorizedAction.WriterGeneration != body.WriterGeneration || stage.AuthorizedAction.WriterFenceDigest != body.WriterFenceDigest {
		return errors.New("coverage activation stage evidence is invalid")
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(agreementDigest), "obligation_id": agentcommerce.ID(body.CoverageObligationID),
		"expected_state_revision": agentcommerce.U64(body.PriorCoverageRevision), "target_state": agentcommerce.State("active"),
		"evidence_set_digest": agentcommerce.Digest32(projectionDigest)}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(stage, bound, requestBytes, fields,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	if body.AuthorityID != bound.ActionAuthorityID || body.SelectedAssuranceLevel != offer.CoverageTerms.SelectedAssuranceLevel ||
		body.SelectedClaimProfileDigest != offer.CoverageTerms.SelectedClaimProfileDigest ||
		body.CoverageStateDomainDigest != offer.CoverageTerms.CoverageStateDomainDigest ||
		body.CoverageEndsAtUnix != offer.CoverageTerms.CoverageEndsAtUnix {
		return errors.New("coverage activation substitutes Agreement-selected authority or profiles")
	}
	if offer.CoverageTerms.SelectedAssuranceLevel != AssuranceUnsecuredSigned {
		if err := verifyActivationCollateralPrerequisiteV1(evidence, offer.CoverageTerms, authorityResolver, fenceResolver,
			collateralFinalityVerifier, now); err != nil {
			return err
		}
	}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-activation-evidence-body.v1", body)
	return ValidateAuthorizationSet(evidence.Authorizations, "activation-evidence", bodyDigest,
		"tos.service.agent-guarantor-activation-evidence-signature.v1", []string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}

func validateActivationEvidenceShape(evidence AuthorizedCoverageActivationEvidenceV1) error {
	body := evidence.Body
	prerequisiteDigest := ""
	var prerequisiteErr error
	if evidence.PrerequisiteEvidenceSet != nil {
		prerequisiteDigest, prerequisiteErr = CanonicalGuarantorEvidenceSetDigestV1(*evidence.PrerequisiteEvidenceSet)
	}
	eligibilityDigest, eligibilityErr := AuthorityAdmissionEligibilityProofSetDigestV1(evidence.AuthorityAdmissionEligibilityProofSet)
	if prerequisiteErr != nil || eligibilityErr != nil || body.SchemaVersion != 1 || !validID(body.AuthorityID) || !validDigest(body.CoverageAgreementBodyDigest) ||
		!validToken(body.CoverageObligationID, 128) || !validDigest(body.CoverageStateDomainDigest) || !validDigest(body.AuthorizationEvidenceSetDigest) ||
		!validDigest(body.UnderlyingAgreementBodyDigest) || !validDigest(body.UnderlyingAuthorizationEvidenceSetDigest) ||
		!validDigest(body.AuthorizedFirmOfferEnvelopeDigest) || !validDigest(body.AcceptanceReceiptDigest) || !validDigest(body.ExposureReceiptDigest) ||
		body.PrerequisiteEvidenceSetDigest != prerequisiteDigest || !validDigest(body.SelectedClaimProfileDigest) ||
		!validDigest(body.TransitionEvidenceProjectionDigest) || !validDigest(body.AuthorizedActionDigest) || !validDigest(body.StableActionID) ||
		!validDigest(body.ExactRequestDigest) || body.WriterGeneration == 0 || !validDigest(body.WriterFenceDigest) ||
		body.PriorCoverageRevision == 0 || body.ActivatedCoverageRevision != body.PriorCoverageRevision+1 ||
		body.PriorClaimFilingState != "not_open" || body.ActivatedClaimFilingState != "open" || body.PriorClaimFilingStateRevision == 0 ||
		body.ActivatedClaimFilingStateRevision != body.PriorClaimFilingStateRevision+1 || !validDigest(body.ResultingCoverageEndCommitmentDigest) ||
		body.ActivatedAtUnix == 0 || body.CoverageEndsAtUnix <= body.ActivatedAtUnix || body.AuthorityAdmissionEligibilityProofSetDigest != eligibilityDigest ||
		len(evidence.Authorizations) == 0 {
		return errors.New("coverage activation evidence shape is invalid")
	}
	return nil
}

func verifyActivationCollateralPrerequisiteV1(evidence AuthorizedCoverageActivationEvidenceV1, terms CoverageTermsV1,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver,
	finalityVerifier CollateralAdapterFinalityVerifier, now time.Time) error {
	if terms.CollateralTerms == nil || evidence.PrerequisiteEvidenceSet == nil {
		return errors.New("collateralized coverage lacks finalized lock evidence")
	}
	set := *evidence.PrerequisiteEvidenceSet
	if set.Purpose != "coverage-activation-collateral" || set.ContextDigest != evidence.Body.CoverageAgreementBodyDigest {
		return errors.New("collateral activation prerequisite has a substituted purpose or context")
	}
	collateralFound := false
	controlFound := false
	independenceFound := terms.SelectedAssuranceLevel != AssuranceIndependentlyEnforced
	for _, item := range set.Items {
		if item.Representation != "inline" || len(item.CanonicalEnvelopeBytes) == 0 {
			continue
		}
		var collateral AuthorizedCollateralEvidenceV1
		if codec.Unmarshal(item.CanonicalEnvelopeBytes, &collateral) == nil {
			digest, err := CollateralEvidenceDigestV1(collateral)
			if err == nil && digest == item.EvidenceEnvelopeDigest &&
				VerifyCollateralEvidenceV1(collateral, terms, authorityResolver, fenceResolver, now, finalityVerifier, false) == nil &&
				collateral.Body.CoverageAgreementBodyDigest == evidence.Body.CoverageAgreementBodyDigest &&
				collateral.Body.CollateralObligationID == terms.CollateralObligationID &&
				(collateral.Body.TransitionKind == "lock" || collateral.Body.TransitionKind == "encumber") &&
				(collateral.ResultingPositionState.Status == CollateralLocked || collateral.ResultingPositionState.Status == CollateralEncumbered) &&
				collateral.ResultingPositionState.RemainingAmount.Asset == terms.CoverageAsset {
				remaining, okRemaining := new(big.Int).SetString(collateral.ResultingPositionState.RemainingAmount.AmountAtomic, 10)
				required, okRequired := new(big.Int).SetString(terms.CollateralTerms.Amount.AmountAtomic, 10)
				if okRemaining && okRequired && remaining.Cmp(required) >= 0 {
					if terms.SelectedAssuranceLevel != AssuranceIndependentlyEnforced {
						collateralFound = true
					} else {
						binding := collateral.CollateralTransitionActionBody.TransitionBinding.AuthorizationBinding
						collateralFound = terms.CollateralTerms.IndependentExecutionProfile != nil &&
							binding.AuthorizationProfile == *terms.CollateralTerms.IndependentExecutionProfile &&
							equalStrings(binding.AuthorizationSubjects, terms.CollateralTerms.IndependentExecutionAuthoritySubjects) &&
							binding.AuthorizationQuorumRule == terms.CollateralTerms.IndependentExecutionQuorumRule
					}
				}
			}
		}
		var control AuthorizedCollateralControlEvidenceV1
		if codec.Unmarshal(item.CanonicalEnvelopeBytes, &control) == nil {
			digest, err := CollateralControlEvidenceDigestV1(control)
			if err == nil && digest == item.EvidenceEnvelopeDigest &&
				VerifyCollateralControlEvidenceV1(control, evidence.Body.CoverageAgreementBodyDigest,
					terms.CollateralObligationID, terms.SelectedCollateralProfileDigest,
					terms.CollateralTerms.CollateralControlDisclosure, terms.LifecycleAuthorizationProfile,
					[]string{terms.GuarantorAgentID}, "all", authorityResolver, now) == nil {
				controlFound = true
			}
		}
		if terms.SelectedAssuranceLevel == AssuranceIndependentlyEnforced {
			var independent AuthorizedGuarantorOperationalIndependenceEvidenceV1
			if codec.Unmarshal(item.CanonicalEnvelopeBytes, &independent) == nil {
				digest, err := OperationalIndependenceEvidenceDigestV1(independent)
				if err == nil && digest == item.EvidenceEnvelopeDigest &&
					VerifyOperationalIndependenceEvidenceV1(independent, terms,
						evidence.Body.CoverageAgreementBodyDigest, authorityResolver, now) == nil {
					independenceFound = true
				}
			}
		}
	}
	if !collateralFound || !controlFound || !independenceFound {
		return errors.New("collateral activation lacks exact allocation, control, or operational-independence proof")
	}
	return nil
}
