package agentguarantor

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	CancellationPolicyDomain  = "tos.service.agent-guarantor-cancellation-policy.v1"
	CancellationRequestDomain = "tos.service.agent-guarantor-cancellation-request-envelope.v1"
	CancellationReceiptDomain = "tos.service.agent-guarantor-cancellation-receipt-envelope.v1"
)

type CoverageCancellationPolicyBranchV1 struct {
	CancellationBranch             string        `json:"cancellation_branch"`
	PermittedRequesterSubjects     []string      `json:"permitted_requester_subjects"`
	RequestAuthorizationProfile    ProfileRefV1  `json:"request_authorization_profile"`
	RequestAuthorizationQuorumRule string        `json:"request_authorization_quorum_rule"`
	EvidenceProfile                *ProfileRefV1 `json:"evidence_profile,omitempty"`
	EarliestAfterActivationSeconds uint64        `json:"earliest_after_activation_seconds"`
	MaximumAdmissionDelaySeconds   uint64        `json:"maximum_admission_delay_seconds"`
}

type CoverageCancellationPolicyV1 struct {
	SchemaVersion uint16                               `json:"schema_version"`
	PolicyID      string                               `json:"policy_id"`
	Branches      []CoverageCancellationPolicyBranchV1 `json:"branches"`
}

type CoverageCancellationRequestBodyV1 struct {
	SchemaVersion                 uint16 `json:"schema_version"`
	CoverageAgreementBodyDigest   string `json:"coverage_agreement_body_digest"`
	CoverageObligationID          string `json:"coverage_obligation_id"`
	CancellationPolicyDigest      string `json:"cancellation_policy_digest"`
	CancellationBranch            string `json:"cancellation_branch"`
	RequesterSubject              string `json:"requester_subject"`
	EffectiveNotBeforeUnix        uint64 `json:"effective_not_before_unix"`
	EffectiveNotAfterUnix         uint64 `json:"effective_not_after_unix"`
	CancellationEvidenceSetDigest string `json:"cancellation_evidence_set_digest,omitempty"`
	CreatedAtUnix                 uint64 `json:"created_at_unix"`
	ExpiresAtUnix                 uint64 `json:"expires_at_unix"`
}

type AuthorizedCoverageCancellationRequestV1 struct {
	Body                    CoverageCancellationRequestBodyV1       `json:"body"`
	CoverageAgreementBody   agentcommerce.AgentAgreementBody        `json:"coverage_agreement_body"`
	CancellationEvidenceSet *CanonicalGuarantorEvidenceSetV1        `json:"cancellation_evidence_set,omitempty"`
	Authorizations          []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type CoverageCancellationReceiptBodyV1 struct {
	SchemaVersion                               uint16 `json:"schema_version"`
	AuthorityID                                 string `json:"authority_id"`
	CoverageAgreementBodyDigest                 string `json:"coverage_agreement_body_digest"`
	CoverageObligationID                        string `json:"coverage_obligation_id"`
	CoverageStateDomainDigest                   string `json:"coverage_state_domain_digest"`
	PriorCoverageEndCommitmentDigest            string `json:"prior_coverage_end_commitment_digest"`
	AuthorizedCancellationRequestDigest         string `json:"authorized_cancellation_request_digest"`
	CancellationPolicyDigest                    string `json:"cancellation_policy_digest"`
	CancellationBranch                          string `json:"cancellation_branch"`
	EffectiveAtUnix                             uint64 `json:"effective_at_unix"`
	IncidentEligibilityEndsAtUnix               uint64 `json:"incident_eligibility_ends_at_unix"`
	ClaimFilingEndsAtUnix                       uint64 `json:"claim_filing_ends_at_unix"`
	TransitionEvidenceProjectionDigest          string `json:"transition_evidence_projection_digest"`
	AuthorizedActionDigest                      string `json:"authorized_action_digest"`
	StableActionID                              string `json:"stable_action_id"`
	ExactRequestDigest                          string `json:"exact_request_digest"`
	WriterGeneration                            uint64 `json:"writer_generation"`
	WriterFenceDigest                           string `json:"writer_fence_digest"`
	PriorCoverageRevision                       uint64 `json:"prior_coverage_revision"`
	EndedCoverageRevision                       uint64 `json:"ended_coverage_revision"`
	State                                       string `json:"state"`
	AdmittedAtUnix                              uint64 `json:"admitted_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedCoverageCancellationReceiptV1 struct {
	Body                                  CoverageCancellationReceiptBodyV1       `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	AuthorizedCancellationRequest         AuthorizedCoverageCancellationRequestV1 `json:"authorized_cancellation_request"`
	TransitionEvidenceProjection          TransitionEvidenceProjectionV1          `json:"transition_evidence_projection"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1 `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

func CoverageCancellationPolicyDigestV1(policy CoverageCancellationPolicyV1) (string, error) {
	if err := ValidateCoverageCancellationPolicyV1(policy); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(CancellationPolicyDomain, policy)
}

func ValidateCoverageCancellationPolicyV1(policy CoverageCancellationPolicyV1) error {
	if policy.SchemaVersion != 1 || !validID(policy.PolicyID) || len(policy.Branches) == 0 || len(policy.Branches) > 32 {
		return errors.New("Guarantor cancellation policy is invalid")
	}
	prior := ""
	for _, branch := range policy.Branches {
		if !validToken(branch.CancellationBranch, 128) || branch.CancellationBranch <= prior ||
			!sortedUnique(branch.PermittedRequesterSubjects, 64, validID) ||
			agentcommerce.ValidateProfileRefV1(branch.RequestAuthorizationProfile) != nil ||
			QuorumThresholdMustFailV1(branch.RequestAuthorizationQuorumRule, branch.PermittedRequesterSubjects) ||
			branch.MaximumAdmissionDelaySeconds == 0 ||
			branch.MaximumAdmissionDelaySeconds > uint64((30*24*time.Hour)/time.Second) {
			return errors.New("Guarantor cancellation policy branch is invalid or unsorted")
		}
		if branch.EvidenceProfile != nil && agentcommerce.ValidateProfileRefV1(*branch.EvidenceProfile) != nil {
			return errors.New("Guarantor cancellation evidence profile is invalid")
		}
		prior = branch.CancellationBranch
	}
	return nil
}

func CanonicalGuarantorEvidenceSetDigestV1(set CanonicalGuarantorEvidenceSetV1) (string, error) {
	if err := ValidateCanonicalGuarantorEvidenceSetV1(set); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-evidence-set.v1", set)
}

// GuarantorMediaTypePrefixV1 begins every media type this profile defines.
const GuarantorMediaTypePrefixV1 = "application/vnd.tos.service.agent-guarantor-"

// IsGuarantorMediaTypeV1 reports whether contentType names a Guarantor object.
func IsGuarantorMediaTypeV1(contentType string) bool {
	return strings.HasPrefix(contentType, GuarantorMediaTypePrefixV1)
}

// ValidateCanonicalGuarantorEvidenceSetV1 validates a canonical evidence set.
// Evidence whose media type is a Guarantor object is descriptor-only: an
// inline copy would repeat, as base64 text, an object already carried or
// referenced elsewhere and is what pushes nested envelopes past the
// complete-object ceiling. Inline is kept for external (non-Guarantor)
// evidence only.
func ValidateCanonicalGuarantorEvidenceSetV1(set CanonicalGuarantorEvidenceSetV1) error {
	if set.SchemaVersion != 1 || !validToken(set.Purpose, 128) || !validDigest(set.ContextDigest) ||
		len(set.Items) == 0 || len(set.Items) > MaxEvidenceItems {
		return errors.New("Guarantor evidence set is invalid")
	}
	var prior []byte
	for _, item := range set.Items {
		if !validToken(item.ContentType, 128) || !validDigest(item.EvidenceProfileDigest) ||
			!validDigest(item.EvidenceEnvelopeDigest) || (item.Representation != "inline" && item.Representation != "content_addressed") {
			return errors.New("Guarantor evidence item is invalid")
		}
		if item.Representation == "inline" {
			if IsGuarantorMediaTypeV1(item.ContentType) {
				return errors.New("Guarantor evidence of a Guarantor media type must be content addressed")
			}
			if len(item.CanonicalEnvelopeBytes) == 0 || len(item.CanonicalEnvelopeBytes) > MaxCanonicalObjectBytes || item.ImmutableDescriptor != nil {
				return errors.New("inline Guarantor evidence representation is invalid")
			}
		} else if len(item.CanonicalEnvelopeBytes) != 0 || item.ImmutableDescriptor == nil ||
			!validToken(item.ImmutableDescriptor.ContentType, 128) || !validDigest(item.ImmutableDescriptor.ContentDigest) ||
			item.ImmutableDescriptor.ContentSize == 0 || item.ImmutableDescriptor.ContentSize > MaxCanonicalObjectBytes ||
			!validDigest(item.ImmutableDescriptor.RetrievalPolicyDigest) {
			return errors.New("content-addressed Guarantor evidence representation is invalid")
		}
		encoded, err := guarantorCodec.Marshal(item)
		if err != nil || prior != nil && bytes.Compare(prior, encoded) >= 0 {
			return errors.New("Guarantor evidence items are not a canonical set")
		}
		prior = encoded
	}
	return nil
}

func CoverageCancellationRequestDigestV1(request AuthorizedCoverageCancellationRequestV1) (string, error) {
	if err := validateCoverageCancellationRequestShapeV1(request); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(CancellationRequestDomain, request)
}

func VerifyCoverageCancellationRequestV1(request AuthorizedCoverageCancellationRequestV1,
	policy CoverageCancellationPolicyV1, resolver AuthorityKeyResolver, now time.Time) error {
	if validateCoverageCancellationRequestShapeV1(request) != nil || ValidateCoverageCancellationPolicyV1(policy) != nil || resolver == nil {
		return errors.New("Guarantor cancellation request or policy is invalid")
	}
	policyDigest, _ := CoverageCancellationPolicyDigestV1(policy)
	agreementDigest, _ := agentcommerce.AgreementBodyDigest(request.CoverageAgreementBody)
	body := request.Body
	if body.CancellationPolicyDigest != policyDigest || body.CoverageAgreementBodyDigest != agreementDigest ||
		uint64(now.UTC().Unix()) >= body.ExpiresAtUnix {
		return errors.New("Guarantor cancellation request binding is invalid")
	}
	var selected *CoverageCancellationPolicyBranchV1
	for index := range policy.Branches {
		if policy.Branches[index].CancellationBranch == body.CancellationBranch {
			selected = &policy.Branches[index]
		}
	}
	if selected == nil || !containsString(selected.PermittedRequesterSubjects, body.RequesterSubject) {
		return errors.New("Guarantor cancellation requester is not permitted")
	}
	if selected.EvidenceProfile == nil {
		if request.CancellationEvidenceSet != nil || body.CancellationEvidenceSetDigest != "" {
			return errors.New("Guarantor cancellation carries forbidden branch evidence")
		}
	} else {
		if request.CancellationEvidenceSet == nil || request.CancellationEvidenceSet.Purpose != "coverage-cancellation" ||
			request.CancellationEvidenceSet.ContextDigest != agreementDigest {
			return errors.New("Guarantor cancellation branch evidence is absent")
		}
		digest, err := CanonicalGuarantorEvidenceSetDigestV1(*request.CancellationEvidenceSet)
		if err != nil || digest != body.CancellationEvidenceSetDigest {
			return errors.New("Guarantor cancellation evidence digest differs")
		}
		for _, item := range request.CancellationEvidenceSet.Items {
			if item.EvidenceProfileDigest != selected.EvidenceProfile.ProfileDigest {
				return errors.New("Guarantor cancellation evidence profile was substituted")
			}
		}
	}
	for _, authorization := range request.Authorizations {
		if !containsString(selected.PermittedRequesterSubjects, authorization.AuthoritySubject) ||
			authorization.ProfileURI != selected.RequestAuthorizationProfile.ProfileURI ||
			authorization.ProfileVersion != selected.RequestAuthorizationProfile.ProfileVersion ||
			authorization.ProfileDigest != selected.RequestAuthorizationProfile.ProfileDigest {
			return errors.New("Guarantor cancellation authorization profile was substituted")
		}
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-cancellation-request-body.v1", body)
	return ValidateAuthorizationQuorumSet(request.Authorizations, "coverage-cancellation-request", bodyDigest,
		"tos.service.agent-guarantor-cancellation-request-signature.v1", selected.PermittedRequesterSubjects,
		selected.RequestAuthorizationQuorumRule, resolver, now)
}

func validateCoverageCancellationRequestShapeV1(request AuthorizedCoverageCancellationRequestV1) error {
	body := request.Body
	agreementDigest, agreementErr := agentcommerce.AgreementBodyDigest(request.CoverageAgreementBody)
	evidenceDigest := ""
	if request.CancellationEvidenceSet != nil {
		evidenceDigest, _ = CanonicalGuarantorEvidenceSetDigestV1(*request.CancellationEvidenceSet)
	}
	if agreementErr != nil || body.SchemaVersion != 1 || body.CoverageAgreementBodyDigest != agreementDigest ||
		!validToken(body.CoverageObligationID, 128) || !validDigest(body.CancellationPolicyDigest) ||
		!validToken(body.CancellationBranch, 128) || !validID(body.RequesterSubject) ||
		body.EffectiveNotBeforeUnix == 0 || body.EffectiveNotAfterUnix < body.EffectiveNotBeforeUnix ||
		body.CreatedAtUnix == 0 || body.ExpiresAtUnix <= body.CreatedAtUnix || body.EffectiveNotAfterUnix > body.ExpiresAtUnix ||
		body.CancellationEvidenceSetDigest != evidenceDigest || len(request.Authorizations) == 0 ||
		len(request.Authorizations) > MaxAuthorizations {
		return errors.New("Guarantor cancellation request is invalid")
	}
	return nil
}

func CoverageCancellationReceiptDigestV1(receipt AuthorizedCoverageCancellationReceiptV1) (string, error) {
	if err := validateCoverageCancellationReceiptShapeV1(receipt); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(CancellationReceiptDomain, receipt)
}

func validateCoverageCancellationReceiptShapeV1(receipt AuthorizedCoverageCancellationReceiptV1) error {
	body := receipt.Body
	requestDigest, requestErr := CoverageCancellationRequestDigestV1(receipt.AuthorizedCancellationRequest)
	projectionDigest, projectionErr := TransitionEvidenceProjectionDigestV1(receipt.TransitionEvidenceProjection)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if requestErr != nil || projectionErr != nil || proofErr != nil || body.SchemaVersion != 1 ||
		!validID(body.AuthorityID) || body.CoverageAgreementBodyDigest != receipt.AuthorizedCancellationRequest.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != receipt.AuthorizedCancellationRequest.Body.CoverageObligationID ||
		!validDigest(body.CoverageStateDomainDigest) || !validDigest(body.PriorCoverageEndCommitmentDigest) ||
		body.AuthorizedCancellationRequestDigest != requestDigest ||
		body.CancellationPolicyDigest != receipt.AuthorizedCancellationRequest.Body.CancellationPolicyDigest ||
		body.CancellationBranch != receipt.AuthorizedCancellationRequest.Body.CancellationBranch ||
		body.EffectiveAtUnix == 0 || body.IncidentEligibilityEndsAtUnix != body.EffectiveAtUnix ||
		body.ClaimFilingEndsAtUnix < body.EffectiveAtUnix || body.TransitionEvidenceProjectionDigest != projectionDigest ||
		!validDigest(body.AuthorizedActionDigest) || !validDigest(body.StableActionID) || !validDigest(body.ExactRequestDigest) ||
		body.WriterGeneration == 0 || !validDigest(body.WriterFenceDigest) || body.PriorCoverageRevision == 0 ||
		body.EndedCoverageRevision != body.PriorCoverageRevision+1 || body.State != "coverage_ended" ||
		body.AdmittedAtUnix != body.EffectiveAtUnix || body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest ||
		len(receipt.Authorizations) == 0 || len(receipt.Authorizations) > MaxAuthorizations {
		return errors.New("Guarantor cancellation receipt shape is invalid")
	}
	return nil
}

// VerifyCoverageCancellationReceiptV1 independently reconstructs every input
// to the cancellation mutation.  In particular, it does not treat a signed
// receipt as sufficient evidence that the Agreement-selected cancellation
// policy, writer fence, or compare-and-swap transition was respected.
func VerifyCoverageCancellationReceiptV1(receipt AuthorizedCoverageCancellationReceiptV1,
	activation AuthorizedCoverageActivationEvidenceV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if err := validateCoverageCancellationReceiptShapeV1(receipt); err != nil {
		return err
	}
	offer, err := extractFirmOfferFromAcceptanceV1(activation.AuthorizedAcceptanceReceipt)
	if err != nil {
		return err
	}
	terms := offer.CoverageTerms
	if err := enforceCanonicalSize(receipt, terms.ClaimClosureCapacity.MaximumCancellationReceiptEnvelopeBytes,
		"coverage cancellation receipt"); err != nil {
		return err
	}
	if err := VerifyCoverageActivationEvidenceV1(activation, offer, agreementVerifier, authorityResolver,
		fenceResolver, collateralFinalityVerifierFromResolverV1(authorityResolver), now); err != nil {
		return err
	}
	body := receipt.Body
	admittedAt := time.Unix(int64(body.AdmittedAtUnix), 0).UTC()
	if admittedAt.After(now.UTC().Add(5 * time.Minute)) {
		return errors.New("Guarantor cancellation admission time is in the future")
	}
	if err := VerifyCoverageCancellationRequestV1(receipt.AuthorizedCancellationRequest,
		terms.CancellationPolicy, authorityResolver, admittedAt); err != nil {
		return err
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "coverage_cancellation")
	if err != nil {
		return err
	}
	var branch *CoverageCancellationPolicyBranchV1
	for index := range terms.CancellationPolicy.Branches {
		if terms.CancellationPolicy.Branches[index].CancellationBranch == body.CancellationBranch {
			branch = &terms.CancellationPolicy.Branches[index]
			break
		}
	}
	if branch == nil {
		return errors.New("Guarantor cancellation policy branch is absent")
	}
	agreementDigest, _ := agentcommerce.AgreementBodyDigest(receipt.AuthorizedCancellationRequest.CoverageAgreementBody)
	activationDigest, _ := CoverageActivationEvidenceDigestV1(activation)
	requestDigest, _ := CoverageCancellationRequestDigestV1(receipt.AuthorizedCancellationRequest)
	priorCommitment := activation.CoverageEndCommitment
	priorCommitmentDigest, _ := CoverageEndCommitmentDigestV1(priorCommitment)
	policyDigest, _ := CoverageCancellationPolicyDigestV1(terms.CancellationPolicy)
	projectionDigest, _ := TransitionEvidenceProjectionDigestV1(receipt.TransitionEvidenceProjection)
	if body.AuthorityID != bound.ActionAuthorityID || agreementDigest != offer.Body.CoverageAgreementBodyDigest ||
		body.CoverageAgreementBodyDigest != agreementDigest || body.CoverageObligationID != offer.Body.CoverageObligationID ||
		body.CoverageStateDomainDigest != terms.CoverageStateDomainDigest || body.PriorCoverageEndCommitmentDigest != priorCommitmentDigest ||
		body.AuthorizedCancellationRequestDigest != requestDigest || body.CancellationPolicyDigest != policyDigest ||
		body.PriorCoverageRevision != activation.Body.ActivatedCoverageRevision ||
		priorCommitment.EndBranch != "scheduled" || priorCommitment.IncidentEligibilityEndsAtUnix != terms.CoverageEndsAtUnix ||
		body.ClaimFilingEndsAtUnix != terms.ClaimFilingEndsAtUnix || body.EffectiveAtUnix >= terms.CoverageEndsAtUnix {
		return errors.New("Guarantor cancellation lineage or Agreement-selected policy is substituted")
	}
	requestBody := receipt.AuthorizedCancellationRequest.Body
	earliest, overflowEarliest := addUint64Checked(activation.Body.ActivatedAtUnix, branch.EarliestAfterActivationSeconds)
	latest, overflowLatest := addUint64Checked(requestBody.CreatedAtUnix, branch.MaximumAdmissionDelaySeconds)
	if overflowEarliest || overflowLatest || requestBody.CreatedAtUnix < activation.Body.ActivatedAtUnix ||
		body.EffectiveAtUnix < maximumUint64(requestBody.CreatedAtUnix, earliest, requestBody.EffectiveNotBeforeUnix) ||
		body.EffectiveAtUnix > minimumUint64(latest, requestBody.EffectiveNotAfterUnix, requestBody.ExpiresAtUnix) {
		return errors.New("Guarantor cancellation timing predicate failed")
	}
	expectedProjection := TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-cancellation",
		CoverageAgreementBodyDigest: agreementDigest, ObligationID: body.CoverageObligationID, TargetState: "coverage_ended",
		EvidenceDigests: []TransitionEvidenceDigestRefV1{
			{EvidenceRole: "activation_evidence", DigestKind: "authorized_envelope", ObjectDigest: activationDigest},
			{EvidenceRole: "cancellation_request", DigestKind: "authorized_envelope", ObjectDigest: requestDigest},
			{EvidenceRole: "prior_coverage_end_commitment", DigestKind: "canonical_object", ObjectDigest: priorCommitmentDigest},
		}}
	sortTransitionEvidenceRefsV1(expectedProjection.EvidenceDigests)
	if !equalCanonical(expectedProjection, receipt.TransitionEvidenceProjection) {
		return errors.New("Guarantor cancellation transition evidence is incomplete or substituted")
	}
	actionRequest := CoverageCancellationActionBodyV1{SchemaVersion: 1,
		AuthorizedCancellationRequest: receipt.AuthorizedCancellationRequest, ExpectedCoverageEndCommitment: priorCommitment,
		TransitionEvidenceProjection: receipt.TransitionEvidenceProjection, ExpectedCoverageRevision: body.PriorCoverageRevision,
		TargetCoverageRevision: body.EndedCoverageRevision, TargetCoverageState: "coverage_ended"}
	requestBytes, err := guarantorCodec.Marshal(actionRequest)
	if err != nil || !bytes.Equal(requestBytes, receipt.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("Guarantor cancellation action request is noncanonical")
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(bound.ActionOwnerID),
		"agent_id": agentcommerce.ID(bound.ActionAgentID), "agreement_body_digest": agentcommerce.Digest32(agreementDigest),
		"obligation_id": agentcommerce.ID(body.CoverageObligationID), "expected_state_revision": agentcommerce.U64(body.PriorCoverageRevision),
		"target_state": agentcommerce.State("coverage_ended"), "evidence_set_digest": agentcommerce.Digest32(projectionDigest)}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, requestBytes,
		fields, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	actionDigest, _ := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	proofDigest, _ := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if body.TransitionEvidenceProjectionDigest != projectionDigest || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != receipt.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest ||
		receipt.AuthorityAdmissionEligibilityProofSet.AdmittedActionDigest != actionDigest {
		return errors.New("Guarantor cancellation action or authority proof is substituted")
	}
	stageResolution := receipt.StageActionAdmissionEvidence.ActionResolution
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-cancellation-receipt-body.v1", body)
	if stageResolution.SinkReference != bodyDigest || !containsString(stageResolution.EvidenceRefs, bodyDigest) {
		return errors.New("Guarantor cancellation terminal result is substituted")
	}
	return ValidateAuthorizationQuorumSet(receipt.Authorizations, "coverage-cancellation-receipt", bodyDigest,
		"tos.service.agent-guarantor-cancellation-receipt-signature.v1", []string{terms.GuarantorAgentID}, "all",
		authorityResolver, now)
}

func addUint64Checked(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result < left
}

func maximumUint64(values ...uint64) uint64 {
	var result uint64
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func minimumUint64(values ...uint64) uint64 {
	result := ^uint64(0)
	for _, value := range values {
		if value < result {
			result = value
		}
	}
	return result
}

func sortTransitionEvidenceRefsV1(refs []TransitionEvidenceDigestRefV1) {
	sort.Slice(refs, func(i, j int) bool {
		left, _ := guarantorCodec.Marshal(refs[i])
		right, _ := guarantorCodec.Marshal(refs[j])
		return bytes.Compare(left, right) < 0
	})
}
