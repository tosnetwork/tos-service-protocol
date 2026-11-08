package agentguarantor

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func validateEligibilityProofSetAgainstV1(set AuthorityAdmissionEligibilityProofSetV1, actionDigest,
	inputEnvelopeDigest string, subjects []string, objectKind, bodyDigest, scopeDigest string,
	profile agentcommerce.ProfileRefV1, domainID string, sequence, admittedAtUnix uint64) error {
	if err := ValidateAuthorityAdmissionEligibilityProofSetV1(set); err != nil || set.AdmittedActionDigest != actionDigest ||
		set.AdmissionDomainID != domainID || set.AdmissionSequence != sequence || set.AdmissionTimeUnix != admittedAtUnix ||
		len(set.Entries) != len(subjects) || !sortedUnique(subjects, MaxAuthorizations, validID) {
		return errors.New("Guarantor authority eligibility cut does not match the admission")
	}
	wanted := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		wanted[subject] = struct{}{}
	}
	for _, proof := range set.Entries {
		if _, found := wanted[proof.AuthoritySubject]; !found || proof.InputAuthorizedEnvelopeDigest != inputEnvelopeDigest ||
			proof.AuthorizedObjectKind != objectKind || proof.AuthorizedBodyDigest != bodyDigest ||
			proof.RequiredScopeDigest != scopeDigest || proof.AuthorityResolverProfile != profile {
			return errors.New("Guarantor authority eligibility proof is substituted")
		}
		delete(wanted, proof.AuthoritySubject)
	}
	if len(wanted) != 0 {
		return errors.New("Guarantor authority eligibility proof is incomplete")
	}
	return nil
}

func VerifyClaimSubmissionIngressReceiptV1(receipt AuthorizedClaimSubmissionIngressReceiptV1, terms CoverageTermsV1,
	bound GuarantorStageActionAuthorityV1, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	body, claim := receipt.Body, receipt.AuthorizedClaim
	claimDigest, claimErr := ClaimEnvelopeDigest(claim)
	claimBodyDigest, bodyErr := ClaimBodyDigest(claim.Body)
	stateDomain, stateErr := ClaimIngressStateDomainDigestV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID)
	logClaimID, ingressKind := claim.Body.ClaimID, "revision"
	if claim.Body.ClaimRevision == 1 {
		logClaimID, ingressKind = "", "initial"
	}
	logID, logErr := ClaimIngressLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID, logClaimID)
	initialRoot, rootErr := InitialClaimLogRootV1(ClaimIngressLogRootDomainV1, logID)
	if body.ClaimIngressSequence > 1 {
		initialRoot = body.PriorClaimIngressLogRoot
	}
	admittedRoot, advanceErr := AdvanceClaimLogRootV1(ClaimIngressLogRootDomainV1, logID, initialRoot,
		body.ClaimIngressSequence, ClaimIngressLogLeafV1{StableActionID: body.StableActionID,
			ExactRequestDigest: body.ExactRequestDigest, ReceivedAtUnix: body.ReceivedAtUnix})
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if claimErr != nil || bodyErr != nil || stateErr != nil || logErr != nil || rootErr != nil || advanceErr != nil ||
		actionErr != nil || proofErr != nil || body.SchemaVersion != 1 || body.AuthorityID != bound.ActionAuthorityID ||
		body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != claim.Body.CoverageObligationID || body.ClaimID != claim.Body.ClaimID ||
		body.ClaimRevision != claim.Body.ClaimRevision || body.IngressKind != ingressKind || body.ClaimBodyDigest != claimBodyDigest ||
		body.AuthorizedClaimEnvelopeDigest != claimDigest || body.IngressStateDomainDigest != stateDomain ||
		bound.AdmissionStateDomainDigest != stateDomain || body.ClaimIngressLogID != logID || body.ClaimIngressSequence == 0 ||
		body.PriorClaimIngressLogRoot != initialRoot || body.AdmittedClaimIngressLogRoot != admittedRoot ||
		body.IngressSlotRevision != 1 || body.State != "received" || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != receipt.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		body.ReceivedAtUnix < claim.Body.CreatedAtUnix || body.ReceivedAtUnix > claim.Body.ExpiresAtUnix ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest {
		return errors.New("Guarantor claim ingress receipt binding is invalid")
	}
	if err := VerifyClaim(claim, terms, body.CoverageAgreementBodyDigest, body.CoverageObligationID,
		authorityResolver, time.Unix(int64(body.ReceivedAtUnix), 0).UTC()); err != nil {
		return err
	}
	requestBody := ClaimSubmissionIngressActionBodyV1{SchemaVersion: 1, AuthorizedClaim: claim, TargetIngressState: "received"}
	request, err := guarantorCodec.Marshal(requestBody)
	if err != nil {
		return err
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(bound.ActionOwnerID),
		"agent_id": agentcommerce.ID(bound.ActionAgentID), "agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest),
		"obligation_id": agentcommerce.ID(body.CoverageObligationID), "claim_id": agentcommerce.ID(body.ClaimID),
		"claim_revision": agentcommerce.U64(body.ClaimRevision)}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, request, fields,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	if receipt.StageActionAdmissionEvidence.ActionResolution.SinkReference != claimDigest ||
		!containsString(receipt.StageActionAdmissionEvidence.ActionResolution.EvidenceRefs, claimDigest) {
		return errors.New("Guarantor claim ingress terminal result is substituted")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest, claimDigest,
		terms.ClaimIngressAuthoritySubjects, "claim-ingress-receipt", claimDigest, terms.ClaimIngressProfile.ProfileDigest,
		terms.ClaimIngressProfile, logID, body.ClaimIngressSequence, body.ReceivedAtUnix); err != nil {
		return err
	}
	receiptBodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-ingress-receipt-body.v1", body)
	if err != nil {
		return err
	}
	return ValidateAuthorizationQuorumSet(receipt.Authorizations, "claim-ingress-receipt", receiptBodyDigest,
		"tos.service.agent-guarantor-claim-ingress-receipt-signature.v1", terms.ClaimIngressAuthoritySubjects,
		terms.ClaimIngressAuthorityQuorumRule, authorityResolver, now)
}

func extractFirmOfferFromAcceptanceV1(receipt AuthorizedCoverageAcceptanceReceiptV1) (AuthorizedFirmCoverageOfferV1, error) {
	var found *AuthorizedFirmCoverageOfferV1
	for _, wrapper := range receipt.AuthorizedAcceptanceRequest.AuthorizationEvidenceSet.Evidence {
		if wrapper.EvidenceProfileURI != FirmOfferAgreementEvidenceProfileURI {
			continue
		}
		var typed GuarantorFirmOfferAgreementEvidenceV1
		if found != nil || wrapper.EvidenceContentType != FirmOfferAgreementEvidenceContentType ||
			guarantorCodec.Unmarshal(wrapper.Evidence, &typed) != nil {
			return AuthorizedFirmCoverageOfferV1{}, errors.New("Guarantor acceptance has ambiguous firm-offer evidence")
		}
		candidate := typed.AuthorizedFirmOffer
		found = &candidate
	}
	if found == nil {
		return AuthorizedFirmCoverageOfferV1{}, errors.New("Guarantor acceptance has no firm-offer evidence")
	}
	return *found, nil
}

func VerifyClaimAdmissionReceiptV1(receipt AuthorizedClaimAdmissionReceiptV1, terms CoverageTermsV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	body, ingress := receipt.Body, receipt.AuthorizedClaimIngressReceipt
	claim := ingress.AuthorizedClaim
	stageName := "claim_revision_admission"
	if claim.Body.ClaimRevision == 1 {
		stageName = "initial_claim_admission"
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, stageName)
	if err != nil {
		return err
	}
	ingressBound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "claim_submission_ingress")
	if err != nil {
		return err
	}
	if err := VerifyClaimSubmissionIngressReceiptV1(ingress, terms, ingressBound, authorityResolver, fenceResolver, now); err != nil {
		return fmt.Errorf("Guarantor claim admission has an invalid ingress predecessor: %w", err)
	}
	ingressDigest, err := ClaimIngressReceiptDigestV1(ingress)
	if err != nil {
		return err
	}
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		return err
	}
	claimBodyDigest, err := ClaimBodyDigest(claim.Body)
	if err != nil {
		return err
	}
	activation := receipt.AuthorizedClaimIngressReceipt
	_ = activation // keep the sole claim path explicit; activation is carried by the action effect below.
	var actionBody ClaimSubmissionActionBodyV1
	if err := guarantorCodec.Unmarshal(receipt.StageActionAdmissionEvidence.CanonicalRequest, &actionBody); err != nil {
		return errors.New("Guarantor claim admission request cannot be decoded")
	}
	effect := actionBody.AuthorityInstanceEffect
	if !equalCanonical(effect.AuthorizedClaimIngressReceipt, ingress) ||
		!equalCanonical(receipt.AuthorityInstanceRecord, actionBody.AuthorityInstanceRecord) ||
		actionBody.SchemaVersion != 1 || actionBody.AuthorityInstanceID != receipt.AuthorityInstanceRecord.AuthorityInstanceID ||
		receipt.AuthorityInstanceRecord.AuthorityInstanceID != body.AuthorityInstanceID ||
		effect.ExpectedCoverageRevision != body.PriorCoverageRevision ||
		!equalCanonical(effect.ExpectedCoverageEndCommitment, receipt.CoverageEndCommitment) {
		return errors.New("Guarantor claim admission authority-instance effect is substituted")
	}
	offer, err := extractFirmOfferFromAcceptanceV1(effect.AuthorizedCoverageActivationEvidence.AuthorizedAcceptanceReceipt)
	if err != nil {
		return err
	}
	if err := VerifyCoverageActivationEvidenceV1(effect.AuthorizedCoverageActivationEvidence, offer, agreementVerifier,
		authorityResolver, fenceResolver, collateralFinalityVerifierFromResolverV1(authorityResolver), now); err != nil {
		return fmt.Errorf("Guarantor claim admission activation predecessor is invalid: %w", err)
	}
	effectBytes, err := guarantorCodec.Marshal(effect)
	if err != nil {
		return err
	}
	effectDigest, err := agentcommerce.DownstreamEffectDescriptorDigest(effectBytes)
	if err != nil {
		return err
	}
	action := receipt.StageActionAdmissionEvidence.AuthorizedAction
	allocation := agentcommerce.AuthorityInstanceAllocationRequest{OwnerID: action.OwnerID, AgentID: action.AgentID,
		PurposeKind: "conditional.claim.submit", MandateDigest: action.MandateDigest,
		ApprovalDigestOrZero: zeroDigestOrEmptyV1(action.ApprovalDigest), DownstreamEffectDescriptorDigest: effectDigest,
		PredecessorAuthorityInstanceID: zeroSHA256DigestV1()}
	allocationDigest, err := agentcommerce.AuthorityInstanceAllocationRequestDigest(allocation)
	if err != nil {
		return err
	}
	instanceID, err := agentcommerce.DeriveAuthorityInstanceID(allocation, receipt.AuthorityInstanceRecord.AllocationSequence)
	if err != nil || receipt.AuthorityInstanceRecord.RequestDigest != allocationDigest ||
		receipt.AuthorityInstanceRecord.AuthorityInstanceID != instanceID || body.AuthorityInstanceAllocationRequestDigest != allocationDigest {
		return errors.New("Guarantor claim authority instance is invalid")
	}
	request, err := guarantorCodec.Marshal(actionBody)
	if err != nil || !bytes.Equal(request, receipt.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("Guarantor claim admission request is noncanonical")
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(bound.ActionOwnerID),
		"agent_id": agentcommerce.ID(bound.ActionAgentID), "agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest),
		"obligation_id": agentcommerce.ID(body.CoverageObligationID), "authority_instance_id": agentcommerce.Digest32(instanceID),
		"claim_body_digest": agentcommerce.Digest32(claimBodyDigest)}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, request, fields,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	claimLogID, claimLogErr := ClaimAdmissionLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID)
	revisionLogID, revisionLogErr := ClaimRevisionLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID, body.ClaimID)
	if err != nil || proofErr != nil || endErr != nil || claimLogErr != nil || revisionLogErr != nil || body.SchemaVersion != 1 ||
		body.AuthorityID != bound.ActionAuthorityID || body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != claim.Body.CoverageObligationID || body.ClaimID != claim.Body.ClaimID ||
		body.AuthorizedClaimEnvelopeDigest != claimDigest || body.ClaimSubmissionIngressReceiptDigest != ingressDigest ||
		body.AuthorizedActionDigest != actionDigest || body.StableActionID != action.StableActionID ||
		body.ExactRequestDigest != action.ExactRequestDigest || body.PriorCoverageRevision == 0 ||
		body.AdmittedCoverageRevision != body.PriorCoverageRevision+1 || body.PriorCoverageEndCommitmentDigest != endDigest ||
		body.ResultingCoverageEndCommitmentDigest != endDigest || body.AdmittedClaimRevision != claim.Body.ClaimRevision ||
		body.ClaimAdmissionLogID != claimLogID || body.ClaimRevisionLogID != revisionLogID ||
		body.WriterGeneration != action.WriterGeneration || body.WriterFenceDigest != action.WriterFenceDigest ||
		body.AdmittedAtUnix == 0 || body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest {
		return errors.New("Guarantor claim admission receipt binding is invalid")
	}
	if body.AdmissionKind == "initial" {
		if claim.Body.ClaimRevision != 1 || body.PriorClaimRevision != 0 || body.ClaimAdmissionSequence == 0 ||
			body.ClaimRevisionAdmissionSequence != 1 || body.InitialClaimAdmissionReceiptDigest != "" ||
			body.PredecessorRevisionAdmissionReceiptDigest != "" {
			return errors.New("initial Guarantor claim admission lineage is invalid")
		}
		wantClaimRoot, rootErr := AdvanceClaimLogRootV1(ClaimAdmissionLogRootDomainV1, claimLogID,
			body.PriorClaimAdmissionLogRoot, body.ClaimAdmissionSequence, InitialClaimAdmissionLeafV1{ClaimID: body.ClaimID,
				AdmissionSequence: body.ClaimAdmissionSequence, AuthorizedClaimEnvelopeDigest: claimDigest})
		initialRevisionRoot, initialErr := InitialClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID)
		wantRevisionRoot, revisionErr := AdvanceClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID,
			initialRevisionRoot, 1, ClaimRevisionAdmissionLeafV1{ClaimID: body.ClaimID,
				ClaimRevisionAdmissionSequence: 1, AuthorizedClaimEnvelopeDigest: claimDigest})
		if rootErr != nil || initialErr != nil || revisionErr != nil || body.AdmittedClaimAdmissionLogRoot != wantClaimRoot ||
			body.PriorClaimRevisionLogRoot != initialRevisionRoot || body.AdmittedClaimRevisionLogRoot != wantRevisionRoot {
			return errors.New("initial Guarantor claim admission roots are invalid")
		}
	} else if body.AdmissionKind == "revision" {
		if claim.Body.ClaimRevision <= 1 || body.PriorClaimRevision+1 != body.AdmittedClaimRevision ||
			body.ClaimRevisionAdmissionSequence != body.AdmittedClaimRevision || !validDigest(body.InitialClaimAdmissionReceiptDigest) ||
			!validDigest(body.PredecessorRevisionAdmissionReceiptDigest) || body.PriorClaimAdmissionLogRoot != body.AdmittedClaimAdmissionLogRoot {
			return errors.New("revised Guarantor claim admission lineage is invalid")
		}
		wantRevisionRoot, rootErr := AdvanceClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID,
			body.PriorClaimRevisionLogRoot, body.ClaimRevisionAdmissionSequence, ClaimRevisionAdmissionLeafV1{ClaimID: body.ClaimID,
				ClaimRevisionAdmissionSequence: body.ClaimRevisionAdmissionSequence, AuthorizedClaimEnvelopeDigest: claimDigest,
				PredecessorRevisionAdmissionReceiptDigest: body.PredecessorRevisionAdmissionReceiptDigest})
		if rootErr != nil || wantRevisionRoot != body.AdmittedClaimRevisionLogRoot {
			return errors.New("revised Guarantor claim admission root is invalid")
		}
	} else {
		return errors.New("Guarantor claim admission kind is invalid")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest,
		ingressDigest, terms.ClaimAdmissionAuthoritySubjects, "claim-admission-receipt", claimDigest,
		terms.ClaimAdmissionProfile.ProfileDigest, terms.ClaimAdmissionProfile, terms.CoverageStateDomainDigest,
		body.ClaimRevisionAdmissionSequence, body.AdmittedAtUnix); err != nil {
		return err
	}
	receiptBodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-admission-receipt-body.v1", body)
	if err != nil {
		return err
	}
	return ValidateAuthorizationQuorumSet(receipt.Authorizations, "claim-admission-receipt", receiptBodyDigest,
		"tos.service.agent-guarantor-claim-admission-receipt-signature.v1", terms.ClaimAdmissionAuthoritySubjects,
		terms.ClaimAdmissionQuorumRule, authorityResolver, now)
}

func zeroSHA256DigestV1() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func zeroDigestOrEmptyV1(value string) string {
	if value == "" {
		return zeroSHA256DigestV1()
	}
	return value
}
