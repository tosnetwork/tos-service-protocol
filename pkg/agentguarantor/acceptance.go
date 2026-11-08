package agentguarantor

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	AcceptanceRequestDomain = "tos.service.agent-guarantor-acceptance-request-envelope.v1"
	AcceptanceReceiptDomain = "tos.service.agent-guarantor-acceptance-receipt-envelope.v1"
)

func CoverageAcceptanceAdmissionDomainIDV1(boundDomainDigest, offerID string) (string, error) {
	if !validDigest(boundDomainDigest) || !validDigest(offerID) {
		return "", errors.New("acceptance admission domain input is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-acceptance-admission-domain.v1", struct {
		BoundDomainDigest string `json:"bound_domain_digest"`
		OfferID           string `json:"offer_id"`
	}{boundDomainDigest, offerID})
}

func CoverageAcceptanceRequestDigestV1(request AuthorizedCoverageAcceptanceRequestV1) (string, error) {
	if err := validateAcceptanceRequestShape(request); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(AcceptanceRequestDomain, request)
}

func VerifyCoverageAcceptanceRequestV1(request AuthorizedCoverageAcceptanceRequestV1,
	offer AuthorizedFirmCoverageOfferV1, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	authorityResolver AuthorityKeyResolver, now time.Time) error {
	if err := validateAcceptanceRequestShape(request); err != nil || agreementVerifier == nil {
		return errors.New("Guarantor acceptance request is invalid")
	}
	if err := enforceCanonicalSize(request, offer.CoverageTerms.ClaimClosureCapacity.MaximumAcceptanceRequestEnvelopeBytes,
		"coverage acceptance request"); err != nil {
		return err
	}
	agreementDigest, _ := agentcommerce.AgreementBodyDigest(request.CoverageAgreementBody)
	offerDigest, err := FirmOfferDigest(offer)
	if err != nil || agreementDigest != request.Body.CoverageAgreementBodyDigest ||
		offerDigest != request.Body.AuthorizedFirmOfferEnvelopeDigest || offer.Body.CoverageAgreementBodyDigest != agreementDigest ||
		uint64(now.UTC().Unix()) > request.Body.ExpiresAtUnix || request.Body.CreatedAtUnix < offer.Body.ValidFromUnix ||
		request.Body.CreatedAtUnix > offer.Body.AcceptByUnix || request.Body.ExpiresAtUnix > offer.Body.ExpiresAtUnix {
		return errors.New("Guarantor acceptance request is outside the firm offer")
	}
	agreement := agentcommerce.AgentAgreement{Body: request.CoverageAgreementBody,
		AuthorizationEvidence: append([]agentcommerce.AgreementAuthorizationEvidence(nil), request.AuthorizationEvidenceSet.Evidence...)}
	firmOfferEvidenceCount := 0
	for _, evidence := range request.AuthorizationEvidenceSet.Evidence {
		if evidence.EvidenceProfileURI == FirmOfferAgreementEvidenceProfileURI {
			firmOfferEvidenceCount++
			if err := verifyFirmOfferAgreementEvidenceAgainstOfferV1(evidence, request.CoverageAgreementBody, offer); err != nil {
				return err
			}
		}
	}
	if firmOfferEvidenceCount != 1 {
		return errors.New("Guarantor acceptance requires exactly one firm-offer Agreement evidence group")
	}
	if err := agentcommerce.ValidateAgreementAuthorization(agreement, agreementVerifier, now); err != nil {
		return errors.New("Guarantor acceptance lacks complete Agreement authorization")
	}
	profileBound := false
	for _, predicate := range request.CoverageAgreementBody.AuthorizationPredicates {
		profileBound = profileBound || predicate.AuthoritySubject.SubjectIdentifier == request.Body.AcceptingSubject &&
			predicate.EvidenceProfileURI == request.Body.SubmissionAuthorizationProfile.ProfileURI &&
			uint64(predicate.EvidenceProfileVersion) == request.Body.SubmissionAuthorizationProfile.ProfileVersion &&
			predicate.EvidenceProfileDigest == request.Body.SubmissionAuthorizationProfile.ProfileDigest
	}
	if !profileBound {
		return errors.New("Guarantor acceptance profile is not body-bound to the accepting subject")
	}
	for _, authorization := range request.Authorizations {
		statement := authorization.AuthorizationStatement()
		if statement.AuthoritySubject != request.Body.AcceptingSubject ||
			statement.ProfileURI != request.Body.SubmissionAuthorizationProfile.ProfileURI ||
			statement.ProfileVersion != request.Body.SubmissionAuthorizationProfile.ProfileVersion ||
			statement.ProfileDigest != request.Body.SubmissionAuthorizationProfile.ProfileDigest {
			return errors.New("Guarantor acceptance authorization uses a substituted profile")
		}
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-acceptance-request-body.v1", request.Body)
	return ValidateAuthorizationSet(request.Authorizations, "coverage-acceptance-request", bodyDigest,
		"tos.service.agent-guarantor-acceptance-request-signature.v1", []string{request.Body.AcceptingSubject}, authorityResolver, now)
}

func CoverageAcceptanceReceiptDigestV1(receipt AuthorizedCoverageAcceptanceReceiptV1) (string, error) {
	if err := validateAcceptanceReceiptShape(receipt); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(AcceptanceReceiptDomain, receipt)
}

func VerifyCoverageAcceptanceReceiptV1(receipt AuthorizedCoverageAcceptanceReceiptV1,
	offer AuthorizedFirmCoverageOfferV1, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	acceptedAt := time.Unix(int64(receipt.Body.AcceptedAtUnix), 0).UTC()
	if err := validateAcceptanceReceiptShape(receipt); err != nil || acceptedAt.After(now.UTC().Add(5*time.Minute)) ||
		VerifyCoverageAcceptanceRequestV1(receipt.AuthorizedAcceptanceRequest, offer, agreementVerifier, authorityResolver, acceptedAt) != nil {
		return errors.New("Guarantor acceptance receipt is invalid")
	}
	if err := enforceCanonicalSize(receipt, offer.CoverageTerms.ClaimClosureCapacity.MaximumAcceptanceReceiptEnvelopeBytes,
		"coverage acceptance receipt"); err != nil {
		return err
	}
	bound, err := derivedAuxiliaryStageAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding,
		"coverage_acceptance", "coverage_activation")
	if err != nil {
		return err
	}
	body := receipt.Body
	projectionDigest, err := TransitionEvidenceProjectionDigestV1(receipt.TransitionEvidenceProjection)
	if err != nil || body.TransitionEvidenceProjectionDigest != projectionDigest ||
		body.AuthorityID != bound.ActionAuthorityID || body.ExposureAdmissionReceiptDigest != offer.Body.ExposureAdmissionReceiptDigest ||
		body.ReservationID != offer.Body.ReservationID || body.ReceivedAtUnix > offer.Body.AcceptByUnix ||
		body.AcceptedAtUnix > offer.Body.AcceptByUnix+offer.Body.AcceptanceProcessingGraceSeconds ||
		body.AcceptedAtUnix > offer.ExposureAdmissionReceipt.Body.ExpiresAtUnix {
		return errors.New("Guarantor acceptance is outside its linearized offer reservation")
	}
	request := CoverageAcceptanceAdmissionActionBodyV1{SchemaVersion: 1,
		AuthorizedAcceptanceRequest:  receipt.AuthorizedAcceptanceRequest,
		TransitionEvidenceProjection: receipt.TransitionEvidenceProjection,
		ExpectedReservationRevision:  offer.ExposureAdmissionReceipt.Body.AdmittedPortfolioRevision,
		ExpectedOfferStateRevision:   body.PriorOfferStateRevision, TargetOfferStateRevision: body.AcceptedOfferStateRevision,
		ExpectedCoverageRevision: body.PriorCoverageRevision, TargetCoverageRevision: body.AcceptedCoverageRevision,
		ExpectedClaimFilingState: body.PriorClaimFilingState, TargetClaimFilingState: body.AcceptedClaimFilingState,
		ExpectedClaimFilingStateRevision: body.PriorClaimFilingStateRevision,
		TargetClaimFilingStateRevision:   body.AcceptedClaimFilingStateRevision}
	requestBytes, err := guarantorCodec.Marshal(request)
	if err != nil || !bytes.Equal(requestBytes, receipt.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("Guarantor acceptance admission request is noncanonical")
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest":   agentcommerce.Digest32(body.CoverageAgreementBodyDigest),
		"obligation_id":           agentcommerce.ID(offer.Body.CoverageObligationID),
		"expected_state_revision": agentcommerce.U64(body.PriorOfferStateRevision), "target_state": agentcommerce.State("accepted"),
		"evidence_set_digest": agentcommerce.Digest32(projectionDigest),
	}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, requestBytes,
		fields, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	actionDigest, _ := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	admissionDomainID, err := CoverageAcceptanceAdmissionDomainIDV1(bound.AdmissionStateDomainDigest, offer.Body.OfferID)
	if err != nil {
		return err
	}
	if body.AuthorizedActionDigest != actionDigest || body.StableActionID != receipt.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		receipt.AuthorityAdmissionEligibilityProofSet.AdmittedActionDigest != actionDigest ||
		receipt.AuthorityAdmissionEligibilityProofSet.AdmissionDomainID != admissionDomainID ||
		receipt.AuthorityAdmissionEligibilityProofSet.AdmissionTimeUnix != body.AcceptedAtUnix {
		return errors.New("Guarantor acceptance admission authority or CAS proof is substituted")
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-acceptance-receipt-body.v1", receipt.Body)
	return ValidateAuthorizationSet(receipt.Authorizations, "coverage-acceptance-receipt", bodyDigest,
		"tos.service.agent-guarantor-acceptance-receipt-signature.v1", []string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}

func validateAcceptanceRequestShape(request AuthorizedCoverageAcceptanceRequestV1) error {
	body := request.Body
	agreementDigest, agreementErr := agentcommerce.AgreementBodyDigest(request.CoverageAgreementBody)
	evidenceDigest, evidenceErr := AgreementAuthorizationEvidenceSetDigestV1(request.AuthorizationEvidenceSet)
	if body.SchemaVersion != 1 || agreementErr != nil || evidenceErr != nil || body.CoverageAgreementBodyDigest != agreementDigest ||
		!validDigest(body.AuthorizedFirmOfferEnvelopeDigest) || body.CompleteAuthorizationEvidenceSetDigest != evidenceDigest ||
		!validID(body.AcceptingSubject) || agentcommerce.ValidateProfileRefV1(body.SubmissionAuthorizationProfile) != nil ||
		body.CreatedAtUnix == 0 || body.ExpiresAtUnix < body.CreatedAtUnix || body.ExpiresAtUnix-body.CreatedAtUnix > 24*60*60 ||
		request.AuthorizationEvidenceSet.AgreementID != request.CoverageAgreementBody.AgreementID ||
		request.AuthorizationEvidenceSet.AgreementVersion != request.CoverageAgreementBody.Version ||
		request.AuthorizationEvidenceSet.AgreementBodyDigest != agreementDigest ||
		len(request.Authorizations) == 0 || len(request.Authorizations) > MaxAuthorizations {
		return errors.New("Guarantor acceptance request shape is invalid")
	}
	return nil
}

func validateAcceptanceReceiptShape(receipt AuthorizedCoverageAcceptanceReceiptV1) error {
	body := receipt.Body
	requestDigest, requestErr := CoverageAcceptanceRequestDigestV1(receipt.AuthorizedAcceptanceRequest)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if requestErr != nil || proofErr != nil || body.SchemaVersion != 1 || !validID(body.AuthorityID) ||
		body.CoverageAgreementBodyDigest != receipt.AuthorizedAcceptanceRequest.Body.CoverageAgreementBodyDigest ||
		body.AuthorizedFirmOfferEnvelopeDigest != receipt.AuthorizedAcceptanceRequest.Body.AuthorizedFirmOfferEnvelopeDigest ||
		body.AuthorizedAcceptanceRequestEnvelopeDigest != requestDigest || !validDigest(body.ExposureAdmissionReceiptDigest) ||
		!validDigest(body.ReservationID) || !validDigest(body.TransitionEvidenceProjectionDigest) ||
		!validDigest(body.AuthorizedActionDigest) || !validDigest(body.StableActionID) || !validDigest(body.ExactRequestDigest) ||
		body.WriterGeneration == 0 || !validDigest(body.WriterFenceDigest) || body.PriorOfferStateRevision == 0 ||
		body.AcceptedOfferStateRevision != body.PriorOfferStateRevision+1 || body.PriorCoverageRevision != 0 ||
		body.AcceptedCoverageRevision != 1 || body.PriorClaimFilingState != "uninitialized" ||
		body.AcceptedClaimFilingState != "not_open" || body.PriorClaimFilingStateRevision != 0 ||
		body.AcceptedClaimFilingStateRevision != 1 || body.ReceivedAtUnix == 0 || body.AcceptedAtUnix < body.ReceivedAtUnix ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest || len(receipt.Authorizations) == 0 {
		return errors.New("Guarantor acceptance receipt shape is invalid")
	}
	return nil
}
