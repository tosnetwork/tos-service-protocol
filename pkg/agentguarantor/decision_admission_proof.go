package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const ClaimDecisionAdmissionReceiptSealDomainV1 = "tos.service.agent-guarantor-claim-decision-admission-receipt-seal.v1"

func NewClaimDecisionAdmissionReceiptSealBodyV1(receipt AuthorizedClaimDecisionAdmissionReceiptV1,
	terms CoverageTermsV1, sealedAt time.Time) (ClaimDecisionAdmissionReceiptSealBodyV1, ImmutableEvidenceDescriptorV1, error) {
	receiptBytes, err := guarantorCodec.Marshal(receipt)
	if err != nil {
		return ClaimDecisionAdmissionReceiptSealBodyV1{}, ImmutableEvidenceDescriptorV1{}, err
	}
	receiptDigest, err := ClaimDecisionAdmissionReceiptDigestV1(receipt)
	if err != nil {
		return ClaimDecisionAdmissionReceiptSealBodyV1{}, ImmutableEvidenceDescriptorV1{}, err
	}
	bodyDigest, bodyErr := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", receipt.Body)
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	decisionDigest, decisionErr := ClaimDecisionDigestV1(receipt.AuthorizedClaimDecision)
	claim := receipt.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	claimDigest, claimErr := ClaimEnvelopeDigest(claim)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	termsDigest, termsErr := CoverageTermsDigest(terms)
	if bodyErr != nil || actionErr != nil || decisionErr != nil || claimErr != nil || endErr != nil || termsErr != nil || sealedAt.IsZero() {
		return ClaimDecisionAdmissionReceiptSealBodyV1{}, ImmutableEvidenceDescriptorV1{}, errors.New("claim decision admission receipt cannot be sealed")
	}
	seal := ClaimDecisionAdmissionReceiptSealBodyV1{SchemaVersion: 1, ReceiptEnvelopeDigest: receiptDigest,
		ReceiptBodyDigest: bodyDigest, AuthorizedActionDigest: actionDigest,
		AuthorizedClaimDecisionDigest: decisionDigest, AuthorizedClaimEnvelopeDigest: claimDigest,
		CoverageEndCommitmentDigest: endDigest, CoverageTermsDigest: termsDigest,
		SealedAtUnix: uint64(sealedAt.UTC().Unix())}
	descriptor := ImmutableEvidenceDescriptorV1{ContentType: "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor",
		ContentDigest: receiptDigest, ContentSize: uint64(len(receiptBytes)), RetrievalPolicyDigest: terms.DecisionAdmissionProfile.ProfileDigest}
	return seal, descriptor, nil
}

func BuildClaimDecisionAdmissionReceiptProofV1(receipt AuthorizedClaimDecisionAdmissionReceiptV1,
	terms CoverageTermsV1, descriptor ImmutableEvidenceDescriptorV1, seal ClaimDecisionAdmissionReceiptSealBodyV1,
	sealAuthorization ProfileQualifiedObjectAuthorizationV1) (ClaimDecisionAdmissionReceiptProofV1, error) {
	wantSeal, wantDescriptor, err := NewClaimDecisionAdmissionReceiptSealBodyV1(receipt, terms,
		time.Unix(int64(seal.SealedAtUnix), 0).UTC())
	if err != nil || !equalCanonical(wantSeal, seal) || !equalCanonical(wantDescriptor, descriptor) {
		return ClaimDecisionAdmissionReceiptProofV1{}, errors.New("claim decision admission receipt seal projection differs")
	}
	claim := receipt.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	proof := ClaimDecisionAdmissionReceiptProofV1{SchemaVersion: 1, ReceiptEnvelopeDigest: seal.ReceiptEnvelopeDigest,
		ReceiptDescriptor: descriptor, ReceiptBody: receipt.Body, CoverageEndCommitment: receipt.CoverageEndCommitment,
		AuthorizedClaimDecision: receipt.AuthorizedClaimDecision, AuthorizedClaim: claim,
		ReceiptAuthorizations: append([]ProfileQualifiedObjectAuthorizationV1(nil), receipt.Authorizations...),
		SealBody:              seal, SealAuthorization: sealAuthorization}
	if _, err := ClaimDecisionAdmissionReceiptProofDigestV1(proof); err != nil {
		return ClaimDecisionAdmissionReceiptProofV1{}, err
	}
	return proof, nil
}

func ClaimDecisionAdmissionReceiptProofDigestV1(proof ClaimDecisionAdmissionReceiptProofV1) (string, error) {
	if proof.SchemaVersion != 1 || !validDigest(proof.ReceiptEnvelopeDigest) ||
		validateImmutableEvidenceDescriptor(proof.ReceiptDescriptor) != nil ||
		proof.ReceiptDescriptor.ContentDigest != proof.ReceiptEnvelopeDigest {
		return "", errors.New("claim decision admission receipt proof is malformed")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-proof.v1", proof)
}

func VerifyClaimDecisionAdmissionReceiptProofV1(proof ClaimDecisionAdmissionReceiptProofV1, terms CoverageTermsV1,
	authorityResolver AuthorityKeyResolver, now time.Time) error {
	if _, err := ClaimDecisionAdmissionReceiptProofDigestV1(proof); err != nil || authorityResolver == nil {
		return errors.New("claim decision admission compact proof is invalid")
	}
	body := proof.ReceiptBody
	decisionDigest, decisionErr := ClaimDecisionDigestV1(proof.AuthorizedClaimDecision)
	claimDigest, claimErr := ClaimEnvelopeDigest(proof.AuthorizedClaim)
	bodyDigest, bodyErr := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", body)
	endDigest, endErr := CoverageEndCommitmentDigestV1(proof.CoverageEndCommitment)
	termsDigest, termsErr := CoverageTermsDigest(terms)
	bound, boundErr := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "terminal_decision")
	seal := proof.SealBody
	if decisionErr != nil || claimErr != nil || bodyErr != nil || endErr != nil || termsErr != nil || boundErr != nil ||
		seal.SchemaVersion != 1 || seal.ReceiptEnvelopeDigest != proof.ReceiptEnvelopeDigest ||
		seal.ReceiptBodyDigest != bodyDigest || seal.AuthorizedActionDigest != body.AuthorizedActionDigest ||
		seal.AuthorizedClaimDecisionDigest != decisionDigest || seal.AuthorizedClaimEnvelopeDigest != claimDigest ||
		seal.CoverageEndCommitmentDigest != endDigest || seal.CoverageTermsDigest != termsDigest ||
		seal.SealedAtUnix < body.AdmittedAtUnix || uint64(now.UTC().Unix()) < seal.SealedAtUnix ||
		proof.ReceiptDescriptor.ContentDigest != proof.ReceiptEnvelopeDigest ||
		proof.ReceiptDescriptor.RetrievalPolicyDigest != terms.DecisionAdmissionProfile.ProfileDigest ||
		body.AuthorizedClaimDecisionDigest != decisionDigest || body.ClaimID != proof.AuthorizedClaim.Body.ClaimID ||
		body.CoverageAgreementBodyDigest != proof.AuthorizedClaim.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != proof.AuthorizedClaim.Body.CoverageObligationID ||
		body.DecisionSequence != proof.AuthorizedClaimDecision.Body.DecisionSequence ||
		body.AdmittedAtUnix == 0 || uint64(now.UTC().Unix()) < body.AdmittedAtUnix {
		return errors.New("claim decision admission compact proof binding is invalid")
	}
	claimValidationTime := time.Unix(int64(proof.AuthorizedClaim.Body.CreatedAtUnix), 0).UTC()
	if err := VerifyClaim(proof.AuthorizedClaim, terms, body.CoverageAgreementBodyDigest,
		body.CoverageObligationID, authorityResolver, claimValidationTime); err != nil {
		return err
	}
	decisionValidationTime := time.Unix(int64(proof.AuthorizedClaimDecision.Body.DecidedAtUnix), 0).UTC()
	if err := ValidateClaimDecision(proof.AuthorizedClaimDecision, proof.AuthorizedClaim, terms,
		authorityResolver, terms.DecisionAuthoritySubjects, decisionValidationTime); err != nil {
		return err
	}
	if err := verifyReceiptAuthorizationSetV1(proof.ReceiptAuthorizations, "claim-decision-admission-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-admission-signature.v1", terms.DecisionAdmissionProfile,
		terms.DecisionAdmissionAuthoritySubjects, terms.DecisionAdmissionQuorumRule, authorityResolver, now); err != nil {
		return err
	}
	wire, err := resolveImmutableEvidenceV1(authorityResolver, proof.ReceiptDescriptor,
		terms.SelectedAssuranceLevel == AssuranceIndependentlyEnforced)
	if err != nil {
		return err
	}
	if len(wire) != 0 {
		var complete AuthorizedClaimDecisionAdmissionReceiptV1
		if guarantorCodec.Unmarshal(wire, &complete) != nil {
			return errors.New("claim decision admission compact proof complete receipt is undecodable")
		}
		completeDigest, digestErr := ClaimDecisionAdmissionReceiptDigestV1(complete)
		completeSeal, completeDescriptor, sealErr := NewClaimDecisionAdmissionReceiptSealBodyV1(complete, terms,
			time.Unix(int64(seal.SealedAtUnix), 0).UTC())
		if digestErr != nil || sealErr != nil || completeDigest != proof.ReceiptEnvelopeDigest ||
			!equalCanonical(completeSeal, seal) || !equalCanonical(completeDescriptor, proof.ReceiptDescriptor) {
			return errors.New("claim decision admission compact proof differs from its immutable complete receipt")
		}
	}
	sealDigest, _ := guarantorCodec.Digest(ClaimDecisionAdmissionReceiptSealDomainV1, seal)
	if proof.SealAuthorization.AuthoritySubject != bound.ActionAuthorityID ||
		proof.SealAuthorization.ValidationTimeUnix != seal.SealedAtUnix {
		return errors.New("claim decision admission receipt seal authority is substituted")
	}
	return VerifyObjectAuthorization(proof.SealAuthorization, "claim-decision-admission-receipt-seal", sealDigest,
		"tos.service.agent-guarantor-claim-decision-admission-receipt-seal-signature.v1", authorityResolver, now)
}
