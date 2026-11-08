package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const DecisionApplicationReceiptSealDomainV1 = "tos.service.agent-guarantor-decision-application-receipt-seal.v1"

func NewDecisionApplicationReceiptSealBodyV1(receipt AuthorizedClaimDecisionApplicationReceiptV1,
	terms CoverageTermsV1, sealedAt time.Time) (DecisionApplicationReceiptSealBodyV1, ImmutableEvidenceDescriptorV1, error) {
	wire, err := guarantorCodec.Marshal(receipt)
	if err != nil {
		return DecisionApplicationReceiptSealBodyV1{}, ImmutableEvidenceDescriptorV1{}, err
	}
	receiptDigest, receiptErr := ClaimDecisionApplicationReceiptDigestV1(receipt)
	bodyDigest, bodyErr := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-application-receipt-body.v1", receipt.Body)
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	transitionDigest, transitionErr := ClaimStateTransitionReceiptDigestV1(receipt.AuthorizedTerminalClaimStateTransitionReceipt)
	payoutDigest, payoutErr := guarantorCodec.Digest(PayoutSetDomain, receipt.MaterializedPayoutObligationSet)
	tokenDigest, tokenErr := DecisionApplicationTokenDigestV1(receipt.DecisionApplicationToken)
	termsDigest, termsErr := CoverageTermsDigest(terms)
	if receiptErr != nil || bodyErr != nil || actionErr != nil || transitionErr != nil || payoutErr != nil || tokenErr != nil ||
		termsErr != nil || sealedAt.IsZero() {
		return DecisionApplicationReceiptSealBodyV1{}, ImmutableEvidenceDescriptorV1{}, errors.New("decision application receipt cannot be sealed")
	}
	seal := DecisionApplicationReceiptSealBodyV1{SchemaVersion: 1, ReceiptEnvelopeDigest: receiptDigest,
		ReceiptBodyDigest: bodyDigest, AuthorizedActionDigest: actionDigest,
		TerminalClaimStateTransitionReceiptDigest: transitionDigest,
		MaterializedPayoutObligationSetDigest:     payoutDigest, DecisionApplicationTokenDigest: tokenDigest,
		CoverageTermsDigest: termsDigest, SealedAtUnix: uint64(sealedAt.UTC().Unix())}
	descriptor := ImmutableEvidenceDescriptorV1{ContentType: "application/vnd.tos.service.agent-guarantor-decision-application.v1+cbor",
		ContentDigest: receiptDigest, ContentSize: uint64(len(wire)), RetrievalPolicyDigest: terms.DecisionAdmissionProfile.ProfileDigest}
	return seal, descriptor, nil
}

func BuildDecisionApplicationReceiptProofV1(receipt AuthorizedClaimDecisionApplicationReceiptV1, terms CoverageTermsV1,
	descriptor ImmutableEvidenceDescriptorV1, seal DecisionApplicationReceiptSealBodyV1,
	authorization ProfileQualifiedObjectAuthorizationV1) (DecisionApplicationReceiptProofV1, error) {
	wantSeal, wantDescriptor, err := NewDecisionApplicationReceiptSealBodyV1(receipt, terms,
		time.Unix(int64(seal.SealedAtUnix), 0).UTC())
	if err != nil || !equalCanonical(wantSeal, seal) || !equalCanonical(wantDescriptor, descriptor) {
		return DecisionApplicationReceiptProofV1{}, errors.New("decision application compact proof projection differs")
	}
	proof := DecisionApplicationReceiptProofV1{SchemaVersion: 1, ReceiptEnvelopeDigest: seal.ReceiptEnvelopeDigest,
		ReceiptDescriptor: descriptor, Body: receipt.Body,
		Authorizations: append([]ProfileQualifiedObjectAuthorizationV1(nil), receipt.Authorizations...),
		SealBody:       seal, SealAuthorization: authorization}
	if err := ValidateDecisionApplicationReceiptProofV1(proof, terms, nil, time.Unix(int64(seal.SealedAtUnix), 0).UTC(), false); err != nil {
		return DecisionApplicationReceiptProofV1{}, err
	}
	return proof, nil
}

func ValidateDecisionApplicationReceiptProofV1(proof DecisionApplicationReceiptProofV1, terms CoverageTermsV1,
	resolver AuthorityKeyResolver, now time.Time, verifySignatures bool) error {
	if proof.SchemaVersion != 1 || !validDigest(proof.ReceiptEnvelopeDigest) ||
		validateImmutableEvidenceDescriptor(proof.ReceiptDescriptor) != nil ||
		proof.ReceiptDescriptor.ContentDigest != proof.ReceiptEnvelopeDigest ||
		proof.ReceiptDescriptor.RetrievalPolicyDigest != terms.DecisionAdmissionProfile.ProfileDigest {
		return errors.New("decision application compact proof is malformed")
	}
	bodyDigest, bodyErr := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-application-receipt-body.v1", proof.Body)
	termsDigest, termsErr := CoverageTermsDigest(terms)
	bound, boundErr := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "decision_application")
	seal := proof.SealBody
	if bodyErr != nil || termsErr != nil || boundErr != nil || seal.SchemaVersion != 1 ||
		seal.ReceiptEnvelopeDigest != proof.ReceiptEnvelopeDigest || seal.ReceiptBodyDigest != bodyDigest ||
		seal.AuthorizedActionDigest != proof.Body.AuthorizedActionDigest ||
		seal.TerminalClaimStateTransitionReceiptDigest != proof.Body.TerminalClaimStateTransitionReceiptDigest ||
		seal.MaterializedPayoutObligationSetDigest != proof.Body.MaterializedPayoutObligationSetDigest ||
		seal.DecisionApplicationTokenDigest != proof.Body.DecisionApplicationTokenDigest ||
		seal.CoverageTermsDigest != termsDigest || seal.SealedAtUnix < proof.Body.AppliedAtUnix ||
		uint64(now.UTC().Unix()) < seal.SealedAtUnix || proof.SealAuthorization.AuthoritySubject != bound.ActionAuthorityID ||
		proof.SealAuthorization.ValidationTimeUnix != seal.SealedAtUnix {
		return errors.New("decision application compact proof binding is invalid")
	}
	if !verifySignatures {
		return nil
	}
	if resolver == nil {
		return errors.New("decision application compact proof resolver is unavailable")
	}
	if err := verifyReceiptAuthorizationSetV1(proof.Authorizations, "claim-decision-application-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-application-signature.v1", terms.DecisionAdmissionProfile,
		terms.DecisionAdmissionAuthoritySubjects, terms.DecisionAdmissionQuorumRule, resolver, now); err != nil {
		return err
	}
	wire, err := resolveImmutableEvidenceV1(resolver, proof.ReceiptDescriptor,
		terms.SelectedAssuranceLevel == AssuranceIndependentlyEnforced)
	if err != nil {
		return err
	}
	if len(wire) != 0 {
		var complete AuthorizedClaimDecisionApplicationReceiptV1
		if guarantorCodec.Unmarshal(wire, &complete) != nil {
			return errors.New("decision application compact proof complete receipt is undecodable")
		}
		completeDigest, digestErr := ClaimDecisionApplicationReceiptDigestV1(complete)
		completeSeal, completeDescriptor, sealErr := NewDecisionApplicationReceiptSealBodyV1(complete, terms,
			time.Unix(int64(seal.SealedAtUnix), 0).UTC())
		if digestErr != nil || sealErr != nil || completeDigest != proof.ReceiptEnvelopeDigest ||
			!equalCanonical(completeSeal, seal) || !equalCanonical(completeDescriptor, proof.ReceiptDescriptor) {
			return errors.New("decision application compact proof differs from its immutable complete receipt")
		}
	}
	sealDigest, _ := guarantorCodec.Digest(DecisionApplicationReceiptSealDomainV1, seal)
	return VerifyObjectAuthorization(proof.SealAuthorization, "decision-application-receipt-seal", sealDigest,
		"tos.service.agent-guarantor-decision-application-receipt-seal-signature.v1", resolver, now)
}
