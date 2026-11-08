package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const ClaimAdmissionReceiptSealDomainV1 = "tos.service.agent-guarantor-claim-admission-receipt-seal.v1"

type ClaimAdmissionReceiptSealBodyV1 struct {
	SchemaVersion                 uint16 `json:"schema_version"`
	ReceiptEnvelopeDigest         string `json:"receipt_envelope_digest"`
	ReceiptBodyDigest             string `json:"receipt_body_digest"`
	AuthorizedActionDigest        string `json:"authorized_action_digest"`
	AuthorizedClaimEnvelopeDigest string `json:"authorized_claim_envelope_digest"`
	ClaimIngressReceiptDigest     string `json:"claim_ingress_receipt_digest"`
	CoverageEndCommitmentDigest   string `json:"coverage_end_commitment_digest"`
	AuthorityInstanceRecordDigest string `json:"authority_instance_record_digest"`
	EligibilityProofSetDigest     string `json:"eligibility_proof_set_digest"`
	CoverageTermsDigest           string `json:"coverage_terms_digest"`
	SealedAtUnix                  uint64 `json:"sealed_at_unix"`
}

// ClaimAdmissionReceiptProofV1 is a bounded, independently authenticated
// projection of a potentially large receipt. The descriptor commits the exact
// complete receipt; the projection carries every value needed by terminal
// lineage verification without recursively embedding activation history.
type ClaimAdmissionReceiptProofV1 struct {
	SchemaVersion                         uint16                                    `json:"schema_version"`
	ReceiptEnvelopeDigest                 string                                    `json:"receipt_envelope_digest"`
	ReceiptDescriptor                     ImmutableEvidenceDescriptorV1             `json:"receipt_descriptor"`
	ReceiptBody                           ClaimAdmissionReceiptBodyV1               `json:"receipt_body"`
	AuthorizedClaimIngressReceipt         AuthorizedClaimSubmissionIngressReceiptV1 `json:"authorized_claim_ingress_receipt"`
	CoverageEndCommitment                 CoverageEndCommitmentV1                   `json:"coverage_end_commitment"`
	AuthorityInstanceRecord               agentcommerce.AuthorityInstanceRecord     `json:"authority_instance_record"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1   `json:"authority_admission_eligibility_proof_set"`
	ReceiptAuthorizations                 []ProfileQualifiedObjectAuthorizationV1   `json:"receipt_authorizations"`
	SealBody                              ClaimAdmissionReceiptSealBodyV1           `json:"seal_body"`
	SealAuthorization                     ProfileQualifiedObjectAuthorizationV1     `json:"seal_authorization"`
}

func NewClaimAdmissionReceiptSealBodyV1(receipt AuthorizedClaimAdmissionReceiptV1,
	terms CoverageTermsV1, sealedAt time.Time) (ClaimAdmissionReceiptSealBodyV1, ImmutableEvidenceDescriptorV1, error) {
	wire, wireErr := guarantorCodec.Marshal(receipt)
	receiptDigest, receiptErr := ClaimAdmissionReceiptDigestV1(receipt)
	bodyDigest, bodyErr := guarantorCodec.Digest("tos.service.agent-guarantor-claim-admission-receipt-body.v1", receipt.Body)
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	claimDigest, claimErr := ClaimEnvelopeDigest(receipt.AuthorizedClaimIngressReceipt.AuthorizedClaim)
	ingressDigest, ingressErr := ClaimIngressReceiptDigestV1(receipt.AuthorizedClaimIngressReceipt)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	instanceDigest, instanceErr := guarantorCodec.Digest("tos.service.authority-instance-record.v1", receipt.AuthorityInstanceRecord)
	eligibilityDigest, eligibilityErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	termsDigest, termsErr := CoverageTermsDigest(terms)
	if wireErr != nil || receiptErr != nil || bodyErr != nil || actionErr != nil || claimErr != nil || ingressErr != nil ||
		endErr != nil || instanceErr != nil || eligibilityErr != nil || termsErr != nil || sealedAt.IsZero() {
		return ClaimAdmissionReceiptSealBodyV1{}, ImmutableEvidenceDescriptorV1{}, errors.New("claim admission receipt cannot be sealed")
	}
	seal := ClaimAdmissionReceiptSealBodyV1{SchemaVersion: 1, ReceiptEnvelopeDigest: receiptDigest,
		ReceiptBodyDigest: bodyDigest, AuthorizedActionDigest: actionDigest,
		AuthorizedClaimEnvelopeDigest: claimDigest, ClaimIngressReceiptDigest: ingressDigest,
		CoverageEndCommitmentDigest: endDigest, AuthorityInstanceRecordDigest: instanceDigest,
		EligibilityProofSetDigest: eligibilityDigest, CoverageTermsDigest: termsDigest,
		SealedAtUnix: uint64(sealedAt.UTC().Unix())}
	descriptor := ImmutableEvidenceDescriptorV1{
		ContentType:   "application/vnd.tos.service.agent-guarantor-claim-admission.v1+cbor",
		ContentDigest: receiptDigest, ContentSize: uint64(len(wire)),
		RetrievalPolicyDigest: terms.ClaimAdmissionProfile.ProfileDigest}
	return seal, descriptor, nil
}

func BuildClaimAdmissionReceiptProofV1(receipt AuthorizedClaimAdmissionReceiptV1, terms CoverageTermsV1,
	descriptor ImmutableEvidenceDescriptorV1, seal ClaimAdmissionReceiptSealBodyV1,
	sealAuthorization ProfileQualifiedObjectAuthorizationV1) (ClaimAdmissionReceiptProofV1, error) {
	wantSeal, wantDescriptor, err := NewClaimAdmissionReceiptSealBodyV1(receipt, terms,
		time.Unix(int64(seal.SealedAtUnix), 0).UTC())
	if err != nil || !equalCanonical(wantSeal, seal) || !equalCanonical(wantDescriptor, descriptor) {
		return ClaimAdmissionReceiptProofV1{}, errors.New("claim admission compact proof projection differs")
	}
	proof := ClaimAdmissionReceiptProofV1{SchemaVersion: 1, ReceiptEnvelopeDigest: seal.ReceiptEnvelopeDigest,
		ReceiptDescriptor: descriptor, ReceiptBody: receipt.Body,
		AuthorizedClaimIngressReceipt:         receipt.AuthorizedClaimIngressReceipt,
		CoverageEndCommitment:                 receipt.CoverageEndCommitment,
		AuthorityInstanceRecord:               receipt.AuthorityInstanceRecord,
		AuthorityAdmissionEligibilityProofSet: receipt.AuthorityAdmissionEligibilityProofSet,
		ReceiptAuthorizations:                 append([]ProfileQualifiedObjectAuthorizationV1(nil), receipt.Authorizations...),
		SealBody:                              seal, SealAuthorization: sealAuthorization}
	if err := ValidateClaimAdmissionReceiptProofV1(proof, terms, nil, nil, time.Unix(int64(seal.SealedAtUnix), 0).UTC(), false); err != nil {
		return ClaimAdmissionReceiptProofV1{}, err
	}
	return proof, nil
}

func ClaimAdmissionReceiptProofDigestV1(proof ClaimAdmissionReceiptProofV1) (string, error) {
	if proof.SchemaVersion != 1 || !validDigest(proof.ReceiptEnvelopeDigest) ||
		validateImmutableEvidenceDescriptor(proof.ReceiptDescriptor) != nil ||
		proof.ReceiptDescriptor.ContentDigest != proof.ReceiptEnvelopeDigest {
		return "", errors.New("claim admission receipt proof is malformed")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-admission-receipt-proof.v1", proof)
}

func ValidateClaimAdmissionReceiptProofV1(proof ClaimAdmissionReceiptProofV1, terms CoverageTermsV1,
	resolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time, verifySignatures bool) error {
	if _, err := ClaimAdmissionReceiptProofDigestV1(proof); err != nil || now.IsZero() {
		return errors.New("claim admission compact proof is invalid")
	}
	body := proof.ReceiptBody
	claim := proof.AuthorizedClaimIngressReceipt.AuthorizedClaim
	stage := "claim_revision_admission"
	if body.AdmissionKind == "initial" {
		stage = "initial_claim_admission"
	}
	bound, boundErr := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, stage)
	bodyDigest, bodyErr := guarantorCodec.Digest("tos.service.agent-guarantor-claim-admission-receipt-body.v1", body)
	claimDigest, claimErr := ClaimEnvelopeDigest(claim)
	ingressDigest, ingressErr := ClaimIngressReceiptDigestV1(proof.AuthorizedClaimIngressReceipt)
	endDigest, endErr := CoverageEndCommitmentDigestV1(proof.CoverageEndCommitment)
	instanceDigest, instanceErr := guarantorCodec.Digest("tos.service.authority-instance-record.v1", proof.AuthorityInstanceRecord)
	eligibilityDigest, eligibilityErr := AuthorityAdmissionEligibilityProofSetDigestV1(proof.AuthorityAdmissionEligibilityProofSet)
	termsDigest, termsErr := CoverageTermsDigest(terms)
	seal := proof.SealBody
	if boundErr != nil || bodyErr != nil || claimErr != nil || ingressErr != nil || endErr != nil || instanceErr != nil ||
		eligibilityErr != nil || termsErr != nil || seal.SchemaVersion != 1 ||
		seal.ReceiptEnvelopeDigest != proof.ReceiptEnvelopeDigest || seal.ReceiptBodyDigest != bodyDigest ||
		seal.AuthorizedActionDigest != body.AuthorizedActionDigest || seal.AuthorizedClaimEnvelopeDigest != claimDigest ||
		seal.ClaimIngressReceiptDigest != ingressDigest || seal.CoverageEndCommitmentDigest != endDigest ||
		seal.AuthorityInstanceRecordDigest != instanceDigest || seal.EligibilityProofSetDigest != eligibilityDigest ||
		seal.CoverageTermsDigest != termsDigest || seal.SealedAtUnix < body.AdmittedAtUnix || uint64(now.UTC().Unix()) < seal.SealedAtUnix ||
		proof.ReceiptDescriptor.RetrievalPolicyDigest != terms.ClaimAdmissionProfile.ProfileDigest ||
		body.AuthorizedClaimEnvelopeDigest != claimDigest || body.ClaimSubmissionIngressReceiptDigest != ingressDigest ||
		body.AuthorityInstanceID != proof.AuthorityInstanceRecord.AuthorityInstanceID ||
		proof.SealAuthorization.AuthoritySubject != bound.ActionAuthorityID ||
		proof.SealAuthorization.ValidationTimeUnix != seal.SealedAtUnix {
		return errors.New("claim admission compact proof binding is invalid")
	}
	if !verifySignatures {
		return nil
	}
	if resolver == nil {
		return errors.New("claim admission compact proof resolver is unavailable")
	}
	ingressValidationTime := time.Unix(int64(proof.AuthorizedClaimIngressReceipt.Body.ReceivedAtUnix), 0).UTC()
	if err := VerifyClaimSubmissionIngressReceiptV1(proof.AuthorizedClaimIngressReceipt, terms,
		mustStageActionAuthorityV1(terms, "claim_submission_ingress"), resolver, fenceResolver, ingressValidationTime); err != nil {
		return errors.New("claim admission proof has an invalid ingress receipt")
	}
	if err := ValidateAuthorizationQuorumSet(proof.ReceiptAuthorizations, "claim-admission-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-admission-receipt-signature.v1", terms.ClaimAdmissionAuthoritySubjects,
		terms.ClaimAdmissionQuorumRule, resolver, now); err != nil {
		return err
	}
	wire, err := resolveImmutableEvidenceV1(resolver, proof.ReceiptDescriptor,
		terms.SelectedAssuranceLevel == AssuranceIndependentlyEnforced)
	if err != nil {
		return err
	}
	if len(wire) != 0 {
		var complete AuthorizedClaimAdmissionReceiptV1
		if guarantorCodec.Unmarshal(wire, &complete) != nil {
			return errors.New("claim admission compact proof complete receipt is undecodable")
		}
		completeDigest, digestErr := ClaimAdmissionReceiptDigestV1(complete)
		completeSeal, completeDescriptor, sealErr := NewClaimAdmissionReceiptSealBodyV1(complete, terms,
			time.Unix(int64(seal.SealedAtUnix), 0).UTC())
		if digestErr != nil || sealErr != nil || completeDigest != proof.ReceiptEnvelopeDigest ||
			!equalCanonical(completeSeal, seal) || !equalCanonical(completeDescriptor, proof.ReceiptDescriptor) {
			return errors.New("claim admission compact proof differs from its immutable complete receipt")
		}
	}
	sealDigest, _ := guarantorCodec.Digest(ClaimAdmissionReceiptSealDomainV1, seal)
	return VerifyObjectAuthorization(proof.SealAuthorization, "claim-admission-receipt-seal", sealDigest,
		"tos.service.agent-guarantor-claim-admission-receipt-seal-signature.v1", resolver, now)
}

func mustStageActionAuthorityV1(terms CoverageTermsV1, stage string) GuarantorStageActionAuthorityV1 {
	value, _ := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, stage)
	return value
}
