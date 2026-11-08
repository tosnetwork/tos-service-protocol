package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const NonActivationExposureReleaseDomainV1 = "tos.service.agent-guarantor-non-activation-exposure-release-envelope.v1"

// NonActivationExposureReleaseReceiptBodyV1 closes the otherwise leaking
// reservation after an accepted offer deterministically fails to activate.
// It is deliberately separate from the post-activation terminal claim set:
// no claim can be eligible on a never-activated coverage.
type NonActivationExposureReleaseReceiptBodyV1 struct {
	SchemaVersion                      uint16         `json:"schema_version"`
	AuthorityID                        string         `json:"authority_id"`
	GuarantorAgentID                   string         `json:"guarantor_agent_id"`
	CoverageAgreementBodyDigest        string         `json:"coverage_agreement_body_digest"`
	CoverageObligationID               string         `json:"coverage_obligation_id"`
	ReservationID                      string         `json:"reservation_id"`
	ExposureAdmissionReceiptDigest     string         `json:"exposure_admission_receipt_digest"`
	NonActivationEvidenceDigest        string         `json:"non_activation_evidence_digest"`
	AuthorizedActionDigest             string         `json:"authorized_action_digest"`
	StableActionID                     string         `json:"stable_action_id"`
	ExactRequestDigest                 string         `json:"exact_request_digest"`
	WriterGeneration                   uint64         `json:"writer_generation"`
	WriterFenceDigest                  string         `json:"writer_fence_digest"`
	BaseReleaseStateRevision           uint64         `json:"base_release_state_revision"`
	ReleasedReleaseStateRevision       uint64         `json:"released_release_state_revision"`
	ReleasedExposure                   AtomicAmountV1 `json:"released_exposure"`
	RemainingReservedExposure          AtomicAmountV1 `json:"remaining_reserved_exposure"`
	ClaimAdmissionHighWater            uint64         `json:"claim_admission_high_water"`
	PendingOrAmbiguousClaimActionCount uint64         `json:"pending_or_ambiguous_claim_action_count"`
	State                              string         `json:"state"`
	ReleasedAtUnix                     uint64         `json:"released_at_unix"`
}

type AuthorizedNonActivationExposureReleaseReceiptV1 struct {
	Body                               NonActivationExposureReleaseReceiptBodyV1    `json:"body"`
	StageActionAdmissionEvidence       PortableStageActionAdmissionEvidenceV1       `json:"stage_action_admission_evidence"`
	AuthorizedExposureAdmissionReceipt AuthorizedProviderExposureAdmissionReceiptV1 `json:"authorized_exposure_admission_receipt"`
	AuthorizedNonActivationEvidence    AuthorizedCoverageNonActivationEvidenceV1    `json:"authorized_non_activation_evidence"`
	Authorizations                     []ProfileQualifiedObjectAuthorizationV1      `json:"authorizations"`
}

func NonActivationExposureReleaseReceiptDigestV1(value AuthorizedNonActivationExposureReleaseReceiptV1) (string, error) {
	if value.Body.SchemaVersion != 1 || value.Body.State != "released" || len(value.Authorizations) == 0 {
		return "", errors.New("non-activation exposure release receipt is invalid")
	}
	return guarantorCodec.Digest(NonActivationExposureReleaseDomainV1, value)
}

func VerifyNonActivationExposureReleaseReceiptV1(value AuthorizedNonActivationExposureReleaseReceiptV1,
	offer AuthorizedFirmCoverageOfferV1, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if _, err := NonActivationExposureReleaseReceiptDigestV1(value); err != nil {
		return err
	}
	if err := VerifyCoverageNonActivationEvidenceV1(value.AuthorizedNonActivationEvidence, offer,
		agreementVerifier, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	if err := VerifyExposureAdmissionReceiptV1(value.AuthorizedExposureAdmissionReceipt,
		authorityResolver, now); err != nil || !equalCanonical(value.AuthorizedExposureAdmissionReceipt, offer.ExposureAdmissionReceipt) {
		return err
	}
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding,
		"post_acceptance_exposure_release")
	if err != nil {
		return err
	}
	body := value.Body
	nonActivationDigest, _ := CoverageNonActivationEvidenceDigestV1(value.AuthorizedNonActivationEvidence)
	exposureDigest, _ := ExposureAdmissionReceiptDigestV1(value.AuthorizedExposureAdmissionReceipt)
	zero := AtomicAmountV1{Asset: offer.CoverageTerms.CoverageAsset, AmountAtomic: "0"}
	if body.AuthorityID != bound.ActionAuthorityID || body.GuarantorAgentID != offer.Body.GuarantorAgentID ||
		body.CoverageAgreementBodyDigest != offer.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != offer.Body.CoverageObligationID || body.ReservationID != offer.Body.ReservationID ||
		body.ExposureAdmissionReceiptDigest != exposureDigest || body.NonActivationEvidenceDigest != nonActivationDigest ||
		body.ReleasedExposure != offer.ExposureAdmissionReceipt.Body.ReservedExposure || body.RemainingReservedExposure != zero ||
		body.ClaimAdmissionHighWater != 0 || body.PendingOrAmbiguousClaimActionCount != 0 ||
		body.ReleasedReleaseStateRevision != body.BaseReleaseStateRevision+1 || body.ReleasedAtUnix == 0 {
		return errors.New("non-activation exposure release binding is invalid")
	}
	request := ExposureReleaseActionBodyV1{ReservationID: body.ReservationID,
		AgreementDigest: body.CoverageAgreementBodyDigest, TargetPortfolioRevision: body.ReleasedReleaseStateRevision,
		TerminalEvidenceSetDigest: nonActivationDigest}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"reservation_id":               agentcommerce.Digest32(body.ReservationID),
		"target_revision":              agentcommerce.U64(body.ReleasedReleaseStateRevision),
		"terminal_evidence_set_digest": agentcommerce.Digest32(nonActivationDigest),
	}
	if err := verifyPortableStage(value.StageActionAdmissionEvidence, &bound, request, fields,
		"post_acceptance_exposure_release", body.AuthorizedActionDigest, body.StableActionID,
		body.ExactRequestDigest, body.WriterGeneration, body.WriterFenceDigest,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-non-activation-exposure-release-body.v1", body)
	return ValidateAuthorizationSet(value.Authorizations, "non-activation-exposure-release-receipt", bodyDigest,
		"tos.service.agent-guarantor-non-activation-exposure-release-signature.v1",
		[]string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}
