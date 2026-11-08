package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	OfferNonAcceptanceDomain   = "tos.service.agent-guarantor-offer-non-acceptance-envelope.v1"
	PreAcceptanceReleaseDomain = "tos.service.agent-guarantor-pre-acceptance-release-receipt-envelope.v1"
)

type OfferNonAcceptanceEvidenceBodyV1 struct {
	SchemaVersion                     uint16 `json:"schema_version"`
	AuthorityID                       string `json:"authority_id"`
	AuthorityInstanceID               string `json:"authority_instance_id"`
	ReservationID                     string `json:"reservation_id"`
	AuthorizedFirmOfferEnvelopeDigest string `json:"authorized_firm_offer_envelope_digest"`
	AcceptanceAdmissionLogID          string `json:"acceptance_admission_log_id"`
	AcceptanceAdmissionHighWater      uint64 `json:"acceptance_admission_high_water"`
	AcceptanceAdmissionLogRoot        string `json:"acceptance_admission_log_root"`
	AcceptanceCutoffUnix              uint64 `json:"acceptance_cutoff_unix"`
	SequencedByCutoffCount            uint64 `json:"sequenced_by_cutoff_count"`
	TerminalRejectedCount             uint64 `json:"terminal_rejected_count"`
	AcceptedCount                     uint64 `json:"accepted_count"`
	PendingOrAmbiguousCount           uint64 `json:"pending_or_ambiguous_count"`
	ExpectedReservationRevision       uint64 `json:"expected_reservation_revision"`
	PriorOfferStateRevision           uint64 `json:"prior_offer_state_revision"`
	ResolvedOfferStateRevision        uint64 `json:"resolved_offer_state_revision"`
	AuthorizedActionDigest            string `json:"authorized_action_digest"`
	StableActionID                    string `json:"stable_action_id"`
	ExactRequestDigest                string `json:"exact_request_digest"`
	WriterGeneration                  uint64 `json:"writer_generation"`
	WriterFenceDigest                 string `json:"writer_fence_digest"`
	ResolvedAtUnix                    uint64 `json:"resolved_at_unix"`
}

type AuthorizedOfferNonAcceptanceEvidenceV1 struct {
	Body                     OfferNonAcceptanceEvidenceBodyV1        `json:"body"`
	AuthorizedFirmOffer      AuthorizedFirmCoverageOfferV1           `json:"authorized_firm_offer"`
	IssuanceActionResolution agentcommerce.ActionResolution          `json:"issuance_action_resolution"`
	Authorizations           []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

type OfferNonAcceptanceResolutionActionBodyV1 struct {
	SchemaVersion               uint16                         `json:"schema_version"`
	AuthorityInstanceID         string                         `json:"authority_instance_id"`
	AuthorizedFirmOffer         AuthorizedFirmCoverageOfferV1  `json:"authorized_firm_offer"`
	IssuanceActionResolution    agentcommerce.ActionResolution `json:"issuance_action_resolution"`
	ReleaseReason               string                         `json:"release_reason"`
	AcceptanceCutoffUnix        uint64                         `json:"acceptance_cutoff_unix"`
	ExpectedReservationRevision uint64                         `json:"expected_reservation_revision"`
	ExpectedOfferStateRevision  uint64                         `json:"expected_offer_state_revision"`
	TargetOfferStateRevision    uint64                         `json:"target_offer_state_revision"`
}

type PreAcceptanceExposureReleaseEvidenceProjectionV1 struct {
	SchemaVersion                     uint16 `json:"schema_version"`
	AuthorityInstanceID               string `json:"authority_instance_id"`
	ReservationID                     string `json:"reservation_id"`
	ExposureReceiptDigest             string `json:"exposure_receipt_digest"`
	AuthorizedFirmOfferEnvelopeDigest string `json:"authorized_firm_offer_envelope_digest"`
	ReleaseReason                     string `json:"release_reason"`
	NonAcceptanceEvidenceDigest       string `json:"non_acceptance_evidence_digest"`
}

type PreAcceptanceExposureReleaseActionBodyV1 struct {
	SchemaVersion                   uint16                                           `json:"schema_version"`
	ReleaseVariant                  string                                           `json:"release_variant"`
	AuthorizedNonAcceptanceEvidence AuthorizedOfferNonAcceptanceEvidenceV1           `json:"authorized_non_acceptance_evidence"`
	ReleaseEvidenceProjection       PreAcceptanceExposureReleaseEvidenceProjectionV1 `json:"release_evidence_projection"`
	ExpectedPortfolioRevision       uint64                                           `json:"expected_portfolio_revision"`
	TargetPortfolioRevision         uint64                                           `json:"target_portfolio_revision"`
	ExpectedReservedExposure        AtomicAmountV1                                   `json:"expected_reserved_exposure"`
}

type PreAcceptanceExposureReleaseReceiptBodyV1 struct {
	SchemaVersion                     uint16         `json:"schema_version"`
	AuthorityID                       string         `json:"authority_id"`
	GuarantorAgentID                  string         `json:"guarantor_agent_id"`
	AuthorityInstanceID               string         `json:"authority_instance_id"`
	ReservationID                     string         `json:"reservation_id"`
	ExposureReceiptDigest             string         `json:"exposure_receipt_digest"`
	AuthorizedFirmOfferEnvelopeDigest string         `json:"authorized_firm_offer_envelope_digest"`
	ReleaseReason                     string         `json:"release_reason"`
	NonAcceptanceEvidenceDigest       string         `json:"non_acceptance_evidence_digest"`
	ReleaseEvidenceProjectionDigest   string         `json:"release_evidence_projection_digest"`
	AuthorizedActionDigest            string         `json:"authorized_action_digest"`
	StableActionID                    string         `json:"stable_action_id"`
	ExactRequestDigest                string         `json:"exact_request_digest"`
	WriterGeneration                  uint64         `json:"writer_generation"`
	WriterFenceDigest                 string         `json:"writer_fence_digest"`
	BasePortfolioRevision             uint64         `json:"base_portfolio_revision"`
	ReleasedPortfolioRevision         uint64         `json:"released_portfolio_revision"`
	ReleasedExposure                  AtomicAmountV1 `json:"released_exposure"`
	RemainingReservedExposure         AtomicAmountV1 `json:"remaining_reserved_exposure"`
	State                             string         `json:"state"`
	ReleasedAtUnix                    uint64         `json:"released_at_unix"`
}

type AuthorizedPreAcceptanceExposureReleaseReceiptV1 struct {
	Body                            PreAcceptanceExposureReleaseReceiptBodyV1        `json:"body"`
	AuthorizedNonAcceptanceEvidence AuthorizedOfferNonAcceptanceEvidenceV1           `json:"authorized_non_acceptance_evidence"`
	ReleaseEvidenceProjection       PreAcceptanceExposureReleaseEvidenceProjectionV1 `json:"release_evidence_projection"`
	Authorizations                  []ProfileQualifiedObjectAuthorizationV1          `json:"authorizations"`
}

func OfferNonAcceptanceDigestV1(value AuthorizedOfferNonAcceptanceEvidenceV1) (string, error) {
	if value.Body.SchemaVersion != 1 || value.Body.AcceptedCount != 0 || value.Body.PendingOrAmbiguousCount != 0 ||
		value.Body.SequencedByCutoffCount != value.Body.TerminalRejectedCount ||
		value.Body.ResolvedOfferStateRevision != value.Body.PriorOfferStateRevision+1 ||
		!validDigest(value.Body.AuthorizedFirmOfferEnvelopeDigest) || !validDigest(value.Body.AcceptanceAdmissionLogRoot) ||
		!validDigest(value.Body.AuthorizedActionDigest) || !validDigest(value.Body.StableActionID) ||
		!validDigest(value.Body.ExactRequestDigest) || !validDigest(value.Body.WriterFenceDigest) ||
		len(value.Authorizations) == 0 {
		return "", errors.New("Guarantor offer non-acceptance evidence is invalid")
	}
	offerDigest, err := FirmOfferDigest(value.AuthorizedFirmOffer)
	if err != nil || offerDigest != value.Body.AuthorizedFirmOfferEnvelopeDigest ||
		value.Body.AuthorityInstanceID != value.AuthorizedFirmOffer.Body.OfferID ||
		value.Body.ReservationID != value.AuthorizedFirmOffer.Body.ReservationID ||
		value.Body.AcceptanceCutoffUnix != value.AuthorizedFirmOffer.Body.AcceptByUnix ||
		value.IssuanceActionResolution.State != agentcommerce.ActionTerminal {
		return "", errors.New("Guarantor offer non-acceptance evidence does not bind the issued offer")
	}
	return guarantorCodec.Digest(OfferNonAcceptanceDomain, value)
}

func VerifyOfferNonAcceptanceV1(value AuthorizedOfferNonAcceptanceEvidenceV1, resolver AuthorityKeyResolver,
	now time.Time) error {
	digest, err := OfferNonAcceptanceDigestV1(value)
	if err != nil || uint64(now.UTC().Unix()) < value.Body.ResolvedAtUnix {
		return errors.New("Guarantor offer non-acceptance evidence is invalid at verification time")
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-offer-non-acceptance-body.v1", value.Body)
	if err := ValidateAuthorizationSet(value.Authorizations, "offer-non-acceptance", bodyDigest,
		"tos.service.agent-guarantor-offer-non-acceptance-signature.v1",
		[]string{value.AuthorizedFirmOffer.Body.GuarantorAgentID}, resolver, now); err != nil {
		return err
	}
	_ = digest
	return nil
}

func PreAcceptanceExposureReleaseReceiptDigestV1(value AuthorizedPreAcceptanceExposureReleaseReceiptV1) (string, error) {
	if value.Body.SchemaVersion != 1 || value.Body.State != "released_unaccepted" ||
		value.Body.ReleasedPortfolioRevision != value.Body.BasePortfolioRevision+1 ||
		value.Body.RemainingReservedExposure.AmountAtomic != "0" || len(value.Authorizations) == 0 {
		return "", errors.New("Guarantor pre-acceptance release receipt is invalid")
	}
	nonAcceptanceDigest, err := OfferNonAcceptanceDigestV1(value.AuthorizedNonAcceptanceEvidence)
	projectionDigest, projectionErr := guarantorCodec.Digest("tos.service.agent-guarantor-pre-acceptance-release-evidence-projection.v1",
		value.ReleaseEvidenceProjection)
	if err != nil || projectionErr != nil || nonAcceptanceDigest != value.Body.NonAcceptanceEvidenceDigest ||
		projectionDigest != value.Body.ReleaseEvidenceProjectionDigest || value.Body.AuthorityInstanceID != value.ReleaseEvidenceProjection.AuthorityInstanceID ||
		value.Body.ReservationID != value.ReleaseEvidenceProjection.ReservationID ||
		value.Body.ExposureReceiptDigest != value.ReleaseEvidenceProjection.ExposureReceiptDigest ||
		value.Body.AuthorizedFirmOfferEnvelopeDigest != value.ReleaseEvidenceProjection.AuthorizedFirmOfferEnvelopeDigest {
		return "", errors.New("Guarantor pre-acceptance release receipt binding is invalid")
	}
	return guarantorCodec.Digest(PreAcceptanceReleaseDomain, value)
}
