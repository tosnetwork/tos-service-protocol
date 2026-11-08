package agentguarantor

import (
	"errors"
)

const (
	ClaimIngressStateDomainV1           = "tos.service.agent-guarantor-claim-ingress-state-domain.v1"
	ClaimIngressLogIDDomainV1           = "tos.service.agent-guarantor-claim-ingress-log-id.v1"
	ClaimIngressLogRootDomainV1         = "tos.service.agent-guarantor-claim-ingress-log-root.v1"
	ClaimAdmissionLogIDDomainV1         = "tos.service.agent-guarantor-claim-admission-log-id.v1"
	ClaimAdmissionLogRootDomainV1       = "tos.service.agent-guarantor-claim-admission-log-root.v1"
	ClaimRevisionLogIDDomainV1          = "tos.service.agent-guarantor-claim-revision-log-id.v1"
	ClaimRevisionLogRootDomainV1        = "tos.service.agent-guarantor-claim-revision-log-root.v1"
	ClaimIngressReceiptEnvelopeDomain   = "tos.service.agent-guarantor-claim-ingress-receipt-envelope.v1"
	ClaimAdmissionReceiptEnvelopeDomain = "tos.service.agent-guarantor-claim-admission-envelope.v1"
)

type claimCoverageKeyV1 struct {
	CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
	CoverageObligationID        string `json:"coverage_obligation_id"`
}

type ClaimIngressLogLeafV1 struct {
	StableActionID     string `json:"stable_action_id"`
	ExactRequestDigest string `json:"exact_request_digest"`
	ReceivedAtUnix     uint64 `json:"received_at_unix"`
}

type InitialClaimAdmissionLeafV1 struct {
	ClaimID                       string `json:"claim_id"`
	AdmissionSequence             uint64 `json:"admission_sequence"`
	AuthorizedClaimEnvelopeDigest string `json:"authorized_claim_envelope_digest"`
}

func validateClaimCoverageKeyV1(agreementDigest, obligationID string) error {
	if !validDigest(agreementDigest) || !validToken(obligationID, 128) {
		return errors.New("claim log coverage key is invalid")
	}
	return nil
}

func ClaimIngressStateDomainDigestV1(agreementDigest, obligationID string) (string, error) {
	if err := validateClaimCoverageKeyV1(agreementDigest, obligationID); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ClaimIngressStateDomainV1, claimCoverageKeyV1{agreementDigest, obligationID})
}

// ClaimIngressLogIDV1 returns the Agreement-wide initial-claim log when
// claimID is empty and the per-claim revision-ingress log otherwise.
func ClaimIngressLogIDV1(agreementDigest, obligationID, claimID string) (string, error) {
	if err := validateClaimCoverageKeyV1(agreementDigest, obligationID); err != nil || claimID != "" && !validDigest(claimID) {
		return "", errors.New("claim ingress log identity is invalid")
	}
	return guarantorCodec.Digest(ClaimIngressLogIDDomainV1, struct {
		CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
		CoverageObligationID        string `json:"coverage_obligation_id"`
		ClaimID                     string `json:"claim_id,omitempty"`
	}{agreementDigest, obligationID, claimID})
}

func ClaimAdmissionLogIDV1(agreementDigest, obligationID string) (string, error) {
	if err := validateClaimCoverageKeyV1(agreementDigest, obligationID); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ClaimAdmissionLogIDDomainV1, claimCoverageKeyV1{agreementDigest, obligationID})
}

func ClaimRevisionLogIDV1(agreementDigest, obligationID, claimID string) (string, error) {
	if err := validateClaimCoverageKeyV1(agreementDigest, obligationID); err != nil || !validDigest(claimID) {
		return "", errors.New("claim revision log identity is invalid")
	}
	return guarantorCodec.Digest(ClaimRevisionLogIDDomainV1, struct {
		CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
		CoverageObligationID        string `json:"coverage_obligation_id"`
		ClaimID                     string `json:"claim_id"`
	}{agreementDigest, obligationID, claimID})
}

func InitialClaimLogRootV1(domain, logID string) (string, error) {
	if !validDigest(logID) || (domain != ClaimIngressLogRootDomainV1 && domain != ClaimAdmissionLogRootDomainV1 && domain != ClaimRevisionLogRootDomainV1) {
		return "", errors.New("claim log root identity is invalid")
	}
	return guarantorCodec.Digest(domain, struct {
		LogID    string `json:"log_id"`
		Sequence uint64 `json:"sequence"`
	}{logID, 0})
}

func AdvanceClaimLogRootV1(domain, logID, priorRoot string, sequence uint64, leaf any) (string, error) {
	if !validDigest(logID) || !validDigest(priorRoot) || sequence == 0 ||
		(domain != ClaimIngressLogRootDomainV1 && domain != ClaimAdmissionLogRootDomainV1 && domain != ClaimRevisionLogRootDomainV1) {
		return "", errors.New("claim log successor is invalid")
	}
	leafDigest, err := guarantorCodec.Digest(domain+".leaf", leaf)
	if err != nil {
		return "", err
	}
	return guarantorCodec.Digest(domain, struct {
		LogID, PriorRoot, LeafDigest string
		Sequence                     uint64
	}{logID, priorRoot, leafDigest, sequence})
}

func ClaimIngressReceiptDigestV1(value AuthorizedClaimSubmissionIngressReceiptV1) (string, error) {
	if value.Body.SchemaVersion != 1 || !validDigest(value.Body.AuthorizedClaimEnvelopeDigest) ||
		value.Body.State != "received" || len(value.Authorizations) == 0 {
		return "", errors.New("claim ingress receipt is invalid")
	}
	return guarantorCodec.Digest(ClaimIngressReceiptEnvelopeDomain, value)
}

func ClaimAdmissionReceiptDigestV1(value AuthorizedClaimAdmissionReceiptV1) (string, error) {
	if value.Body.SchemaVersion != 1 || !validDigest(value.Body.AuthorizedClaimEnvelopeDigest) ||
		!validDigest(value.Body.ClaimSubmissionIngressReceiptDigest) || len(value.Authorizations) == 0 {
		return "", errors.New("claim admission receipt is invalid")
	}
	return guarantorCodec.Digest(ClaimAdmissionReceiptEnvelopeDomain, value)
}
