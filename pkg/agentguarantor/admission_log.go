package agentguarantor

import (
	"errors"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const GuarantorAdmissionLogRootDomainV1 = "tos.service.agent-guarantor-admission-log-root.v1"

type GuarantorAdmissionLogEntryV1 struct {
	Sequence           uint64                         `json:"sequence"`
	StableActionID     string                         `json:"stable_action_id"`
	ExactRequestDigest string                         `json:"exact_request_digest"`
	ReceivedAtUnix     uint64                         `json:"received_at_unix"`
	LogRootAfter       string                         `json:"log_root_after"`
	Resolution         agentcommerce.ActionResolution `json:"resolution"`
}

func InitialAdmissionLogRootV1(domainID string) (string, error) {
	if !validDigest(domainID) {
		return "", errors.New("Guarantor admission domain is invalid")
	}
	return guarantorCodec.Digest(GuarantorAdmissionLogRootDomainV1, struct {
		DomainID string `json:"domain_id"`
		Sequence uint64 `json:"sequence"`
	}{domainID, 0})
}

func AdvanceAdmissionLogRootV1(domainID, priorRoot, stableActionID, exactRequestDigest string,
	sequence, receivedAtUnix uint64) (string, error) {
	if !validDigest(domainID) || !validDigest(priorRoot) || !validDigest(stableActionID) ||
		!validDigest(exactRequestDigest) || sequence == 0 || receivedAtUnix == 0 {
		return "", errors.New("Guarantor admission leaf is invalid")
	}
	return guarantorCodec.Digest(GuarantorAdmissionLogRootDomainV1, struct {
		DomainID, PriorRoot, StableActionID, ExactRequestDigest string
		Sequence, ReceivedAtUnix                                uint64
	}{domainID, priorRoot, stableActionID, exactRequestDigest, sequence, receivedAtUnix})
}

func ActivationAdmissionDomainIDV1(coverageAgreementBodyDigest string) (string, error) {
	if !validDigest(coverageAgreementBodyDigest) {
		return "", errors.New("coverage Agreement digest is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-activation-admission-domain.v1", struct {
		CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
	}{coverageAgreementBodyDigest})
}
