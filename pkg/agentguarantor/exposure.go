package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	ExposureDescriptorDomain = "tos.service.agent-guarantor-exposure-admission.v1"
	ExposureReceiptDomain    = "tos.service.agent-guarantor-exposure-receipt-envelope.v1"
)

type ProviderExposureReservationScopeV1 struct {
	SchemaVersion               uint16          `json:"schema_version"`
	OwnerID                     string          `json:"owner_id"`
	GuarantorAgentID            string          `json:"guarantor_agent_id"`
	CoverageAgreementBodyDigest string          `json:"coverage_agreement_body_digest"`
	CoverageObligationID        string          `json:"coverage_obligation_id"`
	CoverageAsset               AssetIdentityV1 `json:"coverage_asset"`
	MaximumAggregatePayout      AtomicAmountV1  `json:"maximum_aggregate_payout"`
	SelectedAssuranceLevel      AssuranceLevel  `json:"selected_assurance_level"`
	PolicyBucketDigest          string          `json:"policy_bucket_digest"`
	CorrelationBucketDigest     string          `json:"correlation_bucket_digest"`
	DefaultLiabilityDisposition string          `json:"default_liability_disposition"`
	ReservationExpiresAtUnix    uint64          `json:"reservation_expires_at_unix"`
}

type ProviderExposureAdmissionDescriptorV1 struct {
	SchemaVersion               uint16                             `json:"schema_version"`
	GuarantorAgentID            string                             `json:"guarantor_agent_id"`
	ServiceProfileDigest        string                             `json:"service_profile_digest"`
	QuoteRequestDigest          string                             `json:"quote_request_digest"`
	CoverageID                  string                             `json:"coverage_id"`
	CoverageVersion             uint64                             `json:"coverage_version"`
	CoverageAgreementBodyDigest string                             `json:"coverage_agreement_body_digest"`
	CoverageTermsDigest         string                             `json:"coverage_terms_digest"`
	ReservationScope            ProviderExposureReservationScopeV1 `json:"reservation_scope"`
	ReservationScopeDigest      string                             `json:"reservation_scope_digest"`
	ReservedExposure            AtomicAmountV1                     `json:"reserved_exposure"`
	CollateralCredit            AtomicAmountV1                     `json:"collateral_credit"`
	PolicyBucketDigest          string                             `json:"policy_bucket_digest"`
	CorrelationBucketDigest     string                             `json:"correlation_bucket_digest"`
	BasePortfolioRevision       uint64                             `json:"base_portfolio_revision"`
	ReservationExpiresAtUnix    uint64                             `json:"reservation_expires_at_unix"`
}

type ProviderExposureAdmissionReceiptBodyV1 struct {
	SchemaVersion                               uint16         `json:"schema_version"`
	AuthorityID                                 string         `json:"authority_id"`
	GuarantorAgentID                            string         `json:"guarantor_agent_id"`
	DescriptorDigest                            string         `json:"descriptor_digest"`
	AuthorizedActionDigest                      string         `json:"authorized_action_digest"`
	ReservationID                               string         `json:"reservation_id"`
	StableActionID                              string         `json:"stable_action_id"`
	ExactRequestDigest                          string         `json:"exact_request_digest"`
	WriterGeneration                            uint64         `json:"writer_generation"`
	WriterFenceDigest                           string         `json:"writer_fence_digest"`
	BasePortfolioRevision                       uint64         `json:"base_portfolio_revision"`
	AdmittedPortfolioRevision                   uint64         `json:"admitted_portfolio_revision"`
	ReservedExposure                            AtomicAmountV1 `json:"reserved_exposure"`
	State                                       string         `json:"state"`
	AdmittedAtUnix                              uint64         `json:"admitted_at_unix"`
	ExpiresAtUnix                               uint64         `json:"expires_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string         `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedProviderExposureAdmissionReceiptV1 struct {
	Body                                  ProviderExposureAdmissionReceiptBodyV1  `json:"body"`
	Descriptor                            ProviderExposureAdmissionDescriptorV1   `json:"descriptor"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1 `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

func ExposureReservationScopeDigestV1(scope ProviderExposureReservationScopeV1) (string, error) {
	if err := validateExposureReservationScope(scope); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-reservation-scope.v1", scope)
}

func ExposureAdmissionDescriptorDigestV1(descriptor ProviderExposureAdmissionDescriptorV1) (string, error) {
	if err := validateExposureDescriptor(descriptor); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ExposureDescriptorDomain, descriptor)
}

func ExposureAdmissionReceiptDigestV1(receipt AuthorizedProviderExposureAdmissionReceiptV1) (string, error) {
	if err := validateExposureReceiptShape(receipt); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ExposureReceiptDomain, receipt)
}

func VerifyExposureAdmissionReceiptV1(receipt AuthorizedProviderExposureAdmissionReceiptV1,
	resolver AuthorityKeyResolver, now time.Time) error {
	if err := validateExposureReceiptShape(receipt); err != nil {
		return err
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-exposure-receipt-body.v1", receipt.Body)
	return ValidateAuthorizationSet(receipt.Authorizations, "exposure-admission-receipt", bodyDigest,
		"tos.service.agent-guarantor-exposure-receipt-signature.v1", []string{receipt.Body.GuarantorAgentID}, resolver, now)
}

func validateExposureReservationScope(scope ProviderExposureReservationScopeV1) error {
	if scope.SchemaVersion != 1 || !validID(scope.OwnerID) || !validID(scope.GuarantorAgentID) ||
		!validDigest(scope.CoverageAgreementBodyDigest) || !validToken(scope.CoverageObligationID, 128) ||
		agentcommerce.ValidateAssetIdentityV1(scope.CoverageAsset) != nil || validateAmount(scope.MaximumAggregatePayout, true) != nil ||
		scope.MaximumAggregatePayout.Asset != scope.CoverageAsset || !validDigest(scope.PolicyBucketDigest) ||
		!validDigest(scope.CorrelationBucketDigest) || scope.ReservationExpiresAtUnix == 0 ||
		(scope.DefaultLiabilityDisposition != "charge_off" && scope.DefaultLiabilityDisposition != "retain") {
		return errors.New("Guarantor exposure reservation scope is invalid")
	}
	switch scope.SelectedAssuranceLevel {
	case AssuranceUnsecuredSigned, AssuranceCollateralAttested, AssuranceIndependentlyEnforced:
	default:
		return errors.New("Guarantor exposure assurance level is invalid")
	}
	return nil
}

func validateExposureDescriptor(descriptor ProviderExposureAdmissionDescriptorV1) error {
	scopeDigest, err := ExposureReservationScopeDigestV1(descriptor.ReservationScope)
	if err != nil || descriptor.SchemaVersion != 1 || !validID(descriptor.GuarantorAgentID) ||
		!validDigest(descriptor.ServiceProfileDigest) || !validDigest(descriptor.QuoteRequestDigest) ||
		!validDigest(descriptor.CoverageID) || descriptor.CoverageVersion == 0 ||
		!validDigest(descriptor.CoverageAgreementBodyDigest) || !validDigest(descriptor.CoverageTermsDigest) ||
		descriptor.ReservationScopeDigest != scopeDigest || validateAmount(descriptor.ReservedExposure, true) != nil ||
		validateAmount(descriptor.CollateralCredit, false) != nil || descriptor.ReservedExposure.Asset != descriptor.CollateralCredit.Asset ||
		descriptor.PolicyBucketDigest != descriptor.ReservationScope.PolicyBucketDigest ||
		descriptor.CorrelationBucketDigest != descriptor.ReservationScope.CorrelationBucketDigest ||
		descriptor.ReservationExpiresAtUnix != descriptor.ReservationScope.ReservationExpiresAtUnix ||
		descriptor.BasePortfolioRevision == 0 {
		return errors.New("Guarantor exposure descriptor is invalid")
	}
	return nil
}

func validateExposureReceiptShape(receipt AuthorizedProviderExposureAdmissionReceiptV1) error {
	descriptorDigest, err := ExposureAdmissionDescriptorDigestV1(receipt.Descriptor)
	body := receipt.Body
	if err != nil || body.SchemaVersion != 1 || !validID(body.AuthorityID) || !validID(body.GuarantorAgentID) ||
		body.DescriptorDigest != descriptorDigest || !validDigest(body.AuthorizedActionDigest) || !validDigest(body.ReservationID) ||
		!validDigest(body.StableActionID) || !validDigest(body.ExactRequestDigest) || body.WriterGeneration == 0 ||
		!validDigest(body.WriterFenceDigest) || body.BasePortfolioRevision == 0 ||
		body.AdmittedPortfolioRevision != body.BasePortfolioRevision+1 || body.ReservedExposure != receipt.Descriptor.ReservedExposure ||
		body.State != "reserved" || body.AdmittedAtUnix == 0 || body.ExpiresAtUnix != receipt.Descriptor.ReservationExpiresAtUnix ||
		!validDigest(body.AuthorityAdmissionEligibilityProofSetDigest) || len(receipt.Authorizations) == 0 ||
		body.GuarantorAgentID != receipt.Descriptor.GuarantorAgentID {
		return errors.New("Guarantor exposure admission receipt is invalid")
	}
	proofDigest, digestErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if digestErr != nil || proofDigest != body.AuthorityAdmissionEligibilityProofSetDigest {
		return errors.New("Guarantor exposure eligibility proof set differs from its digest")
	}
	return nil
}
