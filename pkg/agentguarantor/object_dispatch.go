package agentguarantor

import (
	"errors"
	"math"
	"reflect"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// DecodeRegisteredObjectV1 is the released byte-level dispatcher for section
// 23.1. It rejects unknown object kinds, unknown fields, non-deterministic CBOR,
// wrong schema versions, and over-bound objects before a profile-specific
// semantic verifier is invoked.
func DecodeRegisteredObjectV1(kind string, canonical []byte) (any, error) {
	factory, found := guarantorObjectFactoriesV1()[kind]
	if !found || factory == nil {
		return nil, errors.New("unsupported Guarantor V1 object kind")
	}
	value := factory()
	if err := registeredObjectCodecV1(value).Unmarshal(canonical, value); err != nil {
		return nil, err
	}
	if err := requireSchemaVersionOneWhenPresent(value); err != nil {
		return nil, err
	}
	if err := rejectUnixSecondsOutsideSignedRange(reflect.ValueOf(value)); err != nil {
		return nil, err
	}
	return value, nil
}

// guarantorPackagePath identifies types declared by this profile.
var guarantorPackagePath = reflect.TypeOf(CommerceCarriageObjectV1{}).PkgPath()

// registeredObjectCodecV1 returns the codec whose limits own value's type. A
// registered kind whose type is declared by this package is a Guarantor
// object and uses GuarantorCodecLimitsV1; a kind that reuses another
// profile's type (for example the commerce Agreement body or the commerce
// profile event) keeps that profile's default limits, so registering it here
// never widens its bound.
func registeredObjectCodecV1(value any) codec.Bounded {
	typeOf := reflect.TypeOf(value)
	for typeOf != nil && typeOf.Kind() == reflect.Pointer {
		typeOf = typeOf.Elem()
	}
	if typeOf != nil && typeOf.PkgPath() == guarantorPackagePath {
		return guarantorCodec
	}
	return codec.Bounded{Limits: codec.DefaultLimits()}
}

// Every implementation eventually converts protocol wall-clock seconds to a
// signed time representation. Rejecting values above MaxInt64 at the closed
// decoder boundary prevents uint64-to-int64 wraparound from turning a far-
// future expiry into a pre-epoch instant (or vice versa).
func rejectUnixSecondsOutsideSignedRange(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Struct:
		typeOf := value.Type()
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			name := typeOf.Field(index).Name
			if strings.HasSuffix(name, "Unix") && field.Kind() >= reflect.Uint && field.Kind() <= reflect.Uint64 &&
				field.Uint() > math.MaxInt64 {
				return errors.New("Guarantor Unix timestamp exceeds the signed protocol range")
			}
			if err := rejectUnixSecondsOutsideSignedRange(field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := rejectUnixSecondsOutsideSignedRange(value.Index(index)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if err := rejectUnixSecondsOutsideSignedRange(iterator.Value()); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireSchemaVersionOneWhenPresent(value any) error {
	current := reflect.ValueOf(value)
	if current.Kind() == reflect.Pointer {
		current = current.Elem()
	}
	if current.Kind() != reflect.Struct {
		return nil
	}
	field := current.FieldByName("SchemaVersion")
	if field.IsValid() && field.Kind() >= reflect.Uint && field.Kind() <= reflect.Uint64 && field.Uint() != 1 {
		return errors.New("Guarantor V1 object has a non-V1 schema version")
	}
	return nil
}

func guarantorObjectFactoriesV1() map[string]func() any {
	return map[string]func() any{
		"service-profile-revision-artifact":             func() any { return &GuarantorServiceProfileRevisionArtifactV1{} },
		"service-profile-artifact":                      func() any { return &GuarantorServiceProfileArtifactV1{} },
		"service-profile":                               func() any { return &ServiceProfileV1{} },
		"collateral-profile":                            func() any { return &CollateralProfileV1{} },
		"collateral-transition-profile":                 func() any { return &CollateralTransitionProfileV1{} },
		"claim-profile":                                 func() any { return &ClaimProfileV1{} },
		"claim-closure-capacity":                        func() any { return &ClaimClosureCapacityV1{} },
		"stage-action-admission-body":                   func() any { return &PortableStageActionAdmissionBodyV1{} },
		"stage-action-admission-evidence":               func() any { return &PortableStageActionAdmissionEvidenceV1{} },
		"payout-execution-evidence":                     func() any { return &AuthorizedGuarantorPayoutExecutionEvidenceV1{} },
		"payout-destination":                            func() any { return &PayoutDestinationV1{} },
		"coverage-end-commitment":                       func() any { return &CoverageEndCommitmentV1{} },
		"stage-operation-binding":                       func() any { return &GuarantorStageOperationBindingV1{} },
		"collateral-control-disclosure":                 func() any { return &CollateralControlDisclosureV1{} },
		"collateral-control-evidence":                   func() any { return &AuthorizedCollateralControlEvidenceV1{} },
		"operational-independence-terms":                func() any { return &GuarantorOperationalIndependenceTermsV1{} },
		"operational-independence-evidence":             func() any { return &AuthorizedGuarantorOperationalIndependenceEvidenceV1{} },
		"requested-coverage-terms":                      func() any { return &RequestedCoverageTermsV1{} },
		"quote-request":                                 func() any { return &AuthorizedCoverageQuoteRequestV1{} },
		"coverage-terms":                                func() any { return &CoverageTermsV1{} },
		"cancellation-policy":                           func() any { return &CoverageCancellationPolicyV1{} },
		"coverage-agreement":                            func() any { return &agentcommerce.AgentAgreementBody{} },
		"agreement-authorization-set":                   func() any { return &GuarantorAgreementAuthorizationEvidenceSetV1{} },
		"authority-admission-proof":                     func() any { return &AuthorityAdmissionEligibilityProofV1{} },
		"authority-admission-proof-set":                 func() any { return &AuthorityAdmissionEligibilityProofSetV1{} },
		"firm-offer-agreement-evidence":                 func() any { return &GuarantorFirmOfferAgreementEvidenceV1{} },
		"guarantor-evidence-set":                        func() any { return &CanonicalGuarantorEvidenceSetV1{} },
		"exposure-admission-descriptor":                 func() any { return &ProviderExposureAdmissionDescriptorV1{} },
		"firm-offer-recipient-set":                      func() any { return &FirmOfferRecipientSetV1{} },
		"exposure-reservation-scope":                    func() any { return &ProviderExposureReservationScopeV1{} },
		"firm-offer-authority-instance-effect":          func() any { return &FirmOfferAuthorityInstanceEffectV1{} },
		"exposure-admission-receipt":                    func() any { return &AuthorizedProviderExposureAdmissionReceiptV1{} },
		"firm-offer":                                    func() any { return &AuthorizedFirmCoverageOfferV1{} },
		"offer-non-acceptance":                          func() any { return &AuthorizedOfferNonAcceptanceEvidenceV1{} },
		"pre-acceptance-exposure-release":               func() any { return &AuthorizedPreAcceptanceExposureReleaseReceiptV1{} },
		"acceptance-request":                            func() any { return &AuthorizedCoverageAcceptanceRequestV1{} },
		"acceptance-receipt":                            func() any { return &AuthorizedCoverageAcceptanceReceiptV1{} },
		"activation-admission-cut":                      func() any { return &ActivationAdmissionCutProofV1{} },
		"activation-evidence":                           func() any { return &AuthorizedCoverageActivationEvidenceV1{} },
		"non-activation-evidence":                       func() any { return &AuthorizedCoverageNonActivationEvidenceV1{} },
		"non-activation-exposure-release":               func() any { return &AuthorizedNonActivationExposureReleaseReceiptV1{} },
		"cancellation-request":                          func() any { return &AuthorizedCoverageCancellationRequestV1{} },
		"cancellation-receipt":                          func() any { return &AuthorizedCoverageCancellationReceiptV1{} },
		"collateral-terms":                              func() any { return &CollateralTermsV1{} },
		"collateral-position-state":                     func() any { return &CollateralPositionStateV1{} },
		"collateral-adapter-request":                    func() any { return &CollateralAdapterRequestV1{} },
		"collateral-adapter-evidence":                   func() any { return &CollateralAdapterEvidenceV1{} },
		"collateral-evidence":                           func() any { return &AuthorizedCollateralEvidenceV1{} },
		"collateral-payout-payment-evidence-projection": func() any { return &CollateralPayoutPaymentEvidenceProjectionV1{} },
		"triggered-obligation-set":                      func() any { return &TriggeredObligationSetV1{} },
		"claim-evidence-manifest":                       func() any { return &ClaimEvidenceManifestV1{} },
		"other-recovery-declaration":                    func() any { return &OtherRecoveryDeclarationV1{} },
		"claim":                                         func() any { return &AuthorizedCoverageClaimV1{} },
		"claim-ingress-receipt":                         func() any { return &AuthorizedClaimSubmissionIngressReceiptV1{} },
		"claim-ingress-cut":                             func() any { return &ClaimIngressAdmissionCutProofV1{} },
		"claim-submission-authority-instance-effect":    func() any { return &ClaimSubmissionAuthorityInstanceEffectV1{} },
		"claim-admission-receipt":                       func() any { return &AuthorizedClaimAdmissionReceiptV1{} },
		"claim-filing-close-receipt":                    func() any { return &AuthorizedClaimFilingCloseReceiptV1{} },
		"claim-decision":                                func() any { return &AuthorizedClaimDecisionV1{} },
		"claim-revision-epoch-expectation":              func() any { return &ClaimRevisionEpochExpectationV1{} },
		"claim-decision-admission-receipt":              func() any { return &AuthorizedClaimDecisionAdmissionReceiptV1{} },
		"claim-decision-admission-receipt-seal":         func() any { return &ClaimDecisionAdmissionReceiptSealBodyV1{} },
		"claim-decision-admission-receipt-proof":        func() any { return &ClaimDecisionAdmissionReceiptProofV1{} },
		"decision-application-token":                    func() any { return &DecisionApplicationTokenV1{} },
		"claim-decision-application-receipt":            func() any { return &AuthorizedClaimDecisionApplicationReceiptV1{} },
		"decision-application-receipt-seal":             func() any { return &DecisionApplicationReceiptSealBodyV1{} },
		"decision-application-receipt-proof":            func() any { return &DecisionApplicationReceiptProofV1{} },
		"claim-admission-receipt-proof":                 func() any { return &ClaimAdmissionReceiptProofV1{} },
		"claim-admission-receipt-seal":                  func() any { return &ClaimAdmissionReceiptSealBodyV1{} },
		"claim-state-transition-receipt":                func() any { return &AuthorizedClaimStateTransitionReceiptV1{} },
		"conditional-settlement-template":               func() any { return &ConditionalSettlementTemplateV1{} },
		"settlement-parameters":                         func() any { return &ProfileQualifiedSettlementParametersV1{} },
		"claim-payout-line":                             func() any { return &ClaimPayoutLineV1{} },
		"materialized-payout-line":                      func() any { return &MaterializedPayoutLineV1{} },
		"materialized-payout-set":                       func() any { return &MaterializedPayoutObligationSetV1{} },
		"terminal-payout-set":                           func() any { return &TerminalPayoutEvidenceSetV1{} },
		"coverage-terminal-payout-set":                  func() any { return &CoverageTerminalPayoutEvidenceSetV1{} },
		"claim-terminal-resolution-ref-set":             func() any { return &ClaimTerminalResolutionRefSetV1{} },
		"coverage-closure-context":                      func() any { return &CoverageClosureEvidenceContextV1{} },
		"terminal-claim-set":                            func() any { return &AuthorizedTerminalClaimSetEvidenceV1{} },
		"exposure-disposition":                          func() any { return &ExposureDispositionComputationV1{} },
		"exposure-release-receipt":                      func() any { return &AuthorizedExposureReleaseReceiptV1{} },
		"coverage-resolution":                           func() any { return &AuthorizedCoverageResolutionV1{} },
		"transition-evidence-projection":                func() any { return &TransitionEvidenceProjectionV1{} },
		"pre-acceptance-release-projection":             func() any { return &PreAcceptanceExposureReleaseEvidenceProjectionV1{} },
		"exposure-release-projection":                   func() any { return &ExposureReleaseEvidenceProjectionV1{} },
		"commerce-profile-event":                        func() any { return &agentcommerce.CommerceProfileEventV1{} },
		"object-verifier-registry":                      func() any { return &ObjectVerifierRegistryV1{} },
		"mutation-verifier-registry":                    func() any { return &MutationVerifierRegistryV1{} },
	}
}

// ReleasedObjectSchemaSamplesV1 returns one zero-value pointer for every
// released object kind. It is intended for deterministic schema generators;
// callers must not treat the samples as semantically valid protocol objects.
func ReleasedObjectSchemaSamplesV1() map[string]any {
	factories := guarantorObjectFactoriesV1()
	result := make(map[string]any, len(factories))
	for kind, factory := range factories {
		result[kind] = factory()
	}
	return result
}
