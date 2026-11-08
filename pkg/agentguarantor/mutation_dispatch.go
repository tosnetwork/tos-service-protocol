package agentguarantor

import (
	"errors"
	"reflect"
)

type MutationDispatchKeyV1 struct {
	ActionKind       string
	OperationPurpose string
}

// DecodeMutationRequestV1 binds action kind and operation purpose to exactly
// one released canonical request type. It is deliberately closed-world.
func DecodeMutationRequestV1(actionKind, operationPurpose string, canonical []byte) (any, error) {
	factory, found := guarantorMutationFactoriesV1()[MutationDispatchKeyV1{ActionKind: actionKind,
		OperationPurpose: operationPurpose}]
	if !found || factory == nil {
		return nil, errors.New("unsupported Guarantor V1 mutation")
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

func guarantorMutationFactoriesV1() map[MutationDispatchKeyV1]func() any {
	return map[MutationDispatchKeyV1]func() any{
		{"commercial.quote.close", "offer-non-acceptance"}:               func() any { return &OfferNonAcceptanceResolutionActionBodyV1{} },
		{"commercial.quote.issue", "firm-offer-issuance"}:                func() any { return &FirmOfferIssuanceActionBodyV1{} },
		{"collateral.transition", "collateral-transition"}:               func() any { return &CollateralTransitionActionBodyV1{} },
		{"conditional.claim-decision.admit", "claim-decision-admission"}: func() any { return &ClaimDecisionAdmissionActionBodyV1{} },
		{"conditional.claim-filing.close", "claim-filing-close"}:         func() any { return &ClaimFilingCloseActionBodyV1{} },
		{"conditional.claim.decide", "claim-decision-application"}:       func() any { return &ClaimDecisionApplicationActionBodyV1{} },
		{"conditional.claim.ingress", "claim-submission-ingress"}:        func() any { return &ClaimSubmissionIngressActionBodyV1{} },
		{"conditional.claim.submit", "claim-admission"}:                  func() any { return &ClaimSubmissionActionBodyV1{} },
		{"conditional.claim.transition", "claim-state-transition"}:       func() any { return &ClaimStateTransitionActionBodyV1{} },
		{"conditional.obligation.transition", "coverage-acceptance"}:     func() any { return &CoverageAcceptanceAdmissionActionBodyV1{} },
		{"conditional.obligation.transition", "coverage-activation"}:     func() any { return &CoverageActivationActionBodyV1{} },
		{"conditional.obligation.transition", "coverage-cancellation"}:   func() any { return &CoverageCancellationActionBodyV1{} },
		{"conditional.obligation.transition", "coverage-closure"}:        func() any { return &CoverageClosureActionBodyV1{} },
		{"conditional.obligation.transition", "coverage-non-activation"}: func() any { return &CoverageNonActivationActionBodyV1{} },
		{"conditional.obligation.transition", "coverage-resolution"}:     func() any { return &CoverageResolutionActionBodyV1{} },
		{"payment.direct", "guarantor-payout"}:                           func() any { return &GuarantorAgreementPaymentActionBodyV1{} },
		{"payment.domain-bound", "guarantor-payout"}:                     func() any { return &GuarantorAgreementPaymentActionBodyV1{} },
		{"portfolio.release", "post-acceptance"}:                         func() any { return &ExposureReleaseActionBodyV1{} },
		{"portfolio.release", "pre-acceptance"}:                          func() any { return &PreAcceptanceExposureReleaseActionBodyV1{} },
		{"settlement.external", "collateral-backed-payout"}:              func() any { return &CollateralBackedAgreementPaymentActionBodyV1{} },
		{"settlement.external", "guarantor-payout"}:                      func() any { return &GuarantorAgreementPaymentActionBodyV1{} },
	}
}

// ReleasedMutationSchemaSamplesV1 exposes the closed mutation wire types to
// deterministic schema generators without exposing mutable decoder tables.
func ReleasedMutationSchemaSamplesV1() map[MutationDispatchKeyV1]any {
	factories := guarantorMutationFactoriesV1()
	result := make(map[MutationDispatchKeyV1]any, len(factories))
	for key, factory := range factories {
		result[key] = factory()
	}
	return result
}

func verifyMutationFactoriesMatchRegistryV1() error {
	factories := guarantorMutationFactoriesV1()
	registry := ReleasedMutationVerifierRegistryV1()
	if len(factories) != len(registry.Entries) {
		return errors.New("Guarantor mutation dispatcher is incomplete")
	}
	for _, entry := range registry.Entries {
		factory := factories[MutationDispatchKeyV1{entry.ActionKind, entry.OperationPurpose}]
		if factory == nil {
			return errors.New("Guarantor mutation registry entry has no decoder")
		}
		requestType := reflect.TypeOf(factory()).Elem().Name()
		if requestType != entry.RequestType {
			return errors.New("Guarantor mutation registry request type differs from decoder")
		}
	}
	return nil
}
