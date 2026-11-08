package agentguarantor

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	GuarantorMutationRegistryProfileURI = "tos.service.agent-guarantor-mutation-verifier-registry.v1"
	MaximumStageRequestBytesV1          = 1 << 20
)

type stageDefinitionV1 struct {
	stage, actionKind, purpose, routeSource, operation, casSource, derivation string
}

var releasedStageDefinitionsV1 = []stageDefinitionV1{
	{"coverage_activation", "conditional.obligation.transition", "coverage-activation", "coverage_operation_adapter_profile", "ActivateCoverage", "coverage_state_domain", "tos.service.agent-guarantor.stage.coverage-activation.v1"},
	{"coverage_non_activation", "conditional.obligation.transition", "coverage-non-activation", "coverage_operation_adapter_profile", "ResolveNonActivation", "coverage_state_domain", "tos.service.agent-guarantor.stage.coverage-non-activation.v1"},
	{"claim_submission_ingress", "conditional.claim.ingress", "claim-submission-ingress", "claim_operation_adapter_profile", "IngestClaim", "claim_ingress_state_domain", "tos.service.agent-guarantor.stage.claim-submission-ingress.v1"},
	{"initial_claim_admission", "conditional.claim.submit", "claim-admission", "claim_operation_adapter_profile", "AdmitClaim", "coverage_state_domain", "tos.service.agent-guarantor.stage.initial-claim-admission.v1"},
	{"claim_revision_admission", "conditional.claim.submit", "claim-admission", "claim_operation_adapter_profile", "AdmitClaim", "coverage_state_domain", "tos.service.agent-guarantor.stage.claim-revision-admission.v1"},
	{"claim_state_transition", "conditional.claim.transition", "claim-state-transition", "claim_operation_adapter_profile", "TransitionClaim", "claim_state_domain", "tos.service.agent-guarantor.stage.claim-state-transition.v1"},
	{"filing_close", "conditional.claim-filing.close", "claim-filing-close", "claim_operation_adapter_profile", "CloseClaimFiling", "coverage_state_domain", "tos.service.agent-guarantor.stage.filing-close.v1"},
	{"terminal_decision", "conditional.claim-decision.admit", "claim-decision-admission", "claim_operation_adapter_profile", "AdmitDecision", "coverage_state_domain", "tos.service.agent-guarantor.stage.terminal-decision.v1"},
	{"decision_application", "conditional.claim.decide", "claim-decision-application", "claim_operation_adapter_profile", "ApplyDecision", "coverage_state_domain", "tos.service.agent-guarantor.stage.decision-application.v1"},
	{"payout_execution", "", "", "selected_payout_adapter_profile", "", "settlement_adapter_state_domain", "tos.service.agent-guarantor.stage.payout-execution.v1"},
	{"coverage_cancellation", "conditional.obligation.transition", "coverage-cancellation", "coverage_operation_adapter_profile", "CancelCoverage", "coverage_state_domain", "tos.service.agent-guarantor.stage.coverage-cancellation.v1"},
	{"coverage_closure", "conditional.obligation.transition", "coverage-closure", "claim_operation_adapter_profile", "BeginClosure", "coverage_state_domain", "tos.service.agent-guarantor.stage.coverage-closure.v1"},
	{"post_acceptance_exposure_release", "portfolio.release", "post-acceptance", "exposure_operation_adapter_profile", "ReleaseExposure", "portfolio_exposure_state_domain", "tos.service.agent-guarantor.stage.post-acceptance-exposure-release.v1"},
	{"coverage_resolution", "conditional.obligation.transition", "coverage-resolution", "coverage_operation_adapter_profile", "ResolveCoverage", "coverage_state_domain", "tos.service.agent-guarantor.stage.coverage-resolution.v1"},
}

// Acceptance is linearized by the Provider exposure authority and collateral
// transitions are linearized by the selected collateral Adapter. They are
// released mutation operations, but are intentionally not members of the
// fourteen-stage operational-independence registry frozen by the Agreement.
// Keep their operation definitions separate so they cannot silently expand
// that closed registry.
var auxiliaryStageDefinitionsV1 = []stageDefinitionV1{
	{"coverage_acceptance", "conditional.obligation.transition", "coverage-acceptance", "coverage_operation_adapter_profile", "AcceptCoverage", "coverage_state_domain", "tos.service.agent-guarantor.stage.coverage-acceptance.v1"},
	{"collateral_transition", "collateral.transition", "collateral-transition", "collateral_transition_binding", "ApplyCollateralTransition", "collateral_position_state_domain", "tos.service.agent-guarantor.stage.collateral-transition.v1"},
}

func ReleasedGuarantorStagesV1() []string {
	result := make([]string, len(releasedStageDefinitionsV1))
	for index, definition := range releasedStageDefinitionsV1 {
		result[index] = definition.stage
	}
	return result
}

func StageOperationBindingDigestV1(binding GuarantorStageOperationBindingV1) (string, error) {
	if err := ValidateStageOperationBindingV1(binding); err != nil {
		return "", err
	}
	return codec.Digest("tos.service.agent-guarantor-stage-operation-binding.v1", binding)
}

func StageActionAuthorityBindingDigestV1(binding GuarantorStageActionAuthorityBindingV1) (string, error) {
	if err := ValidateStageActionAuthorityBindingV1(binding); err != nil {
		return "", err
	}
	return codec.Digest("tos.service.agent-guarantor-stage-action-authority-binding.v1", binding)
}

func mutationEntryV1(actionKind, purpose string) (MutationVerifierEntryV1, bool) {
	for _, entry := range ReleasedMutationVerifierRegistryV1().Entries {
		if entry.ActionKind == actionKind && entry.OperationPurpose == purpose {
			return entry, true
		}
	}
	return MutationVerifierEntryV1{}, false
}

// NewStageOperationBindingV1 constructs the immutable registry projection for
// one stage. actionKind and purpose are ignored for non-payout stages and are
// explicit for payout_execution because its Agreement selects one of three
// released settlement routes.
func NewStageOperationBindingV1(stage, actionKind, purpose string, maximumRequestBytes uint64) (GuarantorStageOperationBindingV1, error) {
	definition, found := stageDefinitionForV1(stage)
	if !found {
		return GuarantorStageOperationBindingV1{}, errors.New("Guarantor stage is unknown")
	}
	operation := definition.operation
	if stage != "payout_execution" {
		actionKind, purpose = definition.actionKind, definition.purpose
	} else if actionKind == "settlement.external" && purpose == "collateral-backed-payout" {
		operation = "SubmitCollateralBackedPayment"
	} else {
		operation = "SubmitPayment"
	}
	entry, found := mutationEntryV1(actionKind, purpose)
	if !found {
		return GuarantorStageOperationBindingV1{}, errors.New("Guarantor stage mutation is unknown")
	}
	registryDigest, err := MutationVerifierRegistryDigestV1()
	if err != nil {
		return GuarantorStageOperationBindingV1{}, err
	}
	components := make([]GuarantorStageOperationResultBindingV1, len(entry.ResultComponents))
	for index, component := range entry.ResultComponents {
		components[index] = GuarantorStageOperationResultBindingV1(component)
	}
	binding := GuarantorStageOperationBindingV1{SchemaVersion: 1, Stage: stage,
		OperationRegistryProfile: agentcommerce.ProfileRefV1{ProfileURI: GuarantorMutationRegistryProfileURI,
			ProfileVersion: 1, ProfileDigest: registryDigest}, OperationID: entry.OperationID,
		ActionKind: actionKind, OperationPurpose: purpose, SemanticActionRegistryVersion: 1,
		SemanticActionEntryVersion: 1, RequestSchemaVersion: entry.RequestSchemaVersion, RequestType: entry.RequestType,
		RequestBodyProfileID: entry.RequestBodyProfileID, MaximumRequestBytes: maximumRequestBytes,
		ResultComponents: components, RequiredContextTypes: append([]string{}, entry.RequiredContextTypes...),
		SemanticFieldDerivationProfileID: entry.SemanticFieldDerivationProfileID,
		TransitionValidatorProfileID:     entry.TransitionValidatorProfileID, MaterializerProfileID: entry.MaterializerProfileID,
		AdapterRouteProfileSource: definition.routeSource, AdapterOperation: operation, CASDomainSource: definition.casSource,
		StageDerivationProfileID: definition.derivation}
	if err := ValidateStageOperationBindingV1(binding); err != nil {
		return GuarantorStageOperationBindingV1{}, err
	}
	return binding, nil
}

func stageDefinitionForV1(stage string) (stageDefinitionV1, bool) {
	for _, definition := range releasedStageDefinitionsV1 {
		if definition.stage == stage {
			return definition, true
		}
	}
	for _, definition := range auxiliaryStageDefinitionsV1 {
		if definition.stage == stage {
			return definition, true
		}
	}
	return stageDefinitionV1{}, false
}

func derivedAuxiliaryStageAuthorityV1(binding GuarantorStageActionAuthorityBindingV1, auxiliary,
	authoritySource string) (GuarantorStageActionAuthorityV1, error) {
	source, err := FindStageActionAuthorityV1(binding, authoritySource)
	if err != nil {
		return GuarantorStageActionAuthorityV1{}, err
	}
	operation, err := NewStageOperationBindingV1(auxiliary, "", "", source.MaximumRequestBytes)
	if err != nil {
		return GuarantorStageActionAuthorityV1{}, err
	}
	digest, err := StageOperationBindingDigestV1(operation)
	if err != nil {
		return GuarantorStageActionAuthorityV1{}, err
	}
	source.Stage = auxiliary
	source.OperationActionKind = operation.ActionKind
	source.OperationPurpose = operation.OperationPurpose
	source.OperationBindingDigest = digest
	return source, nil
}

// AuxiliaryStageActionAuthorityV1 derives the fixed acceptance or collateral
// mutation authority without adding that mutation to the closed fourteen-stage
// operational-independence registry.
func AuxiliaryStageActionAuthorityV1(binding GuarantorStageActionAuthorityBindingV1,
	auxiliary string) (GuarantorStageActionAuthorityV1, error) {
	switch auxiliary {
	case "coverage_acceptance":
		return derivedAuxiliaryStageAuthorityV1(binding, auxiliary, "coverage_activation")
	case "collateral_transition":
		return derivedAuxiliaryStageAuthorityV1(binding, auxiliary, "payout_execution")
	default:
		return GuarantorStageActionAuthorityV1{}, errors.New("Guarantor auxiliary stage is unknown")
	}
}

func ValidateStageOperationBindingV1(binding GuarantorStageOperationBindingV1) error {
	definition, found := stageDefinitionForV1(binding.Stage)
	if !found || binding.SchemaVersion != 1 || binding.MaximumRequestBytes == 0 ||
		binding.MaximumRequestBytes > MaximumStageRequestBytesV1 || binding.SemanticActionRegistryVersion != 1 ||
		binding.SemanticActionEntryVersion != 1 || binding.AdapterRouteProfileSource != definition.routeSource ||
		binding.CASDomainSource != definition.casSource || binding.StageDerivationProfileID != definition.derivation {
		return errors.New("Guarantor stage operation binding header is invalid")
	}
	if binding.Stage == "payout_execution" {
		validRoute := (binding.ActionKind == "payment.direct" || binding.ActionKind == "payment.domain-bound") &&
			binding.OperationPurpose == "guarantor-payout" && binding.AdapterOperation == "SubmitPayment" ||
			binding.ActionKind == "settlement.external" && binding.OperationPurpose == "guarantor-payout" && binding.AdapterOperation == "SubmitPayment" ||
			binding.ActionKind == "settlement.external" && binding.OperationPurpose == "collateral-backed-payout" && binding.AdapterOperation == "SubmitCollateralBackedPayment"
		if !validRoute {
			return errors.New("Guarantor payout stage operation binding is invalid")
		}
	} else if binding.ActionKind != definition.actionKind || binding.OperationPurpose != definition.purpose ||
		binding.AdapterOperation != definition.operation {
		return errors.New("Guarantor stage operation route is invalid")
	}
	entry, found := mutationEntryV1(binding.ActionKind, binding.OperationPurpose)
	if !found || binding.OperationID != entry.OperationID || binding.RequestSchemaVersion != entry.RequestSchemaVersion ||
		binding.RequestType != entry.RequestType || binding.RequestBodyProfileID != entry.RequestBodyProfileID ||
		binding.SemanticFieldDerivationProfileID != entry.SemanticFieldDerivationProfileID ||
		binding.TransitionValidatorProfileID != entry.TransitionValidatorProfileID ||
		binding.MaterializerProfileID != entry.MaterializerProfileID || !equalCanonical(binding.RequiredContextTypes, entry.RequiredContextTypes) {
		return errors.New("Guarantor stage operation differs from the released mutation registry")
	}
	components := make([]GuarantorStageOperationResultBindingV1, len(entry.ResultComponents))
	for index, component := range entry.ResultComponents {
		components[index] = GuarantorStageOperationResultBindingV1(component)
	}
	if !equalCanonical(binding.ResultComponents, components) {
		return errors.New("Guarantor stage result binding differs from the released mutation registry")
	}
	registryDigest, err := MutationVerifierRegistryDigestV1()
	if err != nil || binding.OperationRegistryProfile != (agentcommerce.ProfileRefV1{
		ProfileURI: GuarantorMutationRegistryProfileURI, ProfileVersion: 1, ProfileDigest: registryDigest}) {
		return errors.New("Guarantor stage operation registry profile is invalid")
	}
	return nil
}

func ValidateStageActionAuthorityBindingV1(binding GuarantorStageActionAuthorityBindingV1) error {
	if binding.SchemaVersion != 1 || !validDigest(binding.AuthorityDomainDigest) ||
		len(binding.Stages) != len(releasedStageDefinitionsV1) {
		return errors.New("Guarantor stage authority binding header is invalid")
	}
	for index, stage := range binding.Stages {
		definition := releasedStageDefinitionsV1[index]
		operation, err := StageOperationBindingForAuthorityV1(stage)
		digest, digestErr := StageOperationBindingDigestV1(operation)
		if err != nil || digestErr != nil || stage.Stage != definition.stage || operation.Stage != stage.Stage ||
			stage.OperationBindingDigest != digest || !validID(stage.ActionOwnerID) || !validID(stage.ActionAgentID) ||
			!validID(stage.ActionAuthorityID) || !validID(stage.WriterFenceDomainID) ||
			stage.WriterFenceAuthorityID != stage.ActionAuthorityID ||
			agentcommerce.ValidateProfileRefV1(stage.WriterGenerationHighWaterProfile) != nil ||
			agentcommerce.ValidateProfileRefV1(stage.ActionResolutionProfile) != nil || !validDigest(stage.AdmissionStateDomainDigest) {
			return errors.New("Guarantor stage authority binding entry is invalid")
		}
	}
	return nil
}

// StageOperationBindingForAuthorityV1 reconstructs the released registry
// entry from a compact Agreement binding. This avoids recursively embedding
// the same verbose registry schema in every lifecycle receipt.
func StageOperationBindingForAuthorityV1(bound GuarantorStageActionAuthorityV1) (GuarantorStageOperationBindingV1, error) {
	operation, err := NewStageOperationBindingV1(bound.Stage, bound.OperationActionKind,
		bound.OperationPurpose, bound.MaximumRequestBytes)
	if err != nil {
		return GuarantorStageOperationBindingV1{}, err
	}
	digest, err := StageOperationBindingDigestV1(operation)
	if err != nil || digest != bound.OperationBindingDigest {
		return GuarantorStageOperationBindingV1{}, errors.New("compact Guarantor stage operation binding digest differs")
	}
	return operation, nil
}

func FindStageActionAuthorityV1(binding GuarantorStageActionAuthorityBindingV1, stage string) (GuarantorStageActionAuthorityV1, error) {
	if err := ValidateStageActionAuthorityBindingV1(binding); err != nil {
		return GuarantorStageActionAuthorityV1{}, err
	}
	for _, candidate := range binding.Stages {
		if candidate.Stage == stage {
			return candidate, nil
		}
	}
	return GuarantorStageActionAuthorityV1{}, errors.New("Guarantor stage is not bound")
}

// VerifyPortableStageActionAdmissionEvidenceV1 reproduces the complete side-
// effect admission decision from Agreement-bound authority metadata.  It is
// intentionally independent of any provider journal or transport database.
func VerifyPortableStageActionAdmissionEvidenceV1(evidence PortableStageActionAdmissionEvidenceV1,
	bound GuarantorStageActionAuthorityV1, expectedRequest []byte, semanticFields map[string]agentcommerce.SemanticValue,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	operation, operationErr := StageOperationBindingForAuthorityV1(bound)
	if operationErr != nil || bound.Stage != operation.Stage {
		return errors.New("Guarantor stage authority is invalid")
	}
	bindingDigest, err := StageOperationBindingDigestV1(operation)
	if err != nil || bindingDigest != bound.OperationBindingDigest || len(expectedRequest) == 0 ||
		uint64(len(expectedRequest)) > operation.MaximumRequestBytes ||
		!bytes.Equal(expectedRequest, evidence.CanonicalRequest) {
		return errors.New("Guarantor stage request or operation binding is invalid")
	}
	requestDigest, err := agentcommerce.ExactRequestDigest(expectedRequest)
	if err != nil {
		return err
	}
	actionDigest, err := agentcommerce.AuthorizedActionDigest(evidence.AuthorizedAction)
	if err != nil {
		return err
	}
	fenceDigest, err := agentcommerce.WriterFenceDigest(evidence.WriterFence)
	if err != nil {
		return err
	}
	body := evidence.Body
	if body.SchemaVersion != 1 || body.Stage != bound.Stage || body.OperationID != operation.OperationID ||
		body.OperationBindingDigest != bindingDigest || body.AdmittedAtUnix == 0 || body.CanonicalRequestDigest != requestDigest ||
		body.AuthorizedActionDigest != actionDigest || body.WriterFenceDigest != fenceDigest || body.AdmissionState != "accepted" ||
		body.AdmissionStateRevision == 0 || evidence.CanonicalRequestContentType == "" ||
		evidence.AuthorizedAction.OwnerID != bound.ActionOwnerID || evidence.AuthorizedAction.AgentID != bound.ActionAgentID ||
		evidence.AuthorizedAction.AuthorityID != bound.ActionAuthorityID || evidence.WriterFence.Body.AuthorityID != bound.WriterFenceAuthorityID ||
		evidence.AuthorizedAction.ActionKind != operation.ActionKind ||
		evidence.ActionAdmissionAuthorization.AuthoritySubject != bound.ActionAuthorityID ||
		evidence.ActionAdmissionAuthorization.ValidationTimeUnix != body.AdmittedAtUnix ||
		evidence.AuthorizedAction.ExactRequestDigest != requestDigest || evidence.AuthorizedAction.WriterFenceDigest != fenceDigest {
		return errors.New("Guarantor portable stage admission body is invalid")
	}
	admittedAt := time.Unix(int64(body.AdmittedAtUnix), 0).UTC()
	if admittedAt.After(now.UTC().Add(5*time.Minute)) || authorityResolver == nil || fenceResolver == nil {
		return errors.New("Guarantor portable stage admission time or resolver is invalid")
	}
	if err := agentcommerce.VerifyAuthorizedActionAtAuthorityTime(evidence.AuthorizedAction, semanticFields,
		expectedRequest, evidence.WriterFence, fenceResolver, admittedAt, now); err != nil {
		return err
	}
	if agentcommerce.ValidateActionResolution(evidence.ActionResolution) != nil ||
		evidence.ActionResolution.StableActionID != evidence.AuthorizedAction.StableActionID ||
		evidence.ActionResolution.ExactRequestDigest != requestDigest ||
		evidence.ActionResolution.State != agentcommerce.ActionTerminal ||
		evidence.ActionResolution.StateRevision != body.AdmissionStateRevision {
		return errors.New("Guarantor stage action resolution is not the admitted terminal effect")
	}
	stageBodyDigest, err := codec.Digest("tos.service.agent-guarantor-stage-action-admission.v1", body)
	if err != nil {
		return err
	}
	return verifyStageActionAdmissionAuthorizationV1(evidence.ActionAdmissionAuthorization, evidence.AuthorizedAction,
		stageBodyDigest, authorityResolver, fenceResolver, now)
}
