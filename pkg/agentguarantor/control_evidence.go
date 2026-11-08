package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	CollateralControlEvidenceDomainV1         = "tos.service.agent-guarantor-collateral-control-evidence-envelope.v1"
	OperationalIndependenceTermsDomainV1      = "tos.service.agent-guarantor-operational-independence-terms.v1"
	OperationalIndependenceEvidenceDomainV1   = "tos.service.agent-guarantor-operational-independence-evidence-envelope.v1"
	maxControlResolverFinalityEvidenceBytesV1 = 256 << 10
)

// AuthorityControlResolutionVerifier is the assurance-profile Adapter which
// authenticates finalized authority-control state. Implementations must expand
// transitive controllers, test the bound side-effect infrastructure after the
// declared Guarantor roots are removed, and return the exact tested closure.
// A signed Boolean or an opaque byte string is never sufficient by itself.
type AuthorityControlResolutionVerifier interface {
	VerifyGuarantorAuthorityControlResolution(profile agentcommerce.ProfileRefV1, stage string,
		binding GuarantorStageActionAuthorityV1, operationAdapterProfile agentcommerce.ProfileRefV1,
		guarantorControlRoots []string, finalizedStateRoot string, finalizedStateRevision uint64,
		observedAt time.Time, finalityEvidence []byte) (AuthorityControlResolutionResultV1, error)
}

type AuthorityControlResolutionResultV1 struct {
	SchemaVersion                       uint16
	Stage                               string
	BindingDigest                       string
	OperationAdapterProfile             agentcommerce.ProfileRefV1
	FinalizedAuthorityStateRevision     uint64
	FinalizedAuthorityStateRoot         string
	TransitiveControllerSubjects        []string
	GuarantorRootsDeleted               bool
	ActionAuthoritySurvivedDeletion     bool
	WriterFenceSurvivedDeletion         bool
	GenerationHighWaterSurvivedDeletion bool
	ActionResolverSurvivedDeletion      bool
	AdmissionDomainSurvivedDeletion     bool
	OperationRouteSurvivedDeletion      bool
}

func CollateralControlEvidenceDigestV1(value AuthorizedCollateralControlEvidenceV1) (string, error) {
	if value.Body.SchemaVersion != 1 || len(value.Authorizations) == 0 || len(value.Authorizations) > MaxAuthorizations {
		return "", errors.New("collateral control evidence envelope is invalid")
	}
	return guarantorCodec.Digest(CollateralControlEvidenceDomainV1, value)
}

func VerifyCollateralControlEvidenceV1(value AuthorizedCollateralControlEvidenceV1, agreementDigest,
	collateralObligationID, selectedProfileDigest string, disclosure CollateralControlDisclosureV1,
	fallbackProfile agentcommerce.ProfileRefV1, fallbackSubjects []string, fallbackQuorum string,
	resolver AuthorityKeyResolver, now time.Time) error {
	disclosureDigest, disclosureErr := CollateralControlDisclosureDigestV1(disclosure)
	body := value.Body
	if disclosureErr != nil || !validDigest(agreementDigest) || !validToken(collateralObligationID, 128) ||
		!validDigest(selectedProfileDigest) || resolver == nil || body.SchemaVersion != 1 ||
		body.CoverageAgreementBodyDigest != agreementDigest || body.CollateralObligationID != collateralObligationID ||
		body.SelectedCollateralProfileDigest != selectedProfileDigest || body.CollateralControlDisclosureDigest != disclosureDigest ||
		body.CustodyAdapterProfile != disclosure.CustodyAdapterProfile ||
		!equalStrings(body.AdapterOperatorSubjects, disclosure.AdapterOperatorSubjects) ||
		!equalStrings(body.CustodianControllerRootSubjects, disclosure.CustodianControllerRootSubjects) ||
		body.DeclaredGuarantorControlRelationship != disclosure.DeclaredGuarantorControlRelationship ||
		body.ObservedAtUnix == 0 || body.ExpiresAtUnix <= body.ObservedAtUnix ||
		uint64(now.UTC().Unix()) < body.ObservedAtUnix || uint64(now.UTC().Unix()) >= body.ExpiresAtUnix {
		return errors.New("collateral control evidence is not an exact fresh projection")
	}
	profile, subjects, quorum := fallbackProfile, fallbackSubjects, fallbackQuorum
	if disclosure.DeclaredGuarantorControlRelationship == "third_party_control_asserted" {
		if disclosure.DisclosureEvidenceProfile == nil {
			return errors.New("third-party collateral control has no evidence profile")
		}
		profile, subjects, quorum = *disclosure.DisclosureEvidenceProfile,
			disclosure.DisclosureAuthoritySubjects, disclosure.DisclosureAuthorityQuorumRule
		if body.ExpiresAtUnix-body.ObservedAtUnix > disclosure.MaximumDisclosureEvidenceAgeSeconds {
			return errors.New("collateral control evidence exceeds its selected freshness bound")
		}
	}
	for _, authorization := range value.Authorizations {
		if authorization.ProfileURI != profile.ProfileURI || authorization.ProfileVersion != profile.ProfileVersion ||
			authorization.ProfileDigest != profile.ProfileDigest {
			return errors.New("collateral control evidence authorization profile is substituted")
		}
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-collateral-control-evidence-body.v1", body)
	return ValidateAuthorizationQuorumSet(value.Authorizations, "collateral-control-evidence", bodyDigest,
		"tos.service.agent-guarantor-collateral-control-evidence-signature.v1", subjects, quorum, resolver, now)
}

func OperationalIndependenceTermsDigestV1(value GuarantorOperationalIndependenceTermsV1) (string, error) {
	if err := ValidateOperationalIndependenceTermsV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(OperationalIndependenceTermsDomainV1, value)
}

func ValidateOperationalIndependenceTermsV1(value GuarantorOperationalIndependenceTermsV1) error {
	if value.SchemaVersion != 1 || agentcommerce.ValidateProfileRefV1(value.AuthorityControlResolutionProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(value.CoverageOperationAdapterProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(value.ClaimOperationAdapterProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(value.ExposureOperationAdapterProfile) != nil ||
		!equalStrings(value.RequiredIndependentStages, ReleasedGuarantorStagesV1()) ||
		!sortedUnique(value.GuarantorControlRootSubjects, MaxAuthorizations, validID) ||
		QuorumThresholdMustFailV1(value.ControlEvidenceQuorumRule, value.ControlEvidenceAuthoritySubjects) ||
		!validDigest(value.StageActionAuthorityBindingDigest) || agentcommerce.ValidatePolicyRefV1(value.AuthorityChangePolicy) != nil ||
		value.MaximumControlEvidenceAgeSeconds == 0 || value.MaximumControlEvidenceAgeSeconds > uint64((30*24*time.Hour)/time.Second) {
		return errors.New("Guarantor operational-independence terms are invalid")
	}
	return nil
}

func OperationalIndependenceEvidenceDigestV1(value AuthorizedGuarantorOperationalIndependenceEvidenceV1) (string, error) {
	if value.Body.SchemaVersion != 1 || len(value.Authorizations) == 0 || len(value.Authorizations) > MaxAuthorizations ||
		len(value.ResolverFinalityEvidence) == 0 || len(value.ResolverFinalityEvidence) > maxControlResolverFinalityEvidenceBytesV1 {
		return "", errors.New("operational-independence evidence envelope is invalid")
	}
	return guarantorCodec.Digest(OperationalIndependenceEvidenceDomainV1, value)
}

func VerifyOperationalIndependenceEvidenceV1(value AuthorizedGuarantorOperationalIndependenceEvidenceV1,
	coverageTerms CoverageTermsV1, agreementDigest string, resolver AuthorityKeyResolver, now time.Time) error {
	terms := coverageTerms.OperationalIndependenceTerms
	if terms == nil || ValidateOperationalIndependenceTermsV1(*terms) != nil || resolver == nil ||
		coverageTerms.SelectedAssuranceLevel != AssuranceIndependentlyEnforced {
		return errors.New("operational-independence evidence has no selected terms")
	}
	controlVerifier, ok := resolver.(AuthorityControlResolutionVerifier)
	if !ok || controlVerifier == nil {
		return errors.New("operational-independence control-resolution Adapter is unavailable")
	}
	termsDigest, _ := OperationalIndependenceTermsDigestV1(*terms)
	stageDigest, stageErr := StageActionAuthorityBindingDigestV1(coverageTerms.StageActionAuthorityBinding)
	body := value.Body
	if stageErr != nil || body.SchemaVersion != 1 || body.CoverageAgreementBodyDigest != agreementDigest ||
		body.CollateralObligationID != coverageTerms.CollateralObligationID ||
		body.OperationalIndependenceTermsDigest != termsDigest || body.StageActionAuthorityBindingDigest != stageDigest ||
		stageDigest != terms.StageActionAuthorityBindingDigest || body.AuthorityControlResolutionProfile != terms.AuthorityControlResolutionProfile ||
		!equalStrings(body.RequiredIndependentStages, terms.RequiredIndependentStages) ||
		!equalStrings(body.GuarantorControlRootSubjects, terms.GuarantorControlRootSubjects) || !body.GuarantorControlAbsent ||
		!validDigest(body.FinalizedAuthorityStateRoot) || body.ObservedAtUnix == 0 || body.ExpiresAtUnix <= body.ObservedAtUnix ||
		body.ExpiresAtUnix-body.ObservedAtUnix > terms.MaximumControlEvidenceAgeSeconds ||
		uint64(now.UTC().Unix()) < body.ObservedAtUnix || uint64(now.UTC().Unix()) >= body.ExpiresAtUnix ||
		len(body.ResolvedStageAuthorities) != len(terms.RequiredIndependentStages) ||
		len(value.ResolverFinalityEvidence) == 0 || len(value.ResolverFinalityEvidence) > maxControlResolverFinalityEvidenceBytesV1 {
		return errors.New("operational-independence evidence binding is invalid")
	}
	controlRoots := make(map[string]struct{}, len(terms.GuarantorControlRootSubjects))
	for _, subject := range terms.GuarantorControlRootSubjects {
		controlRoots[subject] = struct{}{}
	}
	for index, stageName := range terms.RequiredIndependentStages {
		entry := body.ResolvedStageAuthorities[index]
		bound, err := FindStageActionAuthorityV1(coverageTerms.StageActionAuthorityBinding, stageName)
		if err != nil || entry.Stage != stageName || entry.AuthoritySubject != bound.ActionAuthorityID ||
			entry.FinalizedAuthorityStateRevision == 0 || !validDigest(entry.FinalizedAuthorityStateRoot) {
			return errors.New("operational-independence stage authority is substituted")
		}
		if _, controlled := controlRoots[entry.AuthoritySubject]; controlled {
			return errors.New("an allegedly independent stage remains Guarantor-controlled")
		}
		adapterProfile, adapterErr := operationAdapterForStageV1(coverageTerms, stageName)
		resolution, resolutionErr := controlVerifier.VerifyGuarantorAuthorityControlResolution(
			terms.AuthorityControlResolutionProfile, stageName, bound, adapterProfile,
			terms.GuarantorControlRootSubjects, entry.FinalizedAuthorityStateRoot,
			entry.FinalizedAuthorityStateRevision, time.Unix(int64(body.ObservedAtUnix), 0).UTC(),
			value.ResolverFinalityEvidence)
		boundDigest, digestErr := guarantorCodec.Digest("tos.service.agent-guarantor-stage-action-authority.v1", bound)
		if adapterErr != nil || resolutionErr != nil || digestErr != nil || resolution.SchemaVersion != 1 ||
			resolution.Stage != stageName || resolution.BindingDigest != boundDigest ||
			resolution.OperationAdapterProfile != adapterProfile ||
			resolution.FinalizedAuthorityStateRevision != entry.FinalizedAuthorityStateRevision ||
			resolution.FinalizedAuthorityStateRoot != entry.FinalizedAuthorityStateRoot ||
			!sortedUnique(resolution.TransitiveControllerSubjects, MaxAuthorizations*8, validID) ||
			!resolution.GuarantorRootsDeleted || !resolution.ActionAuthoritySurvivedDeletion ||
			!resolution.WriterFenceSurvivedDeletion || !resolution.GenerationHighWaterSurvivedDeletion ||
			!resolution.ActionResolverSurvivedDeletion || !resolution.AdmissionDomainSurvivedDeletion ||
			!resolution.OperationRouteSurvivedDeletion {
			return errors.New("operational-independence deletion proof is invalid")
		}
		for _, controller := range resolution.TransitiveControllerSubjects {
			if _, controlled := controlRoots[controller]; controlled {
				return errors.New("a transitive stage controller remains Guarantor-controlled")
			}
		}
	}
	for _, authorization := range value.Authorizations {
		if authorization.ProfileURI != terms.AuthorityControlResolutionProfile.ProfileURI ||
			authorization.ProfileVersion != terms.AuthorityControlResolutionProfile.ProfileVersion ||
			authorization.ProfileDigest != terms.AuthorityControlResolutionProfile.ProfileDigest {
			return errors.New("operational-independence evidence profile is substituted")
		}
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-operational-independence-evidence-body.v1", body)
	return ValidateAuthorizationQuorumSet(value.Authorizations, "operational-independence-evidence", bodyDigest,
		"tos.service.agent-guarantor-operational-independence-evidence-signature.v1",
		terms.ControlEvidenceAuthoritySubjects, terms.ControlEvidenceQuorumRule, resolver, now)
}

func operationAdapterForStageV1(coverageTerms CoverageTermsV1,
	stage string) (agentcommerce.ProfileRefV1, error) {
	terms := coverageTerms.OperationalIndependenceTerms
	if terms == nil {
		return agentcommerce.ProfileRefV1{}, errors.New("operational-independence terms are absent")
	}
	switch stage {
	case "coverage_activation", "coverage_non_activation", "coverage_cancellation", "coverage_resolution":
		return terms.CoverageOperationAdapterProfile, nil
	case "claim_submission_ingress", "initial_claim_admission", "claim_revision_admission",
		"terminal_decision", "claim_state_transition", "filing_close", "decision_application", "coverage_closure":
		return terms.ClaimOperationAdapterProfile, nil
	case "post_acceptance_exposure_release":
		return terms.ExposureOperationAdapterProfile, nil
	case "payout_execution":
		return coverageTerms.SelectedPayoutAdapterProfile, nil
	default:
		return agentcommerce.ProfileRefV1{}, errors.New("unregistered independent stage")
	}
}
