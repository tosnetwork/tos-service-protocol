package agentguarantor

import (
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type testControlResolver struct {
	nativeTestAuthority
	controller             string
	operationRouteSurvives bool
}

func (testControlResolver) ResolveGuarantorAuthority(_ AuthorityResolutionScopeV1, _ string, _ time.Time, proof []byte) error {
	if len(proof) == 0 {
		return errTestAuthority
	}
	return nil
}

func (r testControlResolver) VerifyGuarantorAuthorityControlResolution(_ agentcommerce.ProfileRefV1, stage string,
	binding GuarantorStageActionAuthorityV1, operationProfile agentcommerce.ProfileRefV1, _ []string,
	stateRoot string, stateRevision uint64, _ time.Time, evidence []byte) (AuthorityControlResolutionResultV1, error) {
	if len(evidence) == 0 {
		return AuthorityControlResolutionResultV1{}, errTestAuthority
	}
	bindingDigest, err := codec.Digest("tos.service.agent-guarantor-stage-action-authority.v1", binding)
	if err != nil {
		return AuthorityControlResolutionResultV1{}, err
	}
	return AuthorityControlResolutionResultV1{
		SchemaVersion:                       1,
		Stage:                               stage,
		BindingDigest:                       bindingDigest,
		OperationAdapterProfile:             operationProfile,
		FinalizedAuthorityStateRevision:     stateRevision,
		FinalizedAuthorityStateRoot:         stateRoot,
		TransitiveControllerSubjects:        []string{r.controller},
		GuarantorRootsDeleted:               true,
		ActionAuthoritySurvivedDeletion:     true,
		WriterFenceSurvivedDeletion:         true,
		GenerationHighWaterSurvivedDeletion: true,
		ActionResolverSurvivedDeletion:      true,
		AdmissionDomainSurvivedDeletion:     true,
		OperationRouteSurvivedDeletion:      r.operationRouteSurvives,
	}, nil
}

func testOperationalIndependenceEvidence(t *testing.T) (CoverageTermsV1, AuthorizedGuarantorOperationalIndependenceEvidenceV1, string, time.Time) {
	t.Helper()
	now := time.Unix(2_000_000_100, 0).UTC()
	terms := testCoverageTerms(t)
	terms.SelectedAssuranceLevel = AssuranceIndependentlyEnforced
	terms.CollateralObligationID = "obligation:collateral"
	for index := range terms.StageActionAuthorityBinding.Stages {
		terms.StageActionAuthorityBinding.Stages[index].ActionAuthorityID = "authority:independent"
		terms.StageActionAuthorityBinding.Stages[index].WriterFenceAuthorityID = "authority:independent"
	}
	stageDigest, err := StageActionAuthorityBindingDigestV1(terms.StageActionAuthorityBinding)
	if err != nil {
		t.Fatal(err)
	}
	independenceTerms := GuarantorOperationalIndependenceTermsV1{
		SchemaVersion:                     1,
		AuthorityControlResolutionProfile: testRef("1", "control-resolution"),
		CoverageOperationAdapterProfile:   testRef("a", "coverage-operation"),
		ClaimOperationAdapterProfile:      testRef("b", "claim-operation"),
		ExposureOperationAdapterProfile:   testRef("c", "exposure-operation"),
		RequiredIndependentStages:         ReleasedGuarantorStagesV1(),
		GuarantorControlRootSubjects:      []string{"agent:guarantor"},
		ControlEvidenceAuthoritySubjects:  []string{"authority:auditor"},
		ControlEvidenceQuorumRule:         "all",
		StageActionAuthorityBindingDigest: stageDigest,
		AuthorityChangePolicy:             PolicyRefV1{ContentType: "application/cbor", ContentDigest: testDigest("d"), ContentSize: 1},
		MaximumControlEvidenceAgeSeconds:  600,
	}
	terms.OperationalIndependenceTerms = &independenceTerms
	termsDigest, err := OperationalIndependenceTermsDigestV1(independenceTerms)
	if err != nil {
		t.Fatal(err)
	}
	resolved := make([]ResolvedIndependentStageAuthorityV1, 0, len(independenceTerms.RequiredIndependentStages))
	for _, stage := range independenceTerms.RequiredIndependentStages {
		resolved = append(resolved, ResolvedIndependentStageAuthorityV1{Stage: stage,
			AuthoritySubject: "authority:independent", FinalizedAuthorityStateRevision: 7,
			FinalizedAuthorityStateRoot: testDigest("e")})
	}
	agreementDigest := testDigest("f")
	body := GuarantorOperationalIndependenceEvidenceBodyV1{
		SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CollateralObligationID:             terms.CollateralObligationID,
		OperationalIndependenceTermsDigest: termsDigest, StageActionAuthorityBindingDigest: stageDigest,
		AuthorityControlResolutionProfile: independenceTerms.AuthorityControlResolutionProfile,
		RequiredIndependentStages:         independenceTerms.RequiredIndependentStages,
		ResolvedStageAuthorities:          resolved, GuarantorControlRootSubjects: independenceTerms.GuarantorControlRootSubjects,
		GuarantorControlAbsent: true, FinalizedAuthorityStateRoot: testDigest("e"),
		ObservedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()),
	}
	bodyDigest, err := codec.Digest("tos.service.agent-guarantor-operational-independence-evidence-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	const controller = "auditor"
	authorization := testSignAuthorization(t, AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: "authority:auditor", ProfileURI: independenceTerms.AuthorityControlResolutionProfile.ProfileURI,
		ProfileVersion:       independenceTerms.AuthorityControlResolutionProfile.ProfileVersion,
		ProfileDigest:        independenceTerms.AuthorityControlResolutionProfile.ProfileDigest,
		AuthorizedObjectKind: "operational-independence-evidence", AuthorizedBodyDigest: bodyDigest,
		ValidationTimeUnix: uint64(now.Unix())}, "tos.service.agent-guarantor-operational-independence-evidence-signature.v1",
		controller, []byte("authority-proof"))
	return terms, AuthorizedGuarantorOperationalIndependenceEvidenceV1{Body: body,
		ResolverFinalityEvidence: []byte("finality-proof"), Authorizations: []ProfileQualifiedObjectAuthorizationV1{authorization}}, controller, now
}

func TestOperationalIndependenceRequiresDeletionSurvivalAndTransitiveControlClosure(t *testing.T) {
	terms, evidence, _, now := testOperationalIndependenceEvidence(t)
	agreementDigest := evidence.Body.CoverageAgreementBodyDigest
	if err := VerifyOperationalIndependenceEvidenceV1(evidence, terms, agreementDigest,
		testControlResolver{controller: "authority:independent", operationRouteSurvives: true}, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOperationalIndependenceEvidenceV1(evidence, terms, agreementDigest, allowAuthorityResolver{}, now); err == nil {
		t.Fatal("plain signature resolver was accepted as a control-resolution Adapter")
	}
	if err := VerifyOperationalIndependenceEvidenceV1(evidence, terms, agreementDigest,
		testControlResolver{controller: "agent:guarantor", operationRouteSurvives: true}, now); err == nil {
		t.Fatal("transitive Guarantor control was accepted")
	}
	if err := VerifyOperationalIndependenceEvidenceV1(evidence, terms, agreementDigest,
		testControlResolver{controller: "authority:independent", operationRouteSurvives: false}, now); err == nil {
		t.Fatal("an operation route that disappears with the Guarantor was accepted")
	}
}
