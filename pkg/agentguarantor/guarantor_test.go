package agentguarantor

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type allowAuthorityResolver struct{ nativeTestAuthority }

func (allowAuthorityResolver) ResolveGuarantorAuthority(_ AuthorityResolutionScopeV1, _ string, _ time.Time, proof []byte) error {
	if len(proof) == 0 {
		return errTestAuthority
	}
	return nil
}

type testError string

func (e testError) Error() string { return string(e) }

const errTestAuthority testError = "missing authority proof"

func testDigest(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }

func testRef(ch, name string) ProfileRefV1 {
	return ProfileRefV1{ProfileURI: "tos.test." + name + ".v1", ProfileVersion: 1, ProfileDigest: testDigest(ch)}
}

func testAsset() AssetIdentityV1 {
	return AssetIdentityV1{AssetNamespace: "tos", AssetIdentifier: "asset:tusd", Unit: "atomic"}
}

func testCapacity() ClaimClosureCapacityV1 {
	fallback, err := NewDenyZeroTerminalFallbackV1(testRef("e", "fallback"), []string{"agent:guarantor"}, "all",
		map[string]string{"deny_zero": "fallback-deny", "no_eligible_benefit": "fallback-no-benefit",
			"aggregate_exhausted": "fallback-cap-exhausted", "aggregate_limited": "fallback-cap-limited", "full_benefit": "fallback-full"})
	if err != nil {
		panic(err)
	}
	entries, err := BuildClaimContinuationBudgetEntriesV1(1, 1, 600, 600, 600, 600, 600, 600)
	if err != nil {
		panic(err)
	}
	return ClaimClosureCapacityV1{MaximumClaims: 4, MaximumClaimIngressActions: 8,
		MaximumClaimRevisionsPerClaim: 2, MaximumDecisionAdmissionsPerClaim: 4,
		MaximumClaimStateTransitionsPerClaim: 8, MaximumChallengeRoundsPerClaim: 1,
		MaximumNonterminalRoundsPerClaim: 1, MaximumPayoutLinesPerClaim: 2,
		MaximumAdmittedClaimEnvelopeBytes: 64 << 10, MaximumClaimIngressReceiptEnvelopeBytes: 128 << 10,
		MaximumClaimIngressCutProofBytes: 1 << 20, MaximumAcceptanceRequestEnvelopeBytes: 1 << 20,
		MaximumAcceptanceReceiptEnvelopeBytes: 1 << 20, MaximumActivationEvidenceEnvelopeBytes: 1 << 20,
		MaximumNonActivationEvidenceEnvelopeBytes: 1 << 20, MaximumCancellationReceiptEnvelopeBytes: 1 << 20,
		MaximumClaimFilingCloseReceiptEnvelopeBytes: 1 << 20, MaximumTerminalClaimSetEnvelopeBytes: 1 << 20,
		MaximumExposureReleaseRequestBytes: 1 << 20, MaximumExposureReleaseReceiptBytes: 1 << 20,
		MaximumCoverageResolutionRequestBytes: 1 << 20, MaximumCoverageResolutionEnvelopeBytes: 1 << 20,
		ComputedWorstCaseAcceptanceRequestEnvelopeBytes: 1 << 20, ComputedWorstCaseAcceptanceReceiptEnvelopeBytes: 1 << 20,
		ComputedWorstCaseActivationEvidenceEnvelopeBytes: 1 << 20, ComputedWorstCaseNonActivationEvidenceEnvelopeBytes: 1 << 20,
		ComputedWorstCaseCancellationReceiptEnvelopeBytes: 1 << 20, ComputedWorstCaseClaimFilingCloseReceiptEnvelopeBytes: 1 << 20,
		ComputedWorstCaseTerminalClaimSetBytes: 1 << 20, ComputedWorstCaseExposureReleaseRequestBytes: 1 << 20,
		ComputedWorstCaseExposureReleaseReceiptBytes: 1 << 20, ComputedWorstCaseCoverageResolutionRequestBytes: 1 << 20,
		ComputedWorstCaseCoverageResolutionEnvelopeBytes: 1 << 20,
		ContinuationBudgetProfile:                        testRef("f", "continuation-budget"), ContinuationBudgetEntries: entries,
		TerminalFallback: fallback}
}

func TestClaimClosureCapacityReservesEveryRevisionIngress(t *testing.T) {
	capacity := testCapacity()
	capacity.MaximumClaimIngressActions = capacity.MaximumClaims*capacity.MaximumClaimRevisionsPerClaim - 1
	if err := ValidateClaimClosureCapacity(capacity); err == nil {
		t.Fatal("capacity admitted fewer ingress actions than the complete bounded claim revision history")
	}
}

func testStageAuthorityBinding(t *testing.T) GuarantorStageActionAuthorityBindingV1 {
	t.Helper()
	stages := make([]GuarantorStageActionAuthorityV1, 0, len(ReleasedGuarantorStagesV1()))
	for _, stage := range ReleasedGuarantorStagesV1() {
		actionKind, purpose := "", ""
		if stage == "payout_execution" {
			actionKind, purpose = "payment.domain-bound", "guarantor-payout"
		}
		operation, err := NewStageOperationBindingV1(stage, actionKind, purpose, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := StageOperationBindingDigestV1(operation)
		if err != nil {
			t.Fatal(err)
		}
		stages = append(stages, GuarantorStageActionAuthorityV1{Stage: stage, OperationActionKind: operation.ActionKind,
			OperationPurpose: operation.OperationPurpose, MaximumRequestBytes: operation.MaximumRequestBytes,
			OperationBindingDigest: digest, ActionOwnerID: "owner:guarantor", ActionAgentID: "agent:guarantor",
			ActionAuthorityID: "authority:guarantor", WriterFenceDomainID: "fence:guarantor",
			WriterFenceAuthorityID: "authority:guarantor", WriterGenerationHighWaterProfile: testRef("1", "high-water"),
			ActionResolutionProfile: testRef("2", "resolution"), AdmissionStateDomainDigest: testDigest("3")})
	}
	return GuarantorStageActionAuthorityBindingV1{SchemaVersion: 1, AuthorityDomainDigest: testDigest("4"), Stages: stages}
}

func testCoverageTerms(t *testing.T) CoverageTermsV1 {
	t.Helper()
	asset := testAsset()
	adapter := testRef("1", "payment")
	destination := agentcommerce.PayoutDestinationV1{SchemaVersion: 1, SettlementAdapterProfile: adapter,
		BeneficiarySubject: "agent:beneficiary", Asset: asset, NetworkOrSystemDigest: testDigest("2"),
		DestinationEncoding: "bytes", DestinationBytes: []byte("beneficiary-wallet")}
	destinationDigest, err := agentcommerce.PayoutDestinationDigestV1(destination)
	if err != nil {
		t.Fatal(err)
	}
	parameterBytes, err := codec.Marshal(map[string]interface{}{"network": "tos:test"})
	if err != nil {
		t.Fatal(err)
	}
	parameters := agentcommerce.ProfileQualifiedSettlementParametersV1{SchemaVersion: 1,
		SettlementAdapterProfile: adapter, PayoutDestinationDigest: destinationDigest, AdapterParameters: parameterBytes}
	parameterDigest, err := agentcommerce.SettlementParametersDigestV1(parameters)
	if err != nil {
		t.Fatal(err)
	}
	template := agentcommerce.ConditionalSettlementTemplateV1{TemplateID: "template:payout", AgreementObligationID: "obligation:payout",
		ConditionProfile: testRef("3", "condition"), AuthorizedDecisionProfile: testRef("4", "decision"),
		PayerAgentID: "agent:guarantor", PayeeAgentID: "agent:beneficiary", Asset: asset,
		MaximumPerInstance:     AtomicAmountV1{Asset: asset, AmountAtomic: "500"},
		MaximumAggregateAmount: AtomicAmountV1{Asset: asset, AmountAtomic: "1000"}, MaximumInstances: 8,
		FirstSequence: 1, SettlementAdapterProfile: adapter, SettlementParameters: parameters,
		SettlementParametersDigest: parameterDigest,
		PayoutDestinationBinding: agentcommerce.PayoutDestinationBindingV1{Mode: "agreement_fixed",
			DestinationAuthorizationPredicateID: "predicate:beneficiary", PayoutDestination: destination},
		MaterializationDomain: "tos.test.materialize.v1", CancellationPolicyDigest: testDigest("5"),
		DisputePolicyDigest: testDigest("6")}
	stageBinding := testStageAuthorityBinding(t)
	return CoverageTermsV1{SchemaVersion: 1, CoverageID: testDigest("7"), CoverageVersion: 1,
		ServiceProfileDigest: testDigest("8"), QuoteRequestDigest: testDigest("9"), GuarantorAgentID: "agent:guarantor",
		CoveredPartyAgentID: "agent:covered", BeneficiaryAgentID: "agent:beneficiary",
		PermittedClaimantSubjects: []string{"agent:covered"}, UnderlyingAgreementBodyDigest: testDigest("a"),
		CoveredObligationIDs: []string{"obligation:exchange"}, CoverageCategory: "exchange-default",
		BenefitKind: BenefitFixed, SelectedAssuranceLevel: AssuranceUnsecuredSigned, CoverageAsset: asset,
		MaximumAggregatePayout: AtomicAmountV1{Asset: asset, AmountAtomic: "1000"},
		MaximumPerClaim:        AtomicAmountV1{Asset: asset, AmountAtomic: "500"}, MaximumClaims: 4,
		ClaimClosureCapacity: testCapacity(), CoverageStartsAtUnix: 2_000_000_000,
		CoverageEndsAtUnix: 2_000_003_600, ClaimFilingEndsAtUnix: 2_000_007_200,
		ReviewDeadlineSeconds: 600, ChallengeWindowSeconds: 600, NonterminalResolutionWindowSeconds: 600,
		SuccessorDecisionWindowSeconds: 600, PayoutDeadlineSeconds: 600,
		AdapterRecoveryWindowSeconds: 600, TerminalResolutionDeadlineUnix: 2_000_020_000,
		NonActivationReasonRules: []CoverageNonActivationReasonRuleV1{
			{Reason: "activation_window_expired", EvidenceMode: "deadline_only"},
			{Reason: "mutually_cancelled", EvidenceMode: "agreement_predicates", CancellationAuthorizationPredicateIDs: []string{"predicate:beneficiary"}},
			{Reason: "prerequisite_failed", EvidenceMode: "terminal_prerequisite_failure", PrerequisiteFailureRules: []ActivationPrerequisiteFailureRuleV1{{
				PrerequisiteID: "prerequisite:funding", TerminalFailureEvidenceProfile: testRef("e", "evidence"),
				TerminalFailureAuthoritySubjects: []string{"agent:guarantor"}, TerminalFailureQuorumRule: "all",
				PermittedTerminalFailureOutcomes: []string{"failed"}}}},
		},
		CoverageStateDomainDigest: testDigest("b"), SelectedClaimProfileDigest: testDigest("c"),
		SelectedPayoutAdapterProfile: adapter, CoverageOperationAdapterProfile: testRef("a", "coverage-operation"),
		ClaimOperationAdapterProfile: testRef("b", "claim-operation"), ExposureOperationAdapterProfile: testRef("c", "exposure-operation"),
		StageActionAuthorityBinding: stageBinding, ClaimTriggerProfile: testRef("d", "trigger"),
		ClaimEvidenceProfile: testRef("e", "evidence"), ClaimantAuthorizationProfiles: []ProfileRefV1{testRef("f", "claimant")},
		ClaimIngressProfile: testRef("1", "ingress"), ClaimIngressAuthoritySubjects: []string{"agent:guarantor"},
		ClaimIngressAuthorityQuorumRule: "all", ClaimAdmissionProfile: testRef("2", "admission"),
		ClaimAdmissionAuthoritySubjects: []string{"agent:guarantor"}, ClaimAdmissionQuorumRule: "all",
		AcceptanceAuthorityProfile: testRef("3", "acceptance"), LifecycleAuthorizationProfile: testRef("5", "lifecycle"),
		DecisionAdmissionProfile:           testRef("6", "decision-admission"),
		DecisionAdmissionAuthoritySubjects: []string{"agent:guarantor"}, DecisionAdmissionQuorumRule: "all",
		DecisionProfile: testRef("4", "decision"), DecisionAuthoritySubjects: []string{"agent:guarantor"},
		DecisionQuorumRule: "all",
		PayoutTemplate:     template, PremiumObligationIDs: []string{"obligation:premium"}}
}

func TestObjectAuthorizationBindsExactBody(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	statement := AuthorizationStatementV1{SchemaVersion: 1, AuthoritySubject: "agent:guarantor",
		ProfileURI: "tos.test.authority.v1", ProfileVersion: 1, ProfileDigest: testDigest("1"),
		AuthorizedObjectKind: "firm-coverage-offer", AuthorizedBodyDigest: testDigest("2"),
		ValidationTimeUnix: uint64(now.Unix())}
	authorization := testSignAuthorization(t, statement, "tos.test.signature.v1", "guarantor", []byte("historical-proof"))
	if err := VerifyObjectAuthorization(authorization, statement.AuthorizedObjectKind, statement.AuthorizedBodyDigest,
		"tos.test.signature.v1", allowAuthorityResolver{}, now); err != nil {
		t.Fatal(err)
	}
	if VerifyObjectAuthorization(authorization, statement.AuthorizedObjectKind, testDigest("3"),
		"tos.test.signature.v1", allowAuthorityResolver{}, now) == nil {
		t.Fatal("authorization was replayed onto another body")
	}
}

func TestObjectAuthorizationRejectsUnixTimestampWraparound(t *testing.T) {
	statement := AuthorizationStatementV1{SchemaVersion: 1, AuthoritySubject: "agent:guarantor",
		ProfileURI: "tos.test.authority.v1", ProfileVersion: 1, ProfileDigest: testDigest("1"),
		AuthorizedObjectKind: "firm-coverage-offer", AuthorizedBodyDigest: testDigest("2"),
		ValidationTimeUnix: uint64(math.MaxInt64) + 1}
	if _, err := SignObjectAuthorization(context.Background(), statement, "tos.test.signature.v1", nativeTestFake,
		"guarantor", []byte("historical-proof")); err == nil {
		t.Fatal("authorization timestamp above MaxInt64 was accepted")
	}
	if validUnixTimestampV1(0) || validUnixTimestampV1(uint64(math.MaxInt64)+1) ||
		!validUnixTimestampV1(uint64(math.MaxInt64)) {
		t.Fatal("Guarantor signed Unix timestamp boundary is inconsistent")
	}
}

func TestReleasedMutationRegistryIsExact(t *testing.T) {
	registry := ReleasedMutationVerifierRegistryV1()
	if len(registry.Entries) != 21 {
		t.Fatalf("mutation registry has %d entries", len(registry.Entries))
	}
	if err := VerifyMutationVerifierRegistryV1(registry); err != nil {
		t.Fatal(err)
	}
	registry.Entries[0].OperationPurpose = "substituted"
	if VerifyMutationVerifierRegistryV1(registry) == nil {
		t.Fatal("mutated registry was accepted")
	}
}

func TestReleasedObjectRegistryIsExactAndExhaustive(t *testing.T) {
	registry := ReleasedObjectVerifierRegistryV1()
	if len(registry.Entries) != 89 {
		t.Fatalf("object registry has %d entries", len(registry.Entries))
	}
	if err := VerifyObjectVerifierRegistryV1(registry); err != nil {
		t.Fatal(err)
	}
	registry.Entries[0].CanonicalType = "SubstitutedV1"
	if VerifyObjectVerifierRegistryV1(registry) == nil {
		t.Fatal("mutated object registry was accepted")
	}
}

func TestCancellationRequestBindsPolicyAgreementEvidenceAndRequester(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	authorizationProfile := testRef("1", "cancellation-authority")
	agreement := agentcommerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:cancellation", Version: 1,
		NetworkContext: "tos:test", Participants: []agentcommerce.AgreementParticipant{
			{AgentID: "agent:covered", Roles: []string{"covered"}}, {AgentID: "agent:guarantor", Roles: []string{"guarantor"}}},
		TermsContentType: "text/plain", Terms: []byte("bounded coverage"),
		Obligations: []agentcommerce.AgreementObligation{{ObligationID: "obligation:coverage", Kind: "conditional",
			ObligorAgentID: "agent:guarantor", BeneficiaryAgentID: "agent:covered", SubjectContentType: "text/plain",
			Subject: []byte("coverage"), ConfidentialityPolicy: "participants", CancellationPolicy: "typed",
			DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"predicate:guarantor"}}},
		AuthorizationPredicates: []agentcommerce.AgreementAuthorizationPredicate{{PredicateID: "predicate:guarantor",
			AuthoritySubject: agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent",
				SubjectIdentifier: "agent:guarantor"}, ObligationIDs: []string{"obligation:coverage"},
			EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
			EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	agreement, err := agentcommerce.PrepareAgreementTargets(agreement)
	if err != nil {
		t.Fatal(err)
	}
	agreementDigest, _ := agentcommerce.AgreementBodyDigest(agreement)
	policy := CoverageCancellationPolicyV1{SchemaVersion: 1, PolicyID: "policy:cancellation",
		Branches: []CoverageCancellationPolicyBranchV1{{CancellationBranch: "covered_party_request",
			PermittedRequesterSubjects: []string{"agent:covered"}, RequestAuthorizationProfile: authorizationProfile,
			RequestAuthorizationQuorumRule: "all", MaximumAdmissionDelaySeconds: 300}}}
	policyDigest, err := CoverageCancellationPolicyDigestV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	body := CoverageCancellationRequestBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: "obligation:coverage", CancellationPolicyDigest: policyDigest,
		CancellationBranch: "covered_party_request", RequesterSubject: "agent:covered",
		EffectiveNotBeforeUnix: uint64(now.Unix()), EffectiveNotAfterUnix: uint64(now.Add(5 * time.Minute).Unix()),
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(5 * time.Minute).Unix())}
	bodyDigest, _ := codec.Digest("tos.service.agent-guarantor-cancellation-request-body.v1", body)
	authorization := testSignAuthorization(t, AuthorizationStatementV1{SchemaVersion: 1,
		AuthoritySubject: body.RequesterSubject, ProfileURI: authorizationProfile.ProfileURI,
		ProfileVersion: authorizationProfile.ProfileVersion, ProfileDigest: authorizationProfile.ProfileDigest,
		AuthorizedObjectKind: "coverage-cancellation-request", AuthorizedBodyDigest: bodyDigest,
		ValidationTimeUnix: uint64(now.Unix())}, "tos.service.agent-guarantor-cancellation-request-signature.v1",
		"requester", []byte("requester-history"))
	request := AuthorizedCoverageCancellationRequestV1{Body: body, CoverageAgreementBody: agreement,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{authorization}}
	if err := VerifyCoverageCancellationRequestV1(request, policy, allowAuthorityResolver{}, now); err != nil {
		t.Fatal(err)
	}
	request.Body.RequesterSubject = "agent:attacker"
	if VerifyCoverageCancellationRequestV1(request, policy, allowAuthorityResolver{}, now) == nil {
		t.Fatal("substituted cancellation requester was accepted")
	}
}

func TestOrthogonalStateMachinesRejectStaleAndEarlyRelease(t *testing.T) {
	evidence := testDigest("1")
	record, err := NewAcceptedCoverageRecord(testDigest("2"), "obligation:coverage", testDigest("3"), evidence)
	if err != nil {
		t.Fatal(err)
	}
	record, err = TransitionCoverage(record, 1, CoveragePendingPrerequisites, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TransitionCoverage(record, 1, CoverageActivationResolving, evidence); err == nil {
		t.Fatal("stale coverage revision was accepted")
	}
	record, _ = TransitionCoverage(record, 2, CoverageActivationResolving, evidence)
	record, _ = TransitionCoverage(record, 3, CoverageActive, evidence)
	if _, err := TransitionCoverage(record, 4, CoverageReleasePending, evidence); err == nil {
		t.Fatal("coverage released before filing high-water was frozen")
	}
	record, err = FreezeClaimFiling(record, 4, 2, 1, testDigest("4"), testDigest("5"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TransitionCoverage(record, 5, CoverageReleasePending, testDigest("6")); err != nil {
		t.Fatal(err)
	}
}

func TestClaimValidationAndPayoutMaterialization(t *testing.T) {
	terms := testCoverageTerms(t)
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Fatal(err)
	}
	manifest := ClaimEvidenceManifestV1{SchemaVersion: 1,
		Items: []ClaimEvidenceDescriptorV1{{PredicateID: "predicate:delivery", EvidenceProfile: testRef("1", "evidence-item"),
			ContentType: "application/octet-stream", ContentDigest: testDigest("2"), ContentSize: 100,
			DisclosurePolicyDigest: testDigest("3")}}, TotalDeclaredBytes: 100}
	manifestDigest, err := ValidateClaimEvidenceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	recovery := OtherRecoveryDeclarationV1{SchemaVersion: 1, CoverageAgreementBodyDigest: testDigest("4"),
		CoverageObligationID: "obligation:coverage", UnderlyingAgreementBodyDigest: terms.UnderlyingAgreementBodyDigest,
		ClaimRevision: 1, BeneficiaryAgentID: terms.BeneficiaryAgentID, IncidentKeyDigest: testDigest("5"),
		CoverageAsset: terms.CoverageAsset, RecoveryItems: []OtherRecoveryItemV1{}, DeclaredAtUnix: terms.CoverageStartsAtUnix + 30}
	recoveryDigest, err := ValidateOtherRecoveryDeclaration(recovery, manifest)
	if err != nil {
		t.Fatal(err)
	}
	triggered := TriggeredObligationSetV1{SchemaVersion: 1, UnderlyingAgreementBodyDigest: terms.UnderlyingAgreementBodyDigest,
		ObligationIDs: []string{"obligation:exchange"}}
	triggeredDigest, _ := TriggeredObligationSetDigestV1(triggered)
	claimID, _ := ClaimID(recovery.CoverageAgreementBodyDigest, recovery.CoverageObligationID,
		recovery.IncidentKeyDigest, recovery.BeneficiaryAgentID, triggeredDigest)
	claim := AuthorizedCoverageClaimV1{Body: CoverageClaimBodyV1{SchemaVersion: 1, ClaimID: claimID, ClaimRevision: 1,
		CoverageAgreementBodyDigest: recovery.CoverageAgreementBodyDigest, CoverageObligationID: recovery.CoverageObligationID,
		UnderlyingAgreementBodyDigest: terms.UnderlyingAgreementBodyDigest,
		TriggeredObligationSet:        triggered, ClaimantSubject: "agent:covered",
		ClaimantAuthorizationProfile: terms.ClaimantAuthorizationProfiles[0], BeneficiaryAgentID: terms.BeneficiaryAgentID,
		IncidentKeyDigest: recovery.IncidentKeyDigest, OccurredAtUnix: terms.CoverageStartsAtUnix + 10,
		ClaimedAmount: AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "500"}, EvidenceManifestDigest: manifestDigest,
		OtherRecoveryDeclarationDigest: recoveryDigest,
		PayoutDestinationDigest:        terms.PayoutTemplate.SettlementParameters.PayoutDestinationDigest,
		CreatedAtUnix:                  terms.CoverageStartsAtUnix + 30, ExpiresAtUnix: terms.ClaimFilingEndsAtUnix},
		EvidenceManifest: manifest, OtherRecoveryDeclaration: recovery}
	if _, err := ClaimEnvelopeDigest(claim); err != nil {
		t.Fatal(err)
	}
	claimDigest, _ := ClaimEnvelopeDigest(claim)
	decision := AuthorizedClaimDecisionV1{Body: ClaimDecisionBodyV1{SchemaVersion: 1, ClaimID: claimID,
		CoverageAgreementBodyDigest: claim.Body.CoverageAgreementBodyDigest, CoverageObligationID: claim.Body.CoverageObligationID,
		AuthorizedClaimEnvelopeDigest: claimDigest, DecisionSequence: 1, DecisionRevision: 1, DecisionPath: "initial",
		ExpectedClaimRevision: 1, DecisionProfile: terms.DecisionProfile,
		DecisionAuthoritySubjects: terms.DecisionAuthoritySubjects, DecisionQuorumRule: "all",
		Result: DecisionApproved, ApprovedAmount: AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "500"},
		EvidenceSetDigest: testDigest("7"), PolicyApplicationDigest: testDigest("a"), ReasonDigest: testDigest("b"),
		PayoutLines: []ClaimPayoutLineV1{{DecisionLineIndex: 1,
			Amount:                       AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "500"},
			PayoutDestinationDigest:      terms.PayoutTemplate.SettlementParameters.PayoutDestinationDigest,
			DueAfterTerminalCloseSeconds: 600, ExpiresAfterTerminalCloseSeconds: 1200}},
		ChallengeWindowSeconds: 600, DecidedAtUnix: terms.CoverageStartsAtUnix + 60,
		ExpiresAtUnix: terms.CoverageStartsAtUnix + 1200}}
	set, err := MaterializeClaimPayout("owner:guarantor", "agent:guarantor", testDigest("8"),
		"obligation:payout", terms, decision, testDigest("9"), terms.CoverageStartsAtUnix+100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Obligations) != 1 || set.Obligations[0].Amount.AmountAtomic != "500" || set.FirstPayoutSequence != 1 {
		t.Fatalf("unexpected payout materialization: %+v", set)
	}
	decision.Body.PayoutLines[0].Amount.AmountAtomic = "499"
	if _, err := MaterializeClaimPayout("owner:guarantor", "agent:guarantor", testDigest("8"),
		"obligation:payout", terms, decision, testDigest("9"), terms.CoverageStartsAtUnix+100, 1); err == nil {
		t.Fatal("decision with inconsistent line sum was accepted")
	}
}
