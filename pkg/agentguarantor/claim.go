package agentguarantor

import (
	"errors"
	"math/big"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TriggeredObligationSetDigestV1(value TriggeredObligationSetV1) (string, error) {
	if value.SchemaVersion != 1 || !validDigest(value.UnderlyingAgreementBodyDigest) ||
		!sortedUnique(value.ObligationIDs, 256, func(v string) bool { return validToken(v, 128) }) {
		return "", errors.New("triggered obligation set is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-triggered-obligation-set.v1", value)
}

func ClaimID(coverageAgreementBodyDigest, coverageObligationID, incidentKeyDigest, beneficiaryAgentID,
	triggeredObligationSetDigest string) (string, error) {
	if !validDigest(coverageAgreementBodyDigest) || !validToken(coverageObligationID, 128) ||
		!validDigest(incidentKeyDigest) || !validID(beneficiaryAgentID) || !validDigest(triggeredObligationSetDigest) {
		return "", errors.New("claim identity input is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-id.v1", struct {
		CoverageAgreementBodyDigest  string `json:"coverage_agreement_body_digest"`
		CoverageObligationID         string `json:"coverage_obligation_id"`
		IncidentKeyDigest            string `json:"incident_key_digest"`
		BeneficiaryAgentID           string `json:"beneficiary_agent_id"`
		TriggeredObligationSetDigest string `json:"triggered_obligation_set_digest"`
	}{coverageAgreementBodyDigest, coverageObligationID, incidentKeyDigest, beneficiaryAgentID, triggeredObligationSetDigest})
}

func ClaimBodyDigest(body CoverageClaimBodyV1) (string, error) {
	if err := validateClaimBody(body); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ClaimBodyDomain, body)
}

func ClaimEnvelopeDigest(claim AuthorizedCoverageClaimV1) (string, error) {
	if err := validateClaimEnvelopeShape(claim); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ClaimDomain, claim)
}

func VerifyClaim(claim AuthorizedCoverageClaimV1, terms CoverageTermsV1, coverageAgreementBodyDigest,
	coverageObligationID string, resolver AuthorityKeyResolver, now time.Time) error {
	if ValidateCoverageTerms(terms) != nil || validateClaimEnvelopeShape(claim) != nil ||
		claim.Body.CoverageAgreementBodyDigest != coverageAgreementBodyDigest ||
		claim.Body.CoverageObligationID != coverageObligationID || claim.Body.BeneficiaryAgentID != terms.BeneficiaryAgentID ||
		!containsString(terms.PermittedClaimantSubjects, claim.Body.ClaimantSubject) ||
		!containsProfileRef(terms.ClaimantAuthorizationProfiles, claim.Body.ClaimantAuthorizationProfile) ||
		claim.Body.UnderlyingAgreementBodyDigest != terms.UnderlyingAgreementBodyDigest ||
		claim.Body.TriggeredObligationSet.UnderlyingAgreementBodyDigest != terms.UnderlyingAgreementBodyDigest ||
		!subset(claim.Body.TriggeredObligationSet.ObligationIDs, terms.CoveredObligationIDs) ||
		claim.Body.OccurredAtUnix < terms.CoverageStartsAtUnix || claim.Body.OccurredAtUnix > terms.CoverageEndsAtUnix ||
		claim.Body.CreatedAtUnix > terms.ClaimFilingEndsAtUnix || uint64(now.UTC().Unix()) >= claim.Body.ExpiresAtUnix ||
		claim.Body.ClaimedAmount.Asset != terms.CoverageAsset {
		return errors.New("claim is outside accepted coverage")
	}
	if comparison, _ := compareAmount(claim.Body.ClaimedAmount, terms.MaximumPerClaim); comparison > 0 {
		return errors.New("claim exceeds per-claim coverage")
	}
	for _, authorization := range claim.Authorizations {
		if authorization.AuthoritySubject != claim.Body.ClaimantSubject ||
			authorization.ProfileURI != claim.Body.ClaimantAuthorizationProfile.ProfileURI ||
			authorization.ProfileVersion != claim.Body.ClaimantAuthorizationProfile.ProfileVersion ||
			authorization.ProfileDigest != claim.Body.ClaimantAuthorizationProfile.ProfileDigest {
			return errors.New("claim authorization uses a substituted profile")
		}
	}
	bodyDigest, _ := ClaimBodyDigest(claim.Body)
	return ValidateAuthorizationSet(claim.Authorizations, "coverage-claim", bodyDigest,
		"tos.service.agent-guarantor-claim-signature.v1", []string{claim.Body.ClaimantSubject}, resolver, now)
}

func validateClaimEnvelopeShape(claim AuthorizedCoverageClaimV1) error {
	manifestDigest, err := ValidateClaimEvidenceManifest(claim.EvidenceManifest)
	if err != nil || manifestDigest != claim.Body.EvidenceManifestDigest {
		return errors.New("claim evidence manifest does not match claim")
	}
	recoveryDigest, err := ValidateOtherRecoveryDeclaration(claim.OtherRecoveryDeclaration, claim.EvidenceManifest)
	if err != nil || recoveryDigest != claim.Body.OtherRecoveryDeclarationDigest {
		return errors.New("other recovery declaration does not match claim")
	}
	if claim.OtherRecoveryDeclaration.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		claim.OtherRecoveryDeclaration.CoverageObligationID != claim.Body.CoverageObligationID ||
		claim.OtherRecoveryDeclaration.UnderlyingAgreementBodyDigest != claim.Body.UnderlyingAgreementBodyDigest ||
		claim.OtherRecoveryDeclaration.ClaimRevision != claim.Body.ClaimRevision ||
		claim.OtherRecoveryDeclaration.BeneficiaryAgentID != claim.Body.BeneficiaryAgentID ||
		claim.OtherRecoveryDeclaration.IncidentKeyDigest != claim.Body.IncidentKeyDigest {
		return errors.New("other recovery declaration context differs from claim")
	}
	return validateClaimBody(claim.Body)
}

func validateClaimBody(body CoverageClaimBodyV1) error {
	triggeredDigest, triggeredErr := TriggeredObligationSetDigestV1(body.TriggeredObligationSet)
	wantID, err := ClaimID(body.CoverageAgreementBodyDigest, body.CoverageObligationID, body.IncidentKeyDigest,
		body.BeneficiaryAgentID, triggeredDigest)
	if err != nil || body.SchemaVersion != 1 || body.ClaimID != wantID || body.ClaimRevision == 0 ||
		body.ClaimRevision == 1 && body.PredecessorClaimDigest != "" || body.ClaimRevision > 1 && !validDigest(body.PredecessorClaimDigest) ||
		triggeredErr != nil || !validDigest(body.UnderlyingAgreementBodyDigest) || body.TriggeredObligationSet.SchemaVersion != 1 ||
		body.TriggeredObligationSet.UnderlyingAgreementBodyDigest != body.UnderlyingAgreementBodyDigest ||
		!sortedUnique(body.TriggeredObligationSet.ObligationIDs, 256, func(v string) bool { return validToken(v, 128) }) ||
		!validID(body.ClaimantSubject) || agentcommerce.ValidateProfileRefV1(body.ClaimantAuthorizationProfile) != nil ||
		!validID(body.BeneficiaryAgentID) || body.OccurredAtUnix == 0 || validateAmount(body.ClaimedAmount, true) != nil ||
		!validDigest(body.EvidenceManifestDigest) || !validDigest(body.OtherRecoveryDeclarationDigest) ||
		!validDigest(body.PayoutDestinationDigest) || body.CreatedAtUnix == 0 || body.ExpiresAtUnix <= body.CreatedAtUnix ||
		body.ExpiresAtUnix-body.CreatedAtUnix > uint64((365*24*time.Hour)/time.Second) {
		return errors.New("coverage claim body is invalid")
	}
	return nil
}

func ValidateClaimEvidenceManifest(manifest ClaimEvidenceManifestV1) (string, error) {
	if manifest.SchemaVersion != 1 || len(manifest.Items) == 0 || len(manifest.Items) > MaxEvidenceItems {
		return "", errors.New("claim evidence manifest is invalid")
	}
	previous := ""
	var total uint64
	for _, item := range manifest.Items {
		if !validToken(item.PredicateID, 128) || item.PredicateID <= previous || agentcommerce.ValidateProfileRefV1(item.EvidenceProfile) != nil ||
			!validToken(item.ContentType, 256) || !validDigest(item.ContentDigest) || item.ContentSize == 0 ||
			item.ContentSize > MaxCanonicalObjectBytes || !validDigest(item.DisclosurePolicyDigest) || total > MaxCanonicalObjectBytes-item.ContentSize {
			return "", errors.New("claim evidence item is invalid, duplicated, or over-bound")
		}
		total += item.ContentSize
		previous = item.PredicateID
	}
	if total != manifest.TotalDeclaredBytes {
		return "", errors.New("claim evidence total is not exact")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-evidence-manifest.v1", manifest)
}

func ValidateOtherRecoveryDeclaration(declaration OtherRecoveryDeclarationV1, manifest ClaimEvidenceManifestV1) (string, error) {
	if declaration.SchemaVersion != 1 || !validDigest(declaration.CoverageAgreementBodyDigest) ||
		!validToken(declaration.CoverageObligationID, 128) || !validDigest(declaration.UnderlyingAgreementBodyDigest) ||
		declaration.ClaimRevision == 0 || !validID(declaration.BeneficiaryAgentID) || !validDigest(declaration.IncidentKeyDigest) ||
		agentcommerce.ValidateAssetIdentityV1(declaration.CoverageAsset) != nil || len(declaration.RecoveryItems) > MaxEvidenceItems || declaration.DeclaredAtUnix == 0 {
		return "", errors.New("other recovery declaration is invalid")
	}
	predicates := make(map[string]struct{}, len(manifest.Items))
	for _, item := range manifest.Items {
		predicates[item.PredicateID] = struct{}{}
	}
	previous := ""
	for _, item := range declaration.RecoveryItems {
		if !validToken(item.RecoveryItemID, 128) || item.RecoveryItemID <= previous || !validRecoveryKind(item.SourceKind) ||
			!validID(item.SourceSubject) || item.RelatedInstrumentDigest != "" && !validDigest(item.RelatedInstrumentDigest) ||
			!validRecoveryStatus(item.RecoveryStatus) || validateAmount(item.AmountReceived, false) != nil ||
			validateAmount(item.AmountReceivable, false) != nil || item.AmountReceived.Asset != declaration.CoverageAsset ||
			item.AmountReceivable.Asset != declaration.CoverageAsset ||
			!sortedUniqueAllowEmpty(item.EvidencePredicateIDs, MaxEvidenceItems, func(v string) bool { _, ok := predicates[v]; return ok }) {
			return "", errors.New("other recovery item is invalid")
		}
		previous = item.RecoveryItemID
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-other-recovery-declaration.v1", declaration)
}

func ValidateClaimDecision(decision AuthorizedClaimDecisionV1, claim AuthorizedCoverageClaimV1, terms CoverageTermsV1,
	resolver AuthorityKeyResolver, requiredDecisionSubjects []string, now time.Time) error {
	fallbackPath := isFallbackDecisionPathV1(decision.Body.DecisionPath)
	expectedProfile := terms.DecisionProfile
	expectedSubjects := terms.DecisionAuthoritySubjects
	expectedQuorum := terms.DecisionQuorumRule
	if fallbackPath {
		expectedProfile = terms.ClaimClosureCapacity.TerminalFallback.FallbackProfile
		expectedSubjects = terms.ClaimClosureCapacity.TerminalFallback.FallbackAuthoritySubjects
		expectedQuorum = terms.ClaimClosureCapacity.TerminalFallback.FallbackQuorumRule
	}
	claimDigest, claimErr := ClaimEnvelopeDigest(claim)
	evidenceDigest, evidenceErr := CanonicalGuarantorEvidenceSetDigestV1(decision.DecisionEvidenceSet)
	policyDigest, policyErr := ClaimDecisionPolicyApplicationDigestV1(decision.PolicyApplication)
	reasonDigest, reasonErr := ClaimDecisionReasonDigestV1(decision.DecisionReason)
	bodyDigest, bodyErr := ClaimDecisionBodyDigestV1(decision.Body, terms)
	if claimErr != nil || evidenceErr != nil || policyErr != nil || reasonErr != nil || bodyErr != nil ||
		decision.Body.ClaimID != claim.Body.ClaimID || decision.Body.ExpectedClaimRevision != claim.Body.ClaimRevision ||
		decision.Body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		decision.Body.CoverageObligationID != claim.Body.CoverageObligationID ||
		decision.Body.AuthorizedClaimEnvelopeDigest != claimDigest || !equalStrings(requiredDecisionSubjects, expectedSubjects) ||
		decision.Body.DecisionProfile != expectedProfile || !equalStrings(decision.Body.DecisionAuthoritySubjects, requiredDecisionSubjects) ||
		decision.Body.DecisionQuorumRule != expectedQuorum || decision.Body.EvidenceSetDigest != evidenceDigest ||
		decision.Body.PolicyApplicationDigest != policyDigest || decision.Body.ReasonDigest != reasonDigest ||
		decision.DecisionEvidenceSet.Purpose != "claim-decision-evidence" || decision.DecisionEvidenceSet.ContextDigest != claimDigest ||
		decision.PolicyApplication.CoverageAgreementBodyDigest != decision.Body.CoverageAgreementBodyDigest ||
		decision.PolicyApplication.CoverageObligationID != decision.Body.CoverageObligationID ||
		decision.PolicyApplication.AuthorizedClaimEnvelopeDigest != claimDigest ||
		decision.PolicyApplication.DecisionPath != decision.Body.DecisionPath ||
		decision.PolicyApplication.BenefitCalculationProfile != terms.BenefitCalculationProfile ||
		decision.PolicyApplication.EvidenceSetDigest != evidenceDigest ||
		decision.PolicyApplication.OtherRecoveryDeclarationDigest != claim.Body.OtherRecoveryDeclarationDigest ||
		decision.DecisionReason.DecisionProfile != expectedProfile || decision.DecisionReason.Result != decision.Body.Result ||
		uint64(now.UTC().Unix()) >= decision.Body.ExpiresAtUnix {
		return errors.New("claim decision does not match admitted claim")
	}
	triggeredDigest, err := TriggeredObligationSetDigestV1(claim.Body.TriggeredObligationSet)
	if err != nil || decision.PolicyApplication.TriggeredObligationSetDigest != triggeredDigest ||
		decision.PolicyApplication.FullEligibleBenefitAmount.Asset != terms.CoverageAsset ||
		!subset(decision.DecisionReason.ApplicablePolicyClauseIDs, decision.PolicyApplication.ApplicablePolicyClauseIDs) {
		return errors.New("claim decision policy projection differs from admitted evidence")
	}
	approvedVsEligible, compareErr := compareAmount(decision.Body.ApprovedAmount,
		decision.PolicyApplication.FullEligibleBenefitAmount)
	if compareErr != nil || decision.Body.Result == DecisionApproved && approvedVsEligible != 0 ||
		decision.Body.Result == DecisionPartiallyApproved && (approvedVsEligible >= 0 || decision.Body.ApprovedAmount.AmountAtomic == "0") ||
		decision.Body.Result == DecisionDenied && decision.PolicyApplication.FallbackAggregateProjection == nil &&
			decision.PolicyApplication.FullEligibleBenefitAmount.AmountAtomic != "0" {
		return errors.New("claim decision amount does not follow the benefit calculation")
	}
	manifestPredicates := make(map[string]struct{}, len(claim.EvidenceManifest.Items))
	for _, item := range claim.EvidenceManifest.Items {
		manifestPredicates[item.PredicateID] = struct{}{}
	}
	for _, predicateID := range decision.DecisionReason.EvidencePredicateIDs {
		if _, found := manifestPredicates[predicateID]; !found {
			return errors.New("claim decision reason cites an unknown evidence predicate")
		}
	}
	if fallbackPath {
		if err := validateDeterministicFallbackDecisionV1(decision, claim, terms); err != nil {
			return err
		}
		// A deterministic fallback is not a second discretionary decision by the
		// Guarantor.  The parties authorize the closed total function in the
		// Agreement and the decision-admission authority merely materializes its
		// output after the committed deadline.  Requiring a fresh Guarantor
		// signature here would let the very party whose timeout triggered the
		// fallback keep the claim open forever.
		if len(decision.Authorizations) != 0 {
			return errors.New("Agreement-granted deterministic fallback carries discretionary decision authorization")
		}
		return nil
	}
	for _, authorization := range decision.Authorizations {
		if authorization.ProfileURI != expectedProfile.ProfileURI ||
			authorization.ProfileVersion != expectedProfile.ProfileVersion ||
			authorization.ProfileDigest != expectedProfile.ProfileDigest {
			return errors.New("claim decision authorization uses a substituted profile")
		}
	}
	return ValidateAuthorizationQuorumSet(decision.Authorizations, "claim-decision", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-signature.v1", requiredDecisionSubjects, expectedQuorum, resolver, now)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func isFallbackDecisionPathV1(path string) bool {
	return path == "initial_terminal_fallback" || path == "terminal_fallback" || path == "late_recovery_terminal_fallback"
}

func validateDeterministicFallbackDecisionV1(decision AuthorizedClaimDecisionV1, claim AuthorizedCoverageClaimV1,
	terms CoverageTermsV1) error {
	fallback := terms.ClaimClosureCapacity.TerminalFallback
	fallbackDigest, err := DeterministicClaimTerminalFallbackDigestV1(fallback)
	if err != nil {
		return err
	}
	policy := decision.PolicyApplication
	zero := AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "0"}
	outcomeCase := ""
	if fallback.OutcomeRule == "deny_zero" {
		if decision.Body.Result != DecisionDenied || decision.Body.ApprovedAmount != zero ||
			policy.FullEligibleBenefitAmount != zero || policy.FallbackAggregateProjection != nil ||
			len(policy.PolicyInputProjection) != 0 || len(decision.Body.PayoutLines) != 0 {
			return errors.New("deny-zero fallback output was caller-selected or noncanonical")
		}
		outcomeCase = "deny_zero"
	} else {
		projection := policy.FallbackAggregateProjection
		if projection == nil || projection.FallbackProfileDigest != fallbackDigest || len(policy.PolicyInputProjection) == 0 {
			return errors.New("benefit fallback lacks its Agreement-bound aggregate projection")
		}
		values := []*big.Int{}
		for _, amount := range []AtomicAmountV1{projection.GrossFallbackAmount, projection.CumulativeAppliedApprovedAmount,
			projection.AggregatePendingDecisionReserveBefore, projection.ReclaimablePriorAmount,
			projection.RemainingAggregateCapacity, projection.ProjectedApprovedAmount} {
			parsed, ok := new(big.Int).SetString(amount.AmountAtomic, 10)
			if !ok || amount.Asset != terms.CoverageAsset {
				return errors.New("benefit fallback aggregate operand is invalid")
			}
			values = append(values, parsed)
		}
		gross, cumulative, pending, reclaimable, remaining, approved := values[0], values[1], values[2], values[3], values[4], values[5]
		maximum, ok := new(big.Int).SetString(terms.MaximumAggregatePayout.AmountAtomic, 10)
		if !ok || reclaimable.Cmp(pending) > 0 {
			return errors.New("benefit fallback reclaimable reserve is invalid")
		}
		wantRemaining := new(big.Int).Sub(maximum, cumulative)
		wantRemaining.Sub(wantRemaining, pending).Add(wantRemaining, reclaimable)
		if wantRemaining.Sign() < 0 || remaining.Cmp(wantRemaining) != 0 {
			return errors.New("benefit fallback remaining aggregate capacity differs")
		}
		wantApproved := new(big.Int).Set(gross)
		if wantApproved.Cmp(remaining) > 0 {
			wantApproved.Set(remaining)
		}
		if approved.Cmp(wantApproved) != 0 || decision.Body.ApprovedAmount != projection.ProjectedApprovedAmount ||
			policy.FullEligibleBenefitAmount != projection.GrossFallbackAmount {
			return errors.New("benefit fallback projected approval differs")
		}
		switch {
		case gross.Sign() == 0:
			outcomeCase = "no_eligible_benefit"
		case remaining.Sign() == 0:
			outcomeCase = "aggregate_exhausted"
		case approved.Cmp(gross) < 0:
			outcomeCase = "aggregate_limited"
		default:
			outcomeCase = "full_benefit"
		}
	}
	var selected *DeterministicFallbackReasonRuleV1
	for index := range fallback.ReasonRules {
		if fallback.ReasonRules[index].OutcomeCase == outcomeCase {
			selected = &fallback.ReasonRules[index]
			break
		}
	}
	if selected == nil || decision.DecisionReason.ReasonCode != selected.ReasonCode ||
		decision.Body.Result != ClaimDecisionResult(selected.Result) ||
		!equalStrings(decision.DecisionReason.ApplicablePolicyClauseIDs, selected.ApplicablePolicyClauseIDs) ||
		!equalStrings(policy.ApplicablePolicyClauseIDs, selected.ApplicablePolicyClauseIDs) {
		return errors.New("deterministic fallback reason mapping was substituted")
	}
	wantPredicates := make([]string, len(claim.EvidenceManifest.Items))
	for index, item := range claim.EvidenceManifest.Items {
		wantPredicates[index] = item.PredicateID
	}
	if !equalStrings(decision.DecisionReason.EvidencePredicateIDs, wantPredicates) {
		return errors.New("deterministic fallback omitted admitted evidence predicates")
	}
	return nil
}

func containsProfileRef(values []ProfileRefV1, wanted ProfileRefV1) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func ClaimDecisionPolicyApplicationDigestV1(value ClaimDecisionPolicyApplicationV1) (string, error) {
	if err := validateClaimDecisionPolicyApplicationV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-policy-application.v1", value)
}

func ClaimDecisionReasonDigestV1(value ClaimDecisionReasonV1) (string, error) {
	if value.SchemaVersion != 1 || agentcommerce.ValidateProfileRefV1(value.DecisionProfile) != nil ||
		!validDecisionResult(value.Result) || !validToken(value.ReasonCode, 128) ||
		!sortedUniqueAllowEmpty(value.ApplicablePolicyClauseIDs, 256, func(v string) bool { return validToken(v, 128) }) ||
		!sortedUniqueAllowEmpty(value.EvidencePredicateIDs, MaxEvidenceItems, func(v string) bool { return validToken(v, 128) }) {
		return "", errors.New("claim decision reason is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-reason.v1", value)
}

func ClaimDecisionBodyDigestV1(body ClaimDecisionBodyV1, terms CoverageTermsV1) (string, error) {
	if err := validateClaimDecisionBody(body, terms); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-body.v1", body)
}

func ClaimDecisionDigestV1(value AuthorizedClaimDecisionV1) (string, error) {
	return guarantorCodec.Digest(ClaimDecisionDomain, value)
}

func validateClaimDecisionPolicyApplicationV1(value ClaimDecisionPolicyApplicationV1) error {
	if value.SchemaVersion != 1 || !validDigest(value.CoverageAgreementBodyDigest) ||
		!validToken(value.CoverageObligationID, 128) || !validDigest(value.AuthorizedClaimEnvelopeDigest) ||
		!validDecisionPath(value.DecisionPath) || agentcommerce.ValidateProfileRefV1(value.BenefitCalculationProfile) != nil ||
		!validDigest(value.TriggeredObligationSetDigest) || !validDigest(value.EvidenceSetDigest) ||
		!validDigest(value.OtherRecoveryDeclarationDigest) ||
		!sortedUniqueAllowEmpty(value.ApplicablePolicyClauseIDs, 256, func(v string) bool { return validToken(v, 128) }) ||
		len(value.PolicyInputProjection) > 64<<10 ||
		validateAmount(value.FullEligibleBenefitAmount, false) != nil {
		return errors.New("claim decision policy application is invalid")
	}
	fallback := value.DecisionPath == "initial_terminal_fallback" || value.DecisionPath == "terminal_fallback" ||
		value.DecisionPath == "late_recovery_terminal_fallback"
	if !fallback && (value.FallbackAggregateProjection != nil || len(value.PolicyInputProjection) == 0) {
		return errors.New("ordinary claim decision policy projection is invalid")
	}
	if fallback && value.FallbackAggregateProjection == nil {
		if len(value.PolicyInputProjection) != 0 || value.FullEligibleBenefitAmount.AmountAtomic != "0" {
			return errors.New("deny-zero fallback policy projection is not canonical")
		}
	} else if fallback && len(value.PolicyInputProjection) == 0 {
		return errors.New("benefit-calculation fallback lacks its total-function projection")
	}
	if value.FallbackAggregateProjection != nil {
		projection := value.FallbackAggregateProjection
		amounts := []AtomicAmountV1{projection.GrossFallbackAmount, projection.CumulativeAppliedApprovedAmount,
			projection.AggregatePendingDecisionReserveBefore, projection.ReclaimablePriorAmount,
			projection.RemainingAggregateCapacity, projection.ProjectedApprovedAmount}
		if projection.SchemaVersion != 1 || !validDigest(projection.FallbackProfileDigest) {
			return errors.New("claim decision fallback aggregate projection is invalid")
		}
		for _, amount := range amounts {
			if validateAmount(amount, false) != nil || amount.Asset != value.FullEligibleBenefitAmount.Asset {
				return errors.New("claim decision fallback aggregate amount is invalid")
			}
		}
	}
	return nil
}

func validDecisionPath(value string) bool {
	switch value {
	case "initial", "successor", "initial_terminal_fallback", "terminal_fallback", "late_recovery_terminal_fallback":
		return true
	default:
		return false
	}
}

func validDecisionResult(value ClaimDecisionResult) bool {
	switch value {
	case DecisionApproved, DecisionPartiallyApproved, DecisionDenied, DecisionEvidenceRequired, DecisionDisputed:
		return true
	default:
		return false
	}
}

func validateClaimDecisionBody(body ClaimDecisionBodyV1, terms CoverageTermsV1) error {
	if body.SchemaVersion != 1 || !validDigest(body.ClaimID) || body.ExpectedClaimRevision == 0 ||
		!validDigest(body.CoverageAgreementBodyDigest) || !validToken(body.CoverageObligationID, 128) ||
		!validDigest(body.AuthorizedClaimEnvelopeDigest) || body.DecisionSequence == 0 || body.DecisionRevision != 1 ||
		!validDecisionPath(body.DecisionPath) || agentcommerce.ValidateProfileRefV1(body.DecisionProfile) != nil ||
		QuorumThresholdMustFailV1(body.DecisionQuorumRule, body.DecisionAuthoritySubjects) ||
		!validDigest(body.EvidenceSetDigest) || !validDigest(body.PolicyApplicationDigest) || !validDigest(body.ReasonDigest) ||
		body.DecidedAtUnix == 0 || body.ExpiresAtUnix <= body.DecidedAtUnix ||
		body.ExpiresAtUnix-body.DecidedAtUnix > uint64((30*24*time.Hour)/time.Second) ||
		validateAmount(body.ApprovedAmount, false) != nil || body.ApprovedAmount.Asset != terms.CoverageAsset ||
		len(body.PayoutLines) > int(terms.ClaimClosureCapacity.MaximumPayoutLinesPerClaim) ||
		!sortedProfileRefs(body.RequiredExtensions, MaxExtensions) || !sortedProfileRefs(body.OptionalExtensions, MaxExtensions) {
		return errors.New("claim decision body is invalid")
	}
	if body.DecisionSequence == 1 {
		if body.PredecessorAuthorizedClaimDecisionDigest != "" || body.DecisionPath == "successor" || body.DecisionPath == "terminal_fallback" {
			return errors.New("initial claim decision predecessor is invalid")
		}
	} else if !validDigest(body.PredecessorAuthorizedClaimDecisionDigest) || body.DecisionPath == "initial" ||
		body.DecisionPath == "initial_terminal_fallback" {
		return errors.New("successor claim decision predecessor is invalid")
	}
	zero := body.ApprovedAmount.AmountAtomic == "0"
	switch body.Result {
	case DecisionApproved, DecisionPartiallyApproved:
		if zero || len(body.PayoutLines) == 0 || body.ChallengeWindowSeconds != terms.ChallengeWindowSeconds ||
			body.ResolutionWindowSeconds != 0 {
			return errors.New("approving decision lacks payout lines")
		}
	case DecisionDenied:
		if !zero || len(body.PayoutLines) != 0 || body.ChallengeWindowSeconds != terms.ChallengeWindowSeconds ||
			body.ResolutionWindowSeconds != 0 {
			return errors.New("non-approving decision carries payout")
		}
	case DecisionEvidenceRequired, DecisionDisputed:
		if !zero || len(body.PayoutLines) != 0 || body.ChallengeWindowSeconds != 0 ||
			body.ResolutionWindowSeconds != terms.NonterminalResolutionWindowSeconds || body.ResolutionWindowSeconds == 0 {
			return errors.New("nonterminal decision timing or payout is invalid")
		}
	default:
		return errors.New("claim decision result is unknown")
	}
	var total big.Int
	for index, line := range body.PayoutLines {
		if line.DecisionLineIndex != uint64(index+1) || validateAmount(line.Amount, true) != nil || line.Amount.Asset != terms.CoverageAsset ||
			!validDigest(line.PayoutDestinationDigest) || line.NotBeforeAfterTerminalCloseSeconds > line.DueAfterTerminalCloseSeconds ||
			line.DueAfterTerminalCloseSeconds > terms.PayoutDeadlineSeconds ||
			line.ExpiresAfterTerminalCloseSeconds != line.DueAfterTerminalCloseSeconds+terms.AdapterRecoveryWindowSeconds {
			return errors.New("claim payout line is invalid")
		}
		value, _ := new(big.Int).SetString(line.Amount.AmountAtomic, 10)
		total.Add(&total, value)
	}
	if total.String() != body.ApprovedAmount.AmountAtomic {
		return errors.New("claim payout lines do not sum to approved amount")
	}
	if comparison, _ := compareAmount(body.ApprovedAmount, terms.MaximumPerClaim); comparison > 0 {
		return errors.New("claim decision exceeds per-claim maximum")
	}
	return nil
}

func MaterializeClaimPayout(ownerID, agentID, mandateDigest, payoutTemplateObligationID string, terms CoverageTermsV1,
	decision AuthorizedClaimDecisionV1, terminalClaimStateTransitionReceiptDigest string, terminalCloseUnix, firstPayoutSequence uint64) (MaterializedPayoutObligationSetV1, error) {
	if !validID(ownerID) || !validID(agentID) || !validDigest(mandateDigest) || !validToken(payoutTemplateObligationID, 128) ||
		ValidateCoverageTerms(terms) != nil || validateClaimDecisionBody(decision.Body, terms) != nil ||
		!validDigest(terminalClaimStateTransitionReceiptDigest) || terminalCloseUnix == 0 || firstPayoutSequence == 0 {
		return MaterializedPayoutObligationSetV1{}, errors.New("payout materialization input is invalid")
	}
	decisionDigest, err := ClaimDecisionDigestV1(decision)
	if err != nil {
		return MaterializedPayoutObligationSetV1{}, err
	}
	decisionBodyDigest, err := ClaimDecisionBodyDigestV1(decision.Body, terms)
	if err != nil {
		return MaterializedPayoutObligationSetV1{}, err
	}
	result := MaterializedPayoutObligationSetV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: decision.Body.CoverageAgreementBodyDigest,
		PayoutTemplateObligationID:  payoutTemplateObligationID, AuthorizedClaimDecisionDigest: decisionDigest,
		TerminalClaimStateTransitionReceiptDigest: terminalClaimStateTransitionReceiptDigest}
	if decision.Body.Result == DecisionDenied {
		result.MaterializationState = "not_applicable"
		return result, nil
	}
	if decision.Body.Result != DecisionApproved && decision.Body.Result != DecisionPartiallyApproved {
		return MaterializedPayoutObligationSetV1{}, errors.New("nonterminal decision cannot materialize payout")
	}
	result.MaterializationState = "materialized"
	result.FirstPayoutSequence = firstPayoutSequence
	previousLineDigest := ""
	previousInstanceID := ""
	for offset, line := range decision.Body.PayoutLines {
		sequence := firstPayoutSequence + uint64(offset)
		notBefore, ok := checkedAdd(terminalCloseUnix, line.NotBeforeAfterTerminalCloseSeconds)
		if !ok {
			return MaterializedPayoutObligationSetV1{}, errors.New("payout time overflows")
		}
		due, ok := checkedAdd(terminalCloseUnix, line.DueAfterTerminalCloseSeconds)
		if !ok {
			return MaterializedPayoutObligationSetV1{}, errors.New("payout time overflows")
		}
		expires, ok := checkedAdd(terminalCloseUnix, line.ExpiresAfterTerminalCloseSeconds)
		if !ok || expires > terms.TerminalResolutionDeadlineUnix {
			return MaterializedPayoutObligationSetV1{}, errors.New("payout exceeds terminal resolution deadline")
		}
		lineDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-payout-line.v1", line)
		identity := struct {
			CoverageAgreementBodyDigest               string `json:"coverage_agreement_body_digest"`
			PayoutTemplateObligationID                string `json:"payout_template_obligation_id"`
			ClaimDecisionBodyDigest                   string `json:"claim_decision_body_digest"`
			TerminalClaimStateTransitionReceiptDigest string `json:"terminal_claim_state_transition_receipt_digest"`
			DecisionLineIndex                         uint64 `json:"decision_line_index"`
			ClaimPayoutLineDigest                     string `json:"claim_payout_line_digest"`
			NotBeforeUnix                             uint64 `json:"not_before_unix"`
			DueAtUnix                                 uint64 `json:"due_at_unix"`
			ExpiresAtUnix                             uint64 `json:"expires_at_unix"`
			PayoutSequence                            uint64 `json:"payout_sequence"`
			PredecessorDigest                         string `json:"predecessor_materialized_payout_line_digest_or_zero"`
		}{decision.Body.CoverageAgreementBodyDigest, payoutTemplateObligationID,
			decisionBodyDigest, terminalClaimStateTransitionReceiptDigest, line.DecisionLineIndex, lineDigest,
			notBefore, due, expires, sequence, previousLineDigest}
		instanceID, err := guarantorCodec.Digest("tos.service.agent-guarantor-payout-instance.v1", identity)
		if err != nil {
			return MaterializedPayoutObligationSetV1{}, err
		}
		materialized := MaterializedPayoutLineV1{PayoutSequence: sequence,
			PredecessorMaterializedPayoutLineDigest: previousLineDigest, ClaimDecisionBodyDigest: decisionBodyDigest,
			TerminalClaimStateTransitionReceiptDigest: terminalClaimStateTransitionReceiptDigest,
			DecisionLineIndex:                         line.DecisionLineIndex, ClaimPayoutLine: line, NotBeforeUnix: notBefore,
			DueAtUnix: due, ExpiresAtUnix: expires, ObligationInstanceID: instanceID}
		materializedDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-materialized-payout-line.v1", materialized)
		actionID, _, err := agentcommerce.DeriveStableActionID("billing.materialize", map[string]agentcommerce.SemanticValue{
			"owner_id": agentcommerce.ID(ownerID), "agent_id": agentcommerce.ID(agentID),
			"agreement_body_digest":   agentcommerce.Digest32(decision.Body.CoverageAgreementBodyDigest),
			"agreement_obligation_id": agentcommerce.ID(payoutTemplateObligationID), "sequence": agentcommerce.U64(sequence),
		})
		if err != nil {
			return MaterializedPayoutObligationSetV1{}, err
		}
		obligation := agentcommerce.SettlementObligation{AgreementBodyDigest: decision.Body.CoverageAgreementBodyDigest,
			AgreementObligationID: payoutTemplateObligationID, ObligationInstanceID: instanceID, Sequence: sequence,
			PredecessorInstanceID: previousInstanceID, PayerAgentID: terms.GuarantorAgentID, PayeeAgentID: terms.BeneficiaryAgentID,
			Amount: agentcommerce.AgreementAmount{AssetNamespace: line.Amount.Asset.AssetNamespace,
				AssetIdentifier: line.Amount.Asset.AssetIdentifier, Unit: line.Amount.Asset.Unit, AmountAtomic: line.Amount.AmountAtomic},
			NotBeforeUnix: notBefore, DueAtUnix: due, ExpiresAtUnix: expires,
			MaximumAggregateAmount: agentcommerce.AgreementAmount{AssetNamespace: terms.MaximumAggregatePayout.Asset.AssetNamespace,
				AssetIdentifier: terms.MaximumAggregatePayout.Asset.AssetIdentifier, Unit: terms.MaximumAggregatePayout.Asset.Unit,
				AmountAtomic: terms.MaximumAggregatePayout.AmountAtomic},
			SettlementAdapterURI:       terms.SelectedPayoutAdapterProfile.ProfileURI,
			SettlementParametersDigest: terms.PayoutTemplate.SettlementParametersDigest, MandateDigest: mandateDigest,
			StableActionID: actionID}
		if err := agentcommerce.ValidateSettlementObligation(obligation); err != nil {
			return MaterializedPayoutObligationSetV1{}, err
		}
		result.MaterializedLines = append(result.MaterializedLines, materialized)
		result.Obligations = append(result.Obligations, obligation)
		previousLineDigest, previousInstanceID = materializedDigest, instanceID
	}
	result.LastPayoutSequence = firstPayoutSequence + uint64(len(result.MaterializedLines)) - 1
	return result, nil
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if ^uint64(0)-left < right {
		return 0, false
	}
	return left + right, true
}

func sortedUniqueAllowEmpty(values []string, maximum int, valid func(string) bool) bool {
	if len(values) > maximum || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validRecoveryKind(value string) bool {
	switch value {
	case "guarantee", "insurance", "escrow", "refund", "restitution", "legal_recovery", "other":
		return true
	default:
		return false
	}
}

func validRecoveryStatus(value string) bool {
	switch value {
	case "pending", "receivable", "received", "denied", "waived", "exhausted":
		return true
	default:
		return false
	}
}

func subset(values, superset []string) bool {
	available := make(map[string]struct{}, len(superset))
	for _, value := range superset {
		available[value] = struct{}{}
	}
	for _, value := range values {
		if _, found := available[value]; !found {
			return false
		}
	}
	return true
}
