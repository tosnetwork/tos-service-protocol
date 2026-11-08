package agentguarantor

import (
	"errors"
	"fmt"
	"math"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	MaximumContinuationRoundsV1    = 8
	FallbackEvidenceSnapshotRuleV1 = "current_portable_claim_history"
	FallbackPayoutDerivationRuleV1 = "accepted_payout_template_projection.v1"
	FallbackAuthorizationModeV1    = "agreement_granted_deterministic_admission"
	FallbackFinalRoundRuleV1       = "challenge_window_then_close"
)

var fallbackSourceRulesV1 = []DeterministicClaimTerminalFallbackTriggerDeadlineRuleV1{
	{SourceState: "disputed", DeadlineSource: "resolution_due_at_unix"},
	{SourceState: "evidence_required", DeadlineSource: "resolution_due_at_unix"},
	{SourceState: "initial_reviewing", DeadlineSource: "claim_review_cutoff"},
	{SourceState: "reviewing_after_challenge", DeadlineSource: "successor_decision_due_at_unix"},
	{SourceState: "reviewing_after_nonterminal_response", DeadlineSource: "successor_decision_due_at_unix"},
}

var fallbackOutcomeCasesV1 = []struct {
	caseName string
	result   ClaimDecisionResult
}{
	{"deny_zero", DecisionDenied},
	{"no_eligible_benefit", DecisionDenied},
	{"aggregate_exhausted", DecisionDenied},
	{"aggregate_limited", DecisionPartiallyApproved},
	{"full_benefit", DecisionApproved},
}

func DeterministicClaimTerminalFallbackDigestV1(value DeterministicClaimTerminalFallbackV1) (string, error) {
	if err := ValidateDeterministicClaimTerminalFallbackV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-terminal-fallback.v1", value)
}

func ValidateDeterministicClaimTerminalFallbackV1(value DeterministicClaimTerminalFallbackV1) error {
	if value.SchemaVersion != 1 || agentcommerce.ValidateProfileRefV1(value.FallbackProfile) != nil ||
		QuorumThresholdMustFailV1(value.FallbackQuorumRule, value.FallbackAuthoritySubjects) ||
		value.EvidenceSnapshotRule != FallbackEvidenceSnapshotRuleV1 ||
		value.PayoutLineDerivationRule != FallbackPayoutDerivationRuleV1 ||
		value.AuthorizationMode != FallbackAuthorizationModeV1 || value.FinalRoundRule != FallbackFinalRoundRuleV1 {
		return errors.New("deterministic Guarantor terminal fallback header is invalid")
	}
	if len(value.EligibleSourceStates) != len(fallbackSourceRulesV1) || len(value.TriggerDeadlineRules) != len(fallbackSourceRulesV1) {
		return errors.New("deterministic Guarantor fallback source-state mapping is incomplete")
	}
	for index, rule := range fallbackSourceRulesV1 {
		if value.EligibleSourceStates[index] != rule.SourceState || value.TriggerDeadlineRules[index] != rule {
			return errors.New("deterministic Guarantor fallback source-state mapping differs from V1")
		}
	}
	switch value.OutcomeRule {
	case "deny_zero":
		if value.AggregateCapProjectionRule != "not_applicable_deny_zero" {
			return errors.New("deny-zero fallback carries an aggregate projection")
		}
	case "accepted_benefit_calculation":
		if value.AggregateCapProjectionRule != "remaining-aggregate-min.v1" {
			return errors.New("benefit fallback lacks the closed aggregate projection")
		}
	default:
		return errors.New("deterministic Guarantor fallback outcome rule is unknown")
	}
	if len(value.ReasonRules) != len(fallbackOutcomeCasesV1) {
		return errors.New("deterministic Guarantor fallback reason mapping is incomplete")
	}
	for index, expected := range fallbackOutcomeCasesV1 {
		rule := value.ReasonRules[index]
		if rule.OutcomeCase != expected.caseName || rule.Result != string(expected.result) ||
			!validToken(rule.ReasonCode, 128) ||
			!sortedUniqueAllowEmpty(rule.ApplicablePolicyClauseIDs, 256, func(candidate string) bool { return validToken(candidate, 128) }) ||
			rule.EvidencePredicateSelectionRule != "all_decision_evidence_predicates" {
			return errors.New("deterministic Guarantor fallback reason mapping is invalid")
		}
	}
	return nil
}

// NewDenyZeroTerminalFallbackV1 returns the conservative released fallback:
// once an Agreement-fixed deadline is proven, the claim is deterministically
// denied rather than left open forever. Reason codes are registry identifiers,
// not free-form explanations.
func NewDenyZeroTerminalFallbackV1(profile agentcommerce.ProfileRefV1, subjects []string,
	quorum string, reasonCodes map[string]string) (DeterministicClaimTerminalFallbackV1, error) {
	reasons := make([]DeterministicFallbackReasonRuleV1, len(fallbackOutcomeCasesV1))
	for index, expected := range fallbackOutcomeCasesV1 {
		reasons[index] = DeterministicFallbackReasonRuleV1{OutcomeCase: expected.caseName, Result: string(expected.result),
			ReasonCode: reasonCodes[expected.caseName], EvidencePredicateSelectionRule: "all_decision_evidence_predicates"}
	}
	value := DeterministicClaimTerminalFallbackV1{SchemaVersion: 1, FallbackProfile: profile,
		FallbackAuthoritySubjects: append([]string(nil), subjects...), FallbackQuorumRule: quorum,
		EligibleSourceStates: []string{"disputed", "evidence_required", "initial_reviewing", "reviewing_after_challenge", "reviewing_after_nonterminal_response"},
		TriggerDeadlineRules: append([]DeterministicClaimTerminalFallbackTriggerDeadlineRuleV1(nil), fallbackSourceRulesV1...),
		EvidenceSnapshotRule: FallbackEvidenceSnapshotRuleV1, OutcomeRule: "deny_zero",
		AggregateCapProjectionRule: "not_applicable_deny_zero", ReasonRules: reasons,
		PayoutLineDerivationRule: FallbackPayoutDerivationRuleV1, AuthorizationMode: FallbackAuthorizationModeV1,
		FinalRoundRule: FallbackFinalRoundRuleV1}
	return value, ValidateDeterministicClaimTerminalFallbackV1(value)
}

func BuildClaimContinuationBudgetEntriesV1(maxChallenge, maxNonterminal, initialReview, challenge,
	nonterminal, successor, payout, adapterRecovery uint64) ([]ClaimContinuationBudgetEntryV1, error) {
	if maxChallenge > MaximumContinuationRoundsV1 || maxNonterminal > MaximumContinuationRoundsV1 ||
		initialReview == 0 || challenge == 0 || nonterminal == 0 || successor == 0 || payout == 0 || adapterRecovery == 0 {
		return nil, errors.New("Guarantor continuation budget parameters are invalid or operationally unbounded")
	}
	closureTail, ok := checkedDurationAddV1(payout, adapterRecovery)
	if !ok {
		return nil, errors.New("Guarantor continuation closure duration overflows")
	}
	var result []ClaimContinuationBudgetEntryV1
	add := func(key string, r, n, decisions, transitions, path uint64) error {
		closure, valid := checkedDurationAddV1(path, closureTail)
		if !valid {
			return errors.New("Guarantor continuation duration overflows")
		}
		result = append(result, ClaimContinuationBudgetEntryV1{ProfileStateKey: key,
			ChallengeRoundsRemaining: r, NonterminalRoundsRemaining: n,
			RequiredReservedDecisionAdmissionSlots: decisions, RequiredReservedClaimStateTransitionSlots: transitions,
			MaximumRemainingDecisionPathSeconds: path, MaximumRemainingClosureSeconds: closure})
		return nil
	}
	for r := uint64(0); r <= maxChallenge; r++ {
		challengeTail, valid := checkedLinearDurationV1(r+1, challenge, r, successor)
		if !valid {
			return nil, errors.New("Guarantor challenge duration overflows")
		}
		if err := add(fmt.Sprintf("challengeable_candidate:r=%d", r), r, 0, r, r+1, challengeTail); err != nil {
			return nil, err
		}
		reviewingChallenge, valid := checkedDurationAddV1(successor, challengeTail)
		if !valid {
			return nil, errors.New("Guarantor successor duration overflows")
		}
		if err := add(fmt.Sprintf("reviewing_after_challenge:r=%d", r), r, 0, r+1, r+1, reviewingChallenge); err != nil {
			return nil, err
		}
		for n := uint64(0); n <= maxNonterminal; n++ {
			nonterminalTail, valid := checkedDurationMulAddV1(n, nonterminal, challengeTail)
			if !valid {
				return nil, errors.New("Guarantor nonterminal duration overflows")
			}
			initialPath, valid := checkedDurationAddV1(initialReview, nonterminalTail)
			if !valid {
				return nil, errors.New("Guarantor initial-review duration overflows")
			}
			if err := add(fmt.Sprintf("initial_reviewing:r=%d:n=%d", r, n), r, n, 1+n+r, n+r+1, initialPath); err != nil {
				return nil, err
			}
			if n > 0 {
				if err := add(fmt.Sprintf("disputed:r=%d:n=%d", r, n), r, n, n+r, n+r+1, nonterminalTail); err != nil {
					return nil, err
				}
				if err := add(fmt.Sprintf("evidence_required:r=%d:n=%d", r, n), r, n, n+r, n+r+1, nonterminalTail); err != nil {
					return nil, err
				}
				reviewingPath, valid := checkedDurationMulAddV1(n+1, nonterminal, challengeTail)
				if !valid {
					return nil, errors.New("Guarantor response duration overflows")
				}
				if err := add(fmt.Sprintf("reviewing_after_nonterminal_response:r=%d:n=%d", r, n), r, n, n+r+1, n+r+1, reviewingPath); err != nil {
					return nil, err
				}
			}
		}
	}
	return result, nil
}

func ValidateClaimContinuationBudgetV1(capacity ClaimClosureCapacityV1, initialReview, challenge,
	nonterminal, successor, payout, adapterRecovery uint64) error {
	if agentcommerce.ValidateProfileRefV1(capacity.ContinuationBudgetProfile) != nil ||
		ValidateDeterministicClaimTerminalFallbackV1(capacity.TerminalFallback) != nil {
		return errors.New("Guarantor continuation profile or fallback is invalid")
	}
	want, err := BuildClaimContinuationBudgetEntriesV1(capacity.MaximumChallengeRoundsPerClaim,
		capacity.MaximumNonterminalRoundsPerClaim, initialReview, challenge, nonterminal, successor, payout, adapterRecovery)
	if err != nil || !equalCanonical(want, capacity.ContinuationBudgetEntries) {
		return errors.New("Guarantor continuation budget table is incomplete or noncanonical")
	}
	for _, entry := range want {
		if entry.RequiredReservedDecisionAdmissionSlots > capacity.MaximumDecisionAdmissionsPerClaim ||
			entry.RequiredReservedClaimStateTransitionSlots > capacity.MaximumClaimStateTransitionsPerClaim {
			return errors.New("Guarantor continuation capacity cannot preserve a reachable terminal path")
		}
	}
	return nil
}

func checkedDurationAddV1(left, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}

func checkedDurationMulAddV1(multiplier, value, addend uint64) (uint64, bool) {
	if multiplier != 0 && value > math.MaxUint64/multiplier {
		return 0, false
	}
	return checkedDurationAddV1(multiplier*value, addend)
}

func checkedLinearDurationV1(leftMultiplier, left, rightMultiplier, right uint64) (uint64, bool) {
	first, ok := checkedDurationMulAddV1(leftMultiplier, left, 0)
	if !ok {
		return 0, false
	}
	return checkedDurationMulAddV1(rightMultiplier, right, first)
}
