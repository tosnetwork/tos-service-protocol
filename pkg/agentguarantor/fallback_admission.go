package agentguarantor

import (
	"bytes"
	"errors"
	"math/big"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func DeterministicFallbackAdmissionSourceIdentityV1(variant DeterministicFallbackAdmissionVariantV1) (string, string, error) {
	claimReceiptDigest, claimErr := ClaimAdmissionReceiptDigestV1(variant.AuthorizedClaimAdmissionReceipt)
	epochDigest, epochErr := ClaimRevisionEpochExpectationDigestV1(variant.ClaimRevisionEpochExpectation)
	if claimErr != nil || epochErr != nil || variant.CoverageAgreementBodyDigest != variant.AuthorizedClaimAdmissionReceipt.Body.CoverageAgreementBodyDigest ||
		variant.CoverageObligationID != variant.AuthorizedClaimAdmissionReceipt.Body.CoverageObligationID ||
		variant.ClaimID != variant.AuthorizedClaimAdmissionReceipt.Body.ClaimID || !validDigest(variant.FallbackProfileDigest) ||
		variant.SourceClaimRevision == 0 || variant.SourceClaimStateRevision == 0 ||
		!validToken(variant.SourceClaimState, 128) || variant.TriggerCutoffUnix == 0 || variant.DecisionSequence == 0 {
		return "", "", errors.New("deterministic fallback source identity is invalid")
	}
	currentDecisionDigest, currentTransitionDigest, lateCloseDigest := "", "", ""
	if variant.CurrentDecisionAdmissionReceipt != nil {
		currentDecisionDigest, _ = ClaimDecisionAdmissionReceiptDigestV1(*variant.CurrentDecisionAdmissionReceipt)
	}
	if variant.CurrentClaimStateTransitionReceipt != nil {
		currentTransitionDigest, _ = ClaimStateTransitionReceiptDigestV1(*variant.CurrentClaimStateTransitionReceipt)
	}
	if variant.LateFilingCloseReceipt != nil {
		lateCloseDigest, _ = ClaimFilingCloseReceiptDigestV1(*variant.LateFilingCloseReceipt)
	}
	head := ClaimDecisionSourceHeadV1{SchemaVersion: 1, AuthorizedClaimAdmissionReceiptDigest: claimReceiptDigest,
		CurrentDecisionAdmissionReceiptDigest:    currentDecisionDigest,
		CurrentClaimStateTransitionReceiptDigest: currentTransitionDigest,
		LateFilingCloseReceiptDigest:             lateCloseDigest, ClaimRevisionEpochExpectationDigest: epochDigest}
	headDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-source-head.v1", head)
	if err != nil {
		return "", "", err
	}
	identity := DeterministicFallbackAdmissionIdentityV1{SchemaVersion: 1,
		FallbackProfileDigest: variant.FallbackProfileDigest, TriggerCutoffUnix: variant.TriggerCutoffUnix,
		ClaimRevisionEpochExpectationDigest: epochDigest}
	identityDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-fallback-admission-identity.v1", identity)
	return headDigest, identityDigest, err
}

func verifyDeterministicFallbackAdmissionReceiptV1(receipt AuthorizedClaimDecisionAdmissionReceiptV1, terms CoverageTermsV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if agreementVerifier == nil {
		return errors.New("deterministic fallback Agreement verifier is absent")
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		return err
	}
	var actionBody ClaimDecisionAdmissionActionBodyV1
	request := receipt.StageActionAdmissionEvidence.CanonicalRequest
	if guarantorCodec.Unmarshal(request, &actionBody) != nil || actionBody.SchemaVersion != 1 ||
		actionBody.AdmissionMode != "deterministic_fallback" || actionBody.AuthorizedDecisionVariant != nil ||
		actionBody.DeterministicFallbackVariant == nil {
		return errors.New("claim decision fallback request is not the closed tagged variant")
	}
	variant := *actionBody.DeterministicFallbackVariant
	reencoded, err := guarantorCodec.Marshal(actionBody)
	if err != nil || !bytes.Equal(request, reencoded) {
		return errors.New("claim decision fallback request is noncanonical")
	}
	fallbackDigest, err := DeterministicClaimTerminalFallbackDigestV1(terms.ClaimClosureCapacity.TerminalFallback)
	if err != nil || variant.FallbackProfileDigest != fallbackDigest {
		return errors.New("claim decision fallback profile is not Agreement-bound")
	}
	if err := VerifyClaimAdmissionReceiptV1(variant.AuthorizedClaimAdmissionReceipt, terms, agreementVerifier,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	claimReceiptDigest, _ := ClaimAdmissionReceiptDigestV1(variant.AuthorizedClaimAdmissionReceipt)
	claim := variant.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	decision := receipt.AuthorizedClaimDecision
	decisionDigest, decisionErr := ClaimDecisionDigestV1(decision)
	cutDigest, cutErr := ClaimIngressAdmissionCutProofDigestV1(receipt.ClaimRevisionIngressCutProof)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	if decisionErr != nil || cutErr != nil || endErr != nil || receipt.Body.AuthorizedClaimAdmissionReceiptDigest != claimReceiptDigest ||
		variant.SourceClaimRevision != claim.Body.ClaimRevision || variant.ClaimRevisionEpochExpectation.ExpectedClaimRevision != claim.Body.ClaimRevision ||
		variant.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		variant.CoverageObligationID != claim.Body.CoverageObligationID || variant.ClaimID != claim.Body.ClaimID {
		return errors.New("claim decision fallback source claim is substituted")
	}
	lateRecovery := variant.LateFilingCloseReceipt != nil
	lateFilingDigest := ""
	if lateRecovery {
		if receipt.LateFilingCloseReceipt == nil ||
			!equalCanonical(*receipt.LateFilingCloseReceipt, *variant.LateFilingCloseReceipt) {
			return errors.New("late fallback admission omits or substitutes its filing-close receipt")
		}
		filing := *variant.LateFilingCloseReceipt
		if filing.AuthorizedActivationEvidence == nil {
			return errors.New("late fallback filing receipt lacks activation evidence")
		}
		offer, offerErr := extractFirmOfferFromAcceptanceV1(filing.AuthorizedActivationEvidence.AuthorizedAcceptanceReceipt)
		if offerErr != nil || VerifyClaimFilingCloseReceiptV1(filing, offer, agreementVerifier,
			authorityResolver, fenceResolver, now) != nil {
			return errors.New("late fallback filing-close receipt is invalid")
		}
		lateFilingDigest, _ = ClaimFilingCloseReceiptDigestV1(filing)
		if filing.Body.ClosedAtUnix <= terms.TerminalResolutionDeadlineUnix ||
			filing.Body.ClosedAtUnix > terms.LateIngressRecoveryDeadlineUnix ||
			filing.ClaimIngressAdmissionCutProof.PendingOrAmbiguousCount != 0 {
			return errors.New("late fallback filing-close timing or ingress cut is invalid")
		}
		timelyClaimFound := false
		for _, entry := range filing.ClaimIngressAdmissionCutProof.Entries {
			if entry.ResolutionKind == "claim_admitted" && entry.ClaimAdmissionReceiptDigest == claimReceiptDigest &&
				entry.ReceivedAtUnix <= filing.Body.FilingCutoffUnix {
				timelyClaimFound = true
				break
			}
		}
		if !timelyClaimFound {
			return errors.New("late fallback does not identify a timely admitted ingress")
		}
	} else if receipt.LateFilingCloseReceipt != nil {
		return errors.New("ordinary fallback admission carries a late filing-close receipt")
	}
	wantPriorState, wantPath := "", "terminal_fallback"
	wantSequence := uint64(0)
	cutoff := uint64(0)
	var ok bool
	var predecessorDecisionDigest string
	var predecessorAdmissionDigest string
	var predecessorTransitionDigest string
	var priorPendingToken *DecisionApplicationTokenV1
	switch variant.SourceClaimState {
	case "initial_reviewing":
		if variant.CurrentDecisionAdmissionReceipt != nil || variant.CurrentClaimStateTransitionReceipt != nil {
			return errors.New("initial fallback carries a predecessor head")
		}
		wantPriorState, wantPath, wantSequence = "admitted", "initial_terminal_fallback", 1
		cutoff, ok = checkedDurationAddV1(variant.AuthorizedClaimAdmissionReceipt.Body.AdmittedAtUnix, terms.ReviewDeadlineSeconds)
	case "disputed", "evidence_required":
		if variant.CurrentDecisionAdmissionReceipt == nil || variant.CurrentClaimStateTransitionReceipt != nil {
			return errors.New("nonterminal fallback lacks its current decision admission")
		}
		current := *variant.CurrentDecisionAdmissionReceipt
		if err := VerifyClaimDecisionAdmissionReceiptV1(current, terms, agreementVerifier,
			authorityResolver, fenceResolver, now); err != nil || current.Body.AdmittedClaimState != variant.SourceClaimState ||
			current.Body.ResolutionDueAtUnix == 0 {
			return errors.New("nonterminal fallback decision head is invalid")
		}
		wantPriorState, wantSequence, cutoff, ok = variant.SourceClaimState, current.Body.DecisionSequence+1,
			current.Body.ResolutionDueAtUnix, true
		predecessorDecisionDigest = current.Body.AuthorizedClaimDecisionDigest
		predecessorAdmissionDigest, _ = ClaimDecisionAdmissionReceiptDigestV1(current)
	case "reviewing_after_challenge", "reviewing_after_nonterminal_response":
		if variant.CurrentDecisionAdmissionReceipt == nil || variant.CurrentClaimStateTransitionReceipt == nil {
			return errors.New("reviewing fallback lacks its decision and transition head")
		}
		current := *variant.CurrentDecisionAdmissionReceipt
		transition := *variant.CurrentClaimStateTransitionReceipt
		if err := VerifyClaimDecisionAdmissionReceiptV1(current, terms, agreementVerifier,
			authorityResolver, fenceResolver, now); err != nil {
			return err
		}
		if err := VerifyClaimStateTransitionReceiptV1(transition, terms, agreementVerifier,
			authorityResolver, fenceResolver, now); err != nil {
			return err
		}
		currentDigest, _ := ClaimDecisionAdmissionReceiptDigestV1(current)
		predecessorAdmissionDigest = currentDigest
		predecessorTransitionDigest, _ = ClaimStateTransitionReceiptDigestV1(transition)
		wantKind := "challenge_admission"
		if variant.SourceClaimState == "reviewing_after_nonterminal_response" {
			wantKind = "nonterminal_response_admission"
		}
		if transition.DecisionAdmissionProof.ReceiptEnvelopeDigest != currentDigest ||
			transition.Body.TransitionKind != wantKind || transition.Body.ResultingClaimState != "reviewing" ||
			transition.Body.SuccessorDecisionDueAtUnix == 0 {
			return errors.New("reviewing fallback transition head is substituted")
		}
		wantPriorState, wantSequence, cutoff, ok = "reviewing", current.Body.DecisionSequence+1,
			transition.Body.SuccessorDecisionDueAtUnix, true
		predecessorDecisionDigest = current.Body.AuthorizedClaimDecisionDigest
		if wantKind == "challenge_admission" {
			priorPendingToken = current.Body.ResultingApplicationToken
			if priorPendingToken == nil || receipt.PriorPendingApplicationToken == nil ||
				!equalCanonical(*priorPendingToken, *receipt.PriorPendingApplicationToken) {
				return errors.New("reviewing challenge fallback does not replace the current pending token")
			}
		}
	default:
		return errors.New("claim decision fallback source state is not registered")
	}
	if lateRecovery {
		wantPath = "late_recovery_terminal_fallback"
		cutoff = variant.LateFilingCloseReceipt.Body.ClosedAtUnix
		ok = cutoff > terms.TerminalResolutionDeadlineUnix && cutoff <= terms.LateIngressRecoveryDeadlineUnix
	}
	if !ok || decision.Body.DecisionPath != wantPath || variant.DecisionSequence != wantSequence ||
		decision.Body.DecisionSequence != wantSequence || decision.Body.PredecessorAuthorizedClaimDecisionDigest != predecessorDecisionDigest ||
		variant.SourceClaimStateRevision != receipt.Body.PriorClaimStateRevision {
		return errors.New("claim decision fallback source lineage is invalid")
	}
	if !ok || variant.TriggerCutoffUnix != cutoff || receipt.Body.FallbackTriggerCutoffUnix != cutoff ||
		receipt.Body.AdmittedAtUnix < cutoff || lateRecovery &&
		(receipt.Body.AdmittedAtUnix > terms.LateIngressRecoveryDeadlineUnix ||
			receipt.Body.AdmittedAtUnix > terms.LateRecoveryTerminalDeadlineUnix) {
		return errors.New("claim decision fallback trigger cutoff is invalid")
	}
	if lateRecovery {
		if receipt.Body.ChallengeRoundsUsedAfter > terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim {
			return errors.New("late fallback challenge counter exceeds its reserved capacity")
		}
		remaining := terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim - receipt.Body.ChallengeRoundsUsedAfter
		key := "challengeable_candidate:r=" + new(big.Int).SetUint64(remaining).String()
		var closureSeconds uint64
		for _, entry := range terms.ClaimClosureCapacity.ContinuationBudgetEntries {
			if entry.ProfileStateKey == key {
				closureSeconds = entry.MaximumRemainingClosureSeconds
				break
			}
		}
		terminalAt, fits := checkedDurationAddV1(receipt.Body.AdmittedAtUnix, closureSeconds)
		if closureSeconds == 0 || !fits || terminalAt > terms.LateRecoveryTerminalDeadlineUnix {
			return errors.New("late fallback cannot complete inside its reserved contingency window")
		}
	}
	if err := ValidateClaimDecision(decision, claim, terms, authorityResolver,
		terms.ClaimClosureCapacity.TerminalFallback.FallbackAuthoritySubjects,
		time.Unix(int64(receipt.Body.AdmittedAtUnix), 0).UTC()); err != nil {
		return err
	}
	epoch := variant.ClaimRevisionEpochExpectation
	cut := receipt.ClaimRevisionIngressCutProof
	if epoch.CoverageAgreementBodyDigest != receipt.Body.CoverageAgreementBodyDigest ||
		epoch.CoverageObligationID != receipt.Body.CoverageObligationID || epoch.ClaimID != receipt.Body.ClaimID ||
		epoch.ExpectedEpochState != "open" || cut.CutKind != "claim_revisions" || cut.ClaimID != receipt.Body.ClaimID ||
		cut.RevisionEpoch != epoch.RevisionEpoch || cut.PriorEpochStateRevision != epoch.ExpectedEpochStateRevision ||
		cut.PendingOrAmbiguousCount != 0 {
		return errors.New("claim decision fallback revision epoch cut differs")
	}
	headDigest, identityDigest, err := DeterministicFallbackAdmissionSourceIdentityV1(variant)
	if err != nil {
		return err
	}
	fields := DecisionAdmissionSemanticFieldsV1(bound, actionBody, decision, headDigest, identityDigest)
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, request,
		fields, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	body := receipt.Body
	target, targetErr := decisionTargetStateV1(decision.Body.Result)
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if targetErr != nil || actionErr != nil || proofErr != nil || body.SchemaVersion != 1 || body.AuthorityID != bound.ActionAuthorityID ||
		body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest || body.CoverageObligationID != claim.Body.CoverageObligationID ||
		body.ClaimID != claim.Body.ClaimID || body.AuthorizedClaimDecisionDigest != decisionDigest || body.AdmissionMode != "deterministic_fallback" ||
		body.ClaimRevisionIngressCutProofDigest != cutDigest || body.LateFilingCloseReceiptDigest != lateFilingDigest ||
		body.PredecessorDecisionAdmissionReceiptDigest != predecessorAdmissionDigest ||
		body.PredecessorClaimStateTransitionReceiptDigest != predecessorTransitionDigest ||
		body.DecisionSequence != wantSequence || body.DecisionRevision != 1 || body.DecisionPath != wantPath ||
		body.PriorClaimState != wantPriorState || body.AdmittedClaimState != target || body.AdmittedClaimStateRevision != body.PriorClaimStateRevision+1 ||
		body.AdmittedCoverageRevision != body.PriorCoverageRevision+1 || body.PriorCoverageEndCommitmentDigest != endDigest ||
		body.ResultingCoverageEndCommitmentDigest != endDigest || body.ChallengeRoundsUsedAfter != body.ChallengeRoundsUsedBefore ||
		body.NonterminalRoundsUsedAfter != body.NonterminalRoundsUsedBefore || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != receipt.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest || body.AdmittedAtUnix != decision.Body.DecidedAtUnix {
		return errors.New("claim decision fallback admission receipt binding is invalid")
	}
	if priorPendingToken != nil {
		priorTokenDigest, _ := DecisionApplicationTokenDigestV1(*priorPendingToken)
		if body.PriorApplicationTokenDigest != priorTokenDigest || body.PriorApplicationTokenTerminalState != "replaced" {
			return errors.New("claim decision fallback prior token terminalization is invalid")
		}
	} else if receipt.PriorPendingApplicationToken != nil || body.PriorApplicationTokenDigest != "" ||
		body.PriorApplicationTokenTerminalState != "" {
		return errors.New("claim decision fallback carries an unrelated prior token")
	}
	before, beforeOK := new(big.Int).SetString(body.AggregatePendingDecisionReserveBefore.AmountAtomic, 10)
	after, afterOK := new(big.Int).SetString(body.AggregatePendingDecisionReserveAfter.AmountAtomic, 10)
	approved, approvedOK := new(big.Int).SetString(decision.Body.ApprovedAmount.AmountAtomic, 10)
	maximum, maximumOK := new(big.Int).SetString(terms.MaximumAggregatePayout.AmountAtomic, 10)
	wantAfter := new(big.Int)
	if beforeOK && approvedOK {
		wantAfter.Add(before, approved)
		if priorPendingToken != nil {
			prior, parsed := new(big.Int).SetString(priorPendingToken.ReservedApprovedAmount.AmountAtomic, 10)
			if !parsed || wantAfter.Sub(wantAfter, prior).Sign() < 0 {
				return errors.New("claim decision fallback reserve replacement underflows")
			}
		}
	}
	if !beforeOK || !afterOK || !approvedOK || !maximumOK || after.Cmp(wantAfter) != 0 || after.Cmp(maximum) > 0 {
		return errors.New("claim decision fallback aggregate reserve is invalid")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest,
		decisionDigest, terms.DecisionAdmissionAuthoritySubjects,
		"claim-decision-admission-receipt", decisionDigest, fallbackDigest,
		terms.ClaimClosureCapacity.TerminalFallback.FallbackProfile, terms.CoverageStateDomainDigest,
		body.DecisionSequence, body.AdmittedAtUnix); err != nil {
		return err
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", body)
	return verifyReceiptAuthorizationSetV1(receipt.Authorizations, "claim-decision-admission-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-admission-signature.v1", terms.DecisionAdmissionProfile,
		terms.DecisionAdmissionAuthoritySubjects, terms.DecisionAdmissionQuorumRule, authorityResolver, now)
}
