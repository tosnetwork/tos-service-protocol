package agentguarantor

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	ClaimDecisionAdmissionReceiptDomainV1   = "tos.service.agent-guarantor-claim-decision-admission-envelope.v1"
	ClaimStateTransitionReceiptDomainV1     = "tos.service.agent-guarantor-claim-state-transition-envelope.v1"
	ClaimDecisionApplicationReceiptDomainV1 = "tos.service.agent-guarantor-decision-application-envelope.v1"
)

func ClaimRevisionEpochExpectationDigestV1(value ClaimRevisionEpochExpectationV1) (string, error) {
	if value.SchemaVersion != 1 || !validDigest(value.CoverageAgreementBodyDigest) ||
		!validToken(value.CoverageObligationID, 128) || !validDigest(value.ClaimID) || value.RevisionEpoch == 0 ||
		!validDigest(value.RevisionIngressLogID) || (value.ExpectedEpochState != "open" && value.ExpectedEpochState != "frozen") ||
		value.ExpectedEpochStateRevision == 0 || value.ExpectedClaimRevision == 0 {
		return "", errors.New("claim revision epoch expectation is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-revision-epoch-expectation.v1", value)
}

func ClaimIngressAdmissionCutProofDigestV1(value ClaimIngressAdmissionCutProofV1) (string, error) {
	if err := ValidateClaimIngressAdmissionCutProofV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-ingress-admission-cut-proof.v1", value)
}

func ValidateClaimIngressAdmissionCutProofV1(value ClaimIngressAdmissionCutProofV1) error {
	if value.SchemaVersion != 1 || !validDigest(value.CoverageAgreementBodyDigest) ||
		!validToken(value.CoverageObligationID, 128) || !validDigest(value.ClaimIngressLogID) || value.IngressCutoffUnix == 0 ||
		!validDigest(value.AdmissionLogRoot) || value.AdmissionHighWater != uint64(len(value.Entries)) ||
		value.AdmittedClaimCount+value.RejectedIngressOrClaimCount+value.PendingOrAmbiguousCount != value.AdmissionHighWater {
		return errors.New("claim ingress admission cut header is invalid")
	}
	switch value.CutKind {
	case "initial_claims":
		if value.ClaimID != "" || value.RevisionEpoch != 0 || value.PriorEpochStateRevision != 0 || value.FrozenEpochStateRevision != 0 {
			return errors.New("initial claim ingress cut carries revision fields")
		}
	case "claim_revisions":
		if !validDigest(value.ClaimID) || value.RevisionEpoch == 0 || value.PriorEpochStateRevision == 0 ||
			value.FrozenEpochStateRevision != value.PriorEpochStateRevision+1 {
			return errors.New("claim revision ingress cut has invalid epoch")
		}
	default:
		return errors.New("claim ingress cut kind is unknown")
	}
	initialRoot, err := InitialClaimLogRootV1(ClaimIngressLogRootDomainV1, value.ClaimIngressLogID)
	if err != nil {
		return err
	}
	root := initialRoot
	var admitted, rejected, pending uint64
	for index, entry := range value.Entries {
		sequence := uint64(index + 1)
		if entry.ClaimIngressSequence != sequence || entry.ReceivedAtUnix == 0 || entry.ReceivedAtUnix > value.IngressCutoffUnix ||
			agentcommerce.ValidateActionResolution(entry.IngressActionResolution) != nil {
			return errors.New("claim ingress cut entry is invalid or out of order")
		}
		root, err = AdvanceClaimLogRootV1(ClaimIngressLogRootDomainV1, value.ClaimIngressLogID, root, sequence,
			ClaimIngressLogLeafV1{StableActionID: entry.IngressActionResolution.StableActionID,
				ExactRequestDigest: entry.IngressActionResolution.ExactRequestDigest,
				ReceivedAtUnix:     entry.ReceivedAtUnix})
		if err != nil {
			return err
		}
		switch entry.ResolutionKind {
		case "claim_admitted":
			if !validDigest(entry.ClaimIngressReceiptDigest) || entry.ClaimAdmissionActionResolution == nil ||
				agentcommerce.ValidateActionResolution(*entry.ClaimAdmissionActionResolution) != nil ||
				entry.ClaimAdmissionActionResolution.State != agentcommerce.ActionTerminal || !validDigest(entry.ClaimAdmissionReceiptDigest) {
				return errors.New("admitted claim cut entry lacks exact receipts")
			}
			admitted++
		case "ingress_rejected":
			if entry.ClaimAdmissionActionResolution != nil || entry.ClaimAdmissionReceiptDigest != "" {
				return errors.New("rejected claim cut entry carries admission evidence")
			}
			rejected++
		case "claim_rejected":
			if entry.ClaimAdmissionActionResolution == nil ||
				agentcommerce.ValidateActionResolution(*entry.ClaimAdmissionActionResolution) != nil ||
				entry.ClaimAdmissionActionResolution.State != agentcommerce.ActionRejected || entry.ClaimAdmissionReceiptDigest != "" {
				return errors.New("claim rejection cut entry is invalid")
			}
			rejected++
		case "pending_or_ambiguous":
			pending++
		default:
			return errors.New("claim ingress cut resolution kind is unknown")
		}
	}
	if root != value.AdmissionLogRoot || admitted != value.AdmittedClaimCount || rejected != value.RejectedIngressOrClaimCount ||
		pending != value.PendingOrAmbiguousCount {
		return errors.New("claim ingress cut root or counters differ")
	}
	return nil
}

func DecisionApplicationTokenDigestV1(value DecisionApplicationTokenV1) (string, error) {
	if value.SchemaVersion != 1 || !validDigest(value.TokenID) || !validDigest(value.CoverageAgreementBodyDigest) ||
		!validToken(value.CoverageObligationID, 128) || !validDigest(value.ClaimID) ||
		!validDigest(value.AuthorizedClaimDecisionDigest) || value.DecisionSequence == 0 || value.DecisionRevision != 1 ||
		validateAmount(value.ReservedApprovedAmount, false) != nil || value.TokenRevision == 0 ||
		(value.State != "pending" && value.State != "consumed" && value.State != "replaced" && value.State != "cancelled") {
		return "", errors.New("decision application token is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-decision-application-token.v1", value)
}

func DecisionApplicationTokenIDV1(agreementDigest, obligationID, claimID, decisionDigest string,
	decisionSequence, decisionRevision uint64) (string, error) {
	if !validDigest(agreementDigest) || !validToken(obligationID, 128) || !validDigest(claimID) ||
		!validDigest(decisionDigest) || decisionSequence == 0 || decisionRevision != 1 {
		return "", errors.New("decision application token identity is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-decision-application-token-id.v1", struct {
		CoverageAgreementBodyDigest string `json:"coverage_agreement_body_digest"`
		CoverageObligationID        string `json:"coverage_obligation_id"`
		ClaimID                     string `json:"claim_id"`
		AuthorizedDecisionDigest    string `json:"authorized_claim_decision_digest"`
		DecisionSequence            uint64 `json:"decision_sequence"`
		DecisionRevision            uint64 `json:"decision_revision"`
	}{agreementDigest, obligationID, claimID, decisionDigest, decisionSequence, decisionRevision})
}

func ClaimDecisionAdmissionReceiptDigestV1(value AuthorizedClaimDecisionAdmissionReceiptV1) (string, error) {
	return guarantorCodec.Digest(ClaimDecisionAdmissionReceiptDomainV1, value)
}

func ClaimStateTransitionReceiptDigestV1(value AuthorizedClaimStateTransitionReceiptV1) (string, error) {
	return guarantorCodec.Digest(ClaimStateTransitionReceiptDomainV1, value)
}

func ClaimDecisionApplicationReceiptDigestV1(value AuthorizedClaimDecisionApplicationReceiptV1) (string, error) {
	return guarantorCodec.Digest(ClaimDecisionApplicationReceiptDomainV1, value)
}

func decisionTargetStateV1(result ClaimDecisionResult) (string, error) {
	switch result {
	case DecisionApproved:
		return "approved", nil
	case DecisionPartiallyApproved:
		return "partially_approved", nil
	case DecisionDenied:
		return "denied", nil
	case DecisionEvidenceRequired:
		return "evidence_required", nil
	case DecisionDisputed:
		return "disputed", nil
	default:
		return "", errors.New("claim decision result is unknown")
	}
}

func verifyReceiptAuthorizationSetV1(authorizations []ProfileQualifiedObjectAuthorizationV1, kind, bodyDigest,
	domain string, profile agentcommerce.ProfileRefV1, subjects []string, quorumRule string,
	resolver AuthorityKeyResolver, now time.Time) error {
	for _, authorization := range authorizations {
		if authorization.ProfileURI != profile.ProfileURI || authorization.ProfileVersion != profile.ProfileVersion ||
			authorization.ProfileDigest != profile.ProfileDigest {
			return errors.New("receipt authorization uses a substituted profile")
		}
	}
	return ValidateAuthorizationQuorumSet(authorizations, kind, bodyDigest, domain, subjects, quorumRule, resolver, now)
}

func DecisionAdmissionSemanticFieldsV1(bound GuarantorStageActionAuthorityV1, body ClaimDecisionAdmissionActionBodyV1,
	decision AuthorizedClaimDecisionV1, sourceHeadDigest, modeIdentityDigest string) map[string]agentcommerce.SemanticValue {
	sourceClaimStateRevision := uint64(0)
	if body.AdmissionMode == "authorized_decision" && body.AuthorizedDecisionVariant != nil {
		sourceClaimStateRevision = body.AuthorizedDecisionVariant.ExpectedClaimStateRevision
	} else if body.AdmissionMode == "deterministic_fallback" && body.DeterministicFallbackVariant != nil {
		sourceClaimStateRevision = body.DeterministicFallbackVariant.SourceClaimStateRevision
	}
	return map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(decision.Body.CoverageAgreementBodyDigest),
		"obligation_id":         agentcommerce.ID(decision.Body.CoverageObligationID), "claim_id": agentcommerce.ID(decision.Body.ClaimID),
		"admission_mode": agentcommerce.Kind(body.AdmissionMode), "source_claim_revision": agentcommerce.U64(decision.Body.ExpectedClaimRevision),
		"source_claim_state_revision": agentcommerce.U64(sourceClaimStateRevision),
		"source_head_digest":          agentcommerce.Digest32(sourceHeadDigest), "decision_sequence": agentcommerce.U64(decision.Body.DecisionSequence),
		"mode_specific_identity_digest": agentcommerce.Digest32(modeIdentityDigest),
	}
}

func AuthorizedDecisionAdmissionSourceIdentityV1(variant AuthorizedDecisionAdmissionVariantV1,
	decision AuthorizedClaimDecisionV1) (string, string, error) {
	if !validDigest(variant.AuthorizedClaimDecisionDigest) || !validDigest(variant.AuthorizedClaimAdmissionReceiptDigest) ||
		variant.PredecessorDecisionAdmissionReceiptDigest != "" && !validDigest(variant.PredecessorDecisionAdmissionReceiptDigest) ||
		variant.PredecessorClaimStateTransitionReceiptDigest != "" && !validDigest(variant.PredecessorClaimStateTransitionReceiptDigest) {
		return "", "", errors.New("authorized decision source digest is invalid")
	}
	epochDigest, err := ClaimRevisionEpochExpectationDigestV1(variant.ClaimRevisionEpochExpectation)
	if err != nil {
		return "", "", err
	}
	head := ClaimDecisionSourceHeadV1{SchemaVersion: 1,
		AuthorizedClaimAdmissionReceiptDigest:    variant.AuthorizedClaimAdmissionReceiptDigest,
		CurrentDecisionAdmissionReceiptDigest:    variant.PredecessorDecisionAdmissionReceiptDigest,
		CurrentClaimStateTransitionReceiptDigest: variant.PredecessorClaimStateTransitionReceiptDigest,
		ClaimRevisionEpochExpectationDigest:      epochDigest}
	headDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-source-head.v1", head)
	if err != nil {
		return "", "", err
	}
	bodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-body.v1", decision.Body)
	if err != nil {
		return "", "", err
	}
	target, err := decisionTargetStateV1(decision.Body.Result)
	if err != nil {
		return "", "", err
	}
	identityDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-authorized-decision-admission-identity.v1",
		AuthorizedDecisionAdmissionIdentityV1{SchemaVersion: 1, ClaimDecisionBodyDigest: bodyDigest,
			DecisionRevision: decision.Body.DecisionRevision, DerivedTargetState: target})
	return headDigest, identityDigest, err
}

// VerifyClaimDecisionAdmissionReceiptV1 verifies the ordinary, explicitly
// authorized decision path. Deterministic fallback materialization is a
// separate constructor because its decision is an output of admission rather
// than untrusted caller input.
func VerifyClaimDecisionAdmissionReceiptV1(receipt AuthorizedClaimDecisionAdmissionReceiptV1, terms CoverageTermsV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if receipt.Body.AdmissionMode == "deterministic_fallback" {
		return verifyDeterministicFallbackAdmissionReceiptV1(receipt, terms, agreementVerifier,
			authorityResolver, fenceResolver, now)
	}
	if receipt.Body.AdmissionMode != "authorized_decision" || agreementVerifier == nil {
		return errors.New("claim decision admission mode is unsupported or incomplete")
	}
	// A late filing-close receipt and a fallback trigger cutoff exist only for
	// deterministic fallback admission; an authorized decision carrying either
	// would sign over an object no check ever reads.
	if receipt.LateFilingCloseReceipt != nil || receipt.Body.LateFilingCloseReceiptDigest != "" ||
		receipt.Body.FallbackTriggerCutoffUnix != 0 {
		return errors.New("authorized claim decision admission carries a late filing-close receipt or fallback cutoff")
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		return err
	}
	var actionBody ClaimDecisionAdmissionActionBodyV1
	if err := guarantorCodec.Unmarshal(receipt.StageActionAdmissionEvidence.CanonicalRequest, &actionBody); err != nil ||
		actionBody.SchemaVersion != 1 || actionBody.AdmissionMode != "authorized_decision" ||
		actionBody.AuthorizedDecisionVariant == nil || actionBody.DeterministicFallbackVariant != nil {
		return errors.New("claim decision admission request is not the closed authorized variant")
	}
	variant := *actionBody.AuthorizedDecisionVariant
	decisionDigest, decisionDigestErr := ClaimDecisionDigestV1(receipt.AuthorizedClaimDecision)
	claimReceiptDigest, claimDigestErr := ClaimAdmissionReceiptDigestV1(receipt.AuthorizedClaimAdmissionReceipt)
	if decisionDigestErr != nil || claimDigestErr != nil || variant.AuthorizedClaimDecisionDigest != decisionDigest ||
		variant.AuthorizedClaimAdmissionReceiptDigest != claimReceiptDigest {
		return errors.New("claim decision admission action references substituted objects")
	}
	claim := receipt.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	if err := VerifyClaimAdmissionReceiptV1(receipt.AuthorizedClaimAdmissionReceipt, terms, agreementVerifier,
		authorityResolver, fenceResolver, now); err != nil {
		return fmt.Errorf("claim decision admission has an invalid claim predecessor: %w", err)
	}
	if err := ValidateClaimDecision(receipt.AuthorizedClaimDecision, claim, terms, authorityResolver,
		terms.DecisionAuthoritySubjects, now); err != nil {
		return err
	}
	decisionBody := receipt.AuthorizedClaimDecision.Body
	if decisionBody.DecisionSequence == 1 {
		if receipt.PredecessorClaimStateTransitionReceipt != nil || variant.PredecessorDecisionAdmissionReceiptDigest != "" ||
			variant.PredecessorClaimStateTransitionReceiptDigest != "" || receipt.PriorPendingApplicationToken != nil ||
			receipt.Body.PriorApplicationTokenDigest != "" || receipt.Body.PriorApplicationTokenTerminalState != "" ||
			receipt.Body.PriorClaimState != "admitted" {
			return errors.New("initial decision admission carries successor lineage")
		}
	} else {
		predecessor := receipt.PredecessorClaimStateTransitionReceipt
		if predecessor == nil || decisionBody.DecisionPath != "successor" || receipt.Body.PriorClaimState != "reviewing" ||
			predecessor.Body.ResultingClaimState != "reviewing" ||
			predecessor.Body.ResultingClaimStateRevision != receipt.Body.PriorClaimStateRevision ||
			receipt.Body.AdmittedAtUnix > predecessor.Body.SuccessorDecisionDueAtUnix {
			return errors.New("successor decision admission has no current reviewing predecessor")
		}
		if err := VerifyClaimStateTransitionReceiptV1(*predecessor, terms, agreementVerifier,
			authorityResolver, fenceResolver, now); err != nil {
			return fmt.Errorf("successor decision transition predecessor is invalid: %w", err)
		}
		transitionDigest, _ := ClaimStateTransitionReceiptDigestV1(*predecessor)
		priorProof := predecessor.DecisionAdmissionProof
		priorDecisionDigest, _ := ClaimDecisionDigestV1(priorProof.AuthorizedClaimDecision)
		if variant.PredecessorDecisionAdmissionReceiptDigest != priorProof.ReceiptEnvelopeDigest ||
			variant.PredecessorClaimStateTransitionReceiptDigest != transitionDigest ||
			decisionBody.PredecessorAuthorizedClaimDecisionDigest != priorDecisionDigest ||
			decisionBody.DecisionSequence != priorProof.ReceiptBody.DecisionSequence+1 {
			return errors.New("successor decision lineage digest or sequence is substituted")
		}
		priorToken := priorProof.ReceiptBody.ResultingApplicationToken
		if predecessor.Body.TransitionKind == "challenge_admission" {
			if priorToken == nil || receipt.PriorPendingApplicationToken == nil ||
				!equalCanonical(*priorToken, *receipt.PriorPendingApplicationToken) || priorToken.State != "pending" ||
				receipt.Body.PriorApplicationTokenTerminalState != "replaced" {
				return errors.New("challenged successor does not replace the exact pending application token")
			}
			priorTokenDigest, _ := DecisionApplicationTokenDigestV1(*priorToken)
			if receipt.Body.PriorApplicationTokenDigest != priorTokenDigest {
				return errors.New("successor prior application token digest differs")
			}
		} else if predecessor.Body.TransitionKind == "nonterminal_response_admission" {
			if priorToken != nil || receipt.PriorPendingApplicationToken != nil || receipt.Body.PriorApplicationTokenDigest != "" ||
				receipt.Body.PriorApplicationTokenTerminalState != "" {
				return errors.New("nonterminal successor carries an application token")
			}
		} else {
			return errors.New("successor decision predecessor transition kind is invalid")
		}
	}
	cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(receipt.ClaimRevisionIngressCutProof)
	if err != nil {
		return err
	}
	epoch := variant.ClaimRevisionEpochExpectation
	if epoch.CoverageAgreementBodyDigest != receipt.Body.CoverageAgreementBodyDigest ||
		epoch.CoverageObligationID != receipt.Body.CoverageObligationID || epoch.ClaimID != receipt.Body.ClaimID ||
		epoch.ExpectedClaimRevision != claim.Body.ClaimRevision || epoch.RevisionIngressLogID != receipt.ClaimRevisionIngressCutProof.ClaimIngressLogID ||
		receipt.ClaimRevisionIngressCutProof.CutKind != "claim_revisions" || receipt.ClaimRevisionIngressCutProof.ClaimID != receipt.Body.ClaimID ||
		receipt.ClaimRevisionIngressCutProof.PendingOrAmbiguousCount != 0 {
		return errors.New("claim decision admission revision cut differs")
	}
	headDigest, identityDigest, err := AuthorizedDecisionAdmissionSourceIdentityV1(variant, receipt.AuthorizedClaimDecision)
	if err != nil {
		return err
	}
	request, err := guarantorCodec.Marshal(actionBody)
	if err != nil || !bytes.Equal(request, receipt.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("claim decision admission request is noncanonical")
	}
	fields := DecisionAdmissionSemanticFieldsV1(bound, actionBody, receipt.AuthorizedClaimDecision, headDigest, identityDigest)
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, request, fields,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	decisionDigest, err = ClaimDecisionDigestV1(receipt.AuthorizedClaimDecision)
	claimReceiptDigest, claimErr := ClaimAdmissionReceiptDigestV1(receipt.AuthorizedClaimAdmissionReceipt)
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	targetState, targetErr := decisionTargetStateV1(receipt.AuthorizedClaimDecision.Body.Result)
	if err != nil || claimErr != nil || actionErr != nil || endErr != nil || proofErr != nil || targetErr != nil {
		return errors.New("claim decision admission dependent digest is invalid")
	}
	body := receipt.Body
	if body.SchemaVersion != 1 || body.AuthorityID != bound.ActionAuthorityID ||
		body.CoverageAgreementBodyDigest != receipt.AuthorizedClaimDecision.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != receipt.AuthorizedClaimDecision.Body.CoverageObligationID || body.ClaimID != receipt.AuthorizedClaimDecision.Body.ClaimID ||
		body.AuthorizedClaimDecisionDigest != decisionDigest || body.AuthorizedClaimAdmissionReceiptDigest != claimReceiptDigest ||
		body.ClaimRevisionIngressCutProofDigest != cutDigest || body.DecisionSequence != receipt.AuthorizedClaimDecision.Body.DecisionSequence ||
		body.PredecessorDecisionAdmissionReceiptDigest != variant.PredecessorDecisionAdmissionReceiptDigest ||
		body.PredecessorClaimStateTransitionReceiptDigest != variant.PredecessorClaimStateTransitionReceiptDigest ||
		body.DecisionRevision != 1 || body.DecisionPath != receipt.AuthorizedClaimDecision.Body.DecisionPath ||
		body.AdmittedClaimState != targetState || body.AdmittedClaimStateRevision != body.PriorClaimStateRevision+1 ||
		body.AdmittedCoverageRevision != body.PriorCoverageRevision+1 || body.PriorCoverageEndCommitmentDigest != endDigest ||
		body.ResultingCoverageEndCommitmentDigest != endDigest || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != receipt.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest || body.AdmittedAtUnix == 0 ||
		variant.ExpectedClaimStateRevision != body.PriorClaimStateRevision ||
		variant.ExpectedChallengeRoundsUsed != body.ChallengeRoundsUsedBefore ||
		variant.ExpectedNonterminalRoundsUsed != body.NonterminalRoundsUsedBefore {
		return errors.New("claim decision admission receipt binding is invalid")
	}
	reserveBefore, okBefore := new(big.Int).SetString(body.AggregatePendingDecisionReserveBefore.AmountAtomic, 10)
	reserveAfter, okAfter := new(big.Int).SetString(body.AggregatePendingDecisionReserveAfter.AmountAtomic, 10)
	approvedAmount, okApproved := new(big.Int).SetString(receipt.AuthorizedClaimDecision.Body.ApprovedAmount.AmountAtomic, 10)
	maximumAggregate, okMaximum := new(big.Int).SetString(terms.MaximumAggregatePayout.AmountAtomic, 10)
	wantReserveAfter := new(big.Int)
	if okBefore && okApproved {
		wantReserveAfter.Add(reserveBefore, approvedAmount)
		if receipt.PriorPendingApplicationToken != nil {
			prior, ok := new(big.Int).SetString(receipt.PriorPendingApplicationToken.ReservedApprovedAmount.AmountAtomic, 10)
			if !ok || prior.Sign() < 0 || wantReserveAfter.Sub(wantReserveAfter, prior).Sign() < 0 {
				return errors.New("successor decision reserve replacement underflows")
			}
		}
	}
	if !okBefore || !okAfter || !okApproved || !okMaximum ||
		body.AggregatePendingDecisionReserveBefore.Asset != terms.CoverageAsset ||
		body.AggregatePendingDecisionReserveAfter.Asset != terms.CoverageAsset ||
		reserveAfter.Cmp(wantReserveAfter) != 0 || reserveAfter.Cmp(maximumAggregate) > 0 {
		return errors.New("claim decision admission exceeds or misstates aggregate pending capacity")
	}
	if receipt.ResultingTokenRequiredV1() {
		token := body.ResultingApplicationToken
		if token == nil || token.State != "pending" || token.TokenRevision != 1 ||
			token.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest || token.CoverageObligationID != body.CoverageObligationID ||
			token.ClaimID != body.ClaimID || token.AuthorizedClaimDecisionDigest != decisionDigest ||
			token.DecisionSequence != body.DecisionSequence || token.DecisionRevision != body.DecisionRevision ||
			token.ReservedApprovedAmount != receipt.AuthorizedClaimDecision.Body.ApprovedAmount {
			return errors.New("claim decision admission application token is invalid")
		}
		wantTokenID, tokenErr := DecisionApplicationTokenIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID,
			body.ClaimID, decisionDigest, body.DecisionSequence, body.DecisionRevision)
		if tokenErr != nil || token.TokenID != wantTokenID {
			return errors.New("claim decision application token identity differs")
		}
	} else if body.ResultingApplicationToken != nil {
		return errors.New("nonterminal decision carries an application token")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest,
		decisionDigest, terms.DecisionAdmissionAuthoritySubjects, "claim-decision-admission-receipt", decisionDigest,
		terms.DecisionAdmissionProfile.ProfileDigest, terms.DecisionAdmissionProfile, terms.CoverageStateDomainDigest,
		body.DecisionSequence, body.AdmittedAtUnix); err != nil {
		return err
	}
	bodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", body)
	if err != nil {
		return err
	}
	return verifyReceiptAuthorizationSetV1(receipt.Authorizations, "claim-decision-admission-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-admission-signature.v1", terms.DecisionAdmissionProfile,
		terms.DecisionAdmissionAuthoritySubjects, terms.DecisionAdmissionQuorumRule, authorityResolver, now)
}

func (receipt AuthorizedClaimDecisionAdmissionReceiptV1) ResultingTokenRequiredV1() bool {
	result := receipt.AuthorizedClaimDecision.Body.Result
	return result == DecisionApproved || result == DecisionPartiallyApproved || result == DecisionDenied
}

func ClaimStateTransitionSemanticFieldsV1(bound GuarantorStageActionAuthorityV1,
	request ClaimStateTransitionActionBodyV1, evidenceSetDigest string) map[string]agentcommerce.SemanticValue {
	return map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(request.CoverageAgreementBodyDigest),
		"obligation_id":         agentcommerce.ID(request.CoverageObligationID), "claim_id": agentcommerce.ID(request.ClaimID),
		"expected_claim_state_revision": agentcommerce.U64(request.ExpectedClaimStateRevision),
		"transition_kind":               agentcommerce.Kind(request.TransitionKind), "target_state": agentcommerce.State(request.TargetState),
		"evidence_set_digest": agentcommerce.Digest32(evidenceSetDigest),
	}
}

func VerifyClaimStateTransitionReceiptV1(receipt AuthorizedClaimStateTransitionReceiptV1, terms CoverageTermsV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "claim_state_transition")
	if err != nil {
		return err
	}
	decisionProof := receipt.DecisionAdmissionProof
	if err := VerifyClaimDecisionAdmissionReceiptProofV1(decisionProof, terms, authorityResolver, now); err != nil {
		return fmt.Errorf("claim transition has an invalid decision predecessor: %w", err)
	}
	decisionAdmission := decisionProof.ReceiptBody
	var request ClaimStateTransitionActionBodyV1
	if err := guarantorCodec.Unmarshal(receipt.StageActionAdmissionEvidence.CanonicalRequest, &request); err != nil ||
		request.SchemaVersion != 1 ||
		!equalCanonical(request.TransitionEvidenceProjection, receipt.TransitionEvidenceProjection) ||
		!equalCanonical(request.TransitionEvidenceSet, receipt.TransitionEvidenceSet) {
		return errors.New("claim transition request is noncanonical or substituted")
	}
	decisionAdmissionDigest := decisionProof.ReceiptEnvelopeDigest
	if request.AuthorizedClaimDecisionAdmissionReceiptDigest != decisionAdmissionDigest {
		return errors.New("claim transition action references a substituted decision admission")
	}
	projectionDigest, err := TransitionEvidenceProjectionDigestV1(receipt.TransitionEvidenceProjection)
	if err != nil {
		return err
	}
	evidenceSetDigest, err := CanonicalGuarantorEvidenceSetDigestV1(receipt.TransitionEvidenceSet)
	if err != nil || receipt.TransitionEvidenceSet.ContextDigest != decisionAdmissionDigest {
		return errors.New("claim transition evidence set is invalid or has a substituted context")
	}
	wantPurpose := ""
	priorState := decisionAdmission.AdmittedClaimState
	resultingState := "reviewing"
	wantChallengeAfter := decisionAdmission.ChallengeRoundsUsedAfter
	wantNonterminalAfter := decisionAdmission.NonterminalRoundsUsedAfter
	wantSuccessorDue := uint64(0)
	transitionedAt := receipt.Body.TransitionedAtUnix
	switch request.TransitionKind {
	case "challenge_admission":
		wantPurpose = "claim-challenge-admission"
		if (priorState != "approved" && priorState != "partially_approved" && priorState != "denied") ||
			transitionedAt > decisionAdmission.ChallengeEndsAtUnix ||
			decisionAdmission.ChallengeRoundsUsedAfter >= terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim {
			return errors.New("claim challenge admission is outside its closed window or budget")
		}
		wantChallengeAfter++
		wantSuccessorDue, _ = checkedAdd(transitionedAt, terms.SuccessorDecisionWindowSeconds)
	case "nonterminal_response_admission":
		wantPurpose = "claim-nonterminal-response-admission"
		if (priorState != "evidence_required" && priorState != "disputed") ||
			transitionedAt >= decisionAdmission.ResolutionDueAtUnix ||
			decisionAdmission.NonterminalRoundsUsedAfter >= terms.ClaimClosureCapacity.MaximumNonterminalRoundsPerClaim {
			return errors.New("claim nonterminal response is outside its closed window or budget")
		}
		wantNonterminalAfter++
		wantSuccessorDue = decisionAdmission.ResolutionDueAtUnix
	case "challenge_close":
		wantPurpose = "claim-challenge-close"
		if (priorState != "approved" && priorState != "partially_approved" && priorState != "denied") ||
			transitionedAt < decisionAdmission.ChallengeEndsAtUnix {
			return errors.New("claim challenge close is premature or non-challengeable")
		}
		switch priorState {
		case "approved":
			resultingState = "final_approved"
		case "partially_approved":
			resultingState = "final_partially_approved"
		case "denied":
			resultingState = "final_denied"
		}
	default:
		return errors.New("claim transition kind is unknown")
	}
	if receipt.TransitionEvidenceSet.Purpose != wantPurpose || request.TargetState != resultingState ||
		request.ExpectedClaimStateRevision != decisionAdmission.AdmittedClaimStateRevision ||
		request.ExpectedChallengeRoundsUsed != decisionAdmission.ChallengeRoundsUsedAfter ||
		request.TargetChallengeRoundsUsed != wantChallengeAfter ||
		request.ExpectedNonterminalRoundsUsed != decisionAdmission.NonterminalRoundsUsedAfter ||
		request.TargetNonterminalRoundsUsed != wantNonterminalAfter || request.SuccessorDecisionDueAtUnix != wantSuccessorDue {
		return errors.New("claim transition action does not follow the closed transition table")
	}
	requestBytes, err := guarantorCodec.Marshal(request)
	if err != nil || !bytes.Equal(requestBytes, receipt.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("claim transition request bytes are noncanonical")
	}
	fields := ClaimStateTransitionSemanticFieldsV1(bound, request, evidenceSetDigest)
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound,
		requestBytes, fields, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	action := receipt.StageActionAdmissionEvidence.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if err != nil || proofErr != nil {
		return errors.New("claim transition authority evidence is invalid")
	}
	body := receipt.Body
	if body.SchemaVersion != 1 || body.AuthorityID != bound.ActionAuthorityID ||
		body.CoverageAgreementBodyDigest != request.CoverageAgreementBodyDigest || body.CoverageObligationID != request.CoverageObligationID ||
		body.ClaimID != request.ClaimID || body.TransitionKind != request.TransitionKind ||
		body.TransitionEvidenceProjectionDigest != projectionDigest || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != action.StableActionID || body.ExactRequestDigest != action.ExactRequestDigest ||
		body.WriterGeneration != action.WriterGeneration || body.WriterFenceDigest != action.WriterFenceDigest ||
		body.PriorClaimState != priorState || body.ResultingClaimState != resultingState ||
		body.PriorClaimStateRevision != request.ExpectedClaimStateRevision ||
		body.ResultingClaimStateRevision != request.ExpectedClaimStateRevision+1 ||
		body.ChallengeRoundsUsedBefore != request.ExpectedChallengeRoundsUsed || body.ChallengeRoundsUsedAfter != wantChallengeAfter ||
		body.NonterminalRoundsUsedBefore != request.ExpectedNonterminalRoundsUsed || body.NonterminalRoundsUsedAfter != wantNonterminalAfter ||
		body.SuccessorDecisionDueAtUnix != wantSuccessorDue || body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest ||
		body.TransitionedAtUnix == 0 {
		return errors.New("claim transition receipt binding is invalid")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest,
		decisionAdmissionDigest, terms.DecisionAdmissionAuthoritySubjects, "claim-state-transition-receipt", projectionDigest,
		terms.DecisionAdmissionProfile.ProfileDigest, terms.DecisionAdmissionProfile, bound.AdmissionStateDomainDigest,
		body.ResultingClaimStateRevision, body.TransitionedAtUnix); err != nil {
		return err
	}
	bodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-state-transition-receipt-body.v1", body)
	if err != nil {
		return err
	}
	return verifyReceiptAuthorizationSetV1(receipt.Authorizations, "claim-state-transition-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-state-transition-signature.v1", terms.DecisionAdmissionProfile,
		terms.DecisionAdmissionAuthoritySubjects, terms.DecisionAdmissionQuorumRule, authorityResolver, now)
}

func ClaimDecisionApplicationSemanticFieldsV1(bound GuarantorStageActionAuthorityV1,
	request ClaimDecisionApplicationActionBodyV1, decision AuthorizedClaimDecisionV1,
	claimEnvelopeDigest string) map[string]agentcommerce.SemanticValue {
	return map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest":            agentcommerce.Digest32(decision.Body.CoverageAgreementBodyDigest),
		"obligation_id":                    agentcommerce.ID(decision.Body.CoverageObligationID),
		"authorized_claim_envelope_digest": agentcommerce.Digest32(claimEnvelopeDigest),
		"decision_application_token_id":    agentcommerce.Digest32(request.DecisionApplicationToken.TokenID),
		"expected_coverage_revision":       agentcommerce.U64(request.ExpectedCurrentCoverageRevision),
		"expected_claim_revision":          agentcommerce.U64(decision.Body.ExpectedClaimRevision),
		"expected_claim_state_revision":    agentcommerce.U64(request.ExpectedClaimStateRevision),
		"decision_sequence":                agentcommerce.U64(decision.Body.DecisionSequence),
		"decision_revision":                agentcommerce.U64(decision.Body.DecisionRevision),
		"target_state":                     agentcommerce.State(request.TargetClaimState),
	}
}

func VerifyClaimDecisionApplicationReceiptV1(receipt AuthorizedClaimDecisionApplicationReceiptV1, terms CoverageTermsV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "decision_application")
	if err != nil {
		return err
	}
	transition := receipt.AuthorizedTerminalClaimStateTransitionReceipt
	admission := transition.DecisionAdmissionProof
	if err := VerifyClaimDecisionAdmissionReceiptProofV1(admission, terms, authorityResolver, now); err != nil {
		return fmt.Errorf("decision application has an invalid admission predecessor: %w", err)
	}
	if err := VerifyClaimStateTransitionReceiptV1(transition, terms, agreementVerifier, authorityResolver, fenceResolver, now); err != nil {
		return fmt.Errorf("decision application has an invalid terminal transition: %w", err)
	}
	if transition.Body.TransitionKind != "challenge_close" {
		return errors.New("decision application does not select one terminal decision head")
	}
	var request ClaimDecisionApplicationActionBodyV1
	decision := admission.AuthorizedClaimDecision
	decisionDigest, decisionErr := ClaimDecisionDigestV1(decision)
	claimAdmissionDigest := admission.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest
	admissionDigest := admission.ReceiptEnvelopeDigest
	transitionDigest, transitionErr := ClaimStateTransitionReceiptDigestV1(transition)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	templateDigest, templateErr := agentcommerce.ConditionalSettlementTemplateDigestV1(terms.PayoutTemplate)
	if err := guarantorCodec.Unmarshal(receipt.StageActionAdmissionEvidence.CanonicalRequest, &request); err != nil ||
		decisionErr != nil || transitionErr != nil || endErr != nil || templateErr != nil ||
		request.SchemaVersion != 1 || request.AuthorizedClaimDecisionDigest != decisionDigest ||
		request.AuthorizedClaimAdmissionReceiptDigest != claimAdmissionDigest ||
		request.AuthorizedClaimDecisionAdmissionReceiptDigest != admissionDigest ||
		request.AuthorizedTerminalClaimStateTransitionReceiptDigest != transitionDigest ||
		!equalCanonical(request.DecisionApplicationToken, receipt.DecisionApplicationToken) ||
		request.ExpectedCoverageEndCommitmentDigest != endDigest || request.PayoutTemplateDigest != templateDigest {
		return errors.New("decision application request is noncanonical or substituted")
	}
	claim := admission.AuthorizedClaim
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		return err
	}
	tokenDigest, err := DecisionApplicationTokenDigestV1(receipt.DecisionApplicationToken)
	if err != nil || admission.ReceiptBody.ResultingApplicationToken == nil ||
		!equalCanonical(*admission.ReceiptBody.ResultingApplicationToken, receipt.DecisionApplicationToken) ||
		receipt.DecisionApplicationToken.State != "pending" {
		return errors.New("decision application token is absent, replaced, or consumed")
	}
	expectedTarget := transition.Body.ResultingClaimState
	if request.ExpectedClaimStateRevision != transition.Body.ResultingClaimStateRevision || request.TargetClaimState != expectedTarget ||
		request.TargetCoverageRevision != request.ExpectedCurrentCoverageRevision+1 ||
		request.ExpectedApplicationTokenRevision != receipt.DecisionApplicationToken.TokenRevision {
		return errors.New("decision application state CAS is invalid")
	}
	wantSet, err := MaterializeClaimPayout(bound.ActionOwnerID, bound.ActionAgentID,
		receipt.StageActionAdmissionEvidence.AuthorizedAction.MandateDigest, terms.PayoutTemplate.AgreementObligationID,
		terms, decision, transitionDigest, transition.Body.TransitionedAtUnix, request.ExpectedNextPayoutSequence)
	if err != nil || !equalCanonical(wantSet, receipt.MaterializedPayoutObligationSet) {
		return errors.New("decision application payout materialization differs")
	}
	payoutDigest, err := guarantorCodec.Digest(PayoutSetDomain, receipt.MaterializedPayoutObligationSet)
	if err != nil {
		return err
	}
	requestBytes, err := guarantorCodec.Marshal(request)
	if err != nil || !bytes.Equal(requestBytes, receipt.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("decision application request bytes are noncanonical")
	}
	fields := ClaimDecisionApplicationSemanticFieldsV1(bound, request, decision, claimDigest)
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, requestBytes,
		fields, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	action := receipt.StageActionAdmissionEvidence.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	endDigest, endErr = CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	if err != nil || endErr != nil {
		return errors.New("decision application action or end commitment is invalid")
	}
	body := receipt.Body
	if body.SchemaVersion != 1 || body.AuthorityID != bound.ActionAuthorityID ||
		body.CoverageAgreementBodyDigest != decision.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != decision.Body.CoverageObligationID || body.ClaimID != decision.Body.ClaimID ||
		body.AuthorizedClaimDecisionDigest != decisionDigest || body.ClaimDecisionAdmissionReceiptDigest != admissionDigest ||
		body.TerminalClaimStateTransitionReceiptDigest != transitionDigest ||
		body.DecisionApplicationTokenID != receipt.DecisionApplicationToken.TokenID ||
		body.DecisionApplicationTokenDigest != tokenDigest || body.PriorApplicationTokenRevision != receipt.DecisionApplicationToken.TokenRevision ||
		body.ResultingApplicationTokenRevision != body.PriorApplicationTokenRevision+1 || body.ResultingApplicationTokenState != "consumed" ||
		body.MaterializedPayoutObligationSetDigest != payoutDigest || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != action.StableActionID || body.ExactRequestDigest != action.ExactRequestDigest ||
		body.WriterGeneration != action.WriterGeneration || body.WriterFenceDigest != action.WriterFenceDigest ||
		body.AppliedCoverageRevision != body.PriorCoverageRevision+1 || body.PriorCoverageEndCommitmentDigest != endDigest ||
		body.ResultingCoverageEndCommitmentDigest != endDigest ||
		body.PriorClaimStateRevision != transition.Body.ResultingClaimStateRevision ||
		body.AppliedClaimStateRevision != body.PriorClaimStateRevision || body.AppliedAtUnix == 0 {
		return errors.New("decision application receipt binding is invalid")
	}
	pendingBefore, okPendingBefore := new(big.Int).SetString(body.AggregatePendingDecisionReserveBefore.AmountAtomic, 10)
	pendingAfter, okPendingAfter := new(big.Int).SetString(body.AggregatePendingDecisionReserveAfter.AmountAtomic, 10)
	cumulativeBefore, okCumulativeBefore := new(big.Int).SetString(body.CumulativeApprovedBefore.AmountAtomic, 10)
	cumulativeAfter, okCumulativeAfter := new(big.Int).SetString(body.CumulativeApprovedAfter.AmountAtomic, 10)
	approved, okApproved := new(big.Int).SetString(decision.Body.ApprovedAmount.AmountAtomic, 10)
	maximum, okMaximum := new(big.Int).SetString(terms.MaximumAggregatePayout.AmountAtomic, 10)
	wantPendingAfter, wantCumulativeAfter := new(big.Int), new(big.Int)
	if okPendingBefore && okApproved {
		wantPendingAfter.Sub(pendingBefore, approved)
	}
	if okCumulativeBefore && okApproved {
		wantCumulativeAfter.Add(cumulativeBefore, approved)
	}
	if !okPendingBefore || !okPendingAfter || !okCumulativeBefore || !okCumulativeAfter || !okApproved || !okMaximum ||
		pendingBefore.Sign() < 0 || wantPendingAfter.Sign() < 0 || pendingAfter.Cmp(wantPendingAfter) != 0 ||
		cumulativeAfter.Cmp(wantCumulativeAfter) != 0 || cumulativeAfter.Cmp(maximum) > 0 ||
		request.ExpectedAggregatePendingDecisionReserve != body.AggregatePendingDecisionReserveBefore ||
		request.TargetAggregatePendingDecisionReserve != body.AggregatePendingDecisionReserveAfter ||
		body.CumulativeApprovedBefore.Asset != terms.CoverageAsset || body.CumulativeApprovedAfter.Asset != terms.CoverageAsset ||
		body.AggregatePendingDecisionReserveBefore.Asset != terms.CoverageAsset || body.AggregatePendingDecisionReserveAfter.Asset != terms.CoverageAsset ||
		body.PriorNextPayoutSequence != request.ExpectedNextPayoutSequence ||
		body.ResultingNextPayoutSequence != request.ExpectedNextPayoutSequence+uint64(len(receipt.MaterializedPayoutObligationSet.MaterializedLines)) {
		return errors.New("decision application aggregate capacity or payout sequence is invalid")
	}
	if receipt.StageActionAdmissionEvidence.ActionResolution.SinkReference != payoutDigest ||
		!containsString(receipt.StageActionAdmissionEvidence.ActionResolution.EvidenceRefs, payoutDigest) {
		return errors.New("decision application terminal result does not commit the payout set")
	}
	bodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-application-receipt-body.v1", body)
	if err != nil {
		return err
	}
	return verifyReceiptAuthorizationSetV1(receipt.Authorizations, "claim-decision-application-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-application-signature.v1", terms.DecisionAdmissionProfile,
		terms.DecisionAdmissionAuthoritySubjects, terms.DecisionAdmissionQuorumRule, authorityResolver, now)
}
