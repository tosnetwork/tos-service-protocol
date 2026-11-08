package agentguarantor

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type ActivationAdmissionCutProofV1 struct {
	SchemaVersion               uint16                         `json:"schema_version"`
	CoverageAgreementBodyDigest string                         `json:"coverage_agreement_body_digest"`
	ActivationAdmissionLogID    string                         `json:"activation_admission_log_id"`
	ActivationCutoffUnix        uint64                         `json:"activation_cutoff_unix"`
	AdmissionHighWater          uint64                         `json:"admission_high_water"`
	AdmissionLogRoot            string                         `json:"admission_log_root"`
	Entries                     []GuarantorAdmissionLogEntryV1 `json:"entries"`
	AcceptedCount               uint64                         `json:"accepted_count"`
	PendingOrAmbiguousCount     uint64                         `json:"pending_or_ambiguous_count"`
}

func ActivationAdmissionCutProofDigestV1(proof ActivationAdmissionCutProofV1) (string, error) {
	if err := ValidateActivationAdmissionCutProofV1(proof); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-activation-cut-proof.v1", proof)
}

func ValidateActivationAdmissionCutProofV1(proof ActivationAdmissionCutProofV1) error {
	expectedDomain, err := ActivationAdmissionDomainIDV1(proof.CoverageAgreementBodyDigest)
	if err != nil || proof.SchemaVersion != 1 || proof.ActivationAdmissionLogID != expectedDomain ||
		proof.ActivationCutoffUnix == 0 || proof.AdmissionHighWater != uint64(len(proof.Entries)) {
		return errors.New("Guarantor activation admission cut is invalid")
	}
	root, err := InitialAdmissionLogRootV1(proof.ActivationAdmissionLogID)
	if err != nil {
		return err
	}
	var accepted, pending, priorReceived uint64
	for index, entry := range proof.Entries {
		sequence := uint64(index + 1)
		if entry.Sequence != sequence || entry.ReceivedAtUnix < priorReceived || entry.ReceivedAtUnix > proof.ActivationCutoffUnix ||
			agentcommerce.ValidateActionResolution(entry.Resolution) != nil || entry.Resolution.StableActionID != entry.StableActionID ||
			entry.Resolution.ExactRequestDigest != entry.ExactRequestDigest {
			return errors.New("Guarantor activation admission cut entry is invalid")
		}
		root, err = AdvanceAdmissionLogRootV1(proof.ActivationAdmissionLogID, root, entry.StableActionID,
			entry.ExactRequestDigest, sequence, entry.ReceivedAtUnix)
		if err != nil || root != entry.LogRootAfter {
			return errors.New("Guarantor activation admission root is invalid")
		}
		switch entry.Resolution.State {
		case agentcommerce.ActionTerminal, agentcommerce.ActionAccepted:
			accepted++
		case agentcommerce.ActionRejected, agentcommerce.ActionConflict:
		default:
			pending++
		}
		priorReceived = entry.ReceivedAtUnix
	}
	if proof.AdmissionLogRoot != root || proof.AcceptedCount != accepted || proof.PendingOrAmbiguousCount != pending {
		return errors.New("Guarantor activation admission cut counters differ")
	}
	return nil
}

type TerminalPrerequisiteFailureEvidenceV1 struct {
	PrerequisiteID                 string                                  `json:"prerequisite_id"`
	FailureOutcome                 string                                  `json:"failure_outcome"`
	TerminalFailureEvidenceProfile ProfileRefV1                            `json:"terminal_failure_evidence_profile"`
	TerminalFailureEvidence        []byte                                  `json:"terminal_failure_evidence"`
	TerminalFailureAuthorizations  []ProfileQualifiedObjectAuthorizationV1 `json:"terminal_failure_authorizations"`
}

type PreActivationMutualCancellationBodyV1 struct {
	SchemaVersion                     uint16 `json:"schema_version"`
	CoverageAgreementBodyDigest       string `json:"coverage_agreement_body_digest"`
	CoverageObligationID              string `json:"coverage_obligation_id"`
	AuthorizedFirmOfferEnvelopeDigest string `json:"authorized_firm_offer_envelope_digest"`
	AcceptanceReceiptDigest           string `json:"acceptance_receipt_digest"`
	ActivationCutoffUnix              uint64 `json:"activation_cutoff_unix"`
	ExpectedCoverageRevision          uint64 `json:"expected_coverage_revision"`
	CancellationNonce                 string `json:"cancellation_nonce"`
	CreatedAtUnix                     uint64 `json:"created_at_unix"`
	ExpiresAtUnix                     uint64 `json:"expires_at_unix"`
}

type CoverageNonActivationReasonEvidenceV1 struct {
	SchemaVersion                           uint16                                         `json:"schema_version"`
	CoverageAgreementBodyDigest             string                                         `json:"coverage_agreement_body_digest"`
	CoverageObligationID                    string                                         `json:"coverage_obligation_id"`
	Reason                                  string                                         `json:"reason"`
	ActivationAdmissionCutProofDigest       string                                         `json:"activation_admission_cut_proof_digest"`
	PrerequisiteFailureEvidence             []TerminalPrerequisiteFailureEvidenceV1        `json:"prerequisite_failure_evidence,omitempty"`
	MutualCancellationBody                  *PreActivationMutualCancellationBodyV1         `json:"mutual_cancellation_body,omitempty"`
	MutualCancellationAuthorizationEvidence []agentcommerce.AgreementAuthorizationEvidence `json:"mutual_cancellation_authorization_evidence,omitempty"`
}

type CoverageNonActivationEvidenceBodyV1 struct {
	SchemaVersion                               uint16 `json:"schema_version"`
	AuthorityID                                 string `json:"authority_id"`
	CoverageAgreementBodyDigest                 string `json:"coverage_agreement_body_digest"`
	CoverageObligationID                        string `json:"coverage_obligation_id"`
	CoverageStateDomainDigest                   string `json:"coverage_state_domain_digest"`
	AuthorizedFirmOfferEnvelopeDigest           string `json:"authorized_firm_offer_envelope_digest"`
	AcceptanceReceiptDigest                     string `json:"acceptance_receipt_digest"`
	ExposureReceiptDigest                       string `json:"exposure_receipt_digest"`
	Reason                                      string `json:"reason"`
	ActivationCutoffUnix                        uint64 `json:"activation_cutoff_unix"`
	ActivationAdmissionLogID                    string `json:"activation_admission_log_id"`
	ActivationAdmissionHighWater                uint64 `json:"activation_admission_high_water"`
	ActivationAdmissionLogRoot                  string `json:"activation_admission_log_root"`
	PendingActivationActionCount                uint64 `json:"pending_activation_action_count"`
	ActivationAdmissionCutProofDigest           string `json:"activation_admission_cut_proof_digest"`
	NonActivationReasonEvidenceDigest           string `json:"non_activation_reason_evidence_digest"`
	FeeResolutionEvidenceSetDigest              string `json:"fee_resolution_evidence_set_digest,omitempty"`
	CollateralNonActivationEvidenceSetDigest    string `json:"collateral_non_activation_evidence_set_digest,omitempty"`
	TransitionEvidenceProjectionDigest          string `json:"transition_evidence_projection_digest"`
	AuthorizedActionDigest                      string `json:"authorized_action_digest"`
	StableActionID                              string `json:"stable_action_id"`
	ExactRequestDigest                          string `json:"exact_request_digest"`
	WriterGeneration                            uint64 `json:"writer_generation"`
	WriterFenceDigest                           string `json:"writer_fence_digest"`
	PriorCoverageRevision                       uint64 `json:"prior_coverage_revision"`
	ResolvedCoverageRevision                    uint64 `json:"resolved_coverage_revision"`
	PriorClaimFilingState                       string `json:"prior_claim_filing_state"`
	ResultingClaimFilingState                   string `json:"resulting_claim_filing_state"`
	PriorClaimFilingStateRevision               uint64 `json:"prior_claim_filing_state_revision"`
	ResultingClaimFilingStateRevision           uint64 `json:"resulting_claim_filing_state_revision"`
	ResolvedAtUnix                              uint64 `json:"resolved_at_unix"`
	AuthorityAdmissionEligibilityProofSetDigest string `json:"authority_admission_eligibility_proof_set_digest"`
}

type AuthorizedCoverageNonActivationEvidenceV1 struct {
	Body                                  CoverageNonActivationEvidenceBodyV1     `json:"body"`
	StageActionAdmissionEvidence          PortableStageActionAdmissionEvidenceV1  `json:"stage_action_admission_evidence"`
	AuthorizedAcceptanceReceipt           AuthorizedCoverageAcceptanceReceiptV1   `json:"authorized_acceptance_receipt"`
	ActivationAdmissionCutProof           ActivationAdmissionCutProofV1           `json:"activation_admission_cut_proof"`
	NonActivationReasonEvidence           CoverageNonActivationReasonEvidenceV1   `json:"non_activation_reason_evidence"`
	FeeResolutionEvidenceSet              *CanonicalGuarantorEvidenceSetV1        `json:"fee_resolution_evidence_set,omitempty"`
	CollateralNonActivationEvidenceSet    *CanonicalGuarantorEvidenceSetV1        `json:"collateral_non_activation_evidence_set,omitempty"`
	TransitionEvidenceProjection          TransitionEvidenceProjectionV1          `json:"transition_evidence_projection"`
	AuthorityAdmissionEligibilityProofSet AuthorityAdmissionEligibilityProofSetV1 `json:"authority_admission_eligibility_proof_set"`
	Authorizations                        []ProfileQualifiedObjectAuthorizationV1 `json:"authorizations"`
}

func CoverageNonActivationReasonEvidenceDigestV1(reason CoverageNonActivationReasonEvidenceV1) (string, error) {
	if err := ValidateCoverageNonActivationReasonEvidenceV1(reason); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-non-activation-reason-evidence.v1", reason)
}

func ValidateCoverageNonActivationReasonEvidenceV1(reason CoverageNonActivationReasonEvidenceV1) error {
	if reason.SchemaVersion != 1 || !validDigest(reason.CoverageAgreementBodyDigest) ||
		!validToken(reason.CoverageObligationID, 128) || !validDigest(reason.ActivationAdmissionCutProofDigest) {
		return errors.New("Guarantor non-activation reason evidence is invalid")
	}
	switch reason.Reason {
	case "activation_window_expired":
		if len(reason.PrerequisiteFailureEvidence) != 0 || reason.MutualCancellationBody != nil ||
			len(reason.MutualCancellationAuthorizationEvidence) != 0 {
			return errors.New("activation-window expiry carries forbidden reason evidence")
		}
	case "prerequisite_failed":
		if len(reason.PrerequisiteFailureEvidence) == 0 || len(reason.PrerequisiteFailureEvidence) > MaxEvidenceItems ||
			reason.MutualCancellationBody != nil || len(reason.MutualCancellationAuthorizationEvidence) != 0 {
			return errors.New("prerequisite failure evidence is invalid")
		}
		prior := ""
		for _, failure := range reason.PrerequisiteFailureEvidence {
			if !validToken(failure.PrerequisiteID, 128) || failure.PrerequisiteID <= prior ||
				!validToken(failure.FailureOutcome, 128) || agentcommerce.ValidateProfileRefV1(failure.TerminalFailureEvidenceProfile) != nil ||
				len(failure.TerminalFailureEvidence) == 0 || len(failure.TerminalFailureEvidence) > MaxCanonicalObjectBytes ||
				len(failure.TerminalFailureAuthorizations) == 0 || len(failure.TerminalFailureAuthorizations) > MaxAuthorizations {
				return errors.New("prerequisite terminal failure item is invalid or unsorted")
			}
			prior = failure.PrerequisiteID
		}
	case "mutually_cancelled":
		body := reason.MutualCancellationBody
		if body == nil || len(reason.PrerequisiteFailureEvidence) != 0 || len(reason.MutualCancellationAuthorizationEvidence) == 0 ||
			body.SchemaVersion != 1 || body.CoverageAgreementBodyDigest != reason.CoverageAgreementBodyDigest ||
			body.CoverageObligationID != reason.CoverageObligationID || !validDigest(body.AuthorizedFirmOfferEnvelopeDigest) ||
			!validDigest(body.AcceptanceReceiptDigest) || body.ActivationCutoffUnix == 0 || body.ExpectedCoverageRevision == 0 ||
			!validToken(body.CancellationNonce, 256) || body.CreatedAtUnix == 0 || body.ExpiresAtUnix <= body.CreatedAtUnix ||
			body.ExpiresAtUnix > body.ActivationCutoffUnix {
			return errors.New("pre-activation mutual cancellation is invalid")
		}
	default:
		return errors.New("Guarantor non-activation reason is unknown")
	}
	return nil
}

func ValidateCoverageNonActivationReasonRulesV1(rules []CoverageNonActivationReasonRuleV1) error {
	wanted := []struct{ reason, mode string }{{"activation_window_expired", "deadline_only"},
		{"mutually_cancelled", "agreement_predicates"}, {"prerequisite_failed", "terminal_prerequisite_failure"}}
	if len(rules) != len(wanted) {
		return errors.New("Guarantor non-activation reason registry is incomplete")
	}
	for index, rule := range rules {
		if rule.Reason != wanted[index].reason || rule.EvidenceMode != wanted[index].mode {
			return errors.New("Guarantor non-activation reason registry differs from V1")
		}
		switch rule.Reason {
		case "activation_window_expired":
			if len(rule.PrerequisiteFailureRules) != 0 || len(rule.CancellationAuthorizationPredicateIDs) != 0 {
				return errors.New("deadline-only non-activation rule carries extra authority")
			}
		case "mutually_cancelled":
			if len(rule.PrerequisiteFailureRules) != 0 ||
				!sortedUnique(rule.CancellationAuthorizationPredicateIDs, MaxAuthorizations, func(v string) bool { return validToken(v, 128) }) {
				return errors.New("mutual-cancellation rule has no exact Agreement predicates")
			}
		case "prerequisite_failed":
			if len(rule.CancellationAuthorizationPredicateIDs) != 0 || len(rule.PrerequisiteFailureRules) == 0 ||
				len(rule.PrerequisiteFailureRules) > MaxEvidenceItems {
				return errors.New("prerequisite-failure rule is empty or mixed")
			}
			previous := ""
			for _, prerequisite := range rule.PrerequisiteFailureRules {
				if !validToken(prerequisite.PrerequisiteID, 128) || prerequisite.PrerequisiteID <= previous ||
					agentcommerce.ValidateProfileRefV1(prerequisite.TerminalFailureEvidenceProfile) != nil ||
					QuorumThresholdMustFailV1(prerequisite.TerminalFailureQuorumRule,
						prerequisite.TerminalFailureAuthoritySubjects) ||
					!sortedUnique(prerequisite.PermittedTerminalFailureOutcomes, 32,
						func(v string) bool { return validToken(v, 128) }) {
					return errors.New("prerequisite-failure rule is invalid or unsorted")
				}
				previous = prerequisite.PrerequisiteID
			}
		}
	}
	return nil
}

func verifyCoverageNonActivationReasonV1(reason CoverageNonActivationReasonEvidenceV1, evidence AuthorizedCoverageNonActivationEvidenceV1,
	offer AuthorizedFirmCoverageOfferV1, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	authorityResolver AuthorityKeyResolver, now time.Time) error {
	if ValidateCoverageNonActivationReasonRulesV1(offer.CoverageTerms.NonActivationReasonRules) != nil {
		return errors.New("accepted coverage has no released non-activation reason registry")
	}
	var selected CoverageNonActivationReasonRuleV1
	for _, candidate := range offer.CoverageTerms.NonActivationReasonRules {
		if candidate.Reason == reason.Reason {
			selected = candidate
		}
	}
	switch reason.Reason {
	case "activation_window_expired":
		if reason.ActivationAdmissionCutProofDigest == "" || evidence.Body.ActivationCutoffUnix != offer.CoverageTerms.CoverageStartsAtUnix ||
			evidence.Body.ResolvedAtUnix < offer.CoverageTerms.CoverageStartsAtUnix {
			return errors.New("activation-window expiry is not proven at the Agreement deadline")
		}
	case "prerequisite_failed":
		ruleByID := make(map[string]ActivationPrerequisiteFailureRuleV1, len(selected.PrerequisiteFailureRules))
		for _, rule := range selected.PrerequisiteFailureRules {
			ruleByID[rule.PrerequisiteID] = rule
		}
		for _, failure := range reason.PrerequisiteFailureEvidence {
			rule, found := ruleByID[failure.PrerequisiteID]
			if !found || !containsString(rule.PermittedTerminalFailureOutcomes, failure.FailureOutcome) ||
				failure.TerminalFailureEvidenceProfile != rule.TerminalFailureEvidenceProfile {
				return errors.New("non-activation cites an unselected prerequisite failure")
			}
			for _, authorization := range failure.TerminalFailureAuthorizations {
				if authorization.ProfileURI != rule.TerminalFailureEvidenceProfile.ProfileURI ||
					authorization.ProfileVersion != rule.TerminalFailureEvidenceProfile.ProfileVersion ||
					authorization.ProfileDigest != rule.TerminalFailureEvidenceProfile.ProfileDigest {
					return errors.New("prerequisite terminal-failure authorization profile is substituted")
				}
			}
			failureBodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-prerequisite-terminal-failure.v1", struct {
				CoverageAgreementBodyDigest string       `json:"coverage_agreement_body_digest"`
				CoverageObligationID        string       `json:"coverage_obligation_id"`
				PrerequisiteID              string       `json:"prerequisite_id"`
				FailureOutcome              string       `json:"failure_outcome"`
				EvidenceProfile             ProfileRefV1 `json:"terminal_failure_evidence_profile"`
				Evidence                    []byte       `json:"terminal_failure_evidence"`
			}{reason.CoverageAgreementBodyDigest, reason.CoverageObligationID, failure.PrerequisiteID,
				failure.FailureOutcome, failure.TerminalFailureEvidenceProfile, failure.TerminalFailureEvidence})
			if err != nil || ValidateAuthorizationQuorumSet(failure.TerminalFailureAuthorizations,
				"activation-prerequisite-terminal-failure", failureBodyDigest,
				"tos.service.agent-guarantor-prerequisite-terminal-failure-signature.v1",
				rule.TerminalFailureAuthoritySubjects, rule.TerminalFailureQuorumRule, authorityResolver, now) != nil {
				return errors.New("prerequisite terminal-failure quorum does not verify")
			}
		}
	case "mutually_cancelled":
		if agreementVerifier == nil || reason.MutualCancellationBody == nil {
			return errors.New("mutual cancellation has no Agreement evidence verifier")
		}
		body := *reason.MutualCancellationBody
		offerDigest, _ := FirmOfferDigest(offer)
		acceptanceDigest, _ := CoverageAcceptanceReceiptDigestV1(evidence.AuthorizedAcceptanceReceipt)
		if body.AuthorizedFirmOfferEnvelopeDigest != offerDigest || body.AcceptanceReceiptDigest != acceptanceDigest ||
			body.ActivationCutoffUnix != evidence.Body.ActivationCutoffUnix || body.ExpectedCoverageRevision != evidence.Body.PriorCoverageRevision ||
			uint64(now.UTC().Unix()) >= body.ExpiresAtUnix {
			return errors.New("mutual-cancellation body is stale or substituted")
		}
		cancellationDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-pre-activation-mutual-cancellation.v1", body)
		agreementBody := evidence.AuthorizedAcceptanceReceipt.AuthorizedAcceptanceRequest.CoverageAgreementBody
		agreementDigest, _ := agentcommerce.AgreementBodyDigest(agreementBody)
		predicates := make(map[string]agentcommerce.AgreementAuthorizationPredicate)
		for _, predicate := range agreementBody.AuthorizationPredicates {
			predicates[predicate.PredicateID] = predicate
		}
		seen := make(map[string]struct{})
		for _, authorization := range reason.MutualCancellationAuthorizationEvidence {
			if authorization.AgreementID != agreementBody.AgreementID || authorization.AgreementVersion != agreementBody.Version ||
				authorization.AgreementBodyDigest != agreementDigest || len(authorization.PredicateIDs) == 0 ||
				len(authorization.PredicateIDs) != len(authorization.EvidenceTargetProjectionDigests) {
				return errors.New("mutual-cancellation authorization context is substituted")
			}
			for index, predicateID := range authorization.PredicateIDs {
				predicate, found := predicates[predicateID]
				if !found || !containsString(selected.CancellationAuthorizationPredicateIDs, predicateID) ||
					authorization.EvidenceTargetProjectionDigests[index] != cancellationDigest ||
					authorization.AuthoritySubject != predicate.AuthoritySubject ||
					authorization.EvidenceProfileURI != predicate.EvidenceProfileURI ||
					authorization.EvidenceProfileVersion != predicate.EvidenceProfileVersion ||
					authorization.EvidenceProfileDigest != predicate.EvidenceProfileDigest {
					return errors.New("mutual-cancellation evidence does not satisfy its Agreement predicate")
				}
				if _, duplicate := seen[predicateID]; duplicate {
					return errors.New("mutual-cancellation predicate is duplicated")
				}
				seen[predicateID] = struct{}{}
			}
			if err := agreementVerifier.VerifyAgreementEvidence(authorization, now); err != nil {
				return err
			}
		}
		for _, predicateID := range selected.CancellationAuthorizationPredicateIDs {
			if _, found := seen[predicateID]; !found {
				return errors.New("mutual-cancellation Agreement predicate is missing")
			}
		}
	}
	return nil
}

func CoverageNonActivationEvidenceDigestV1(evidence AuthorizedCoverageNonActivationEvidenceV1) (string, error) {
	if err := validateCoverageNonActivationEvidenceShapeV1(evidence); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-non-activation-evidence-envelope.v1", evidence)
}

func validateCoverageNonActivationEvidenceShapeV1(evidence AuthorizedCoverageNonActivationEvidenceV1) error {
	body := evidence.Body
	cutDigest, cutErr := ActivationAdmissionCutProofDigestV1(evidence.ActivationAdmissionCutProof)
	reasonDigest, reasonErr := CoverageNonActivationReasonEvidenceDigestV1(evidence.NonActivationReasonEvidence)
	acceptanceDigest, acceptanceErr := CoverageAcceptanceReceiptDigestV1(evidence.AuthorizedAcceptanceReceipt)
	projectionDigest, projectionErr := TransitionEvidenceProjectionDigestV1(evidence.TransitionEvidenceProjection)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(evidence.AuthorityAdmissionEligibilityProofSet)
	if cutErr != nil || reasonErr != nil || acceptanceErr != nil || projectionErr != nil || proofErr != nil ||
		body.SchemaVersion != 1 || !validID(body.AuthorityID) || !validDigest(body.CoverageAgreementBodyDigest) ||
		!validToken(body.CoverageObligationID, 128) || !validDigest(body.CoverageStateDomainDigest) ||
		!validDigest(body.AuthorizedFirmOfferEnvelopeDigest) || body.AcceptanceReceiptDigest != acceptanceDigest ||
		!validDigest(body.ExposureReceiptDigest) || body.Reason != evidence.NonActivationReasonEvidence.Reason ||
		body.ActivationCutoffUnix != evidence.ActivationAdmissionCutProof.ActivationCutoffUnix ||
		body.ActivationAdmissionLogID != evidence.ActivationAdmissionCutProof.ActivationAdmissionLogID ||
		body.ActivationAdmissionHighWater != evidence.ActivationAdmissionCutProof.AdmissionHighWater ||
		body.ActivationAdmissionLogRoot != evidence.ActivationAdmissionCutProof.AdmissionLogRoot ||
		body.PendingActivationActionCount != 0 || evidence.ActivationAdmissionCutProof.AcceptedCount != 0 ||
		evidence.ActivationAdmissionCutProof.PendingOrAmbiguousCount != 0 || body.ActivationAdmissionCutProofDigest != cutDigest ||
		body.NonActivationReasonEvidenceDigest != reasonDigest || body.TransitionEvidenceProjectionDigest != projectionDigest ||
		!validDigest(body.AuthorizedActionDigest) || !validDigest(body.StableActionID) || !validDigest(body.ExactRequestDigest) ||
		body.WriterGeneration == 0 || !validDigest(body.WriterFenceDigest) || body.PriorCoverageRevision == 0 ||
		body.ResolvedCoverageRevision != body.PriorCoverageRevision+1 || body.PriorClaimFilingState != "not_open" ||
		body.ResultingClaimFilingState != "not_open" || body.PriorClaimFilingStateRevision == 0 ||
		body.ResultingClaimFilingStateRevision != body.PriorClaimFilingStateRevision || body.ResolvedAtUnix < body.ActivationCutoffUnix ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest || len(evidence.Authorizations) == 0 ||
		len(evidence.Authorizations) > MaxAuthorizations {
		return errors.New("Guarantor non-activation evidence shape is invalid")
	}
	if body.CoverageAgreementBodyDigest != evidence.NonActivationReasonEvidence.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != evidence.NonActivationReasonEvidence.CoverageObligationID {
		return errors.New("Guarantor non-activation reason context differs")
	}
	return nil
}

func VerifyCoverageNonActivationEvidenceV1(evidence AuthorizedCoverageNonActivationEvidenceV1,
	offer AuthorizedFirmCoverageOfferV1, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if err := validateCoverageNonActivationEvidenceShapeV1(evidence); err != nil {
		return err
	}
	if err := enforceCanonicalSize(evidence, offer.CoverageTerms.ClaimClosureCapacity.MaximumNonActivationEvidenceEnvelopeBytes,
		"coverage non-activation evidence"); err != nil {
		return err
	}
	if err := VerifyCoverageAcceptanceReceiptV1(evidence.AuthorizedAcceptanceReceipt, offer, agreementVerifier,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "coverage_non_activation")
	if err != nil {
		return err
	}
	body := evidence.Body
	offerDigest, _ := FirmOfferDigest(offer)
	acceptanceDigest, _ := CoverageAcceptanceReceiptDigestV1(evidence.AuthorizedAcceptanceReceipt)
	exposureDigest, _ := ExposureAdmissionReceiptDigestV1(offer.ExposureAdmissionReceipt)
	cutDigest, _ := ActivationAdmissionCutProofDigestV1(evidence.ActivationAdmissionCutProof)
	reasonDigest, _ := CoverageNonActivationReasonEvidenceDigestV1(evidence.NonActivationReasonEvidence)
	projectionDigest, _ := TransitionEvidenceProjectionDigestV1(evidence.TransitionEvidenceProjection)
	feeDigest, collateralDigest := "", ""
	if evidence.FeeResolutionEvidenceSet != nil {
		feeDigest, _ = CanonicalGuarantorEvidenceSetDigestV1(*evidence.FeeResolutionEvidenceSet)
	}
	if evidence.CollateralNonActivationEvidenceSet != nil {
		collateralDigest, _ = CanonicalGuarantorEvidenceSetDigestV1(*evidence.CollateralNonActivationEvidenceSet)
	}
	if body.AuthorityID != bound.ActionAuthorityID || body.CoverageAgreementBodyDigest != offer.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != offer.Body.CoverageObligationID || body.CoverageStateDomainDigest != offer.CoverageTerms.CoverageStateDomainDigest ||
		body.AuthorizedFirmOfferEnvelopeDigest != offerDigest || body.AcceptanceReceiptDigest != acceptanceDigest ||
		body.ExposureReceiptDigest != exposureDigest || body.ActivationAdmissionCutProofDigest != cutDigest ||
		body.NonActivationReasonEvidenceDigest != reasonDigest || body.TransitionEvidenceProjectionDigest != projectionDigest ||
		body.FeeResolutionEvidenceSetDigest != feeDigest || body.CollateralNonActivationEvidenceSetDigest != collateralDigest {
		return errors.New("Guarantor non-activation lineage or prerequisite disposition is substituted")
	}
	if body.Reason == "activation_window_expired" && body.ActivationCutoffUnix != offer.CoverageTerms.CoverageStartsAtUnix ||
		body.ResolvedAtUnix < body.ActivationCutoffUnix {
		return errors.New("Guarantor non-activation timing is invalid")
	}
	if err := verifyCoverageNonActivationReasonV1(evidence.NonActivationReasonEvidence, evidence, offer,
		agreementVerifier, authorityResolver, now); err != nil {
		return err
	}
	if offer.CoverageTerms.SelectedAssuranceLevel != AssuranceUnsecuredSigned && evidence.CollateralNonActivationEvidenceSet == nil {
		return errors.New("collateralized non-activation lacks collateral disposition evidence")
	}
	request := CoverageNonActivationActionBodyV1{SchemaVersion: 1,
		AuthorizedAcceptanceReceipt: evidence.AuthorizedAcceptanceReceipt, ActivationAdmissionCutProof: evidence.ActivationAdmissionCutProof,
		NonActivationReasonEvidence: evidence.NonActivationReasonEvidence, FeeResolutionEvidenceSet: evidence.FeeResolutionEvidenceSet,
		CollateralNonActivationEvidenceSet: evidence.CollateralNonActivationEvidenceSet,
		TransitionEvidenceProjection:       evidence.TransitionEvidenceProjection, ExpectedCoverageRevision: body.PriorCoverageRevision,
		TargetCoverageRevision: body.ResolvedCoverageRevision, TargetCoverageState: "not_activated_confirmed",
		ExpectedClaimFilingState: body.PriorClaimFilingState, TargetClaimFilingState: body.ResultingClaimFilingState,
		ExpectedClaimFilingStateRevision: body.PriorClaimFilingStateRevision,
		TargetClaimFilingStateRevision:   body.ResultingClaimFilingStateRevision}
	requestBytes, err := guarantorCodec.Marshal(request)
	if err != nil || !bytes.Equal(requestBytes, evidence.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("non-activation action request is noncanonical")
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest), "obligation_id": agentcommerce.ID(body.CoverageObligationID),
		"expected_state_revision": agentcommerce.U64(body.PriorCoverageRevision), "target_state": agentcommerce.State("not_activated_confirmed"),
		"evidence_set_digest": agentcommerce.Digest32(projectionDigest)}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(evidence.StageActionAdmissionEvidence, bound, requestBytes,
		fields, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	actionDigest, _ := agentcommerce.AuthorizedActionDigest(evidence.StageActionAdmissionEvidence.AuthorizedAction)
	proofDigest, _ := AuthorityAdmissionEligibilityProofSetDigestV1(evidence.AuthorityAdmissionEligibilityProofSet)
	if body.AuthorizedActionDigest != actionDigest || body.StableActionID != evidence.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != evidence.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != evidence.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != evidence.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest ||
		evidence.AuthorityAdmissionEligibilityProofSet.AdmittedActionDigest != actionDigest {
		return errors.New("non-activation action or authority proof is substituted")
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-non-activation-evidence-body.v1", body)
	return ValidateAuthorizationSet(evidence.Authorizations, "non-activation-evidence", bodyDigest,
		"tos.service.agent-guarantor-non-activation-evidence-signature.v1", []string{offer.Body.GuarantorAgentID}, authorityResolver, now)
}
