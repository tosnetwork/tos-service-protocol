package agentguarantor

import (
	"errors"
	"math/big"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func RequestedCoverageTermsDigest(terms RequestedCoverageTermsV1) (string, error) {
	if err := ValidateRequestedCoverageTerms(terms); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(RequestedTermsDomain, terms)
}

func ValidateRequestedCoverageTerms(terms RequestedCoverageTermsV1) error {
	if terms.SchemaVersion != 1 || !validToken(terms.CoverageCategory, 128) ||
		(terms.BenefitKind != BenefitFixed && terms.BenefitKind != BenefitIndemnity) ||
		agentcommerce.ValidateAssetIdentityV1(terms.CoverageAsset) != nil ||
		validateAmount(terms.RequestedAggregatePayout, true) != nil || validateAmount(terms.RequestedPerClaim, true) != nil ||
		!sameAsset(terms.CoverageAsset, terms.RequestedAggregatePayout.Asset) ||
		!sameAsset(terms.CoverageAsset, terms.RequestedPerClaim.Asset) || terms.MaximumClaims == 0 || terms.MaximumClaims > MaxClaims ||
		ValidateClaimClosureCapacity(terms.RequestedClosureCapacity) != nil || terms.RequestedClosureCapacity.MaximumClaims != terms.MaximumClaims ||
		terms.RequestedCoverageStartsAtUnix == 0 || terms.RequestedCoverageStartsAtUnix >= terms.RequestedCoverageEndsAtUnix ||
		terms.RequestedCoverageEndsAtUnix > terms.RequestedClaimFilingEndsAtUnix || terms.MaximumReviewDeadlineSeconds == 0 ||
		terms.MaximumChallengeWindowSeconds == 0 || terms.MaximumNonterminalResolutionWindowSeconds == 0 ||
		terms.MaximumSuccessorDecisionWindowSeconds == 0 || terms.MaximumPayoutDeadlineSeconds == 0 ||
		terms.MaximumAdapterRecoveryWindowSeconds == 0 || agentcommerce.ValidateProfileRefV1(terms.ClaimTriggerProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(terms.ClaimEvidenceProfile) != nil || !validDigest(terms.SelectedClaimProfileDigest) ||
		agentcommerce.ValidateProfileRefV1(terms.SelectedPayoutAdapterProfile) != nil ||
		!sortedProfileRefs(terms.RequiredExtensions, MaxExtensions) || !sortedProfileRefs(terms.OptionalExtensions, MaxExtensions) {
		return errors.New("requested Guarantor coverage terms are invalid")
	}
	if comparison, _ := compareAmount(terms.RequestedPerClaim, terms.RequestedAggregatePayout); comparison > 0 {
		return errors.New("requested per-claim amount exceeds aggregate payout")
	}
	if err := ValidateClaimContinuationBudgetV1(terms.RequestedClosureCapacity,
		terms.MaximumReviewDeadlineSeconds, terms.MaximumChallengeWindowSeconds,
		terms.MaximumNonterminalResolutionWindowSeconds, terms.MaximumSuccessorDecisionWindowSeconds,
		terms.MaximumPayoutDeadlineSeconds, terms.MaximumAdapterRecoveryWindowSeconds); err != nil {
		return err
	}
	switch terms.SelectedAssuranceLevel {
	case AssuranceUnsecuredSigned:
		if terms.SelectedCollateralProfileDigest != "" {
			return errors.New("unsecured coverage selects collateral")
		}
	case AssuranceCollateralAttested, AssuranceIndependentlyEnforced:
		if !validDigest(terms.SelectedCollateralProfileDigest) {
			return errors.New("collateralized coverage lacks its exact profile digest")
		}
	default:
		return errors.New("Guarantor assurance level is invalid")
	}
	return nil
}

func ValidateClaimClosureCapacity(capacity ClaimClosureCapacityV1) error {
	// Every initial claim and every permitted revision consumes a distinct,
	// durably sequenced ingress action.  Reserving only one slot per claim can
	// create a perfectly valid history which can no longer be admitted or
	// closed.  Perform the multiplication with an explicit overflow guard.
	if capacity.MaximumClaimRevisionsPerClaim == 0 ||
		capacity.MaximumClaims > ^uint64(0)/capacity.MaximumClaimRevisionsPerClaim ||
		capacity.MaximumClaimIngressActions < capacity.MaximumClaims*capacity.MaximumClaimRevisionsPerClaim {
		return errors.New("claim closure capacity does not reserve every claim revision ingress action")
	}
	byteCeilings := []uint64{capacity.MaximumAdmittedClaimEnvelopeBytes, capacity.MaximumClaimIngressReceiptEnvelopeBytes,
		capacity.MaximumClaimIngressCutProofBytes, capacity.MaximumAcceptanceRequestEnvelopeBytes,
		capacity.MaximumAcceptanceReceiptEnvelopeBytes, capacity.MaximumActivationEvidenceEnvelopeBytes,
		capacity.MaximumNonActivationEvidenceEnvelopeBytes, capacity.MaximumCancellationReceiptEnvelopeBytes,
		capacity.MaximumClaimFilingCloseReceiptEnvelopeBytes, capacity.MaximumTerminalClaimSetEnvelopeBytes,
		capacity.MaximumExposureReleaseRequestBytes, capacity.MaximumExposureReleaseReceiptBytes,
		capacity.MaximumCoverageResolutionRequestBytes, capacity.MaximumCoverageResolutionEnvelopeBytes}
	for _, ceiling := range byteCeilings {
		if ceiling == 0 || ceiling > MaxCanonicalObjectBytes {
			return errors.New("claim closure capacity has an absent or oversized envelope ceiling")
		}
	}
	computedPairs := [][2]uint64{
		{capacity.ComputedWorstCaseAcceptanceRequestEnvelopeBytes, capacity.MaximumAcceptanceRequestEnvelopeBytes},
		{capacity.ComputedWorstCaseAcceptanceReceiptEnvelopeBytes, capacity.MaximumAcceptanceReceiptEnvelopeBytes},
		{capacity.ComputedWorstCaseActivationEvidenceEnvelopeBytes, capacity.MaximumActivationEvidenceEnvelopeBytes},
		{capacity.ComputedWorstCaseNonActivationEvidenceEnvelopeBytes, capacity.MaximumNonActivationEvidenceEnvelopeBytes},
		{capacity.ComputedWorstCaseCancellationReceiptEnvelopeBytes, capacity.MaximumCancellationReceiptEnvelopeBytes},
		{capacity.ComputedWorstCaseClaimFilingCloseReceiptEnvelopeBytes, capacity.MaximumClaimFilingCloseReceiptEnvelopeBytes},
		{capacity.ComputedWorstCaseTerminalClaimSetBytes, capacity.MaximumTerminalClaimSetEnvelopeBytes},
		{capacity.ComputedWorstCaseExposureReleaseRequestBytes, capacity.MaximumExposureReleaseRequestBytes},
		{capacity.ComputedWorstCaseExposureReleaseReceiptBytes, capacity.MaximumExposureReleaseReceiptBytes},
		{capacity.ComputedWorstCaseCoverageResolutionRequestBytes, capacity.MaximumCoverageResolutionRequestBytes},
		{capacity.ComputedWorstCaseCoverageResolutionEnvelopeBytes, capacity.MaximumCoverageResolutionEnvelopeBytes},
	}
	for _, pair := range computedPairs {
		if pair[0] == 0 || pair[0] != pair[1] {
			return errors.New("claim closure computed bound is absent or does not reserve its full envelope ceiling")
		}
	}
	if capacity.MaximumClaims == 0 || capacity.MaximumClaims > MaxClaims ||
		capacity.MaximumClaimIngressActions > MaxClaims*MaxClaimRevisions ||
		capacity.MaximumClaimRevisionsPerClaim == 0 || capacity.MaximumClaimRevisionsPerClaim > MaxClaimRevisions ||
		capacity.MaximumDecisionAdmissionsPerClaim == 0 || capacity.MaximumDecisionAdmissionsPerClaim > 512 ||
		capacity.MaximumClaimStateTransitionsPerClaim == 0 || capacity.MaximumClaimStateTransitionsPerClaim > 1024 ||
		capacity.MaximumChallengeRoundsPerClaim > MaximumContinuationRoundsV1 ||
		capacity.MaximumNonterminalRoundsPerClaim > MaximumContinuationRoundsV1 ||
		capacity.MaximumPayoutLinesPerClaim == 0 || capacity.MaximumPayoutLinesPerClaim > MaxPayoutLines ||
		capacity.MaximumClaimIngressReceiptEnvelopeBytes < capacity.MaximumAdmittedClaimEnvelopeBytes ||
		capacity.MaximumTerminalClaimSetEnvelopeBytes > capacity.MaximumExposureReleaseReceiptBytes ||
		capacity.MaximumExposureReleaseReceiptBytes > capacity.MaximumCoverageResolutionEnvelopeBytes {
		return errors.New("claim closure capacity is invalid or unbounded")
	}
	if agentcommerce.ValidateProfileRefV1(capacity.ContinuationBudgetProfile) != nil ||
		ValidateDeterministicClaimTerminalFallbackV1(capacity.TerminalFallback) != nil ||
		len(capacity.ContinuationBudgetEntries) == 0 || len(capacity.ContinuationBudgetEntries) > 4096 {
		return errors.New("claim closure continuation profile is invalid")
	}
	seen := make(map[string]struct{}, len(capacity.ContinuationBudgetEntries))
	for _, entry := range capacity.ContinuationBudgetEntries {
		if !validToken(entry.ProfileStateKey, 256) || entry.MaximumRemainingDecisionPathSeconds == 0 ||
			entry.MaximumRemainingClosureSeconds < entry.MaximumRemainingDecisionPathSeconds {
			return errors.New("claim closure continuation entry is invalid")
		}
		if _, exists := seen[entry.ProfileStateKey]; exists {
			return errors.New("claim closure continuation entry is duplicated")
		}
		seen[entry.ProfileStateKey] = struct{}{}
	}
	return nil
}

func QuoteRequestDigest(request AuthorizedCoverageQuoteRequestV1) (string, error) {
	if err := validateQuoteRequestShape(request); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(QuoteRequestDomain, request)
}

func VerifyQuoteRequest(request AuthorizedCoverageQuoteRequestV1, profile ServiceProfileV1, resolver AuthorityKeyResolver,
	underlyingResolver UnderlyingAgreementResolver, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	now time.Time) error {
	if err := ValidateServiceProfile(profile, now); err != nil || validateQuoteRequestShape(request) != nil {
		return errors.New("Guarantor quote request or service profile is invalid")
	}
	profileDigest, _ := ServiceProfileDigest(profile)
	body := request.Body
	if body.ServiceProfileDigest != profileDigest || body.GuarantorAgentID != profile.ProviderAgentID ||
		body.CreatedAtUnix < profile.CreatedAtUnix || body.ExpiresAtUnix > profile.ExpiresAtUnix ||
		uint64(now.UTC().Unix()) >= body.ExpiresAtUnix {
		return errors.New("Guarantor quote request is outside the selected service profile")
	}
	if !profileSupportsRequest(profile, request.RequestedTerms, body.SelectedDecisionProfile, body.MaximumFee) {
		return errors.New("Guarantor quote request selects an unsupported tuple")
	}
	if err := resolveAndVerifyCoveredUnderlyingAgreementV1(underlyingResolver, agreementVerifier,
		body.UnderlyingAgreementBodyDigest, body.CoveredPartyAgentID, body.GuarantorAgentID,
		body.CoveredObligationIDs, now); err != nil {
		return err
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-quote-request-body.v1", body)
	return ValidateAuthorizationSet(request.Authorizations, "coverage-quote-request", bodyDigest,
		"tos.service.agent-guarantor-quote-request-signature.v1", []string{body.RequesterAgentID}, resolver, now)
}

func validateQuoteRequestShape(request AuthorizedCoverageQuoteRequestV1) error {
	body := request.Body
	termsDigest, err := RequestedCoverageTermsDigest(request.RequestedTerms)
	if err != nil || body.SchemaVersion != 1 || !validID(body.RequestID) || !validDigest(body.ServiceIntentDigest) ||
		!validDigest(body.ServiceProfileDigest) || !validID(body.RequesterAgentID) || !validID(body.GuarantorAgentID) ||
		!validID(body.CoveredPartyAgentID) || !validID(body.BeneficiaryAgentID) || body.RequesterAgentID != body.CoveredPartyAgentID ||
		!sortedUnique(body.ClaimantSubjects, 64, validID) || !validDigest(body.UnderlyingAgreementBodyDigest) ||
		!sortedUnique(body.CoveredObligationIDs, 256, func(value string) bool { return validToken(value, 128) }) ||
		body.RequestedTermsDigest != termsDigest || validateAmount(body.MaximumFee, false) != nil ||
		body.SelectedAssuranceLevel != request.RequestedTerms.SelectedAssuranceLevel ||
		body.SelectedClaimProfileDigest != request.RequestedTerms.SelectedClaimProfileDigest ||
		body.SelectedCollateralProfileDigest != request.RequestedTerms.SelectedCollateralProfileDigest ||
		body.SelectedPayoutAdapterProfile != request.RequestedTerms.SelectedPayoutAdapterProfile ||
		agentcommerce.ValidateProfileRefV1(body.SelectedDecisionProfile) != nil ||
		body.PrivateInputManifestDigest != "" && !validDigest(body.PrivateInputManifestDigest) ||
		body.CreatedAtUnix == 0 || body.ExpiresAtUnix <= body.CreatedAtUnix || body.ExpiresAtUnix-body.CreatedAtUnix > 24*60*60 ||
		len(request.Authorizations) == 0 || len(request.Authorizations) > MaxAuthorizations {
		return errors.New("Guarantor quote request is invalid")
	}
	return nil
}

func profileSupportsRequest(profile ServiceProfileV1, terms RequestedCoverageTermsV1, decisionProfile agentcommerce.ProfileRefV1,
	maximumFee AtomicAmountV1) bool {
	capabilityFound := false
	for _, capability := range profile.CoverageCapabilities {
		if capability.Category != terms.CoverageCategory || !containsBenefit(capability.BenefitKinds, terms.BenefitKind) ||
			!containsAsset(capability.SupportedAssets, terms.CoverageAsset) ||
			terms.RequestedCoverageEndsAtUnix-terms.RequestedCoverageStartsAtUnix > capability.MaximumCoverageSeconds ||
			terms.RequestedClaimFilingEndsAtUnix-terms.RequestedCoverageEndsAtUnix > capability.MaximumClaimWindowSeconds ||
			!amountInRanges(terms.RequestedAggregatePayout, capability.CoverageRanges) ||
			!amountInRanges(maximumFee, capability.FeeRanges) {
			continue
		}
		capabilityFound = true
		break
	}
	if !capabilityFound || !profileRefsSubset(terms.RequiredExtensions, profile.RequiredExtensions) {
		return false
	}
	claimFound := false
	for _, claim := range profile.ClaimProfiles {
		digest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-claim-profile.v1", claim)
		if digest == terms.SelectedClaimProfileDigest && claim.TriggerProfile == terms.ClaimTriggerProfile &&
			claim.EvidenceProfile == terms.ClaimEvidenceProfile && claim.DecisionProfile == decisionProfile &&
			terms.MaximumClaims <= claim.MaximumClaims &&
			terms.RequestedClosureCapacity.MaximumClaimIngressActions <= claim.MaximumClaimIngressActions &&
			terms.RequestedClosureCapacity.MaximumClaimRevisionsPerClaim <= claim.MaximumClaimRevisionsPerClaim &&
			terms.RequestedClosureCapacity.MaximumDecisionAdmissionsPerClaim <= claim.MaximumDecisionAdmissionsPerClaim &&
			terms.RequestedClosureCapacity.MaximumClaimStateTransitionsPerClaim <= claim.MaximumClaimStateTransitionsPerClaim &&
			terms.RequestedClosureCapacity.MaximumChallengeRoundsPerClaim <= claim.MaximumChallengeRoundsPerClaim &&
			terms.RequestedClosureCapacity.MaximumNonterminalRoundsPerClaim <= claim.MaximumNonterminalRoundsPerClaim &&
			terms.RequestedClosureCapacity.MaximumPayoutLinesPerClaim <= claim.MaximumPayoutLinesPerClaim &&
			claim.ReviewDeadlineSeconds <= terms.MaximumReviewDeadlineSeconds &&
			claim.PayoutDeadlineSeconds <= terms.MaximumPayoutDeadlineSeconds {
			claimFound = true
			break
		}
	}
	if !claimFound {
		return false
	}
	if terms.SelectedAssuranceLevel != AssuranceUnsecuredSigned {
		found := false
		for _, collateral := range profile.CollateralProfiles {
			digest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-collateral-profile.v1", collateral)
			if digest == terms.SelectedCollateralProfileDigest && collateral.AssuranceLevel == terms.SelectedAssuranceLevel &&
				collateral.Asset == terms.CoverageAsset {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, adapter := range profile.PayoutAdapterProfiles {
		if adapter == terms.SelectedPayoutAdapterProfile {
			return true
		}
	}
	return false
}

func containsBenefit(values []BenefitKind, wanted BenefitKind) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsAsset(values []AssetIdentityV1, wanted AssetIdentityV1) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func amountInRanges(amount AtomicAmountV1, ranges []AtomicRangeV1) bool {
	for _, value := range ranges {
		if amount.Asset != value.Minimum.Asset || amount.Asset != value.Maximum.Asset {
			continue
		}
		minimum, minimumErr := compareAmount(amount, value.Minimum)
		maximum, maximumErr := compareAmount(amount, value.Maximum)
		if minimumErr == nil && maximumErr == nil && minimum >= 0 && maximum <= 0 {
			return true
		}
	}
	return false
}

func profileRefsSubset(wanted, available []ProfileRefV1) bool {
	for _, item := range wanted {
		found := false
		for _, candidate := range available {
			found = found || item == candidate
		}
		if !found {
			return false
		}
	}
	return true
}

func CoverageID(guarantorAgentID, quoteRequestDigest string) (string, error) {
	if !validID(guarantorAgentID) || !validDigest(quoteRequestDigest) {
		return "", errors.New("coverage identity input is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-coverage-id.v1", struct {
		GuarantorAgentID   string `json:"guarantor_agent_id"`
		QuoteRequestDigest string `json:"quote_request_digest"`
	}{guarantorAgentID, quoteRequestDigest})
}

func CoverageTermsDigest(terms CoverageTermsV1) (string, error) {
	if err := ValidateCoverageTerms(terms); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(CoverageTermsDomain, terms)
}

func ValidateCoverageTerms(terms CoverageTermsV1) error {
	if terms.SchemaVersion != 1 || !validDigest(terms.CoverageID) || terms.CoverageVersion == 0 ||
		terms.CoverageVersion == 1 && terms.PredecessorTermsDigest != "" ||
		terms.CoverageVersion > 1 && !validDigest(terms.PredecessorTermsDigest) || !validDigest(terms.ServiceProfileDigest) ||
		!validDigest(terms.QuoteRequestDigest) || !validID(terms.GuarantorAgentID) || !validID(terms.CoveredPartyAgentID) ||
		!validID(terms.BeneficiaryAgentID) || !sortedUnique(terms.PermittedClaimantSubjects, 64, validID) ||
		!validDigest(terms.UnderlyingAgreementBodyDigest) || !sortedUnique(terms.CoveredObligationIDs, 256, func(v string) bool { return validToken(v, 128) }) ||
		!validToken(terms.CoverageCategory, 128) || (terms.BenefitKind != BenefitFixed && terms.BenefitKind != BenefitIndemnity) ||
		agentcommerce.ValidateAssetIdentityV1(terms.CoverageAsset) != nil || validateAmount(terms.MaximumAggregatePayout, true) != nil ||
		validateAmount(terms.MaximumPerClaim, true) != nil || !sameAsset(terms.CoverageAsset, terms.MaximumAggregatePayout.Asset) ||
		!sameAsset(terms.CoverageAsset, terms.MaximumPerClaim.Asset) || terms.MaximumClaims == 0 || terms.MaximumClaims > MaxClaims ||
		ValidateClaimClosureCapacity(terms.ClaimClosureCapacity) != nil || terms.ClaimClosureCapacity.MaximumClaims != terms.MaximumClaims ||
		terms.CoverageStartsAtUnix == 0 || terms.CoverageStartsAtUnix >= terms.CoverageEndsAtUnix ||
		terms.CoverageEndsAtUnix > terms.ClaimFilingEndsAtUnix || terms.ReviewDeadlineSeconds == 0 ||
		ValidateCoverageNonActivationReasonRulesV1(terms.NonActivationReasonRules) != nil ||
		terms.ChallengeWindowSeconds == 0 || terms.PayoutDeadlineSeconds == 0 || terms.AdapterRecoveryWindowSeconds == 0 ||
		terms.TerminalResolutionDeadlineUnix < terms.ClaimFilingEndsAtUnix || !validDigest(terms.CoverageStateDomainDigest) ||
		!validDigest(terms.SelectedClaimProfileDigest) || agentcommerce.ValidateProfileRefV1(terms.SelectedPayoutAdapterProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(terms.CoverageOperationAdapterProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(terms.ClaimOperationAdapterProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(terms.ExposureOperationAdapterProfile) != nil ||
		ValidateStageActionAuthorityBindingV1(terms.StageActionAuthorityBinding) != nil ||
		agentcommerce.ValidateProfileRefV1(terms.ClaimTriggerProfile) != nil || agentcommerce.ValidateProfileRefV1(terms.ClaimEvidenceProfile) != nil ||
		!sortedProfileRefs(terms.ClaimantAuthorizationProfiles, 64) ||
		agentcommerce.ValidateProfileRefV1(terms.ClaimIngressProfile) != nil ||
		QuorumThresholdMustFailV1(terms.ClaimIngressAuthorityQuorumRule, terms.ClaimIngressAuthoritySubjects) ||
		agentcommerce.ValidateProfileRefV1(terms.ClaimAdmissionProfile) != nil ||
		QuorumThresholdMustFailV1(terms.ClaimAdmissionQuorumRule, terms.ClaimAdmissionAuthoritySubjects) ||
		agentcommerce.ValidateProfileRefV1(terms.DecisionAdmissionProfile) != nil ||
		QuorumThresholdMustFailV1(terms.DecisionAdmissionQuorumRule, terms.DecisionAdmissionAuthoritySubjects) ||
		agentcommerce.ValidateProfileRefV1(terms.DecisionProfile) != nil ||
		QuorumThresholdMustFailV1(terms.DecisionQuorumRule, terms.DecisionAuthoritySubjects) ||
		agentcommerce.ValidateProfileRefV1(terms.AcceptanceAuthorityProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(terms.LifecycleAuthorizationProfile) != nil ||
		agentcommerce.ValidateConditionalSettlementTemplateV1(terms.PayoutTemplate) != nil ||
		!sortedUnique(terms.PremiumObligationIDs, 64, func(v string) bool { return validToken(v, 128) }) ||
		!sortedProfileRefs(terms.RequiredExtensions, MaxExtensions) || !sortedProfileRefs(terms.OptionalExtensions, MaxExtensions) {
		return errors.New("Guarantor coverage terms are invalid")
	}
	if comparison, _ := compareAmount(terms.MaximumPerClaim, terms.MaximumAggregatePayout); comparison > 0 ||
		terms.PayoutTemplate.PayerAgentID != terms.GuarantorAgentID || terms.PayoutTemplate.PayeeAgentID != terms.BeneficiaryAgentID ||
		terms.PayoutTemplate.Asset != terms.CoverageAsset || terms.PayoutTemplate.MaximumPerInstance != terms.MaximumPerClaim ||
		terms.PayoutTemplate.MaximumAggregateAmount != terms.MaximumAggregatePayout ||
		terms.PayoutTemplate.SettlementAdapterProfile != terms.SelectedPayoutAdapterProfile {
		return errors.New("Guarantor payout template differs from coverage bounds")
	}
	if err := ValidateClaimContinuationBudgetV1(terms.ClaimClosureCapacity, terms.ReviewDeadlineSeconds,
		terms.ChallengeWindowSeconds, terms.NonterminalResolutionWindowSeconds, terms.SuccessorDecisionWindowSeconds,
		terms.PayoutDeadlineSeconds, terms.AdapterRecoveryWindowSeconds); err != nil {
		return err
	}
	switch terms.SelectedAssuranceLevel {
	case AssuranceUnsecuredSigned:
		if terms.SelectedCollateralProfileDigest != "" || terms.CollateralObligationID != "" || terms.CollateralTerms != nil {
			return errors.New("unsecured terms carry collateral")
		}
	case AssuranceCollateralAttested, AssuranceIndependentlyEnforced:
		if !validDigest(terms.SelectedCollateralProfileDigest) || !validToken(terms.CollateralObligationID, 128) ||
			terms.CollateralTerms == nil || ValidateCollateralTermsV1(*terms.CollateralTerms) != nil ||
			terms.CollateralTerms.SelectedCollateralProfileDigest != terms.SelectedCollateralProfileDigest ||
			terms.CollateralTerms.AssuranceLevel != terms.SelectedAssuranceLevel || terms.CollateralTerms.Asset != terms.CoverageAsset {
			return errors.New("collateralized terms lack collateral binding")
		}
	default:
		return errors.New("Guarantor assurance level is invalid")
	}
	if terms.SelectedAssuranceLevel == AssuranceIndependentlyEnforced {
		if terms.OperationalIndependenceTerms == nil || ValidateOperationalIndependenceTermsV1(*terms.OperationalIndependenceTerms) != nil {
			return errors.New("independently enforced coverage lacks frozen control evidence terms")
		}
		stageDigest, err := StageActionAuthorityBindingDigestV1(terms.StageActionAuthorityBinding)
		if err != nil || terms.OperationalIndependenceTerms.StageActionAuthorityBindingDigest != stageDigest ||
			terms.OperationalIndependenceTerms.CoverageOperationAdapterProfile != terms.CoverageOperationAdapterProfile ||
			terms.OperationalIndependenceTerms.ClaimOperationAdapterProfile != terms.ClaimOperationAdapterProfile ||
			terms.OperationalIndependenceTerms.ExposureOperationAdapterProfile != terms.ExposureOperationAdapterProfile {
			return errors.New("operational-independence terms do not bind the selected operation authorities")
		}
	} else if terms.OperationalIndependenceTerms != nil {
		return errors.New("non-independent coverage carries operational-independence terms")
	}
	return nil
}

// ValidateCoverageTermsAgainstServiceProfile prevents a provider coordinator
// from signing terms which substitute claimant or decision authorization after
// the requester selected the released claim profile.
func ValidateCoverageTermsAgainstServiceProfile(terms CoverageTermsV1, profile ServiceProfileV1) error {
	if ValidateCoverageTerms(terms) != nil {
		return errors.New("Guarantor terms are invalid")
	}
	for _, claimProfile := range profile.ClaimProfiles {
		digest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-claim-profile.v1", claimProfile)
		if digest == terms.SelectedClaimProfileDigest {
			if terms.ClaimTriggerProfile != claimProfile.TriggerProfile || terms.ClaimEvidenceProfile != claimProfile.EvidenceProfile ||
				!equalProfileRefs(terms.ClaimantAuthorizationProfiles, claimProfile.ClaimantAuthorizationProfiles) ||
				terms.ClaimIngressProfile != claimProfile.IngressProfile ||
				!equalStrings(terms.ClaimIngressAuthoritySubjects, claimProfile.IngressAuthoritySubjects) ||
				terms.ClaimIngressAuthorityQuorumRule != claimProfile.IngressAuthorityQuorumRule ||
				terms.ClaimAdmissionProfile != claimProfile.AdmissionProfile ||
				!equalStrings(terms.ClaimAdmissionAuthoritySubjects, claimProfile.AdmissionAuthoritySubjects) ||
				terms.ClaimAdmissionQuorumRule != claimProfile.AdmissionQuorumRule ||
				terms.DecisionAdmissionProfile != claimProfile.DecisionAdmissionProfile ||
				!equalStrings(terms.DecisionAdmissionAuthoritySubjects, claimProfile.DecisionAdmissionAuthoritySubjects) ||
				terms.DecisionAdmissionQuorumRule != claimProfile.DecisionAdmissionQuorumRule ||
				terms.DecisionProfile != claimProfile.DecisionProfile ||
				terms.ClaimClosureCapacity.ContinuationBudgetProfile != claimProfile.ContinuationBudgetProfile ||
				!claimProfilePermitsFallbackV1(claimProfile, terms.ClaimClosureCapacity.TerminalFallback) ||
				!claimProfileCapacityContainsV1(claimProfile, terms.ClaimClosureCapacity) ||
				terms.ReviewDeadlineSeconds > claimProfile.ReviewDeadlineSeconds ||
				terms.NonterminalResolutionWindowSeconds > claimProfile.MaximumNonterminalResolutionWindowSeconds ||
				terms.SuccessorDecisionWindowSeconds > claimProfile.MaximumSuccessorDecisionWindowSeconds ||
				terms.PayoutDeadlineSeconds > claimProfile.PayoutDeadlineSeconds ||
				terms.LifecycleAuthorizationProfile != profile.LifecycleAuthorizationProfile {
				return errors.New("Guarantor terms substitute the selected claim authorization profile")
			}
			if terms.SelectedAssuranceLevel == AssuranceUnsecuredSigned {
				return nil
			}
			for _, collateralProfile := range profile.CollateralProfiles {
				collateralDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-collateral-profile.v1", collateralProfile)
				if collateralDigest == terms.SelectedCollateralProfileDigest &&
					containsString(collateralProfile.CompatibleClaimProfileDigests, digest) && terms.CollateralTerms != nil &&
					terms.CollateralTerms.CustodyAdapterProfile == collateralProfile.CustodyAdapterProfile &&
					equalCanonical(terms.CollateralTerms.CollateralControlDisclosure, collateralProfile.CollateralControlDisclosure) &&
					terms.CollateralTerms.MaximumEvidenceAgeSeconds <= collateralProfile.MaximumEvidenceAgeSeconds &&
					terms.CollateralTerms.ExclusiveAllocationRequired == collateralProfile.ExclusiveAllocationRequired {
					maximum, okMaximum := new(big.Int).SetString(terms.MaximumAggregatePayout.AmountAtomic, 10)
					allocated, okAllocated := new(big.Int).SetString(terms.CollateralTerms.Amount.AmountAtomic, 10)
					if !okMaximum || !okAllocated {
						return errors.New("Guarantor collateral amount is malformed")
					}
					required := new(big.Int).Mul(maximum, new(big.Int).SetUint64(collateralProfile.MinimumCollateralizationPPM))
					required.Add(required, big.NewInt(999_999)).Quo(required, big.NewInt(1_000_000))
					if allocated.Cmp(required) < 0 {
						return errors.New("Guarantor collateral is below the authenticated profile minimum")
					}
					if terms.SelectedAssuranceLevel == AssuranceIndependentlyEnforced &&
						(terms.CollateralTerms.IndependentExecutionProfile == nil || collateralProfile.IndependentExecutionProfile == nil ||
							*terms.CollateralTerms.IndependentExecutionProfile != *collateralProfile.IndependentExecutionProfile ||
							!equalStrings(terms.CollateralTerms.IndependentExecutionAuthoritySubjects, collateralProfile.IndependentExecutionAuthoritySubjects) ||
							terms.CollateralTerms.IndependentExecutionQuorumRule != collateralProfile.IndependentExecutionQuorumRule) {
						return errors.New("Guarantor independently enforceable collateral substitutes its execution authority")
					}
					return nil
				}
			}
			return errors.New("Guarantor terms select an incompatible collateral profile")
		}
	}
	return errors.New("Guarantor terms select an unknown claim profile")
}

func claimProfilePermitsFallbackV1(profile ClaimProfileV1, selected DeterministicClaimTerminalFallbackV1) bool {
	selectedDigest, err := DeterministicClaimTerminalFallbackDigestV1(selected)
	if err != nil {
		return false
	}
	for _, candidate := range profile.PermittedTerminalFallbacks {
		digest, digestErr := DeterministicClaimTerminalFallbackDigestV1(candidate)
		if digestErr == nil && digest == selectedDigest && equalCanonical(candidate, selected) {
			return true
		}
	}
	return false
}

func claimProfileCapacityContainsV1(profile ClaimProfileV1, capacity ClaimClosureCapacityV1) bool {
	return capacity.MaximumClaims <= profile.MaximumClaims &&
		capacity.MaximumClaimIngressActions <= profile.MaximumClaimIngressActions &&
		capacity.MaximumClaimRevisionsPerClaim <= profile.MaximumClaimRevisionsPerClaim &&
		capacity.MaximumDecisionAdmissionsPerClaim <= profile.MaximumDecisionAdmissionsPerClaim &&
		capacity.MaximumClaimStateTransitionsPerClaim <= profile.MaximumClaimStateTransitionsPerClaim &&
		capacity.MaximumChallengeRoundsPerClaim <= profile.MaximumChallengeRoundsPerClaim &&
		capacity.MaximumNonterminalRoundsPerClaim <= profile.MaximumNonterminalRoundsPerClaim &&
		capacity.MaximumPayoutLinesPerClaim <= profile.MaximumPayoutLinesPerClaim &&
		capacity.MaximumAdmittedClaimEnvelopeBytes <= profile.MaximumAdmittedClaimEnvelopeBytes &&
		capacity.MaximumClaimIngressReceiptEnvelopeBytes <= profile.MaximumClaimIngressReceiptEnvelopeBytes &&
		capacity.MaximumClaimIngressCutProofBytes <= profile.MaximumClaimIngressCutProofBytes &&
		capacity.MaximumAcceptanceRequestEnvelopeBytes <= profile.MaximumAcceptanceRequestEnvelopeBytes &&
		capacity.MaximumAcceptanceReceiptEnvelopeBytes <= profile.MaximumAcceptanceReceiptEnvelopeBytes &&
		capacity.MaximumActivationEvidenceEnvelopeBytes <= profile.MaximumActivationEvidenceEnvelopeBytes &&
		capacity.MaximumNonActivationEvidenceEnvelopeBytes <= profile.MaximumNonActivationEvidenceEnvelopeBytes &&
		capacity.MaximumCancellationReceiptEnvelopeBytes <= profile.MaximumCancellationReceiptEnvelopeBytes &&
		capacity.MaximumClaimFilingCloseReceiptEnvelopeBytes <= profile.MaximumClaimFilingCloseReceiptEnvelopeBytes &&
		capacity.MaximumTerminalClaimSetEnvelopeBytes <= profile.MaximumTerminalClaimSetEnvelopeBytes &&
		capacity.MaximumExposureReleaseRequestBytes <= profile.MaximumExposureReleaseRequestBytes &&
		capacity.MaximumExposureReleaseReceiptBytes <= profile.MaximumExposureReleaseReceiptBytes &&
		capacity.MaximumCoverageResolutionRequestBytes <= profile.MaximumCoverageResolutionRequestBytes &&
		capacity.MaximumCoverageResolutionEnvelopeBytes <= profile.MaximumCoverageResolutionEnvelopeBytes
}

func equalProfileRefs(left, right []ProfileRefV1) bool {
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

func FirmOfferDigest(offer AuthorizedFirmCoverageOfferV1) (string, error) {
	if err := validateFirmOfferShape(offer); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(FirmOfferDomain, offer)
}

func VerifyFirmOffer(offer AuthorizedFirmCoverageOfferV1, request AuthorizedCoverageQuoteRequestV1,
	agreement agentcommerce.AgentAgreementBody, resolver AuthorityKeyResolver,
	publicationResolver agentcommerce.AgentOperationAuthorityResolver, underlyingResolver UnderlyingAgreementResolver,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, now time.Time) error {
	if validateFirmOfferShape(offer) != nil || agentcommerce.ValidateAgreementBody(agreement) != nil || publicationResolver == nil {
		return errors.New("firm Guarantor offer or Agreement is invalid")
	}
	profile, err := ResolveServiceProfileArtifactV1(offer.ServiceProfileArtifact, publicationResolver, now)
	if err != nil {
		return err
	}
	if err := ValidateCoverageTermsAgainstServiceProfile(offer.CoverageTerms, profile); err != nil {
		return err
	}
	if err := VerifyQuoteRequest(request, profile, resolver, underlyingResolver, agreementVerifier, now); err != nil {
		return err
	}
	agreementDigest, _ := agentcommerce.AgreementBodyDigest(agreement)
	requestDigest, _ := QuoteRequestDigest(request)
	termsDigest, _ := CoverageTermsDigest(offer.CoverageTerms)
	profileDigest, _ := ServiceProfileDigest(profile)
	body := offer.Body
	embeddedRequestDigest, _ := QuoteRequestDigest(offer.AuthorizedQuoteRequest)
	if body.CoverageAgreementBodyDigest != agreementDigest || body.QuoteRequestDigest != requestDigest ||
		embeddedRequestDigest != requestDigest ||
		body.CoverageTermsDigest != termsDigest || body.ServiceProfileDigest != request.Body.ServiceProfileDigest ||
		body.ServiceProfileDigest != profileDigest || body.ServiceIntentDigest != offer.ServiceProfileArtifact.SelectedServiceIntentOperationDigest ||
		body.GuarantorAgentID != request.Body.GuarantorAgentID || body.CoveredPartyAgentID != request.Body.CoveredPartyAgentID ||
		body.BeneficiaryAgentID != request.Body.BeneficiaryAgentID || body.CoverageID != offer.CoverageTerms.CoverageID ||
		body.CoverageVersion != offer.CoverageTerms.CoverageVersion || body.UnderlyingAgreementBodyDigest != request.Body.UnderlyingAgreementBodyDigest ||
		!equalStrings(body.CoveredObligationIDs, request.Body.CoveredObligationIDs) || body.CoverageObligationID == "" ||
		!equalStrings(body.PremiumObligationIDs, offer.CoverageTerms.PremiumObligationIDs) ||
		body.CollateralObligationID != offer.CoverageTerms.CollateralObligationID ||
		body.ValidFromUnix > uint64(now.UTC().Unix()) || uint64(now.UTC().Unix()) >= body.AcceptByUnix {
		return errors.New("firm Guarantor offer binding is invalid")
	}
	obligations := make(map[string]agentcommerce.AgreementObligation, len(agreement.Obligations))
	for _, obligation := range agreement.Obligations {
		obligations[obligation.ObligationID] = obligation
	}
	referencedObligations := append([]string{body.CoverageObligationID, body.PayoutTemplateObligationID}, body.PremiumObligationIDs...)
	if body.CollateralObligationID != "" {
		referencedObligations = append(referencedObligations, body.CollateralObligationID)
	}
	for _, obligationID := range referencedObligations {
		if _, found := obligations[obligationID]; !found {
			return errors.New("firm Guarantor offer references an absent Agreement obligation")
		}
	}
	expectedTargets := make(map[string]string)
	var expectedProfile agentcommerce.ProfileRefV1
	for _, predicate := range agreement.AuthorizationPredicates {
		if predicate.AuthoritySubject.SubjectIdentifier != body.GuarantorAgentID {
			continue
		}
		profile := agentcommerce.ProfileRefV1{ProfileURI: predicate.EvidenceProfileURI,
			ProfileVersion: uint64(predicate.EvidenceProfileVersion), ProfileDigest: predicate.EvidenceProfileDigest}
		if expectedProfile.ProfileURI != "" && expectedProfile != profile {
			return errors.New("firm Guarantor offer Agreement uses conflicting Guarantor evidence profiles")
		}
		expectedProfile = profile
		expectedTargets[predicate.PredicateID] = predicate.EvidenceTargetProjectionDigest
	}
	if expectedProfile != body.GuarantorEvidenceProfile || len(expectedTargets) != len(body.GuarantorPredicateTargets) {
		return errors.New("firm Guarantor offer predicate target set is incomplete")
	}
	for _, target := range body.GuarantorPredicateTargets {
		if expectedTargets[target.PredicateID] != target.TargetProjectionDigest {
			return errors.New("firm Guarantor offer predicate target is not body-bound")
		}
	}
	if err := VerifyExposureAdmissionReceiptV1(offer.ExposureAdmissionReceipt, resolver, now); err != nil {
		return err
	}
	receiptDigest, _ := ExposureAdmissionReceiptDigestV1(offer.ExposureAdmissionReceipt)
	descriptor := offer.ExposureAdmissionReceipt.Descriptor
	if receiptDigest != body.ExposureAdmissionReceiptDigest || descriptor.CoverageAgreementBodyDigest != agreementDigest ||
		descriptor.CoverageTermsDigest != termsDigest || descriptor.QuoteRequestDigest != requestDigest ||
		descriptor.ServiceProfileDigest != body.ServiceProfileDigest || descriptor.ReservedExposure != offer.ExposureAdmissionReceipt.Body.ReservedExposure ||
		offer.ExposureAdmissionReceipt.Body.ReservationID != body.ReservationID ||
		descriptor.GuarantorAgentID != body.GuarantorAgentID || descriptor.CoverageID != offer.CoverageTerms.CoverageID ||
		descriptor.CoverageVersion != offer.CoverageTerms.CoverageVersion ||
		descriptor.ReservationScope.GuarantorAgentID != body.GuarantorAgentID ||
		descriptor.ReservationScope.CoverageAgreementBodyDigest != agreementDigest ||
		descriptor.ReservationScope.CoverageObligationID != body.CoverageObligationID ||
		descriptor.ReservationScope.CoverageAsset != offer.CoverageTerms.CoverageAsset ||
		descriptor.ReservationScope.SelectedAssuranceLevel != offer.CoverageTerms.SelectedAssuranceLevel ||
		descriptor.ReservationScope.MaximumAggregatePayout != offer.CoverageTerms.MaximumAggregatePayout ||
		descriptor.ReservedExposure != offer.CoverageTerms.MaximumAggregatePayout {
		return errors.New("firm Guarantor offer exposure receipt is not bound to the offer")
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-firm-offer-body.v1", body)
	return ValidateAuthorizationSet(offer.Authorizations, "firm-coverage-offer", bodyDigest,
		"tos.service.agent-guarantor-firm-offer-signature.v1", []string{body.GuarantorAgentID}, resolver, now)
}

func validateFirmOfferShape(offer AuthorizedFirmCoverageOfferV1) error {
	body := offer.Body
	termsDigest, err := CoverageTermsDigest(offer.CoverageTerms)
	requestDigest, requestErr := QuoteRequestDigest(offer.AuthorizedQuoteRequest)
	receiptDigest, receiptErr := ExposureAdmissionReceiptDigestV1(offer.ExposureAdmissionReceipt)
	if err != nil || body.SchemaVersion != 1 || !validDigest(body.OfferID) || body.OfferVersion != 1 || body.PredecessorOfferDigest != "" ||
		!validDigest(body.CoverageAgreementBodyDigest) ||
		requestErr != nil || receiptErr != nil || body.QuoteRequestDigest != requestDigest || !validDigest(body.ServiceProfileDigest) ||
		!validDigest(body.ServiceIntentDigest) || !validDigest(body.CoverageID) || body.CoverageVersion == 0 ||
		body.CoverageTermsDigest != termsDigest || body.ExposureAdmissionReceiptDigest != receiptDigest ||
		!validID(body.GuarantorAgentID) || !validID(body.CoveredPartyAgentID) || !validID(body.BeneficiaryAgentID) ||
		!validDigest(body.UnderlyingAgreementBodyDigest) || !sortedUnique(body.CoveredObligationIDs, 256, func(v string) bool { return validToken(v, 128) }) ||
		!validToken(body.CoverageObligationID, 128) ||
		!sortedUnique(body.PremiumObligationIDs, 64, func(v string) bool { return validToken(v, 128) }) ||
		body.CollateralObligationID != "" && !validToken(body.CollateralObligationID, 128) ||
		!validToken(body.PayoutTemplateObligationID, 128) || len(body.GuarantorPredicateTargets) == 0 ||
		agentcommerce.ValidateProfileRefV1(body.GuarantorEvidenceProfile) != nil || !validDigest(body.ReservationID) ||
		body.MaxAcceptances != 1 || body.WithdrawalPolicy != "forbidden" ||
		!validDigest(body.ExposureAdmissionReceiptDigest) || body.ValidFromUnix == 0 || body.ValidFromUnix >= body.AcceptByUnix ||
		body.AcceptanceProcessingGraceSeconds == 0 || body.AcceptByUnix > ^uint64(0)-body.AcceptanceProcessingGraceSeconds ||
		body.AcceptByUnix+body.AcceptanceProcessingGraceSeconds > offer.ExposureAdmissionReceipt.Body.ExpiresAtUnix ||
		body.AcceptByUnix >= body.ExpiresAtUnix ||
		!sortedProfileRefs(body.RequiredExtensions, MaxExtensions) || !sortedProfileRefs(body.OptionalExtensions, MaxExtensions) ||
		len(offer.Authorizations) == 0 || len(offer.Authorizations) > MaxAuthorizations {
		return errors.New("firm Guarantor offer is invalid")
	}
	var prior []byte
	for _, target := range body.GuarantorPredicateTargets {
		if !validToken(target.PredicateID, 128) || !validDigest(target.TargetProjectionDigest) {
			return errors.New("firm Guarantor predicate target is invalid")
		}
		encoded, encodeErr := guarantorCodec.Marshal(target)
		if encodeErr != nil || prior != nil && string(prior) >= string(encoded) {
			return errors.New("firm Guarantor predicate targets are unsorted or duplicated")
		}
		prior = encoded
	}
	return nil
}
