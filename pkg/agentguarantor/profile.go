package agentguarantor

import (
	"errors"
	"net/url"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func ServiceProfileDigest(profile ServiceProfileV1) (string, error) {
	if err := ValidateServiceProfile(profile, time.Unix(int64(profile.CreatedAtUnix), 0).UTC()); err != nil {
		return "", err
	}
	return guarantorCodec.Digest(ServiceProfileDomain, profile)
}

func ValidateServiceProfile(profile ServiceProfileV1, now time.Time) error {
	if profile.SchemaVersion != 1 || !validID(profile.ProfileID) || profile.Revision == 0 ||
		profile.Revision == 1 && profile.PredecessorProfileDigest != "" ||
		profile.Revision > 1 && !validDigest(profile.PredecessorProfileDigest) || !validID(profile.ProviderAgentID) ||
		!validDigest(profile.AuthorityDomainDigest) || len(profile.CoverageCapabilities) == 0 ||
		len(profile.CoverageCapabilities) > MaxCoverageCapabilities || len(profile.ClaimProfiles) == 0 ||
		len(profile.ClaimProfiles) > MaxClaimProfiles || len(profile.CollateralProfiles) > MaxCollateralProfiles ||
		len(profile.PayoutAdapterProfiles) == 0 || len(profile.PayoutAdapterProfiles) > MaxPayoutAdapters ||
		!validID(profile.ExposureAuthorityID) || agentcommerce.ValidateProfileRefV1(profile.ExposureAuthorizationProfile) != nil ||
		!validID(profile.LifecycleAuthorityID) || agentcommerce.ValidateProfileRefV1(profile.LifecycleAuthorizationProfile) != nil ||
		profile.PolicyRevision == 0 || !validUnixTimestampV1(profile.CreatedAtUnix) ||
		!validUnixTimestampV1(profile.ExpiresAtUnix) || profile.ExpiresAtUnix <= profile.CreatedAtUnix ||
		profile.ExpiresAtUnix-profile.CreatedAtUnix > uint64((90*24*time.Hour)/time.Second) ||
		profile.CreatedAtUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) || uint64(now.UTC().Unix()) >= profile.ExpiresAtUnix {
		return errors.New("Guarantor service profile is invalid")
	}
	if err := validateAdmissionLimits(profile.AdmissionLimits); err != nil || validateEndpoints(profile.Endpoints) != nil {
		return errors.New("Guarantor service admission limits or endpoints are invalid")
	}
	previousCategory := ""
	for _, capability := range profile.CoverageCapabilities {
		if capability.Category <= previousCategory || validateCoverageCapability(capability) != nil {
			return errors.New("Guarantor coverage capabilities are unsorted or invalid")
		}
		previousCategory = capability.Category
	}
	if err := validateClaimProfiles(profile.ClaimProfiles); err != nil || validateCollateralProfiles(profile.CollateralProfiles, profile.ClaimProfiles) != nil ||
		!sortedProfileRefs(profile.PayoutAdapterProfiles, MaxPayoutAdapters) ||
		!sortedProfileRefs(profile.RequiredExtensions, MaxExtensions) || !sortedProfileRefs(profile.OptionalExtensions, MaxExtensions) {
		return errors.New("Guarantor nested profiles are invalid")
	}
	return nil
}

func validateCoverageCapability(capability CoverageCapabilityV1) error {
	if !validToken(capability.Category, 128) || len(capability.BenefitKinds) == 0 || len(capability.BenefitKinds) > 2 ||
		len(capability.SupportedUnderlyingProfiles) == 0 || !sortedProfileRefs(capability.SupportedUnderlyingProfiles, 64) ||
		len(capability.SupportedClaimProfiles) == 0 || !sortedProfileRefs(capability.SupportedClaimProfiles, 64) ||
		len(capability.SupportedAssets) == 0 || len(capability.SupportedAssets) > 32 ||
		len(capability.CoverageRanges) == 0 || len(capability.CoverageRanges) > 32 ||
		len(capability.FeeRanges) == 0 || len(capability.FeeRanges) > 32 ||
		capability.MaximumCoverageSeconds == 0 || capability.MaximumClaimWindowSeconds == 0 ||
		agentcommerce.ValidatePolicyRefV1(capability.JurisdictionPolicy) != nil {
		return errors.New("Guarantor coverage capability is invalid")
	}
	previousBenefit := BenefitKind("")
	for _, benefit := range capability.BenefitKinds {
		if benefit != BenefitFixed && benefit != BenefitIndemnity || benefit <= previousBenefit {
			return errors.New("Guarantor benefit kinds are invalid")
		}
		previousBenefit = benefit
	}
	previousAsset := ""
	for _, asset := range capability.SupportedAssets {
		key := asset.AssetNamespace + "\x00" + asset.AssetIdentifier + "\x00" + asset.Unit
		if key <= previousAsset || agentcommerce.ValidateAssetIdentityV1(asset) != nil {
			return errors.New("Guarantor capability assets are invalid")
		}
		previousAsset = key
	}
	for _, value := range append(append([]AtomicRangeV1(nil), capability.CoverageRanges...), capability.FeeRanges...) {
		if agentcommerce.ValidateAtomicAmountRangeV1(value) != nil {
			return errors.New("Guarantor capability amount range is invalid")
		}
	}
	return nil
}

func validateClaimProfiles(profiles []ClaimProfileV1) error {
	previous := ""
	for _, profile := range profiles {
		digest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-profile.v1", profile)
		if err != nil || digest <= previous || !validID(profile.ProfileID) || profile.ProfileVersion == 0 ||
			profile.ProfileVersion == 1 && profile.PredecessorProfileDigest != "" ||
			profile.ProfileVersion > 1 && !validDigest(profile.PredecessorProfileDigest) ||
			agentcommerce.ValidateProfileRefV1(profile.TriggerProfile) != nil || agentcommerce.ValidateProfileRefV1(profile.EvidenceProfile) != nil ||
			!sortedProfileRefs(profile.ClaimantAuthorizationProfiles, 32) || agentcommerce.ValidateProfileRefV1(profile.IngressProfile) != nil ||
			QuorumThresholdMustFailV1(profile.IngressAuthorityQuorumRule, profile.IngressAuthoritySubjects) ||
			agentcommerce.ValidateProfileRefV1(profile.AdmissionProfile) != nil || agentcommerce.ValidateProfileRefV1(profile.DecisionAdmissionProfile) != nil ||
			QuorumThresholdMustFailV1(profile.AdmissionQuorumRule, profile.AdmissionAuthoritySubjects) ||
			QuorumThresholdMustFailV1(profile.DecisionAdmissionQuorumRule, profile.DecisionAdmissionAuthoritySubjects) ||
			agentcommerce.ValidateProfileRefV1(profile.DecisionProfile) != nil || profile.MaximumClaims == 0 || profile.MaximumClaims > MaxClaims ||
			profile.MaximumClaimIngressActions < profile.MaximumClaims || profile.MaximumClaimRevisionsPerClaim == 0 ||
			profile.MaximumClaims > profile.MaximumClaimIngressActions/profile.MaximumClaimRevisionsPerClaim ||
			profile.MaximumClaimRevisionsPerClaim > MaxClaimRevisions || profile.MaximumDecisionAdmissionsPerClaim == 0 ||
			profile.MaximumClaimStateTransitionsPerClaim == 0 || profile.MaximumChallengeRoundsPerClaim > MaximumContinuationRoundsV1 ||
			profile.MaximumNonterminalRoundsPerClaim > MaximumContinuationRoundsV1 || profile.MaximumPayoutLinesPerClaim == 0 ||
			profile.MaximumPayoutLinesPerClaim > MaxPayoutLines || profile.MaximumAdmittedClaimEnvelopeBytes == 0 ||
			profile.MaximumClaimIngressReceiptEnvelopeBytes == 0 || profile.MaximumClaimIngressCutProofBytes == 0 ||
			profile.MaximumAcceptanceRequestEnvelopeBytes == 0 || profile.MaximumAcceptanceReceiptEnvelopeBytes == 0 ||
			profile.MaximumActivationEvidenceEnvelopeBytes == 0 || profile.MaximumNonActivationEvidenceEnvelopeBytes == 0 ||
			profile.MaximumCancellationReceiptEnvelopeBytes == 0 || profile.MaximumClaimFilingCloseReceiptEnvelopeBytes == 0 ||
			profile.MaximumTerminalClaimSetEnvelopeBytes == 0 || profile.MaximumExposureReleaseRequestBytes == 0 ||
			profile.MaximumExposureReleaseReceiptBytes == 0 || profile.MaximumCoverageResolutionRequestBytes == 0 ||
			profile.MaximumCoverageResolutionEnvelopeBytes == 0 || profile.MaximumEvidenceItems == 0 ||
			profile.MaximumEvidenceItems > MaxEvidenceItems || profile.MaximumEvidenceBytes == 0 ||
			profile.MaximumEvidenceBytes > MaxCanonicalObjectBytes || profile.ReviewDeadlineSeconds == 0 ||
			profile.PayoutDeadlineSeconds == 0 || agentcommerce.ValidateProfileRefV1(profile.ContinuationBudgetProfile) != nil ||
			len(profile.PermittedTerminalFallbacks) == 0 || len(profile.PermittedTerminalFallbacks) > 16 {
			return errors.New("Guarantor claim profile is invalid or unsorted")
		}
		previousFallback := ""
		for _, fallback := range profile.PermittedTerminalFallbacks {
			fallbackDigest, fallbackErr := DeterministicClaimTerminalFallbackDigestV1(fallback)
			if fallbackErr != nil || fallbackDigest <= previousFallback {
				return errors.New("Guarantor claim profile fallback set is invalid or unsorted")
			}
			previousFallback = fallbackDigest
		}
		if profile.DisputeProfile != nil && agentcommerce.ValidateProfileRefV1(*profile.DisputeProfile) != nil ||
			profile.IndependentClaimOperationProfile != nil && agentcommerce.ValidateProfileRefV1(*profile.IndependentClaimOperationProfile) != nil {
			return errors.New("Guarantor optional claim profile is invalid")
		}
		previous = digest
	}
	return nil
}

func validateCollateralProfiles(profiles []CollateralProfileV1, claims []ClaimProfileV1) error {
	claimDigests := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		digest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-claim-profile.v1", claim)
		claimDigests[digest] = struct{}{}
	}
	previous := ""
	for _, profile := range profiles {
		digest, err := guarantorCodec.Digest("tos.service.agent-guarantor-collateral-profile.v1", profile)
		if err != nil || digest <= previous || !validID(profile.ProfileID) || profile.ProfileVersion == 0 ||
			(profile.AssuranceLevel != AssuranceCollateralAttested && profile.AssuranceLevel != AssuranceIndependentlyEnforced) ||
			agentcommerce.ValidateAssetIdentityV1(profile.Asset) != nil || agentcommerce.ValidateProfileRefV1(profile.CustodyAdapterProfile) != nil ||
			ValidateCollateralControlDisclosureV1(profile.CollateralControlDisclosure) != nil ||
			profile.CollateralControlDisclosure.CustodyAdapterProfile != profile.CustodyAdapterProfile ||
			!profile.ExclusiveAllocationRequired || profile.MinimumCollateralizationPPM == 0 || profile.MaximumEvidenceAgeSeconds == 0 ||
			!sortedUnique(profile.CompatibleClaimProfileDigests, MaxClaimProfiles, validDigest) {
			return errors.New("Guarantor collateral profile is invalid or unsorted")
		}
		for _, claimDigest := range profile.CompatibleClaimProfileDigests {
			if _, found := claimDigests[claimDigest]; !found {
				return errors.New("Guarantor collateral profile references an unknown claim profile")
			}
		}
		previousKind := ""
		if len(profile.TransitionProfiles) == 0 || len(profile.TransitionProfiles) > len(collateralTransitionRulesV1) {
			return errors.New("Guarantor collateral profile has no bounded transition registry")
		}
		for _, transition := range profile.TransitionProfiles {
			if transition.TransitionKind <= previousKind || ValidateCollateralTransitionProfileV1(transition) != nil ||
				(transition.AdapterProfile != profile.CustodyAdapterProfile && transition.AuthorizationSubjectSource == "custodian") {
				return errors.New("Guarantor collateral transition profiles are invalid or unsorted")
			}
			previousKind = transition.TransitionKind
		}
		if profile.AssuranceLevel == AssuranceIndependentlyEnforced {
			if profile.MinimumCollateralizationPPM < 1_000_000 || profile.IndependentExecutionProfile == nil ||
				agentcommerce.ValidateProfileRefV1(*profile.IndependentExecutionProfile) != nil ||
				QuorumThresholdMustFailV1(profile.IndependentExecutionQuorumRule, profile.IndependentExecutionAuthoritySubjects) {
				return errors.New("independently enforceable collateral lacks an independent authority")
			}
		} else if profile.IndependentExecutionProfile != nil || len(profile.IndependentExecutionAuthoritySubjects) != 0 || profile.IndependentExecutionQuorumRule != "" {
			return errors.New("attested collateral carries independent-execution authority")
		}
		previous = digest
	}
	return nil
}

func validateAdmissionLimits(limits AdmissionLimitsV1) error {
	if limits.MaximumQuoteReservations == 0 || limits.MaximumQuoteReservations > 1_000_000 ||
		limits.MaximumActiveCoverages == 0 || limits.MaximumActiveCoverages > limits.MaximumQuoteReservations ||
		limits.MaximumActiveClaims == 0 || limits.MaximumActiveClaims > 10_000_000 ||
		limits.MaximumActivePerCoveredParty == 0 || limits.MaximumActivePerCoveredParty > limits.MaximumActiveCoverages ||
		limits.MaximumActivationAttemptsPerCoverage == 0 || limits.MaximumActivationAttemptsPerCoverage > 64 ||
		limits.MaximumQuoteRequestsPerWindow == 0 || limits.MaximumQuoteRequestsPerWindow > 1_000_000 ||
		limits.QuoteRequestWindowSeconds == 0 || limits.QuoteRequestWindowSeconds > 86_400 ||
		limits.MaximumAcceptanceProcessingGraceSeconds == 0 || limits.MaximumAcceptanceProcessingGraceSeconds > 86_400 {
		return errors.New("Guarantor admission limits are invalid")
	}
	return nil
}

func validateEndpoints(endpoints ServiceEndpointsV1) error {
	for _, raw := range []string{endpoints.QuoteRoute, endpoints.AcceptanceRoute, endpoints.ClaimRoute, endpoints.ResolveRoute, endpoints.EvidenceRoute} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Fragment != "" || len(raw) > 2048 {
			return errors.New("Guarantor endpoint is invalid")
		}
	}
	return nil
}

func sortedProfileRefs(refs []ProfileRefV1, maximum int) bool {
	if len(refs) > maximum {
		return false
	}
	previous := ""
	for _, ref := range refs {
		if agentcommerce.ValidateProfileRefV1(ref) != nil {
			return false
		}
		canonical, err := guarantorCodec.Marshal(ref)
		if err != nil {
			return false
		}
		key := string(canonical)
		if key <= previous {
			return false
		}
		previous = key
	}
	return sort.SliceIsSorted(refs, func(i, j int) bool {
		left, _ := guarantorCodec.Marshal(refs[i])
		right, _ := guarantorCodec.Marshal(refs[j])
		return string(left) < string(right)
	})
}
