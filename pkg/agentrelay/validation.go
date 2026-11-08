package agentrelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	cellHashPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
)

func ValidateResolveCall(call ResolveCall) error {
	if !digestPattern.MatchString(call.StableActionID) || !digestPattern.MatchString(call.ExactRequestDigest) {
		return errors.New("relay resolution query is invalid")
	}
	return nil
}

func ValidateEvidenceCall(call EvidenceCall) error {
	return ValidateResolveCall(ResolveCall{StableActionID: call.StableActionID, ExactRequestDigest: call.ExactRequestDigest})
}

func ValidateRelayServiceProfile(profile RelayServiceProfile, now time.Time) error {
	if err := validateRelayServiceProfileShape(profile); err != nil {
		return err
	}
	if profile.CreatedAtUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) || uint64(now.UTC().Unix()) >= profile.ExpiresAtUnix {
		return errors.New("relay service profile is premature or expired")
	}
	return nil
}

func validateRelayServiceProfileShape(profile RelayServiceProfile) error {
	if profile.SchemaVersion != 1 || !identifier(profile.ProfileID, 256) || profile.Revision == 0 ||
		!identifier(profile.ProviderAgentID, 256) || profile.MaximumRequestBytes == 0 || profile.MaximumRequestBytes > MaxSignedTransactionBytes ||
		profile.PolicyRevision == 0 || profile.CreatedAtUnix == 0 || profile.ExpiresAtUnix <= profile.CreatedAtUnix ||
		profile.ExpiresAtUnix-profile.CreatedAtUnix > MaxRelayProfileLifetime {
		return errors.New("relay service profile envelope is invalid")
	}
	if len(profile.NetworkDomains) == 0 || len(profile.NetworkDomains) > 64 || !sortedNetworkDomains(profile.NetworkDomains) {
		return errors.New("relay service network domains are invalid")
	}
	if len(profile.SupportedModes) == 0 || len(profile.SupportedModes) > 3 || !sortedModes(profile.SupportedModes) {
		return errors.New("relay service modes are invalid")
	}
	if len(profile.SupportedAssuranceLevels) == 0 || len(profile.SupportedAssuranceLevels) > 3 ||
		!sortedAssuranceLevels(profile.SupportedAssuranceLevels) {
		return errors.New("relay service assurance levels are invalid")
	}
	if len(profile.TransactionProfiles) == 0 || len(profile.TransactionProfiles) > 32 || !sortedTransactionProfiles(profile.TransactionProfiles) {
		return errors.New("relay transaction profiles are invalid")
	}
	for _, candidate := range profile.TransactionProfiles {
		if !identifier(candidate.ProfileURI, 256) || !digestPattern.MatchString(candidate.ProfileDigest) ||
			candidate.MaximumSignedBytes == 0 || candidate.MaximumSignedBytes > profile.MaximumRequestBytes ||
			!candidate.InspectableSourceSequence || !candidate.InspectableTransactionExpiry {
			return errors.New("relay transaction profile is not safely inspectable")
		}
	}
	if len(profile.FinalityProfiles) == 0 || len(profile.FinalityProfiles) > 16 || !sortedFinalityProfiles(profile.FinalityProfiles) {
		return errors.New("relay finality profiles are invalid")
	}
	for _, candidate := range profile.FinalityProfiles {
		if err := validateFinalityProfile(candidate); err != nil {
			return err
		}
	}
	if len(profile.FeeAssets) == 0 || len(profile.FeeAssets) > 16 || !sortedAssets(profile.FeeAssets) {
		return errors.New("relay fee assets are invalid")
	}
	for _, asset := range profile.FeeAssets {
		if err := validateAsset(asset); err != nil {
			return err
		}
	}
	if len(profile.ExposureLimits) == 0 || len(profile.ExposureLimits) > 32 || !sortedExposureLimits(profile.ExposureLimits) {
		return errors.New("relay exposure limits are invalid")
	}
	for _, limit := range profile.ExposureLimits {
		if err := validateAsset(limit.Asset); err != nil || !positiveAtomic(limit.MaximumPerRequestAtomic) ||
			!positiveAtomic(limit.MaximumOutstandingAtomic) || compareAtomic(limit.MaximumPerRequestAtomic, limit.MaximumOutstandingAtomic) > 0 {
			return errors.New("relay exposure limit is invalid")
		}
	}
	limits := profile.AdmissionLimits
	if limits.MaximumQuoteReservations == 0 || limits.MaximumQuoteReservations > 1_000_000 ||
		limits.MaximumActiveExecutions == 0 || limits.MaximumActiveExecutions > 1_000_000 ||
		limits.MaximumActivePerRequester == 0 ||
		limits.MaximumActivePerRequester > limits.MaximumActiveExecutions ||
		limits.MaximumQuoteRequestsPerWindow == 0 || limits.MaximumQuoteRequestsPerWindow > 1_000_000 ||
		limits.MaximumQuoteRequestsPerRequesterWindow == 0 ||
		limits.MaximumQuoteRequestsPerRequesterWindow > limits.MaximumQuoteRequestsPerWindow ||
		limits.QuoteRequestWindowSeconds == 0 || limits.QuoteRequestWindowSeconds > 86_400 {
		return errors.New("relay admission limits are invalid")
	}
	for _, endpoint := range []string{profile.Endpoints.QuoteURL, profile.Endpoints.SubmitURL, profile.Endpoints.ResolveURL, profile.Endpoints.EvidenceURL} {
		if err := validateEndpoint(endpoint); err != nil {
			return err
		}
	}
	return nil
}

func validateRelayQuoteRequestShape(body RelayQuoteRequestBody) error {
	if body.SchemaVersion != 1 || !identifier(body.RequestID, 256) || !identifier(body.RequesterAgentID, 256) ||
		!identifier(body.ProviderAgentID, 256) || validateNetworkDomain(body.Network) != nil || !validMode(body.Mode) ||
		!validAssuranceLevel(body.AssuranceLevel) ||
		!identifier(body.SourceAccount, 256) || !digestPattern.MatchString(body.SourceAccountAuthorityDigest) ||
		!identifier(body.TransactionProfileURI, 256) ||
		!digestPattern.MatchString(body.TransactionProfileDigest) || agentcommerce.SemanticActionRegistry()[body.UnderlyingActionKind].ActionKind == "" ||
		!digestPattern.MatchString(body.StableActionID) || !digestPattern.MatchString(body.ExactRequestDigest) ||
		!digestPattern.MatchString(body.SignedTransactionDigest) || !cellHashPattern.MatchString(body.SignedTransactionCellHash) ||
		body.SignedTransactionSize == 0 || body.SignedTransactionSize > MaxSignedTransactionBytes ||
		!digestPattern.MatchString(body.TransactionIntentDigest) || body.TransactionValidUntilUnix == 0 ||
		validateAmount(body.MaximumServiceFee, false) != nil || !canonicalAtomic(body.MaximumNetworkFeeAtomic) ||
		!canonicalAtomic(body.MaximumTransactionValueAtomic) || body.CreatedAtUnix == 0 || body.ExpiresAtUnix <= body.CreatedAtUnix ||
		body.ExpiresAtUnix-body.CreatedAtUnix > MaxRelayRequestLifetime || body.ExpiresAtUnix >= body.TransactionValidUntilUnix {
		return errors.New("relay quote request body is invalid")
	}
	switch body.Mode {
	case ModeRelayExact:
		if !validProfileSelection(body.RelayFinalityProfileURI, body.RelayFinalityProfileDigest) ||
			!validRelayTerminalClass(body.RelayTerminalEvidenceClass, body.AssuranceLevel) ||
			body.SponsorshipTerminalEvidenceClass != "" ||
			body.SponsorshipTerminalProfileURI != "" || body.SponsorshipTerminalProfileDigest != "" ||
			body.RequestedSponsorship != nil || validateSponsorshipReleaseSelection(body.Mode, body.AssuranceLevel,
			body.SponsorshipReleaseEvidenceClass, body.SponsorshipReleaseProfileURI,
			body.SponsorshipReleaseProfileDigest, "", "", "") != nil {
			return errors.New("relay-only request carries sponsorship")
		}
	case ModeSponsorOnly:
		if body.RelayFinalityProfileURI != "" || body.RelayFinalityProfileDigest != "" ||
			body.RelayTerminalEvidenceClass != "" ||
			!validSponsorshipTerminalClass(body.SponsorshipTerminalEvidenceClass, body.AssuranceLevel) ||
			!validProfileSelection(body.SponsorshipTerminalProfileURI, body.SponsorshipTerminalProfileDigest) ||
			body.RequestedSponsorship == nil || validateAmount(*body.RequestedSponsorship, true) != nil ||
			validateSponsorshipReleaseSelection(body.Mode, body.AssuranceLevel,
				body.SponsorshipReleaseEvidenceClass, body.SponsorshipReleaseProfileURI,
				body.SponsorshipReleaseProfileDigest, body.SponsorshipTerminalProfileURI,
				body.SponsorshipTerminalProfileDigest, body.SponsorshipTerminalEvidenceClass) != nil {
			return errors.New("sponsor-only request lacks its exact terminal predicate or positive amount")
		}
	case ModeSponsorAndRelay:
		if !validProfileSelection(body.RelayFinalityProfileURI, body.RelayFinalityProfileDigest) ||
			!validProfileSelection(body.SponsorshipTerminalProfileURI, body.SponsorshipTerminalProfileDigest) ||
			!validRelayTerminalClass(body.RelayTerminalEvidenceClass, body.AssuranceLevel) ||
			!validSponsorshipTerminalClass(body.SponsorshipTerminalEvidenceClass, body.AssuranceLevel) ||
			body.RequestedSponsorship == nil || validateAmount(*body.RequestedSponsorship, true) != nil ||
			validateSponsorshipReleaseSelection(body.Mode, body.AssuranceLevel,
				body.SponsorshipReleaseEvidenceClass, body.SponsorshipReleaseProfileURI,
				body.SponsorshipReleaseProfileDigest, body.SponsorshipTerminalProfileURI,
				body.SponsorshipTerminalProfileDigest, body.SponsorshipTerminalEvidenceClass) != nil {
			return errors.New("combined request lacks exact relay or sponsorship predicates")
		}
	default:
		return errors.New("relay mode is invalid")
	}
	return nil
}

func validProfileSelection(uri, digest string) bool {
	return identifier(uri, 256) && digestPattern.MatchString(digest)
}

func validRelayTerminalClass(class TerminalEvidenceClass, assurance AssuranceLevel) bool {
	return class == RelayTerminalValidatorFinality ||
		class == RelayTerminalProviderCorroborated && assurance != AssuranceAutonomousDecentralized
}

func validSponsorshipTerminalClass(class TerminalEvidenceClass, assurance AssuranceLevel) bool {
	return class == SponsorshipTerminalValidatorFinality ||
		class == SponsorshipTerminalClientCorroborated && assurance != AssuranceAutonomousDecentralized
}

func validateSponsorshipReleaseSelection(mode Mode, assurance AssuranceLevel,
	evidenceClass SponsorshipReleaseEvidenceClass, profileURI, profileDigest,
	finalityProfileURI, finalityProfileDigest string, terminalClass TerminalEvidenceClass) error {
	return ValidateSponsorshipReleaseProfile(mode, assurance,
		SponsorshipReleaseProfile{EvidenceClass: evidenceClass, ProfileURI: profileURI, ProfileDigest: profileDigest},
		FinalityProfile{ProfileURI: finalityProfileURI, ProfileDigest: finalityProfileDigest,
			TerminalEvidenceClass: terminalClass})
}

// ValidateSponsorshipReleaseProfile validates one concrete capability
// descriptor against the selected mode, assurance level, and validator
// finality profile. It intentionally performs no deployment-certification
// check; callers decide readiness from current exact capabilities.
func ValidateSponsorshipReleaseProfile(mode Mode, assurance AssuranceLevel,
	selection SponsorshipReleaseProfile, finality FinalityProfile) error {
	if !validAssuranceLevel(assurance) {
		return errors.New("sponsorship release assurance level is invalid")
	}
	if mode == ModeRelayExact {
		if selection.EvidenceClass != "" || selection.ProfileURI != "" || selection.ProfileDigest != "" {
			return errors.New("relay-only action carries a sponsorship release policy")
		}
		return nil
	}
	if mode != ModeSponsorOnly && mode != ModeSponsorAndRelay ||
		!identifier(selection.ProfileURI, 256) || !digestPattern.MatchString(selection.ProfileDigest) {
		return errors.New("sponsorship release policy is invalid")
	}
	switch selection.EvidenceClass {
	case SponsorshipReleaseValidatorFinality:
		if selection.ProfileURI != finality.ProfileURI || selection.ProfileDigest != finality.ProfileDigest ||
			finality.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality {
			return errors.New("validator sponsorship release policy differs from selected finality")
		}
	case SponsorshipReleaseObservedUnproven:
		if assurance == AssuranceAutonomousDecentralized ||
			selection.ProfileURI != RPCCorroborationEvidenceProfileURI ||
			finality.ProfileURI != ClientCorroboratedTerminalProfileURI ||
			finality.TerminalEvidenceClass != SponsorshipTerminalClientCorroborated {
			return errors.New("unproven sponsorship release is not permitted by the selected assurance")
		}
	default:
		return errors.New("sponsorship release evidence class is invalid")
	}
	return nil
}

// VerifyRelayQuoteRequest authenticates the requester and checks the signed
// transaction descriptor against the discovered provider profile. The exact
// bearer-executable bytes are intentionally unavailable until Submit, where
// they are independently parsed before admission or any side effect.
func VerifyRelayQuoteRequest(signed SignedRelayQuoteRequest, profile RelayServiceProfile, resolver AgentKeyResolver,
	now time.Time) error {
	if err := ValidateRelayServiceProfile(profile, now); err != nil || validateRelayQuoteRequestShape(signed.Body) != nil {
		return errors.New("relay quote request or provider profile is invalid")
	}
	body := signed.Body
	if body.ProviderAgentID != profile.ProviderAgentID || !containsMode(profile.SupportedModes, body.Mode) ||
		!containsAssuranceLevel(profile.SupportedAssuranceLevels, body.AssuranceLevel) ||
		!containsNetwork(profile.NetworkDomains, body.Network) || body.SignedTransactionSize > profile.MaximumRequestBytes ||
		body.CreatedAtUnix < profile.CreatedAtUnix || body.ExpiresAtUnix > profile.ExpiresAtUnix {
		return errors.New("relay quote request is outside the provider profile")
	}
	transactionProfile, found := findTransactionProfile(profile.TransactionProfiles, body.TransactionProfileURI, body.TransactionProfileDigest)
	if !found || body.SignedTransactionSize > transactionProfile.MaximumSignedBytes {
		return errors.New("relay transaction profile is unsupported")
	}
	var relayFinality, sponsorshipFinality FinalityProfile
	if body.Mode != ModeSponsorOnly {
		var found bool
		relayFinality, found = findFinalityProfile(profile.FinalityProfiles, body.RelayFinalityProfileURI,
			body.RelayFinalityProfileDigest)
		if !found {
			return errors.New("relay finality profile is unsupported")
		}
		if relayFinality.TerminalEvidenceClass != body.RelayTerminalEvidenceClass {
			return errors.New("relay terminal evidence class conflicts with its selected profile")
		}
	}
	if body.Mode != ModeRelayExact {
		var found bool
		sponsorshipFinality, found = findFinalityProfile(profile.FinalityProfiles,
			body.SponsorshipTerminalProfileURI, body.SponsorshipTerminalProfileDigest)
		if !found {
			return errors.New("sponsorship terminal profile is unsupported")
		}
		if sponsorshipFinality.TerminalEvidenceClass != body.SponsorshipTerminalEvidenceClass {
			return errors.New("sponsorship terminal evidence class conflicts with its selected profile")
		}
	}
	maximumResolution := relayFinality.MaximumResolutionSeconds
	if sponsorshipFinality.MaximumResolutionSeconds > maximumResolution {
		maximumResolution = sponsorshipFinality.MaximumResolutionSeconds
	}
	if !hasStrictRemainingWindow(body.CreatedAtUnix, body.TransactionValidUntilUnix,
		uint64(maximumResolution)+MinimumRelayInclusionMarginSeconds) {
		return errors.New("relay transaction cannot remain valid through every selected terminal predicate")
	}
	if !containsAsset(profile.FeeAssets, body.MaximumServiceFee.Asset) || body.RequestedSponsorship != nil &&
		!withinExposure(profile.ExposureLimits, *body.RequestedSponsorship) {
		return errors.New("relay fee or sponsorship exceeds the published profile")
	}
	if uint64(now.UTC().Unix()) >= body.ExpiresAtUnix || body.CreatedAtUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) {
		return errors.New("relay quote request is premature or expired")
	}
	if err := verifyAgentSignature(body.Network, body.RequesterAgentID, signed.PublicKey, signed.Signature,
		"tos.agent-relay-quote-request-signature.v1\x00", body, resolver, now); err != nil {
		return err
	}
	return nil
}

// VerifyRelayRemainingValidity applies the same current-time safety budget at
// every irreversible provider boundary. A syntactically live request is not
// sufficient: all signed authorization windows must remain live for the
// selected finality profile's maximum resolution time plus an inclusion
// margin. The strict inequality and checked addition make edge timestamps and
// uint64 wrap fail closed.
func VerifyRelayRemainingValidity(request RelayExecutionRequest, now time.Time, stage SideEffectStage) error {
	mode := request.QuoteRequest.Body.Mode
	switch stage {
	case SideEffectSponsorship:
		if mode == ModeRelayExact || request.ProviderQuote.Body.ReservedSponsorship == nil {
			return errors.New("relay request has no sponsorship side-effect stage")
		}
	case SideEffectBroadcast:
		if mode == ModeSponsorOnly {
			return errors.New("sponsor-only request has no broadcast side-effect stage")
		}
	default:
		return errors.New("relay side-effect stage is invalid")
	}
	nowSeconds := now.UTC().Unix()
	if nowSeconds < 0 {
		return errors.New("relay side-effect time is invalid")
	}
	var finality *FinalityProfile
	if stage == SideEffectSponsorship {
		finality = request.ProviderQuote.Body.SponsorshipTerminalProfile
	} else {
		finality = request.ProviderQuote.Body.RelayFinalityProfile
	}
	if finality == nil || validateFinalityProfile(*finality) != nil {
		return errors.New("relay side-effect terminal profile is invalid")
	}
	budget := uint64(finality.MaximumResolutionSeconds) +
		MinimumRelayInclusionMarginSeconds
	deadlines := []uint64{
		request.ExpiresAtUnix,
		request.AgreementExpiresAtUnix,
		request.QuoteRequest.Body.ExpiresAtUnix,
		request.ProviderQuote.Body.ExpiresAtUnix,
		request.QuoteRequest.Body.TransactionValidUntilUnix,
		request.AuthorizedAction.ExpiresAtUnix,
		request.WriterFence.Body.ExpiresAtUnix,
	}
	for _, deadline := range deadlines {
		if !hasStrictRemainingWindow(uint64(nowSeconds), deadline, budget) {
			return fmt.Errorf("relay %s lacks the required finality and inclusion window", stage)
		}
	}
	return nil
}

func hasStrictRemainingWindow(nowUnix, deadlineUnix, budgetSeconds uint64) bool {
	if deadlineUnix == 0 || nowUnix > ^uint64(0)-budgetSeconds {
		return false
	}
	return nowUnix+budgetSeconds < deadlineUnix
}

func validateInspection(body RelayQuoteRequestBody, inspected InspectedTransaction) error {
	networkDigest, err := NetworkDomainDigest(body.Network)
	if err != nil || inspected.NetworkDigest != networkDigest || inspected.SourceAccount != body.SourceAccount ||
		inspected.SourceAccountAuthorityDigest != body.SourceAccountAuthorityDigest || inspected.AuthorizedAgentID != body.RequesterAgentID ||
		!digestPattern.MatchString(inspected.SourceAccountAuthorityDigest) || !identifier(inspected.AuthorizedAgentID, 256) ||
		inspected.SourceSequence != body.SourceSequence || inspected.ValidUntilUnix != body.TransactionValidUntilUnix ||
		!identifier(inspected.Destination, 256) || !positiveAtomic(inspected.ValueAtomic) ||
		inspected.TransactionIntentDigest != body.TransactionIntentDigest || inspected.SignedTransactionCellHash != body.SignedTransactionCellHash ||
		!canonicalAtomic(inspected.MaximumNetworkFeeAtomic) || !canonicalAtomic(inspected.MaximumTransactionValueAtomic) ||
		compareAtomic(inspected.MaximumNetworkFeeAtomic, body.MaximumNetworkFeeAtomic) > 0 ||
		compareAtomic(inspected.MaximumTransactionValueAtomic, body.MaximumTransactionValueAtomic) > 0 ||
		compareAtomic(inspected.ValueAtomic, body.MaximumTransactionValueAtomic) > 0 {
		return errors.New("inspected transaction conflicts with the relay request")
	}
	return nil
}

func validateProviderRelayQuoteShape(body ProviderRelayQuoteBody) error {
	if body.SchemaVersion != 1 || !identifier(body.QuoteID, 256) || !digestPattern.MatchString(body.QuoteRequestDigest) ||
		!digestPattern.MatchString(body.ServiceProfileDigest) || !identifier(body.ProviderAgentID, 256) || !validMode(body.Mode) ||
		!validAssuranceLevel(body.AssuranceLevel) ||
		len(body.FeeLines) == 0 || len(body.FeeLines) > MaxRelayFeeLines || !sortedFeeLines(body.FeeLines) ||
		!canonicalAtomic(body.MaximumNetworkFeeAtomic) || !canonicalAtomic(body.MaximumTransactionValueAtomic) ||
		body.MaximumRequestBytes == 0 || body.MaximumRequestBytes > MaxSignedTransactionBytes ||
		validateEndpoint(body.StatusEndpoint) != nil ||
		body.ProviderPolicyRevision == 0 || body.OfferIntentDigest != "" && !digestPattern.MatchString(body.OfferIntentDigest) ||
		body.ValidFromUnix == 0 || body.ExpiresAtUnix <= body.ValidFromUnix || body.ExpiresAtUnix-body.ValidFromUnix > MaxRelayRequestLifetime {
		return errors.New("provider relay quote body is invalid")
	}
	for _, line := range body.FeeLines {
		if line.Kind != ObligationRelayFee && line.Kind != ObligationSponsorshipFee || validateAmount(line.Amount, false) != nil {
			return errors.New("provider relay quote fee line is invalid")
		}
	}
	switch body.Mode {
	case ModeRelayExact:
		if body.RelayFinalityProfile == nil || validateFinalityProfile(*body.RelayFinalityProfile) != nil ||
			body.RelayFinalityProfile.TerminalEvidenceClass != body.RelayTerminalEvidenceClass ||
			!validRelayTerminalClass(body.RelayTerminalEvidenceClass, body.AssuranceLevel) ||
			body.SponsorshipTerminalEvidenceClass != "" ||
			body.SponsorshipTerminalProfile != nil || body.ReservedSponsorship != nil ||
			len(body.FeeLines) != 1 || body.FeeLines[0].Kind != ObligationRelayFee ||
			validateSponsorshipReleaseSelection(body.Mode, body.AssuranceLevel,
				body.SponsorshipReleaseEvidenceClass, body.SponsorshipReleaseProfileURI,
				body.SponsorshipReleaseProfileDigest, "", "", "") != nil {
			return errors.New("relay-only quote has invalid fee or sponsorship lines")
		}
	case ModeSponsorOnly:
		if body.RelayFinalityProfile != nil || body.SponsorshipTerminalProfile == nil ||
			validateFinalityProfile(*body.SponsorshipTerminalProfile) != nil ||
			body.RelayTerminalEvidenceClass != "" ||
			body.SponsorshipTerminalProfile.TerminalEvidenceClass != body.SponsorshipTerminalEvidenceClass ||
			!validSponsorshipTerminalClass(body.SponsorshipTerminalEvidenceClass, body.AssuranceLevel) ||
			body.ReservedSponsorship == nil || validateAmount(*body.ReservedSponsorship, true) != nil ||
			len(body.FeeLines) != 1 || body.FeeLines[0].Kind != ObligationSponsorshipFee ||
			validateSponsorshipReleaseSelection(body.Mode, body.AssuranceLevel,
				body.SponsorshipReleaseEvidenceClass, body.SponsorshipReleaseProfileURI,
				body.SponsorshipReleaseProfileDigest, body.SponsorshipTerminalProfile.ProfileURI,
				body.SponsorshipTerminalProfile.ProfileDigest, body.SponsorshipTerminalEvidenceClass) != nil {
			return errors.New("sponsor-only quote is incomplete")
		}
	case ModeSponsorAndRelay:
		if body.RelayFinalityProfile == nil || validateFinalityProfile(*body.RelayFinalityProfile) != nil ||
			body.SponsorshipTerminalProfile == nil || validateFinalityProfile(*body.SponsorshipTerminalProfile) != nil ||
			body.RelayFinalityProfile.TerminalEvidenceClass != body.RelayTerminalEvidenceClass ||
			body.SponsorshipTerminalProfile.TerminalEvidenceClass != body.SponsorshipTerminalEvidenceClass ||
			!validRelayTerminalClass(body.RelayTerminalEvidenceClass, body.AssuranceLevel) ||
			!validSponsorshipTerminalClass(body.SponsorshipTerminalEvidenceClass, body.AssuranceLevel) ||
			body.ReservedSponsorship == nil || validateAmount(*body.ReservedSponsorship, true) != nil || len(body.FeeLines) != 2 ||
			body.FeeLines[0].Kind != ObligationSponsorshipFee || body.FeeLines[1].Kind != ObligationRelayFee ||
			validateSponsorshipReleaseSelection(body.Mode, body.AssuranceLevel,
				body.SponsorshipReleaseEvidenceClass, body.SponsorshipReleaseProfileURI,
				body.SponsorshipReleaseProfileDigest, body.SponsorshipTerminalProfile.ProfileURI,
				body.SponsorshipTerminalProfile.ProfileDigest, body.SponsorshipTerminalEvidenceClass) != nil {
			return errors.New("combined relay quote is incomplete")
		}
	}
	return nil
}

func VerifyProviderRelayQuote(signed SignedProviderRelayQuote, request SignedRelayQuoteRequest, profile RelayServiceProfile,
	resolver AgentKeyResolver, now time.Time) error {
	if err := ValidateRelayServiceProfile(profile, now); err != nil || validateProviderRelayQuoteShape(signed.Body) != nil {
		return errors.New("provider relay quote or service profile is invalid")
	}
	body := signed.Body
	requestDigest, err := RelayQuoteRequestDigest(request.Body)
	profileDigest, profileErr := RelayServiceProfileDigest(profile)
	if err != nil || profileErr != nil || body.QuoteRequestDigest != requestDigest || body.ServiceProfileDigest != profileDigest ||
		body.ProviderAgentID != request.Body.ProviderAgentID || body.ProviderAgentID != profile.ProviderAgentID || body.Mode != request.Body.Mode ||
		body.AssuranceLevel != request.Body.AssuranceLevel ||
		body.RelayTerminalEvidenceClass != request.Body.RelayTerminalEvidenceClass ||
		body.SponsorshipTerminalEvidenceClass != request.Body.SponsorshipTerminalEvidenceClass ||
		body.SponsorshipReleaseEvidenceClass != request.Body.SponsorshipReleaseEvidenceClass ||
		body.SponsorshipReleaseProfileURI != request.Body.SponsorshipReleaseProfileURI ||
		body.SponsorshipReleaseProfileDigest != request.Body.SponsorshipReleaseProfileDigest ||
		body.MaximumRequestBytes < request.Body.SignedTransactionSize || body.MaximumRequestBytes > profile.MaximumRequestBytes ||
		body.MaximumNetworkFeeAtomic != request.Body.MaximumNetworkFeeAtomic ||
		body.MaximumTransactionValueAtomic != request.Body.MaximumTransactionValueAtomic ||
		!profilePointerMatchesSelection(body.RelayFinalityProfile, request.Body.RelayFinalityProfileURI,
			request.Body.RelayFinalityProfileDigest) ||
		!profilePointerMatchesSelection(body.SponsorshipTerminalProfile,
			request.Body.SponsorshipTerminalProfileURI, request.Body.SponsorshipTerminalProfileDigest) ||
		body.StatusEndpoint != profile.Endpoints.ResolveURL || body.ProviderPolicyRevision != profile.PolicyRevision ||
		body.ValidFromUnix < request.Body.CreatedAtUnix || body.ExpiresAtUnix > request.Body.ExpiresAtUnix ||
		body.ExpiresAtUnix >= request.Body.TransactionValidUntilUnix || uint64(now.UTC().Unix()) < body.ValidFromUnix || uint64(now.UTC().Unix()) >= body.ExpiresAtUnix {
		return errors.New("provider quote does not match the exact request and profile")
	}
	if body.RelayFinalityProfile != nil {
		finality, found := findFinalityProfile(profile.FinalityProfiles, request.Body.RelayFinalityProfileURI,
			request.Body.RelayFinalityProfileDigest)
		if !found || *body.RelayFinalityProfile != finality {
			return errors.New("provider quote changes the selected relay finality profile")
		}
	}
	if body.SponsorshipTerminalProfile != nil {
		finality, found := findFinalityProfile(profile.FinalityProfiles,
			request.Body.SponsorshipTerminalProfileURI, request.Body.SponsorshipTerminalProfileDigest)
		if !found || *body.SponsorshipTerminalProfile != finality {
			return errors.New("provider quote changes the selected sponsorship terminal profile")
		}
	}
	if body.ReservedSponsorship == nil != (request.Body.RequestedSponsorship == nil) || body.ReservedSponsorship != nil &&
		!sameAmount(*body.ReservedSponsorship, *request.Body.RequestedSponsorship) {
		return errors.New("provider quote changes the requested sponsorship")
	}
	var total string = "0"
	for _, line := range body.FeeLines {
		if !sameAsset(line.Amount.Asset, request.Body.MaximumServiceFee.Asset) || !containsAsset(profile.FeeAssets, line.Amount.Asset) {
			return errors.New("provider quote selects an unauthorized fee asset")
		}
		total = addAtomic(total, line.Amount.AmountAtomic)
	}
	if compareAtomic(total, request.Body.MaximumServiceFee.AmountAtomic) > 0 {
		return errors.New("provider quote exceeds the maximum service fee")
	}
	return verifyAgentSignature(request.Body.Network, body.ProviderAgentID, signed.PublicKey, signed.Signature,
		"tos.agent-relay-provider-quote-signature.v1\x00", body, resolver, now)
}

func profilePointerMatchesSelection(profile *FinalityProfile, uri, digest string) bool {
	if profile == nil {
		return uri == "" && digest == ""
	}
	return profile.ProfileURI == uri && profile.ProfileDigest == digest
}

func validateRelayAgreementBinding(binding RelayAgreementBinding) error {
	if binding.SchemaVersion != 1 || !digestPattern.MatchString(binding.QuoteRequestDigest) ||
		!digestPattern.MatchString(binding.ProviderQuoteDigest) || !digestPattern.MatchString(binding.ServiceProfileDigest) ||
		!validMode(binding.Mode) || !validAssuranceLevel(binding.AssuranceLevel) ||
		!identifier(binding.RequesterAgentID, 256) || !identifier(binding.ProviderAgentID, 256) ||
		!digestPattern.MatchString(binding.StableActionID) || !digestPattern.MatchString(binding.ExactRequestDigest) ||
		!digestPattern.MatchString(binding.SignedTransactionDigest) {
		return errors.New("relay Agreement binding is invalid")
	}
	if binding.Mode == ModeRelayExact {
		if binding.SponsorshipReleaseEvidenceClass != "" || binding.SponsorshipReleaseProfileURI != "" ||
			binding.SponsorshipReleaseProfileDigest != "" ||
			!validRelayTerminalClass(binding.RelayTerminalEvidenceClass, binding.AssuranceLevel) ||
			binding.SponsorshipTerminalEvidenceClass != "" ||
			!validProfileSelection(binding.RelayFinalityProfileURI, binding.RelayFinalityProfileDigest) ||
			binding.SponsorshipTerminalProfileURI != "" || binding.SponsorshipTerminalProfileDigest != "" {
			return errors.New("relay Agreement carries an unexpected sponsorship release policy")
		}
	} else if !identifier(binding.SponsorshipReleaseProfileURI, 256) ||
		!digestPattern.MatchString(binding.SponsorshipReleaseProfileDigest) ||
		!validProfileSelection(binding.SponsorshipTerminalProfileURI, binding.SponsorshipTerminalProfileDigest) ||
		!validSponsorshipTerminalClass(binding.SponsorshipTerminalEvidenceClass, binding.AssuranceLevel) ||
		(binding.Mode == ModeSponsorOnly && (binding.RelayFinalityProfileURI != "" ||
			binding.RelayFinalityProfileDigest != "" || binding.RelayTerminalEvidenceClass != "") ||
			binding.Mode == ModeSponsorAndRelay && !validProfileSelection(binding.RelayFinalityProfileURI,
				binding.RelayFinalityProfileDigest) ||
			binding.Mode == ModeSponsorAndRelay &&
				!validRelayTerminalClass(binding.RelayTerminalEvidenceClass, binding.AssuranceLevel)) ||
		(binding.SponsorshipReleaseEvidenceClass != SponsorshipReleaseValidatorFinality &&
			binding.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven) ||
		binding.SponsorshipReleaseEvidenceClass == SponsorshipReleaseObservedUnproven &&
			(binding.AssuranceLevel == AssuranceAutonomousDecentralized ||
				binding.SponsorshipReleaseProfileURI != RPCCorroborationEvidenceProfileURI) ||
		validateSponsorshipReleaseSelection(binding.Mode, binding.AssuranceLevel,
			binding.SponsorshipReleaseEvidenceClass, binding.SponsorshipReleaseProfileURI,
			binding.SponsorshipReleaseProfileDigest, binding.SponsorshipTerminalProfileURI,
			binding.SponsorshipTerminalProfileDigest, binding.SponsorshipTerminalEvidenceClass) != nil {
		return errors.New("relay Agreement sponsorship release policy is invalid")
	}
	return nil
}

func validateRelayExecutionRequestShape(request RelayExecutionRequest) error {
	if err := validateRelayExecutionRequestCoreShape(request); err != nil {
		return err
	}
	if err := validateRelaySideEffectAdmissionReceiptShape(request.AdmissionReceipt); err != nil {
		return err
	}
	return nil
}

func validateRelayExecutionRequestCoreShape(request RelayExecutionRequest) error {
	if request.SchemaVersion != 1 || validateRelayQuoteRequestShape(request.QuoteRequest.Body) != nil ||
		validateProviderRelayQuoteShape(request.ProviderQuote.Body) != nil || !digestPattern.MatchString(request.AgreementBodyDigest) ||
		request.AgreementExpiresAtUnix == 0 || len(request.FeeObligationIDs) == 0 ||
		!sortedIdentifiers(request.FeeObligationIDs, MaxRelayFeeLines) || len(request.SignedTransactionBytes) == 0 ||
		len(request.SignedTransactionBytes) > MaxSignedTransactionBytes || len(request.UnderlyingActionRequest) == 0 ||
		len(request.UnderlyingActionRequest) > MaxRelayActionRequestBytes || request.CreatedAtUnix == 0 ||
		request.ExpiresAtUnix <= request.CreatedAtUnix || request.ExpiresAtUnix > request.AgreementExpiresAtUnix ||
		request.ExpiresAtUnix > request.ProviderQuote.Body.ExpiresAtUnix {
		return errors.New("relay execution request envelope is invalid")
	}
	switch request.QuoteRequest.Body.Mode {
	case ModeRelayExact:
		if !identifier(request.RelayObligationID, 128) || request.SponsorshipObligationID != "" {
			return errors.New("relay execution obligation set is invalid")
		}
	case ModeSponsorOnly:
		if request.RelayObligationID != "" || !identifier(request.SponsorshipObligationID, 128) {
			return errors.New("sponsor execution obligation set is invalid")
		}
	case ModeSponsorAndRelay:
		if !identifier(request.RelayObligationID, 128) || !identifier(request.SponsorshipObligationID, 128) {
			return errors.New("combined execution obligation set is invalid")
		}
	}
	return nil
}

// VerifyRelayExecutionRequest verifies both service envelopes and the original
// owner-authorized economic action. It intentionally leaves Agreement evidence
// validation to VerifyRelayExecutionAgreement so callers cannot accidentally
// substitute a body after transport validation.
func VerifyRelayExecutionRequest(ctx context.Context, request RelayExecutionRequest, profile RelayServiceProfile, agentResolver AgentKeyResolver,
	fenceResolver agentcommerce.CurrentWriterFenceResolver, inspector TransactionInspector, now time.Time) error {
	if err := VerifyRelaySideEffectAdmissionReceipt(request.AdmissionReceipt, request, fenceResolver, now); err != nil {
		return err
	}
	authorityAt := time.Unix(int64(request.AdmissionReceipt.Body.IssuedAtUnix), 0).UTC()
	return verifyRelayExecutionRequestCoreAtAuthorityTime(ctx, request, profile, agentResolver,
		fenceResolver, inspector, now, authorityAt, false)
}

// VerifyRelayExecutionRequestForAdmission is the owner-side preflight used
// immediately before asking the Action Authority to atomically issue the
// receipt. It requires the current writer and deliberately permits the receipt
// field to be empty because issuance is the next linearized operation.
func VerifyRelayExecutionRequestForAdmission(ctx context.Context, request RelayExecutionRequest,
	profile RelayServiceProfile, agentResolver AgentKeyResolver,
	fenceResolver agentcommerce.CurrentWriterFenceResolver, inspector TransactionInspector, now time.Time) error {
	return verifyRelayExecutionRequestCoreAtAuthorityTime(ctx, request, profile, agentResolver,
		fenceResolver, inspector, now, now, true)
}

func verifyRelayExecutionRequestCore(ctx context.Context, request RelayExecutionRequest, profile RelayServiceProfile,
	agentResolver AgentKeyResolver, fenceResolver agentcommerce.CurrentWriterFenceResolver,
	inspector TransactionInspector, now time.Time, requireCurrentWriter bool) error {
	return verifyRelayExecutionRequestCoreAtAuthorityTime(ctx, request, profile, agentResolver,
		fenceResolver, inspector, now, now, requireCurrentWriter)
}

func verifyRelayExecutionRequestCoreAtAuthorityTime(ctx context.Context, request RelayExecutionRequest,
	profile RelayServiceProfile, agentResolver AgentKeyResolver,
	fenceResolver agentcommerce.CurrentWriterFenceResolver, inspector TransactionInspector,
	now, actionAuthorityAt time.Time, requireCurrentWriter bool) error {
	if ctx == nil {
		return errors.New("relay transaction inspection context is required")
	}
	if err := validateRelayExecutionRequestCoreShape(request); err != nil {
		return err
	}
	if err := VerifyRelayQuoteRequest(request.QuoteRequest, profile, agentResolver, now); err != nil {
		return err
	}
	if err := VerifyProviderRelayQuote(request.ProviderQuote, request.QuoteRequest, profile, agentResolver, now); err != nil {
		return err
	}
	transactionProfile, found := findTransactionProfile(profile.TransactionProfiles,
		request.QuoteRequest.Body.TransactionProfileURI, request.QuoteRequest.Body.TransactionProfileDigest)
	if !found || inspector == nil {
		return errors.New("relay transaction inspector is required")
	}
	digest, err := SignedTransactionDigest(request.SignedTransactionBytes)
	if err != nil || digest != request.QuoteRequest.Body.SignedTransactionDigest ||
		uint32(len(request.SignedTransactionBytes)) != request.QuoteRequest.Body.SignedTransactionSize {
		return errors.New("relay execution bytes do not match the quoted descriptor")
	}
	phase := InspectionReadyToBroadcast
	if request.QuoteRequest.Body.Mode != ModeRelayExact {
		phase = InspectionAdmission
	}
	inspection, err := inspector.InspectTransaction(ctx, request.QuoteRequest.Body, transactionProfile,
		request.SignedTransactionBytes, phase)
	if err != nil {
		return fmt.Errorf("inspect exact relay transaction: %w", err)
	}
	if err := validateInspection(request.QuoteRequest.Body, inspection); err != nil {
		return err
	}
	body := request.QuoteRequest.Body
	if uint64(now.UTC().Unix()) >= request.ExpiresAtUnix || request.CreatedAtUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) ||
		request.CreatedAtUnix < body.CreatedAtUnix || request.CreatedAtUnix < request.ProviderQuote.Body.ValidFromUnix ||
		request.ExpiresAtUnix > body.TransactionValidUntilUnix || request.AuthorizedAction.ActionKind != body.UnderlyingActionKind ||
		request.AuthorizedAction.StableActionID != body.StableActionID || request.AuthorizedAction.ExactRequestDigest != body.ExactRequestDigest ||
		request.AuthorizedAction.AgentID != body.RequesterAgentID || request.ExpiresAtUnix > request.AuthorizedAction.ExpiresAtUnix ||
		request.ExpiresAtUnix > request.WriterFence.Body.ExpiresAtUnix || len(request.FeeObligationIDs) != len(request.ProviderQuote.Body.FeeLines) {
		return errors.New("relay execution does not bind the quoted underlying action")
	}
	fields, err := agentcommerce.ImportSemanticFields(body.UnderlyingActionKind, request.SemanticFields)
	if err != nil {
		return err
	}
	if err := agentcommerce.VerifyAuthorizedActionAtAuthorityTime(request.AuthorizedAction, fields,
		request.UnderlyingActionRequest, request.WriterFence, fenceResolver, now, actionAuthorityAt); err != nil {
		return fmt.Errorf("verify underlying authorized action: %w", err)
	}
	if requireCurrentWriter {
		if err := ConfirmRelayCurrentWriterFence(request, fenceResolver, now); err != nil {
			return err
		}
	}
	return nil
}

// ConfirmRelayCurrentWriterFence performs the live lease-authority check used
// before asking the Action Authority to issue a side-effect admission receipt.
// Receipt issuance is the linearization point; once a Provider durably consumes
// that exact receipt, its frozen stages may drain after a writer takeover.
func ConfirmRelayCurrentWriterFence(request RelayExecutionRequest,
	resolver agentcommerce.CurrentWriterFenceResolver, now time.Time) error {
	if err := agentcommerce.ConfirmCurrentWriterFence(request.WriterFence, resolver, now); err != nil {
		return fmt.Errorf("confirm current relay writer fence: %w", err)
	}
	return nil
}

func VerifyActionTransactionBinding(ctx context.Context, request RelayExecutionRequest, profile RelayServiceProfile,
	inspector TransactionInspector, binder ActionTransactionBinder) error {
	if ctx == nil || inspector == nil || binder == nil {
		return errors.New("relay action-to-transaction verifier is required")
	}
	transactionProfile, found := findTransactionProfile(profile.TransactionProfiles,
		request.QuoteRequest.Body.TransactionProfileURI, request.QuoteRequest.Body.TransactionProfileDigest)
	if !found {
		return errors.New("relay transaction profile is unsupported")
	}
	phase := InspectionReadyToBroadcast
	if request.QuoteRequest.Body.Mode != ModeRelayExact {
		phase = InspectionAdmission
	}
	inspected, err := inspector.InspectTransaction(ctx, request.QuoteRequest.Body, transactionProfile,
		request.SignedTransactionBytes, phase)
	if err != nil {
		return err
	}
	if err := validateInspection(request.QuoteRequest.Body, inspected); err != nil {
		return err
	}
	return binder.VerifyActionTransaction(request, inspected)
}

// VerifyRelayReadyToBroadcast repeats chain-state inspection after a combined
// sponsorship has finalized. At this boundary the source account must have
// the real finalized balance, authority, sequence, and validity required by
// the frozen transaction; pending sponsorship credit is no longer projected.
func VerifyRelayReadyToBroadcast(ctx context.Context, request RelayExecutionRequest, profile RelayServiceProfile,
	inspector TransactionInspector, binder ActionTransactionBinder) error {
	if request.QuoteRequest.Body.Mode == ModeSponsorOnly {
		return errors.New("sponsor-only requests have no relay broadcast stage")
	}
	if ctx == nil || inspector == nil || binder == nil {
		return errors.New("relay action-to-transaction verifier is required")
	}
	transactionProfile, found := findTransactionProfile(profile.TransactionProfiles,
		request.QuoteRequest.Body.TransactionProfileURI, request.QuoteRequest.Body.TransactionProfileDigest)
	if !found {
		return errors.New("relay transaction profile is unsupported")
	}
	inspected, err := inspector.InspectTransaction(ctx, request.QuoteRequest.Body, transactionProfile,
		request.SignedTransactionBytes, InspectionReadyToBroadcast)
	if err != nil {
		return err
	}
	if err := validateInspection(request.QuoteRequest.Body, inspected); err != nil {
		return err
	}
	return binder.VerifyActionTransaction(request, inspected)
}

// VerifyRelayExecutionAgreement enforces the exact generic obligations and
// their complete profile-qualified authorization evidence.
func VerifyRelayExecutionAgreement(request RelayExecutionRequest, agreement agentcommerce.AgentAgreement,
	verifier agentcommerce.AgreementEvidenceVerifier, now time.Time) error {
	if err := agentcommerce.ValidateAgreementAuthorization(agreement, verifier, now); err != nil {
		return fmt.Errorf("verify relay Agreement authorization: %w", err)
	}
	digest, err := agentcommerce.AgreementBodyDigest(agreement.Body)
	if err != nil || digest != request.AgreementBodyDigest || agreement.Body.ExpiresAtUnix != request.AgreementExpiresAtUnix {
		return errors.New("relay execution Agreement digest or expiry mismatch")
	}
	binding, err := CompileRelayAgreementBinding(request.QuoteRequest, request.ProviderQuote)
	if err != nil {
		return err
	}
	bindingBytes, err := RelayAgreementBindingBytes(binding)
	if err != nil {
		return err
	}
	if agreement.Body.TermsContentType != AgreementBindingContentType ||
		!bytes.Equal(agreement.Body.Terms, bindingBytes) {
		return errors.New("relay Agreement top-level terms do not bind the exact quote pair")
	}
	obligations := make(map[string]agentcommerce.AgreementObligation, len(agreement.Body.Obligations))
	for _, obligation := range agreement.Body.Obligations {
		if _, duplicate := obligations[obligation.ObligationID]; duplicate {
			return errors.New("relay Agreement obligation identity is duplicated")
		}
		obligations[obligation.ObligationID] = obligation
	}
	expectedServiceObligations := make(map[string]string, 2+len(request.FeeObligationIDs))
	client, provider := request.QuoteRequest.Body.RequesterAgentID, request.QuoteRequest.Body.ProviderAgentID
	if request.RelayObligationID != "" {
		expectedServiceObligations[request.RelayObligationID] = ObligationRelayDelivery
		obligation := obligations[request.RelayObligationID]
		if !sameBoundObligation(obligation, ObligationRelayDelivery, provider, client, bindingBytes) || obligation.Amount != nil {
			return errors.New("relay delivery obligation is missing or conflicts")
		}
	}
	if request.SponsorshipObligationID != "" {
		expectedServiceObligations[request.SponsorshipObligationID] = ObligationSponsorDelivery
		obligation := obligations[request.SponsorshipObligationID]
		if !sameBoundObligation(obligation, ObligationSponsorDelivery, provider, client, bindingBytes) || obligation.Amount == nil ||
			request.ProviderQuote.Body.ReservedSponsorship == nil || !sameAgreementAmount(*obligation.Amount, *request.ProviderQuote.Body.ReservedSponsorship) ||
			obligation.SettlementAdapterURI != DirectPaymentAdapterURI {
			return errors.New("gas sponsorship obligation is missing or conflicts")
		}
	}
	feeLines := make(map[string]FeeLine, len(request.ProviderQuote.Body.FeeLines))
	for _, line := range request.ProviderQuote.Body.FeeLines {
		feeLines[line.Kind] = line
	}
	seenKinds := make(map[string]struct{}, len(request.FeeObligationIDs))
	for _, obligationID := range request.FeeObligationIDs {
		obligation := obligations[obligationID]
		line, found := feeLines[obligation.Kind]
		if !found {
			return errors.New("relay service fee obligation kind is not quoted")
		}
		if _, duplicate := seenKinds[obligation.Kind]; duplicate {
			return errors.New("relay fee obligations contain a duplicate kind")
		}
		expectedServiceObligations[obligationID] = obligation.Kind
		if !sameBoundObligation(obligation, line.Kind, client, provider, bindingBytes) || obligation.Amount == nil ||
			!sameAgreementAmount(*obligation.Amount, line.Amount) {
			return errors.New("relay service fee obligation is missing or conflicts")
		}
		seenKinds[obligation.Kind] = struct{}{}
	}
	if len(seenKinds) != len(feeLines) {
		return errors.New("relay service fee obligation set is incomplete")
	}
	// The Agreement may contain unrelated business obligations, but every
	// reserved relay kind and every obligation that reuses this exact service
	// binding must be named exactly once by the execution request. Otherwise a
	// coordinator can authorize a second fee/liability that one implementation
	// ignores while another treats it as part of the relay transaction.
	for _, obligation := range agreement.Body.Obligations {
		expectedKind, expected := expectedServiceObligations[obligation.ObligationID]
		reservedKind := relayReservedObligationKind(obligation.Kind)
		reusesBinding := obligation.SubjectContentType == AgreementBindingContentType &&
			bytes.Equal(obligation.Subject, bindingBytes)
		if (reservedKind || reusesBinding) && (!expected || expectedKind != obligation.Kind) {
			return errors.New("relay Agreement contains an unreferenced or conflicting service obligation")
		}
	}
	return nil
}

func relayReservedObligationKind(kind string) bool {
	switch kind {
	case ObligationRelayDelivery, ObligationSponsorDelivery, ObligationRelayFee, ObligationSponsorshipFee:
		return true
	default:
		return false
	}
}

func sameBoundObligation(obligation agentcommerce.AgreementObligation, kind, obligor, beneficiary string, subject []byte) bool {
	return obligation.ObligationID != "" && obligation.Kind == kind && obligation.ObligorAgentID == obligor &&
		obligation.BeneficiaryAgentID == beneficiary && obligation.SubjectContentType == AgreementBindingContentType &&
		bytes.Equal(obligation.Subject, subject)
}

func validateRelayResolutionBody(body RelayResolutionBody) error {
	hasSponsorshipIdentity, validSponsorshipIdentity := validSponsorshipIdentityPair(
		body.SponsorshipStableActionID, body.SponsorshipExactRequestDigest)
	if body.SchemaVersion != 1 || !identifier(body.ProviderAgentID, 256) || validateNetworkDomain(body.Network) != nil ||
		!validAssuranceLevel(body.AssuranceLevel) ||
		!digestPattern.MatchString(body.StableActionID) ||
		!digestPattern.MatchString(body.ExactRequestDigest) || !digestPattern.MatchString(body.RelayExecutionDigest) ||
		body.StateRevision == 0 || body.ObservedAtUnix == 0 || body.ExpiresAtUnix <= body.ObservedAtUnix ||
		body.ExpiresAtUnix-body.ObservedAtUnix > 24*60*60 || len(body.TransactionReference) > 1024 ||
		len(body.SponsorshipTransferReference) > 1024 || !validSponsorshipIdentity ||
		hasSponsorshipIdentity != (body.SponsorshipValidUntilUnix != 0) ||
		body.SponsorshipTransferReference != "" && !hasSponsorshipIdentity {
		return errors.New("relay resolution body is invalid")
	}
	switch body.SponsorshipStatus {
	case "":
		if body.SponsorshipObservationDigest != "" {
			return errors.New("relay resolution carries an untyped sponsorship observation")
		}
	case SponsorshipResolutionObservedUnproven:
		if !hasSponsorshipIdentity || body.SponsorshipTransferReference != "" ||
			!digestPattern.MatchString(body.SponsorshipObservationDigest) ||
			(body.State != agentcommerce.ActionPrepared && body.State != agentcommerce.ActionSubmitted &&
				body.State != agentcommerce.ActionAccepted) {
			return errors.New("observed-unproven sponsorship resolution is invalid")
		}
	default:
		return errors.New("relay resolution carries an unknown sponsorship substate")
	}
	switch body.State {
	case agentcommerce.ActionPrepared, agentcommerce.ActionSubmitted,
		agentcommerce.ActionAccepted, agentcommerce.ActionRejected, agentcommerce.ActionConflict:
		if body.TerminalOutcome != "" || body.EvidenceSetDigest != "" {
			return errors.New("nonterminal relay resolution carries terminal evidence")
		}
	case agentcommerce.ActionTerminal:
		if !validOutcome(body.TerminalOutcome) || !digestPattern.MatchString(body.EvidenceSetDigest) {
			return errors.New("terminal relay resolution lacks exact evidence")
		}
	default:
		return errors.New("relay resolution state is unknown")
	}
	return nil
}

func validateRelayFinalityEvidenceBody(body RelayFinalityEvidenceBody) error {
	hasSponsorshipIdentity, validSponsorshipIdentity := validSponsorshipIdentityPair(
		body.SponsorshipStableActionID, body.SponsorshipExactRequestDigest)
	hasSponsorshipAbsence := len(body.SponsorshipAbsenceObservations) != 0
	hasTransactionAbsence := len(body.TransactionAbsenceObservations) != 0
	hasAnyAbsence := hasSponsorshipAbsence || hasTransactionAbsence
	hasSponsorshipTransactionEvidence := body.SponsorshipTransactionEvidence != nil
	relayPortableProofPresent := body.RelayValidatorAuthenticatedPortableProof != nil
	relayPortableProofAuthenticated := relayPortableProofPresent && *body.RelayValidatorAuthenticatedPortableProof
	if body.SchemaVersion != 1 || !identifier(body.ProviderAgentID, 256) || validateNetworkDomain(body.Network) != nil ||
		!validAssuranceLevel(body.AssuranceLevel) ||
		!digestPattern.MatchString(body.StableActionID) || !digestPattern.MatchString(body.ExactRequestDigest) ||
		!digestPattern.MatchString(body.RelayExecutionDigest) || !digestPattern.MatchString(body.SignedTransactionDigest) ||
		!cellHashPattern.MatchString(body.SignedTransactionCellHash) || body.TransactionValidUntilUnix == 0 ||
		!identifier(body.SourceAccount, 256) ||
		len(body.SponsorshipTransferReference) > 1024 || len(body.SubmittedTransactionHash) > 1024 ||
		len(body.SourceExecutionReference) > 1024 || body.ObservedAtUnix > ^uint64(0)-5*60 ||
		body.SigningAuthorityAtUnix == 0 || body.SigningAuthorityAtUnix > ^uint64(0)-5*60 ||
		body.ObservedAtUnix > body.SigningAuthorityAtUnix+5*60 ||
		!validOutcome(body.Outcome) || body.ObservedAtUnix == 0 || !sortedOptionalDigests(body.DestinationCreditReferences) ||
		!validSponsorshipIdentity || hasSponsorshipIdentity != (body.SponsorshipValidUntilUnix != 0) ||
		body.SponsorshipTransferReference != "" && !hasSponsorshipIdentity ||
		(body.SponsorshipTransferReference != "") != hasSponsorshipTransactionEvidence ||
		hasSponsorshipIdentity && body.SponsorshipTransferReference == "" && !hasSponsorshipAbsence ||
		body.SponsorshipTransferReference != "" && hasSponsorshipAbsence {
		return errors.New("relay finality evidence body is invalid")
	}
	if err := validateRelayAbsenceProofBundleForBody(body); err != nil {
		return err
	}
	hasRelayTerminal := body.RelayTerminalEvidenceClass != "" ||
		relayPortableProofPresent || body.RelayFinalizedCheckpointID != "" ||
		body.RelayFinalizedCheckpointSequence != 0 || body.RelayFinalizedCheckpointUnix != 0 ||
		body.RelayConfirmationDepth != 0 || len(body.RelayObservationDigests) != 0 ||
		body.SubmittedTransactionHash != "" || body.SourceExecutionReference != "" ||
		len(body.DestinationCreditReferences) != 0
	if body.RelayFinalityProfile != nil {
		if validateFinalityProfile(*body.RelayFinalityProfile) != nil {
			return errors.New("relay terminal profile is invalid")
		}
	} else if hasRelayTerminal {
		return errors.New("relay terminal result lacks its signed profile")
	}
	if hasRelayTerminal {
		profile := *body.RelayFinalityProfile
		validClass := body.RelayTerminalEvidenceClass == RelayTerminalValidatorFinality &&
			relayPortableProofPresent && relayPortableProofAuthenticated ||
			body.RelayTerminalEvidenceClass == RelayTerminalProviderCorroborated &&
				relayPortableProofPresent && !relayPortableProofAuthenticated &&
				body.AssuranceLevel != AssuranceAutonomousDecentralized
		if !validClass || profile.TerminalEvidenceClass != body.RelayTerminalEvidenceClass ||
			!identifier(body.RelayFinalizedCheckpointID, 1024) || body.RelayFinalizedCheckpointSequence == 0 ||
			body.RelayFinalizedCheckpointUnix == 0 ||
			body.RelayFinalizedCheckpointUnix > body.ObservedAtUnix+5*60 ||
			body.RelayConfirmationDepth < profile.MinimumConfirmationDepth ||
			!sortedDigests(body.RelayObservationDigests, MaxRelayEvidenceRefs) ||
			len(body.RelayObservationDigests) < int(profile.MinimumObservers) {
			return errors.New("relay terminal result does not meet its selected evidence profile")
		}
	}
	if body.SponsorshipTerminalProfile != nil {
		if validateFinalityProfile(*body.SponsorshipTerminalProfile) != nil ||
			!validSponsorshipTerminalClass(body.SponsorshipTerminalProfile.TerminalEvidenceClass,
				body.AssuranceLevel) {
			return errors.New("sponsorship terminal profile is invalid")
		}
	} else if hasSponsorshipIdentity || hasSponsorshipTransactionEvidence || hasAnyAbsence {
		return errors.New("sponsorship terminal result lacks its signed profile")
	}
	if hasSponsorshipTransactionEvidence {
		evidence := *body.SponsorshipTransactionEvidence
		networkDigest, networkErr := NetworkDomainDigest(body.Network)
		profile := *body.SponsorshipTerminalProfile
		if validateRelaySponsorshipTransactionEvidenceShape(evidence) != nil || networkErr != nil ||
			evidence.NetworkDigest != networkDigest ||
			evidence.SponsorshipStableActionID != body.SponsorshipStableActionID ||
			evidence.SponsorshipExactRequestDigest != body.SponsorshipExactRequestDigest ||
			evidence.ProviderSponsorValidUntilUnix != body.SponsorshipValidUntilUnix ||
			evidence.SubmittedTransactionHash != body.SponsorshipTransferReference ||
			evidence.DestinationSourceAccount != body.SourceAccount ||
			evidence.SponsorshipTerminalProfileDigest != profile.ProfileDigest ||
			evidence.TerminalEvidenceClass != profile.TerminalEvidenceClass ||
			evidence.ConfirmationDepth < profile.MinimumConfirmationDepth ||
			len(evidence.ObservationDigests) < int(profile.MinimumObservers) ||
			body.AssuranceLevel == AssuranceAutonomousDecentralized &&
				(evidence.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality ||
					!evidence.ValidatorAuthenticatedPortableProof) ||
			evidence.ObservedAtUnix > body.ObservedAtUnix+5*60 {
			return errors.New("relay sponsorship transaction evidence conflicts with its signed parent")
		}
		if evidence.TerminalEvidenceClass == SponsorshipTerminalClientCorroborated &&
			(profile.ProfileURI != ClientCorroboratedTerminalProfileURI ||
				(body.Outcome != OutcomeCorroboratedSponsorshipOnly && body.Outcome != OutcomeCorroboratedSuccess)) {
			return errors.New("client-corroborated sponsorship was relabeled as validator-finalized")
		}
	}
	if hasAnyAbsence {
		networkDigest, networkErr := NetworkDomainDigest(body.Network)
		profile := *body.SponsorshipTerminalProfile
		observationProfileURI := ""
		observationProfileDigest := ""
		if hasSponsorshipAbsence {
			observationProfileURI = body.SponsorshipAbsenceObservations[0].ObservationEvidenceProfileURI
			observationProfileDigest = body.SponsorshipAbsenceObservations[0].ObservationEvidenceProfileDigest
		} else {
			observationProfileURI = body.TransactionAbsenceObservations[0].ObservationEvidenceProfileURI
			observationProfileDigest = body.TransactionAbsenceObservations[0].ObservationEvidenceProfileDigest
		}
		context := relayAbsenceContext{providerAgentID: body.ProviderAgentID, networkDigest: networkDigest,
			relayStableActionID: body.StableActionID, relayExactRequestDigest: body.ExactRequestDigest,
			relayExecutionDigest: body.RelayExecutionDigest, sponsorshipStableActionID: body.SponsorshipStableActionID,
			sponsorshipExactRequestDigest: body.SponsorshipExactRequestDigest,
			sponsorshipValidUntilUnix:     body.SponsorshipValidUntilUnix,
			transactionValidUntilUnix:     body.TransactionValidUntilUnix,
			signedTransactionDigest:       body.SignedTransactionDigest, signedTransactionCellHash: body.SignedTransactionCellHash,
			observationEvidenceProfileURI:    observationProfileURI,
			observationEvidenceProfileDigest: observationProfileDigest,
			sponsorshipTerminalProfile:       profile, relayFinalityProfile: body.RelayFinalityProfile,
			maximumObservedAtUnix: body.ObservedAtUnix, outcome: body.Outcome}
		var absenceErr error
		var merged []string
		switch {
		case hasSponsorshipAbsence && hasTransactionAbsence:
			merged, absenceErr = validateRelayAbsenceObservationSets(body.SponsorshipAbsenceObservations,
				body.TransactionAbsenceObservations, context)
			if body.SponsorshipTransferReference != "" || hasRelayTerminal ||
				!safeTerminalAbsenceOutcome(body.Outcome) {
				absenceErr = errors.New("whole-negative absence shape conflicts with side-effect evidence")
			}
		case hasSponsorshipAbsence:
			merged, absenceErr = validateRelaySponsorshipAbsenceObservationSet(
				body.SponsorshipAbsenceObservations, context)
			relayOnly := (body.Outcome == OutcomeFinalizedRelayOnly ||
				body.Outcome == OutcomeCorroboratedRelayOnly) && hasRelayTerminal &&
				body.SubmittedTransactionHash != "" && body.SourceExecutionReference != ""
			sponsorOnlyNegative := safeTerminalAbsenceOutcome(body.Outcome) && !hasRelayTerminal &&
				body.SubmittedTransactionHash == "" && body.SourceExecutionReference == ""
			if body.SponsorshipTransferReference != "" || (!relayOnly && !sponsorOnlyNegative) {
				absenceErr = errors.New("relay-only component outcome has invalid side-effect evidence")
			}
		case hasTransactionAbsence:
			merged, absenceErr = validateRelayTransactionAbsenceObservationSet(
				body.TransactionAbsenceObservations, context)
			if body.Outcome != OutcomeFinalizedSponsorshipOnly &&
				body.Outcome != OutcomeCorroboratedSponsorshipOnly ||
				body.SponsorshipTransferReference == "" || body.SponsorshipTransactionEvidence == nil || hasRelayTerminal {
				absenceErr = errors.New("sponsorship-only component outcome has invalid side-effect evidence")
			}
		}
		if !hasSponsorshipIdentity || networkErr != nil || absenceErr != nil || len(merged) == 0 {
			return errors.New("relay finality sponsorship absence evidence is invalid")
		}
	}
	switch body.Outcome {
	case OutcomeFinalizedSuccess:
		if !hasRelayTerminal || body.SubmittedTransactionHash == "" || body.SourceExecutionReference == "" ||
			hasAnyAbsence ||
			body.RelayTerminalEvidenceClass != RelayTerminalValidatorFinality ||
			body.SponsorshipTransactionEvidence != nil &&
				body.SponsorshipTransactionEvidence.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality {
			return errors.New("successful relay evidence lacks source execution")
		}
	case OutcomeCorroboratedSuccess:
		allValidator := body.RelayTerminalEvidenceClass == RelayTerminalValidatorFinality &&
			(body.SponsorshipTransactionEvidence == nil ||
				body.SponsorshipTransactionEvidence.TerminalEvidenceClass == SponsorshipTerminalValidatorFinality)
		if body.AssuranceLevel == AssuranceAutonomousDecentralized || !hasRelayTerminal || hasAnyAbsence || allValidator ||
			body.SubmittedTransactionHash == "" || body.SourceExecutionReference == "" {
			return errors.New("corroborated relay success overstates or understates its selected assurance")
		}
	case OutcomeFinalizedSponsorshipOnly, OutcomeCorroboratedSponsorshipOnly:
		if body.SponsorshipTransferReference == "" || !hasSponsorshipIdentity || hasSponsorshipAbsence ||
			body.SubmittedTransactionHash != "" ||
			body.SourceExecutionReference != "" || len(body.DestinationCreditReferences) != 0 ||
			body.SponsorshipTransactionEvidence == nil ||
			body.Outcome == OutcomeFinalizedSponsorshipOnly &&
				(body.SponsorshipTransactionEvidence.TerminalEvidenceClass != SponsorshipTerminalValidatorFinality ||
					!body.SponsorshipTransactionEvidence.ValidatorAuthenticatedPortableProof ||
					hasTransactionAbsence && body.TransactionAbsenceObservations[0].TerminalEvidenceClass !=
						RelayTerminalValidatorFinality) ||
			body.Outcome == OutcomeCorroboratedSponsorshipOnly &&
				(body.AssuranceLevel == AssuranceAutonomousDecentralized ||
					body.SponsorshipTransactionEvidence.TerminalEvidenceClass == SponsorshipTerminalValidatorFinality &&
						(!hasTransactionAbsence || body.TransactionAbsenceObservations[0].TerminalEvidenceClass ==
							RelayTerminalValidatorFinality)) ||
			hasRelayTerminal {
			return errors.New("sponsorship-only evidence is invalid")
		}
	case OutcomeFinalizedRelayOnly, OutcomeCorroboratedRelayOnly:
		allValidator := body.RelayTerminalEvidenceClass == RelayTerminalValidatorFinality &&
			relayPortableProofAuthenticated && hasSponsorshipAbsence &&
			body.SponsorshipAbsenceObservations[0].TerminalEvidenceClass == SponsorshipTerminalValidatorFinality
		if body.AssuranceLevel == AssuranceAutonomousDecentralized && !allValidator ||
			!hasSponsorshipAbsence || hasTransactionAbsence || body.SponsorshipTransferReference != "" ||
			body.SponsorshipTransactionEvidence != nil || !hasRelayTerminal ||
			body.SubmittedTransactionHash == "" || body.SourceExecutionReference == "" ||
			body.Outcome == OutcomeFinalizedRelayOnly && !allValidator ||
			body.Outcome == OutcomeCorroboratedRelayOnly && allValidator {
			return errors.New("relay-only component evidence is invalid")
		}
	case OutcomeFinalizedExpired, OutcomeFinalizedAbsent, OutcomeFinalizedInvalidated:
		if hasSponsorshipAbsence {
			if body.SponsorshipTerminalProfile == nil || body.SponsorshipTerminalProfile.TerminalEvidenceClass !=
				SponsorshipTerminalValidatorFinality ||
				body.SponsorshipAbsenceObservations[0].TerminalEvidenceClass != RelayTerminalValidatorFinality ||
				hasTransactionAbsence &&
					body.TransactionAbsenceObservations[0].TerminalEvidenceClass != RelayTerminalValidatorFinality {
				return errors.New("validator-finalized sponsorship absence lacks validator evidence")
			}
		} else if !hasRelayTerminal || body.RelayTerminalEvidenceClass != RelayTerminalValidatorFinality {
			return errors.New("validator-finalized relay result lacks validator evidence")
		}
	case OutcomeCorroboratedExpired, OutcomeCorroboratedAbsent, OutcomeCorroboratedInvalidated:
		if body.AssuranceLevel == AssuranceAutonomousDecentralized {
			return errors.New("corroborated negative outcome is invalid for autonomous assurance")
		}
		if hasSponsorshipAbsence {
			allValidator := body.SponsorshipAbsenceObservations[0].TerminalEvidenceClass ==
				RelayTerminalValidatorFinality && (!hasTransactionAbsence ||
				body.TransactionAbsenceObservations[0].TerminalEvidenceClass == RelayTerminalValidatorFinality)
			if body.SponsorshipTerminalProfile == nil || allValidator {
				return errors.New("corroborated absence lacks a selected lower-assurance predicate")
			}
		} else if !hasRelayTerminal || body.RelayTerminalEvidenceClass != RelayTerminalProviderCorroborated {
			return errors.New("corroborated relay result lacks its Provider predicate")
		}
	}
	return nil
}

func validateRelaySponsorshipTransactionEvidenceShape(evidence RelaySponsorshipTransactionEvidence) error {
	paymentDigest, paymentDigestErr := agentcommerce.AgreementPaymentRequestDigest(evidence.AgreementPaymentRequest)
	paymentCanonical, _, paymentMaterialErr := agentcommerce.PaymentAuthorizationMaterial(evidence.AgreementPaymentRequest)
	paymentExactDigest, paymentExactDigestErr := agentcommerce.ExactRequestDigest(paymentCanonical)
	proofBundleDigest := ""
	var proofBundleDigestErr error
	if len(evidence.ProofBundle) != 0 {
		proofBundleDigest, proofBundleDigestErr = RelaySponsorshipProofBundleDigest(evidence.ProofBundle)
	}
	validTerminalClass := evidence.TerminalEvidenceClass == SponsorshipTerminalValidatorFinality &&
		evidence.ValidatorAuthenticatedPortableProof ||
		evidence.TerminalEvidenceClass == SponsorshipTerminalClientCorroborated &&
			!evidence.ValidatorAuthenticatedPortableProof
	if evidence.SchemaVersion != 1 || !validTerminalClass || !digestPattern.MatchString(evidence.NetworkDigest) ||
		evidence.AgreementPaymentRequest.SchemaVersion != 3 || paymentDigestErr != nil ||
		paymentMaterialErr != nil || paymentExactDigestErr != nil ||
		paymentDigest != evidence.AgreementPaymentRequestDigest ||
		evidence.AgreementPaymentRequest.NetworkDomainDigest != evidence.NetworkDigest ||
		evidence.AgreementPaymentRequest.StableActionID != evidence.SponsorshipStableActionID ||
		paymentExactDigest != evidence.SponsorshipExactRequestDigest ||
		string(evidence.AgreementPaymentRequest.Destination) != evidence.DestinationSourceAccount ||
		evidence.AgreementPaymentRequest.ExpiresAtUnix != evidence.ProviderSponsorValidUntilUnix ||
		evidence.AgreementPaymentRequest.Amount.AssetNamespace != evidence.Amount.Asset.AssetNamespace ||
		evidence.AgreementPaymentRequest.Amount.AssetIdentifier != evidence.Amount.Asset.AssetIdentifier ||
		evidence.AgreementPaymentRequest.Amount.Unit != evidence.Amount.Asset.Unit ||
		evidence.AgreementPaymentRequest.Amount.AmountAtomic != evidence.Amount.AmountAtomic ||
		!digestPattern.MatchString(evidence.AgreementPaymentRequestDigest) ||
		!digestPattern.MatchString(evidence.SponsorshipStableActionID) ||
		!digestPattern.MatchString(evidence.SponsorshipExactRequestDigest) ||
		!identifier(evidence.ProviderSponsorSourceAccount, 256) ||
		evidence.ProviderSponsorValidUntilUnix == 0 ||
		!digestPattern.MatchString(evidence.SignedTopUpTransactionDigest) ||
		!cellHashPattern.MatchString(evidence.SignedTopUpTransactionCellHash) ||
		!cellHashPattern.MatchString(evidence.SponsorshipPaymentCommitmentCellHash) ||
		!identifier(evidence.DestinationSourceAccount, 256) || validateAmount(evidence.Amount, true) != nil ||
		!identifier(evidence.SubmittedTransactionHash, 1024) ||
		!identifier(evidence.SourceExecutionReference, 1024) ||
		!sortedDigests(evidence.DestinationCreditReferences, MaxRelayEvidenceRefs) ||
		!identifier(evidence.FinalizedCheckpointID, 1024) || evidence.FinalizedCheckpointSequence == 0 ||
		evidence.FinalizedCheckpointUnix == 0 || evidence.ConfirmationDepth == 0 ||
		!digestPattern.MatchString(evidence.SponsorshipTerminalProfileDigest) ||
		!sortedDigests(evidence.ObservationDigests, MaxRelayEvidenceRefs) ||
		!digestPattern.MatchString(evidence.ProofBundleDigest) ||
		len(evidence.ProofBundle) == 0 && evidence.PortableProofLocator == "" ||
		len(evidence.ProofBundle) != 0 && (proofBundleDigestErr != nil || proofBundleDigest != evidence.ProofBundleDigest) ||
		evidence.PortableProofLocator != "" && !identifier(evidence.PortableProofLocator, 1024) ||
		evidence.ObservedAtUnix == 0 || evidence.FinalizedCheckpointUnix > evidence.ObservedAtUnix+5*60 {
		return errors.New("relay sponsorship transaction evidence is invalid")
	}
	return nil
}

func validateRelaySponsorshipCreditObservationShape(observation RelaySponsorshipCreditObservation) error {
	paymentDigest, paymentDigestErr := agentcommerce.AgreementPaymentRequestDigest(observation.AgreementPaymentRequest)
	paymentCanonical, _, paymentMaterialErr := agentcommerce.PaymentAuthorizationMaterial(observation.AgreementPaymentRequest)
	paymentExactDigest, paymentExactDigestErr := agentcommerce.ExactRequestDigest(paymentCanonical)
	if observation.SchemaVersion != 1 || !digestPattern.MatchString(observation.NetworkDigest) ||
		observation.AgreementPaymentRequest.SchemaVersion != 3 || paymentDigestErr != nil ||
		paymentMaterialErr != nil || paymentExactDigestErr != nil ||
		paymentDigest != observation.AgreementPaymentRequestDigest ||
		observation.AgreementPaymentRequest.NetworkDomainDigest != observation.NetworkDigest ||
		observation.AgreementPaymentRequest.StableActionID != observation.SponsorshipStableActionID ||
		paymentExactDigest != observation.SponsorshipExactRequestDigest ||
		string(observation.AgreementPaymentRequest.Destination) != observation.DestinationSourceAccount ||
		observation.AgreementPaymentRequest.ExpiresAtUnix != observation.ProviderSponsorValidUntilUnix ||
		observation.AgreementPaymentRequest.Amount.AssetNamespace != observation.Amount.Asset.AssetNamespace ||
		observation.AgreementPaymentRequest.Amount.AssetIdentifier != observation.Amount.Asset.AssetIdentifier ||
		observation.AgreementPaymentRequest.Amount.Unit != observation.Amount.Asset.Unit ||
		observation.AgreementPaymentRequest.Amount.AmountAtomic != observation.Amount.AmountAtomic ||
		!digestPattern.MatchString(observation.AgreementPaymentRequestDigest) ||
		!digestPattern.MatchString(observation.SponsorshipStableActionID) ||
		!digestPattern.MatchString(observation.SponsorshipExactRequestDigest) ||
		!identifier(observation.ProviderSponsorSourceAccount, 256) || observation.ProviderSponsorValidUntilUnix == 0 ||
		!digestPattern.MatchString(observation.SignedTopUpTransactionDigest) ||
		!cellHashPattern.MatchString(observation.SignedTopUpTransactionCellHash) ||
		!cellHashPattern.MatchString(observation.SponsorshipPaymentCommitmentCellHash) ||
		!identifier(observation.DestinationSourceAccount, 256) || validateAmount(observation.Amount, true) != nil ||
		!identifier(observation.SubmittedTransactionHash, 1024) ||
		!identifier(observation.SourceExecutionReference, 1024) ||
		!sortedDigests(observation.DestinationCreditReferences, MaxRelayEvidenceRefs) ||
		observation.EvidenceProfileURI != RPCCorroborationEvidenceProfileURI ||
		!digestPattern.MatchString(observation.EvidenceProfileDigest) ||
		!identifier(observation.ObservedCheckpointID, 1024) || observation.ObservedCheckpointSequence == 0 ||
		observation.ObservedCheckpointUnix == 0 ||
		!sortedDigests(observation.ObservationDigests, MaxRelayEvidenceRefs) ||
		observation.ObservedAtUnix == 0 || observation.ObservedCheckpointUnix > observation.ObservedAtUnix+5*60 {
		return errors.New("relay sponsorship credit observation is invalid")
	}
	return nil
}

func validateNetworkDomain(network NetworkDomain) error {
	if !identifier(network.NetworkID, 128) || !digestPattern.MatchString(network.ZeroStateRootHash) ||
		!digestPattern.MatchString(network.ZeroStateFileHash) {
		return errors.New("relay network domain is invalid")
	}
	return nil
}

func validateFinalityProfile(profile FinalityProfile) error {
	if !identifier(profile.ProfileURI, 256) || !digestPattern.MatchString(profile.ProfileDigest) ||
		(profile.TerminalEvidenceClass != RelayTerminalValidatorFinality &&
			profile.TerminalEvidenceClass != RelayTerminalProviderCorroborated &&
			profile.TerminalEvidenceClass != SponsorshipTerminalClientCorroborated) ||
		profile.MinimumConfirmationDepth == 0 || profile.MinimumObservers == 0 || profile.MinimumOperatorDomains == 0 ||
		profile.MinimumOperatorDomains > profile.MinimumObservers || profile.MaximumResolutionSeconds == 0 ||
		profile.MaximumResolutionSeconds > 24*60*60 || profile.ReorgWindowSeconds > profile.MaximumResolutionSeconds {
		return errors.New("relay finality profile is invalid")
	}
	switch profile.TerminalEvidenceClass {
	case RelayTerminalProviderCorroborated:
		if profile.ProfileURI != ProviderCorroboratedTerminalProfileURI {
			return errors.New("provider-corroborated relay profile URI is invalid")
		}
	case SponsorshipTerminalClientCorroborated:
		if profile.ProfileURI != ClientCorroboratedTerminalProfileURI {
			return errors.New("client-corroborated sponsorship profile URI is invalid")
		}
	}
	return nil
}

func validateAsset(asset AssetIdentity) error {
	if !identifier(asset.AssetNamespace, 128) || !identifier(asset.AssetIdentifier, 256) || !identifier(asset.Unit, 128) {
		return errors.New("relay asset identity is invalid")
	}
	return nil
}

func validateAmount(amount AssetAmount, positive bool) error {
	if err := validateAsset(amount.Asset); err != nil || !canonicalAtomic(amount.AmountAtomic) || positive && amount.AmountAtomic == "0" {
		return errors.New("relay asset amount is invalid")
	}
	return nil
}

func validateEndpoint(value string) error {
	if len(value) == 0 || len(value) > 2048 {
		return errors.New("relay endpoint is invalid")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" || parsed.Path == "" {
		return errors.New("relay endpoint must be an HTTPS origin path without credentials, query, or fragment")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || nonPublicRelayIPLiteral(host) {
		return errors.New("relay endpoint cannot target a local, private, or reserved address")
	}
	return nil
}

func nonPublicRelayIPLiteral(host string) bool {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return true
	}
	// Go classifies documentation and benchmarking ranges as global unicast;
	// they are not globally reachable service authorities.
	for _, raw := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b:1::/48", "100::/64", "2001::/23", "2002::/16", "3fff::/20", "5f00::/16",
	} {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func validMode(mode Mode) bool {
	return mode == ModeRelayExact || mode == ModeSponsorOnly || mode == ModeSponsorAndRelay
}

func validAssuranceLevel(level AssuranceLevel) bool {
	return level == AssuranceTrustedLocal || level == AssuranceAuthorizedSingleProvider ||
		level == AssuranceAutonomousDecentralized
}

func validOutcome(outcome TerminalOutcome) bool {
	switch outcome {
	case OutcomeFinalizedSuccess, OutcomeFinalizedExpired, OutcomeFinalizedAbsent,
		OutcomeFinalizedInvalidated, OutcomeFinalizedSponsorshipOnly,
		OutcomeFinalizedRelayOnly,
		OutcomeCorroboratedExpired, OutcomeCorroboratedAbsent, OutcomeCorroboratedInvalidated,
		OutcomeCorroboratedSponsorshipOnly, OutcomeCorroboratedRelayOnly,
		OutcomeCorroboratedSuccess:
		return true
	default:
		return false
	}
}

func identifier(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func canonicalAtomic(value string) bool {
	if value == "0" {
		return true
	}
	if len(value) == 0 || len(value) > 78 || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func positiveAtomic(value string) bool { return canonicalAtomic(value) && value != "0" }

func compareAtomic(left, right string) int {
	a, okA := new(big.Int).SetString(left, 10)
	b, okB := new(big.Int).SetString(right, 10)
	if !okA || !okB {
		return 1
	}
	return a.Cmp(b)
}

func addAtomic(left, right string) string {
	a, _ := new(big.Int).SetString(left, 10)
	b, _ := new(big.Int).SetString(right, 10)
	return new(big.Int).Add(a, b).String()
}

func sameAsset(left, right AssetIdentity) bool { return left == right }

func sameAmount(left, right AssetAmount) bool {
	return sameAsset(left.Asset, right.Asset) && left.AmountAtomic == right.AmountAtomic
}

func sameAgreementAmount(left agentcommerce.AgreementAmount, right AssetAmount) bool {
	return left.AssetNamespace == right.Asset.AssetNamespace && left.AssetIdentifier == right.Asset.AssetIdentifier &&
		left.Unit == right.Asset.Unit && left.AmountAtomic == right.AmountAtomic && left.AmountDecimal == ""
}

func sortedNetworkDomains(values []NetworkDomain) bool {
	for index, value := range values {
		if validateNetworkDomain(value) != nil {
			return false
		}
		if index > 0 && !networkDomainLess(values[index-1], value) {
			return false
		}
	}
	return true
}

func networkDomainLess(left, right NetworkDomain) bool {
	if left.NetworkID != right.NetworkID {
		return left.NetworkID < right.NetworkID
	}
	if left.GlobalID != right.GlobalID {
		return left.GlobalID < right.GlobalID
	}
	if left.ZeroStateRootHash != right.ZeroStateRootHash {
		return left.ZeroStateRootHash < right.ZeroStateRootHash
	}
	if left.ZeroStateFileHash != right.ZeroStateFileHash {
		return left.ZeroStateFileHash < right.ZeroStateFileHash
	}
	return left.WorkchainID < right.WorkchainID
}

func sortedModes(values []Mode) bool {
	previous := Mode("")
	for _, value := range values {
		if !validMode(value) || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func sortedAssuranceLevels(values []AssuranceLevel) bool {
	previous := AssuranceLevel("")
	for _, value := range values {
		if !validAssuranceLevel(value) || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func sortedTransactionProfiles(values []TransactionProfile) bool {
	previous := ""
	for _, value := range values {
		key := value.ProfileURI + "\x00" + value.ProfileDigest
		if key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func sortedFinalityProfiles(values []FinalityProfile) bool {
	previous := ""
	for _, value := range values {
		key := value.ProfileURI + "\x00" + value.ProfileDigest
		if key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func assetKey(value AssetIdentity) string {
	return value.AssetNamespace + "\x00" + value.AssetIdentifier + "\x00" + value.Unit
}

func sortedAssets(values []AssetIdentity) bool {
	previous := ""
	for _, value := range values {
		key := assetKey(value)
		if key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func sortedExposureLimits(values []ExposureLimit) bool {
	previous := ""
	for _, value := range values {
		key := assetKey(value.Asset)
		if key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func sortedFeeLines(values []FeeLine) bool {
	previous := ""
	for _, value := range values {
		if value.Kind <= previous {
			return false
		}
		previous = value.Kind
	}
	return true
}

func sortedIdentifiers(values []string, maximum int) bool {
	if len(values) == 0 || len(values) > maximum {
		return false
	}
	for index, value := range values {
		if !identifier(value, 128) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func sortedDigests(values []string, maximum int) bool {
	if len(values) == 0 || len(values) > maximum {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func containsMode(values []Mode, wanted Mode) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= wanted })
	return index < len(values) && values[index] == wanted
}

func containsAssuranceLevel(values []AssuranceLevel, wanted AssuranceLevel) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= wanted })
	return index < len(values) && values[index] == wanted
}

func containsNetwork(values []NetworkDomain, wanted NetworkDomain) bool {
	for _, candidate := range values {
		if candidate == wanted {
			return true
		}
	}
	return false
}

func findTransactionProfile(values []TransactionProfile, uri, digest string) (TransactionProfile, bool) {
	for _, candidate := range values {
		if candidate.ProfileURI == uri && candidate.ProfileDigest == digest {
			return candidate, true
		}
	}
	return TransactionProfile{}, false
}

func findFinalityProfile(values []FinalityProfile, uri, digest string) (FinalityProfile, bool) {
	for _, candidate := range values {
		if candidate.ProfileURI == uri && candidate.ProfileDigest == digest {
			return candidate, true
		}
	}
	return FinalityProfile{}, false
}

func containsAsset(values []AssetIdentity, wanted AssetIdentity) bool {
	for _, candidate := range values {
		if candidate == wanted {
			return true
		}
	}
	return false
}

func withinExposure(values []ExposureLimit, amount AssetAmount) bool {
	limit, found := findExposureLimit(values, amount.Asset)
	return found && compareAtomic(amount.AmountAtomic, limit.MaximumPerRequestAtomic) <= 0
}

func findExposureLimit(values []ExposureLimit, asset AssetIdentity) (ExposureLimit, bool) {
	for _, candidate := range values {
		if sameAsset(candidate.Asset, asset) {
			return candidate, true
		}
	}
	return ExposureLimit{}, false
}
