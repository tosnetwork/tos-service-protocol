package agentguarantor

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	FirmOfferAgreementEvidenceProfileURI  = "tos.service.agreement.evidence.guarantor-firm-offer.v1"
	FirmOfferAgreementEvidenceContentType = "application/vnd.tos.service.agent-guarantor-firm-offer-agreement-evidence.v1+cbor"
)

type FirmOfferAgreementEvidenceProfileDescriptorV1 struct {
	ProfileURI     string `json:"profile_uri"`
	ProfileVersion uint64 `json:"profile_version"`
	ContentType    string `json:"content_type"`
	GroupRule      string `json:"group_rule"`
	TargetRule     string `json:"target_rule"`
	Verifier       string `json:"verifier"`
}

func FirmOfferAgreementEvidenceProfileV1() ProfileRefV1 {
	descriptor := FirmOfferAgreementEvidenceProfileDescriptorV1{ProfileURI: FirmOfferAgreementEvidenceProfileURI,
		ProfileVersion: 1, ContentType: FirmOfferAgreementEvidenceContentType,
		GroupRule: "complete-subject-profile-group", TargetRule: "agreement-predicate-target-v1",
		Verifier: "tos.service.agent-guarantor.verify.firm-offer-agreement-evidence.v1"}
	digest, _ := guarantorCodec.Digest("tos.service.agreement.evidence-profile.guarantor-firm-offer.v1", descriptor)
	return ProfileRefV1{ProfileURI: descriptor.ProfileURI, ProfileVersion: descriptor.ProfileVersion, ProfileDigest: digest}
}

type GuarantorSatisfiedPredicateTargetV1 struct {
	PredicateID            string `json:"predicate_id"`
	TargetProjectionDigest string `json:"target_projection_digest"`
}

type GuarantorFirmOfferAgreementEvidenceV1 struct {
	SchemaVersion                     uint16                                `json:"schema_version"`
	EvidenceProfile                   ProfileRefV1                          `json:"evidence_profile"`
	AgreementBodyDigest               string                                `json:"agreement_body_digest"`
	GuarantorAgentID                  string                                `json:"guarantor_agent_id"`
	SatisfiedPredicateTargets         []GuarantorSatisfiedPredicateTargetV1 `json:"satisfied_predicate_targets"`
	AuthorizedFirmOfferEnvelopeDigest string                                `json:"authorized_firm_offer_envelope_digest"`
	AuthorizedFirmOffer               AuthorizedFirmCoverageOfferV1         `json:"authorized_firm_offer"`
}

type GuarantorAgreementAuthorizationEvidenceSetV1 struct {
	SchemaVersion       uint16                                         `json:"schema_version"`
	AgreementID         string                                         `json:"agreement_id"`
	AgreementVersion    uint64                                         `json:"agreement_version"`
	AgreementBodyDigest string                                         `json:"agreement_body_digest"`
	Evidence            []agentcommerce.AgreementAuthorizationEvidence `json:"evidence"`
}

func AgreementAuthorizationEvidenceSetDigestV1(value GuarantorAgreementAuthorizationEvidenceSetV1) (string, error) {
	if err := ValidateAgreementAuthorizationEvidenceSetV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-agreement-authorization-evidence-set.v1", value)
}

func ValidateAgreementAuthorizationEvidenceSetV1(value GuarantorAgreementAuthorizationEvidenceSetV1) error {
	if value.SchemaVersion != 1 || !validID(value.AgreementID) || value.AgreementVersion == 0 ||
		!validDigest(value.AgreementBodyDigest) || len(value.Evidence) == 0 || len(value.Evidence) > MaxAuthorizations {
		return errors.New("Guarantor Agreement authorization evidence set is invalid")
	}
	var prior []byte
	seen := make(map[string]struct{}, len(value.Evidence))
	for _, evidence := range value.Evidence {
		if evidence.AgreementID != value.AgreementID || evidence.AgreementVersion != value.AgreementVersion ||
			evidence.AgreementBodyDigest != value.AgreementBodyDigest {
			return errors.New("Guarantor Agreement evidence set mixes Agreement contexts")
		}
		encoded, err := guarantorCodec.Marshal(evidence)
		identity, identityErr := guarantorCodec.Digest("tos.service.agent-guarantor-agreement-evidence-identity.v1", struct {
			AuthoritySubject agentcommerce.AgreementAuthoritySubject `json:"authority_subject"`
			ProfileURI       string                                  `json:"profile_uri"`
			ProfileVersion   uint32                                  `json:"profile_version"`
			ProfileDigest    string                                  `json:"profile_digest"`
			PredicateIDs     []string                                `json:"predicate_ids"`
		}{evidence.AuthoritySubject, evidence.EvidenceProfileURI, evidence.EvidenceProfileVersion,
			evidence.EvidenceProfileDigest, evidence.PredicateIDs})
		if err != nil || identityErr != nil || prior != nil && bytes.Compare(prior, encoded) >= 0 {
			return errors.New("Guarantor Agreement evidence set is unsorted or duplicated")
		}
		if _, duplicate := seen[identity]; duplicate {
			return errors.New("Guarantor Agreement evidence semantic identity is duplicated")
		}
		seen[identity] = struct{}{}
		prior = encoded
	}
	return nil
}

func NewFirmOfferAgreementEvidenceV1(offer AuthorizedFirmCoverageOfferV1, agreement agentcommerce.AgentAgreementBody,
	resolver AuthorityKeyResolver, publicationResolver agentcommerce.AgentOperationAuthorityResolver,
	underlyingResolver UnderlyingAgreementResolver, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	now time.Time) (agentcommerce.AgreementAuthorizationEvidence, error) {
	if err := VerifyFirmOffer(offer, offer.AuthorizedQuoteRequest, agreement, resolver, publicationResolver,
		underlyingResolver, agreementVerifier, now); err != nil {
		return agentcommerce.AgreementAuthorizationEvidence{}, err
	}
	agreementDigest, _ := agentcommerce.AgreementBodyDigest(agreement)
	offerDigest, _ := FirmOfferDigest(offer)
	profile := FirmOfferAgreementEvidenceProfileV1()
	var subject agentcommerce.AgreementAuthoritySubject
	targets := make([]GuarantorSatisfiedPredicateTargetV1, 0)
	predicateIDs := make([]string, 0)
	targetDigests := make([]string, 0)
	for _, predicate := range agreement.AuthorizationPredicates {
		if predicate.AuthoritySubject.SubjectIdentifier != offer.Body.GuarantorAgentID ||
			predicate.EvidenceProfileURI != profile.ProfileURI || uint64(predicate.EvidenceProfileVersion) != profile.ProfileVersion ||
			predicate.EvidenceProfileDigest != profile.ProfileDigest {
			continue
		}
		if len(predicateIDs) > 0 && subject != predicate.AuthoritySubject {
			return agentcommerce.AgreementAuthorizationEvidence{}, errors.New("firm offer predicates use multiple Guarantor subjects")
		}
		subject = predicate.AuthoritySubject
		predicateIDs = append(predicateIDs, predicate.PredicateID)
		targetDigests = append(targetDigests, predicate.EvidenceTargetProjectionDigest)
		targets = append(targets, GuarantorSatisfiedPredicateTargetV1{PredicateID: predicate.PredicateID,
			TargetProjectionDigest: predicate.EvidenceTargetProjectionDigest})
	}
	if len(predicateIDs) == 0 || !equalCanonical(targets, offer.Body.GuarantorPredicateTargets) || offer.Body.GuarantorEvidenceProfile != profile {
		return agentcommerce.AgreementAuthorizationEvidence{}, errors.New("firm offer does not satisfy the complete Agreement Guarantor predicate group")
	}
	typed := GuarantorFirmOfferAgreementEvidenceV1{SchemaVersion: 1, EvidenceProfile: profile,
		AgreementBodyDigest: agreementDigest, GuarantorAgentID: offer.Body.GuarantorAgentID,
		SatisfiedPredicateTargets: targets, AuthorizedFirmOfferEnvelopeDigest: offerDigest, AuthorizedFirmOffer: offer}
	canonical, err := guarantorCodec.Marshal(typed)
	if err != nil {
		return agentcommerce.AgreementAuthorizationEvidence{}, err
	}
	return agentcommerce.AgreementAuthorizationEvidence{AgreementID: agreement.AgreementID, AgreementVersion: agreement.Version,
		AgreementBodyDigest: agreementDigest, AuthoritySubject: subject, PredicateIDs: predicateIDs,
		EvidenceProfileURI: profile.ProfileURI, EvidenceProfileVersion: uint32(profile.ProfileVersion),
		EvidenceProfileDigest: profile.ProfileDigest, EvidenceTargetProjectionDigests: targetDigests,
		EvidenceContentType: FirmOfferAgreementEvidenceContentType, Evidence: canonical}, nil
}

func VerifyFirmOfferAgreementEvidenceV1(wrapper agentcommerce.AgreementAuthorizationEvidence,
	agreement agentcommerce.AgentAgreementBody, resolver AuthorityKeyResolver,
	publicationResolver agentcommerce.AgentOperationAuthorityResolver, underlyingResolver UnderlyingAgreementResolver,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, now time.Time) error {
	profile := FirmOfferAgreementEvidenceProfileV1()
	if wrapper.EvidenceProfileURI != profile.ProfileURI || uint64(wrapper.EvidenceProfileVersion) != profile.ProfileVersion ||
		wrapper.EvidenceProfileDigest != profile.ProfileDigest || wrapper.EvidenceContentType != FirmOfferAgreementEvidenceContentType {
		return errors.New("firm-offer Agreement evidence profile is invalid")
	}
	var value GuarantorFirmOfferAgreementEvidenceV1
	if err := guarantorCodec.Unmarshal(wrapper.Evidence, &value); err != nil {
		return err
	}
	agreementDigest, err := agentcommerce.AgreementBodyDigest(agreement)
	offerDigest, offerErr := FirmOfferDigest(value.AuthorizedFirmOffer)
	if err != nil || offerErr != nil || wrapper.AgreementID != agreement.AgreementID || wrapper.AgreementVersion != agreement.Version ||
		wrapper.AgreementBodyDigest != agreementDigest || value.SchemaVersion != 1 || value.EvidenceProfile != profile ||
		value.AgreementBodyDigest != agreementDigest || value.GuarantorAgentID != value.AuthorizedFirmOffer.Body.GuarantorAgentID ||
		value.AuthorizedFirmOfferEnvelopeDigest != offerDigest ||
		VerifyFirmOffer(value.AuthorizedFirmOffer, value.AuthorizedFirmOffer.AuthorizedQuoteRequest,
			agreement, resolver, publicationResolver, underlyingResolver, agreementVerifier, now) != nil {
		return errors.New("firm-offer Agreement evidence binding is invalid")
	}
	expected, buildErr := NewFirmOfferAgreementEvidenceV1(value.AuthorizedFirmOffer, agreement, resolver,
		publicationResolver, underlyingResolver, agreementVerifier, now)
	if buildErr != nil || !equalCanonical(expected, wrapper) {
		return errors.New("firm-offer Agreement evidence differs from its canonical projection")
	}
	return nil
}

func verifyFirmOfferAgreementEvidenceAgainstOfferV1(wrapper agentcommerce.AgreementAuthorizationEvidence,
	agreement agentcommerce.AgentAgreementBody, offer AuthorizedFirmCoverageOfferV1) error {
	profile := FirmOfferAgreementEvidenceProfileV1()
	var value GuarantorFirmOfferAgreementEvidenceV1
	if wrapper.EvidenceProfileURI != profile.ProfileURI || uint64(wrapper.EvidenceProfileVersion) != profile.ProfileVersion ||
		wrapper.EvidenceProfileDigest != profile.ProfileDigest || wrapper.EvidenceContentType != FirmOfferAgreementEvidenceContentType ||
		guarantorCodec.Unmarshal(wrapper.Evidence, &value) != nil {
		return errors.New("firm-offer Agreement evidence wire profile is invalid")
	}
	agreementDigest, agreementErr := agentcommerce.AgreementBodyDigest(agreement)
	offerDigest, offerErr := FirmOfferDigest(offer)
	if agreementErr != nil || offerErr != nil || wrapper.AgreementID != agreement.AgreementID ||
		wrapper.AgreementVersion != agreement.Version || wrapper.AgreementBodyDigest != agreementDigest ||
		value.SchemaVersion != 1 || value.EvidenceProfile != profile || value.AgreementBodyDigest != agreementDigest ||
		value.GuarantorAgentID != offer.Body.GuarantorAgentID || value.AuthorizedFirmOfferEnvelopeDigest != offerDigest ||
		!equalCanonical(value.AuthorizedFirmOffer, offer) || !equalCanonical(value.SatisfiedPredicateTargets, offer.Body.GuarantorPredicateTargets) {
		return errors.New("firm-offer Agreement evidence does not carry the exact offer")
	}
	if wrapper.AuthoritySubject.SubjectIdentifier != offer.Body.GuarantorAgentID ||
		len(wrapper.PredicateIDs) != len(value.SatisfiedPredicateTargets) ||
		len(wrapper.EvidenceTargetProjectionDigests) != len(value.SatisfiedPredicateTargets) {
		return errors.New("firm-offer Agreement evidence subject or target cardinality is invalid")
	}
	for index, target := range value.SatisfiedPredicateTargets {
		if wrapper.PredicateIDs[index] != target.PredicateID || wrapper.EvidenceTargetProjectionDigests[index] != target.TargetProjectionDigest {
			return errors.New("firm-offer Agreement evidence target projection differs")
		}
	}
	return nil
}

// VerifyFirmOfferAgreementEvidenceIntrinsicV1 validates everything carried by
// the evidence itself. The containing Agreement verifier must additionally
// call VerifyFirmOfferAgreementEvidenceV1 (or the acceptance verifier, which
// does so against its embedded Agreement body) to validate predicate targets.
func VerifyFirmOfferAgreementEvidenceIntrinsicV1(wrapper agentcommerce.AgreementAuthorizationEvidence,
	resolver AuthorityKeyResolver, publicationResolver agentcommerce.AgentOperationAuthorityResolver,
	underlyingResolver UnderlyingAgreementResolver, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	now time.Time) error {
	profileRef := FirmOfferAgreementEvidenceProfileV1()
	var value GuarantorFirmOfferAgreementEvidenceV1
	if resolver == nil || publicationResolver == nil || wrapper.EvidenceProfileURI != profileRef.ProfileURI ||
		uint64(wrapper.EvidenceProfileVersion) != profileRef.ProfileVersion || wrapper.EvidenceProfileDigest != profileRef.ProfileDigest ||
		wrapper.EvidenceContentType != FirmOfferAgreementEvidenceContentType || guarantorCodec.Unmarshal(wrapper.Evidence, &value) != nil {
		return errors.New("firm-offer Agreement evidence intrinsic profile is invalid")
	}
	offer := value.AuthorizedFirmOffer
	if validateFirmOfferShape(offer) != nil || value.SchemaVersion != 1 || value.EvidenceProfile != profileRef ||
		value.AgreementBodyDigest != wrapper.AgreementBodyDigest || value.GuarantorAgentID != wrapper.AuthoritySubject.SubjectIdentifier ||
		value.GuarantorAgentID != offer.Body.GuarantorAgentID || offer.Body.CoverageAgreementBodyDigest != wrapper.AgreementBodyDigest ||
		!equalCanonical(value.SatisfiedPredicateTargets, offer.Body.GuarantorPredicateTargets) {
		return errors.New("firm-offer Agreement evidence intrinsic body is invalid")
	}
	offerDigest, _ := FirmOfferDigest(offer)
	if value.AuthorizedFirmOfferEnvelopeDigest != offerDigest || len(wrapper.PredicateIDs) != len(value.SatisfiedPredicateTargets) ||
		len(wrapper.EvidenceTargetProjectionDigests) != len(value.SatisfiedPredicateTargets) {
		return errors.New("firm-offer Agreement evidence intrinsic digest or target count differs")
	}
	for index, target := range value.SatisfiedPredicateTargets {
		if wrapper.PredicateIDs[index] != target.PredicateID || wrapper.EvidenceTargetProjectionDigests[index] != target.TargetProjectionDigest {
			return errors.New("firm-offer Agreement evidence intrinsic targets differ")
		}
	}
	profile, err := ResolveServiceProfileArtifactV1(offer.ServiceProfileArtifact, publicationResolver, now)
	if err != nil || VerifyQuoteRequest(offer.AuthorizedQuoteRequest, profile, resolver,
		underlyingResolver, agreementVerifier, now) != nil ||
		ValidateCoverageTermsAgainstServiceProfile(offer.CoverageTerms, profile) != nil ||
		VerifyExposureAdmissionReceiptV1(offer.ExposureAdmissionReceipt, resolver, now) != nil {
		return errors.New("firm-offer Agreement evidence intrinsic lineage is invalid")
	}
	profileDigest, _ := ServiceProfileDigest(profile)
	requestDigest, _ := QuoteRequestDigest(offer.AuthorizedQuoteRequest)
	termsDigest, _ := CoverageTermsDigest(offer.CoverageTerms)
	receiptDigest, _ := ExposureAdmissionReceiptDigestV1(offer.ExposureAdmissionReceipt)
	body := offer.Body
	if body.ServiceProfileDigest != profileDigest || body.ServiceIntentDigest != offer.ServiceProfileArtifact.SelectedServiceIntentOperationDigest ||
		body.QuoteRequestDigest != requestDigest || body.CoverageTermsDigest != termsDigest ||
		body.ExposureAdmissionReceiptDigest != receiptDigest || body.ReservationID != offer.ExposureAdmissionReceipt.Body.ReservationID ||
		body.GuarantorEvidenceProfile != profileRef {
		return errors.New("firm-offer Agreement evidence intrinsic offer projection differs")
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-firm-offer-body.v1", body)
	return ValidateAuthorizationSet(offer.Authorizations, "firm-coverage-offer", bodyDigest,
		"tos.service.agent-guarantor-firm-offer-signature.v1", []string{body.GuarantorAgentID}, resolver, now)
}

type FirmOfferRecipientSetV1 struct {
	SchemaVersion       uint16   `json:"schema_version"`
	RequesterAgentID    string   `json:"requester_agent_id"`
	GuarantorAgentID    string   `json:"guarantor_agent_id"`
	CoveredPartyAgentID string   `json:"covered_party_agent_id"`
	BeneficiaryAgentID  string   `json:"beneficiary_agent_id"`
	ClaimantSubjects    []string `json:"claimant_subjects"`
	AcceptanceSubjects  []string `json:"acceptance_subjects"`
}

type FirmOfferAuthorityInstanceEffectV1 struct {
	SchemaVersion                        uint16                             `json:"schema_version"`
	GuarantorAgentID                     string                             `json:"guarantor_agent_id"`
	AuthorizedQuoteRequestEnvelopeDigest string                             `json:"authorized_quote_request_envelope_digest"`
	CoverageAgreementBodyDigest          string                             `json:"coverage_agreement_body_digest"`
	CoverageTermsDigest                  string                             `json:"coverage_terms_digest"`
	RecipientSet                         FirmOfferRecipientSetV1            `json:"recipient_set"`
	RecipientSetDigest                   string                             `json:"recipient_set_digest"`
	ReservationScope                     ProviderExposureReservationScopeV1 `json:"reservation_scope"`
	ReservationScopeDigest               string                             `json:"reservation_scope_digest"`
	ReservedExposure                     AtomicAmountV1                     `json:"reserved_exposure"`
	PreallocationOfferTemplate           FirmCoverageOfferBodyV1            `json:"preallocation_offer_template"`
}

type FirmOfferIssuanceActionBodyV1 struct {
	SchemaVersion               uint16                                `json:"schema_version"`
	AuthorityInstanceID         string                                `json:"authority_instance_id"`
	AuthorityInstanceRecord     agentcommerce.AuthorityInstanceRecord `json:"authority_instance_record"`
	AuthorityInstanceEffect     FirmOfferAuthorityInstanceEffectV1    `json:"authority_instance_effect"`
	AuthorizedQuoteRequest      AuthorizedCoverageQuoteRequestV1      `json:"authorized_quote_request"`
	ServiceProfileArtifact      GuarantorServiceProfileArtifactV1     `json:"service_profile_artifact"`
	UnsignedOfferTemplate       FirmCoverageOfferBodyV1               `json:"unsigned_offer_template"`
	ExposureAdmissionDescriptor ProviderExposureAdmissionDescriptorV1 `json:"exposure_admission_descriptor"`
	ExpectedPortfolioRevision   uint64                                `json:"expected_portfolio_revision"`
}

func FirmOfferRecipientSetDigestV1(value FirmOfferRecipientSetV1) (string, error) {
	if value.SchemaVersion != 1 || !validID(value.RequesterAgentID) || !validID(value.GuarantorAgentID) ||
		!validID(value.CoveredPartyAgentID) || !validID(value.BeneficiaryAgentID) ||
		!sortedUnique(value.ClaimantSubjects, MaxAuthorizations, validID) ||
		!sortedUnique(value.AcceptanceSubjects, MaxAuthorizations, validID) {
		return "", errors.New("Guarantor firm-offer recipient set is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-firm-offer-recipient-set.v1", value)
}

func FirmOfferAuthorityInstanceEffectDigestV1(value FirmOfferAuthorityInstanceEffectV1) (string, error) {
	if err := ValidateFirmOfferAuthorityInstanceEffectV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-firm-offer-authority-effect.v1", value)
}

func ReservationIDV1(guarantorAgentID, authorityInstanceID, descriptorDigest string) (string, error) {
	if !validID(guarantorAgentID) || !validDigest(authorityInstanceID) || !validDigest(descriptorDigest) {
		return "", errors.New("Guarantor reservation identity input is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-reservation-id.v1", struct {
		GuarantorAgentID  string `json:"guarantor_agent_id"`
		AuthorityInstance string `json:"authority_instance_id"`
		DescriptorDigest  string `json:"descriptor_digest"`
	}{guarantorAgentID, authorityInstanceID, descriptorDigest})
}

func ValidateFirmOfferAuthorityInstanceEffectV1(value FirmOfferAuthorityInstanceEffectV1) error {
	recipientDigest, recipientErr := FirmOfferRecipientSetDigestV1(value.RecipientSet)
	scopeDigest, scopeErr := ExposureReservationScopeDigestV1(value.ReservationScope)
	zero := "sha256:" + strings.Repeat("0", 64)
	template := value.PreallocationOfferTemplate
	if recipientErr != nil || scopeErr != nil || value.SchemaVersion != 1 || !validID(value.GuarantorAgentID) ||
		!validDigest(value.AuthorizedQuoteRequestEnvelopeDigest) || !validDigest(value.CoverageAgreementBodyDigest) ||
		!validDigest(value.CoverageTermsDigest) || value.RecipientSetDigest != recipientDigest ||
		value.ReservationScopeDigest != scopeDigest || validateAmount(value.ReservedExposure, true) != nil ||
		value.ReservedExposure != value.ReservationScope.MaximumAggregatePayout || template.SchemaVersion != 1 ||
		template.OfferID != zero || template.ExposureAdmissionReceiptDigest != zero ||
		template.OfferVersion != 1 || template.PredecessorOfferDigest != "" || template.MaxAcceptances != 1 ||
		template.WithdrawalPolicy != "forbidden" || template.ReservationID != zero ||
		template.CoverageAgreementBodyDigest != value.CoverageAgreementBodyDigest ||
		template.QuoteRequestDigest != value.AuthorizedQuoteRequestEnvelopeDigest ||
		template.CoverageTermsDigest != value.CoverageTermsDigest || template.GuarantorAgentID != value.GuarantorAgentID ||
		template.CoveredPartyAgentID != value.RecipientSet.CoveredPartyAgentID ||
		template.BeneficiaryAgentID != value.RecipientSet.BeneficiaryAgentID ||
		template.CoverageObligationID != value.ReservationScope.CoverageObligationID {
		return errors.New("Guarantor firm-offer authority-instance effect is invalid")
	}
	return nil
}

func ValidateFirmOfferIssuanceActionBodyV1(value FirmOfferIssuanceActionBodyV1) error {
	if value.SchemaVersion != 1 || ValidateFirmOfferAuthorityInstanceEffectV1(value.AuthorityInstanceEffect) != nil ||
		!validDigest(value.AuthorityInstanceID) || value.AuthorityInstanceRecord.AuthorityInstanceID != value.AuthorityInstanceID ||
		value.AuthorityInstanceRecord.AllocationSequence == 0 || value.AuthorityInstanceRecord.PolicyRevision == 0 ||
		value.AuthorityInstanceRecord.Terminal || !validDigest(value.AuthorityInstanceRecord.RequestDigest) ||
		value.ExpectedPortfolioRevision == 0 {
		return errors.New("Guarantor firm-offer issuance authority allocation is invalid")
	}
	requestDigest, requestErr := QuoteRequestDigest(value.AuthorizedQuoteRequest)
	descriptorDigest, descriptorErr := ExposureAdmissionDescriptorDigestV1(value.ExposureAdmissionDescriptor)
	reservationID, reservationErr := ReservationIDV1(value.AuthorityInstanceEffect.GuarantorAgentID,
		value.AuthorityInstanceID, descriptorDigest)
	zero := "sha256:" + strings.Repeat("0", 64)
	expectedTemplate := value.AuthorityInstanceEffect.PreallocationOfferTemplate
	expectedTemplate.OfferID = value.AuthorityInstanceID
	expectedTemplate.ReservationID = reservationID
	expectedTemplateBytes, expectedTemplateErr := guarantorCodec.Marshal(expectedTemplate)
	actualTemplateBytes, actualTemplateErr := guarantorCodec.Marshal(value.UnsignedOfferTemplate)
	if requestErr != nil || descriptorErr != nil || reservationErr != nil || requestDigest != value.AuthorityInstanceEffect.AuthorizedQuoteRequestEnvelopeDigest ||
		expectedTemplateErr != nil || actualTemplateErr != nil || !bytes.Equal(expectedTemplateBytes, actualTemplateBytes) ||
		value.UnsignedOfferTemplate.ExposureAdmissionReceiptDigest != zero ||
		value.ExposureAdmissionDescriptor.BasePortfolioRevision != value.ExpectedPortfolioRevision ||
		value.ExposureAdmissionDescriptor.CoverageAgreementBodyDigest != value.AuthorityInstanceEffect.CoverageAgreementBodyDigest ||
		value.ExposureAdmissionDescriptor.CoverageTermsDigest != value.AuthorityInstanceEffect.CoverageTermsDigest ||
		value.ExposureAdmissionDescriptor.ReservationScope != value.AuthorityInstanceEffect.ReservationScope ||
		value.ExposureAdmissionDescriptor.ReservedExposure != value.AuthorityInstanceEffect.ReservedExposure {
		return errors.New("Guarantor firm-offer issuance projection differs")
	}
	return nil
}
