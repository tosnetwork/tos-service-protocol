package agentcommerce

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxAgreementParticipants  = 64
	MaxAgreementObligations   = 256
	MaxAgreementPredicates    = 512
	MaxAgreementTermsBytes    = 256 << 10
	MaxAgreementEvidenceBytes = 1 << 20
)

const (
	EvidenceProfileAgentSignature     = "tos.agreement.evidence.agent-signature.v1"
	EvidenceProfileAuthoritySignature = "tos.agreement.evidence.authority-signature.v1"
)

// retiredEvidenceProfiles are built-in evidence profiles whose settlement rail
// no longer exists. An Agreement naming one is refused rather than treated as
// an external profile that nothing constrains.
var retiredEvidenceProfiles = map[string]bool{
	"tos.agreement.evidence.paid-demand-quote.v1": true,
}

const AgreementAcceptanceContentType = "application/vnd.tos.agreement-acceptance.v1+cbor"

const AuthorityAcceptanceContentType = "application/vnd.tos.agreement-authority-acceptance.v1+cbor"

// AgentSignatureProfileDigest returns the immutable descriptor digest for the
// built-in V1 profile. Implementations must not accept an arbitrary digest
// beside a well-known profile URI: doing so would let an Agreement name the
// verifier while silently changing its grouping or target semantics.
func AgentSignatureProfileDigest() string {
	digest, err := ProfileDescriptorDigest(EvidenceProfileAgentSignature, 1, []string{"agent"},
		[]string{AgreementAcceptanceContentType}, "complete-subject-profile-group", "agreement-predicate-target-v1",
		"tos.verifier.agent-signature.v1", "expires-before-agreement")
	if err != nil {
		panic(err)
	}
	return digest
}

func AuthoritySignatureProfileDigest() string {
	digest, err := ProfileDescriptorDigest(EvidenceProfileAuthoritySignature, 1,
		[]string{"capability_owner", "custody_principal", "data_owner", "key_owner", "wallet"},
		[]string{AuthorityAcceptanceContentType}, "complete-subject-profile-group", "agreement-predicate-target-v1",
		"tos.verifier.authority-signature.v1", "expires-before-agreement")
	if err != nil {
		panic(err)
	}
	return digest
}

type AgreementParticipant struct {
	AgentID string   `json:"agent_id"`
	Roles   []string `json:"roles"`
}

type AgreementAmount struct {
	AssetNamespace  string `json:"asset_namespace"`
	AssetIdentifier string `json:"asset_identifier"`
	AmountAtomic    string `json:"amount_atomic,omitempty"`
	AmountDecimal   string `json:"amount_decimal,omitempty"`
	Unit            string `json:"unit"`
}

type AgreementAuthoritySubject struct {
	SubjectKind        string `json:"subject_kind"`
	SubjectNamespace   string `json:"subject_namespace"`
	SubjectIdentifier  string `json:"subject_identifier"`
	RepresentedAgentID string `json:"represented_agent_id,omitempty"`
}

func (s AgreementAuthoritySubject) key() string {
	return s.SubjectKind + "\x00" + s.SubjectNamespace + "\x00" + s.SubjectIdentifier + "\x00" + s.RepresentedAgentID
}

type AgreementAuthorizationPredicate struct {
	PredicateID                    string                    `json:"predicate_id"`
	AuthoritySubject               AgreementAuthoritySubject `json:"authority_subject"`
	RoleScope                      []string                  `json:"role_scope,omitempty"`
	ObligationIDs                  []string                  `json:"obligation_ids"`
	EvidenceProfileURI             string                    `json:"evidence_profile_uri"`
	EvidenceProfileVersion         uint32                    `json:"evidence_profile_version"`
	EvidenceProfileDigest          string                    `json:"evidence_profile_digest"`
	EvidenceTargetProjectionDigest string                    `json:"evidence_target_projection_digest"`
	ValidFromUnix                  uint64                    `json:"valid_from_unix,omitempty"`
	ExpiresAtUnix                  uint64                    `json:"expires_at_unix"`
	RequiredExtensions             []string                  `json:"required_extensions,omitempty"`
	OptionalExtensions             []string                  `json:"optional_extensions,omitempty"`
}

type BillingTerms struct {
	BillingKind              string          `json:"billing_kind"`
	FirstSequence            uint64          `json:"first_sequence"`
	RecurrenceStartUnix      uint64          `json:"recurrence_start_unix,omitempty"`
	RecurrenceEndUnix        uint64          `json:"recurrence_end_unix,omitempty"`
	RecurrenceCount          uint64          `json:"recurrence_count,omitempty"`
	RecurrenceIntervalSecs   uint64          `json:"recurrence_interval_seconds,omitempty"`
	MaximumAggregateAmount   AgreementAmount `json:"maximum_aggregate_amount"`
	CancellationCutoffPolicy string          `json:"cancellation_cutoff_policy"`
}

type AgreementObligation struct {
	ObligationID                   string           `json:"obligation_id"`
	Kind                           string           `json:"kind"`
	ObligorAgentID                 string           `json:"obligor_agent_id"`
	BeneficiaryAgentID             string           `json:"beneficiary_agent_id,omitempty"`
	DependsOnObligationIDs         []string         `json:"depends_on_obligation_ids,omitempty"`
	SubjectContentType             string           `json:"subject_content_type"`
	Subject                        []byte           `json:"subject"`
	AttachmentDigests              []string         `json:"attachment_digests,omitempty"`
	Amount                         *AgreementAmount `json:"amount,omitempty"`
	NotBeforeUnix                  uint64           `json:"not_before_unix,omitempty"`
	DueAtUnix                      uint64           `json:"due_at_unix,omitempty"`
	ExpiresAtUnix                  uint64           `json:"expires_at_unix,omitempty"`
	AcceptanceEvidenceRequirements []string         `json:"acceptance_evidence_requirements,omitempty"`
	ConfidentialityPolicy          string           `json:"confidentiality_and_disclosure_policy"`
	CancellationPolicy             string           `json:"cancellation_policy"`
	DisputePolicy                  string           `json:"dispute_policy"`
	BillingTerms                   *BillingTerms    `json:"billing_terms,omitempty"`
	SettlementAdapterURI           string           `json:"settlement_adapter_uri,omitempty"`
	SettlementParameters           []byte           `json:"settlement_parameters,omitempty"`
	AuthorizationPredicateIDs      []string         `json:"authorization_predicate_ids"`
	RequiredExtensions             []string         `json:"required_extensions,omitempty"`
	OptionalExtensions             []string         `json:"optional_extensions,omitempty"`
}

type AgentAgreementBody struct {
	SchemaVersion              uint16                            `json:"schema_version"`
	AgreementID                string                            `json:"agreement_id"`
	Version                    uint64                            `json:"version"`
	PredecessorAgreementDigest string                            `json:"predecessor_agreement_digest,omitempty"`
	NetworkContext             string                            `json:"network_context"`
	Participants               []AgreementParticipant            `json:"participants"`
	ReferencedIntents          []string                          `json:"referenced_intents,omitempty"`
	TermsContentType           string                            `json:"terms_content_type"`
	Terms                      []byte                            `json:"terms"`
	AttachmentDigests          []string                          `json:"attachment_digests,omitempty"`
	Obligations                []AgreementObligation             `json:"obligations"`
	AuthorizationPredicates    []AgreementAuthorizationPredicate `json:"authorization_predicates"`
	RequiredExtensions         []string                          `json:"required_extensions,omitempty"`
	OptionalExtensions         map[string][]byte                 `json:"optional_extensions,omitempty"`
	ValidFromUnix              uint64                            `json:"valid_from_unix"`
	ExpiresAtUnix              uint64                            `json:"expires_at_unix"`
}

type AgreementAuthorizationEvidence struct {
	AgreementID                     string                    `json:"agreement_id"`
	AgreementVersion                uint64                    `json:"agreement_version"`
	AgreementBodyDigest             string                    `json:"agreement_body_digest"`
	AuthoritySubject                AgreementAuthoritySubject `json:"authority_subject"`
	PredicateIDs                    []string                  `json:"predicate_ids"`
	EvidenceProfileURI              string                    `json:"evidence_profile_uri"`
	EvidenceProfileVersion          uint32                    `json:"evidence_profile_version"`
	EvidenceProfileDigest           string                    `json:"evidence_profile_digest"`
	EvidenceTargetProjectionDigests []string                  `json:"evidence_target_projection_digests"`
	EvidenceContentType             string                    `json:"evidence_content_type"`
	Evidence                        []byte                    `json:"evidence"`
}

type AgentAgreement struct {
	Body                  AgentAgreementBody               `json:"body"`
	AuthorizationEvidence []AgreementAuthorizationEvidence `json:"authorization_evidence"`
}

type AgreementAcceptanceBody struct {
	AgreementID                     string                    `json:"agreement_id"`
	AgreementVersion                uint64                    `json:"agreement_version"`
	AgreementBodyDigest             string                    `json:"agreement_body_digest"`
	AcceptingSubject                AgreementAuthoritySubject `json:"accepting_subject"`
	AcceptedRoles                   []string                  `json:"accepted_roles,omitempty"`
	PredicateIDs                    []string                  `json:"predicate_ids"`
	EvidenceTargetProjectionDigests []string                  `json:"evidence_target_projection_digests"`
	ExpiresAtUnix                   uint64                    `json:"expires_at_unix"`
}

type SignedAgreementAcceptance struct {
	Body      AgreementAcceptanceBody `json:"body"`
	PublicKey string                  `json:"public_key"`
	Signature string                  `json:"signature"`
}

type AgreementEvidenceVerifier interface {
	VerifyAgreementEvidence(evidence AgreementAuthorizationEvidence, at time.Time) error
}

// PrepareAgreementTargets computes the non-circular authorization targets. It
// refuses malformed core/policy data before adding any target digest.
func PrepareAgreementTargets(body AgentAgreementBody) (AgentAgreementBody, error) {
	if err := validateAgreementBody(body, false); err != nil {
		return AgentAgreementBody{}, err
	}
	core, err := agreementCoreBytes(body)
	if err != nil {
		return AgentAgreementBody{}, err
	}
	policy, err := agreementPolicyBytes(body.AuthorizationPredicates)
	if err != nil {
		return AgentAgreementBody{}, err
	}
	coreDigest := framedSHA256("tos.agreement-core.v1\x00", core)
	policyDigest := framedSHA256("tos.agreement-authorization-policy.v1\x00", policy)
	prepared := body
	prepared.AuthorizationPredicates = append([]AgreementAuthorizationPredicate(nil), body.AuthorizationPredicates...)
	for index := range prepared.AuthorizationPredicates {
		predicate := &prepared.AuthorizationPredicates[index]
		hasher := sha256.New()
		hasher.Write([]byte("tos.agreement-authorization-target.v1\x00"))
		hasher.Write(coreDigest)
		hasher.Write(policyDigest)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(predicate.PredicateID)))
		hasher.Write(length[:])
		hasher.Write([]byte(predicate.PredicateID))
		predicate.EvidenceTargetProjectionDigest = "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	}
	return prepared, nil
}

func ValidateAgreementBody(body AgentAgreementBody) error { return validateAgreementBody(body, true) }

func AgreementBodyDigest(body AgentAgreementBody) (string, error) {
	if err := ValidateAgreementBody(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-agreement-body.v1", body)
}

// ValidateAgreementSuccessor verifies the cross-object lineage rules that
// cannot be checked by ValidateAgreementBody in isolation. A successor is a
// complete replacement body in the same Agreement version chain; it is never a
// patch and its predecessor digest must identify the exact validated body.
func ValidateAgreementSuccessor(predecessor, successor AgentAgreementBody) error {
	if err := ValidateAgreementBody(predecessor); err != nil {
		return fmt.Errorf("agreement predecessor body: %w", err)
	}
	if err := ValidateAgreementBody(successor); err != nil {
		return fmt.Errorf("agreement successor body: %w", err)
	}
	if successor.AgreementID != predecessor.AgreementID {
		return errors.New("agreement successor changes Agreement ID")
	}
	if predecessor.Version == ^uint64(0) || successor.Version != predecessor.Version+1 {
		return errors.New("agreement successor version is not consecutive")
	}
	predecessorDigest, err := AgreementBodyDigest(predecessor)
	if err != nil {
		return err
	}
	if successor.PredecessorAgreementDigest != predecessorDigest {
		return errors.New("agreement successor does not bind the exact predecessor")
	}
	if successor.NetworkContext != predecessor.NetworkContext {
		return errors.New("agreement successor changes network context")
	}
	return nil
}

func validateAgreementBody(body AgentAgreementBody, requireTargets bool) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.AgreementID, 256) || body.Version == 0 ||
		!boundedIdentifier(body.NetworkContext, 256) || body.ValidFromUnix == 0 || body.ValidFromUnix > math.MaxInt64 ||
		body.ExpiresAtUnix > math.MaxInt64 || body.ExpiresAtUnix <= body.ValidFromUnix ||
		!boundedIdentifier(body.TermsContentType, 128) || len(body.Terms) == 0 || len(body.Terms) > MaxAgreementTermsBytes {
		return errors.New("agreement envelope is invalid")
	}
	if body.Version == 1 && body.PredecessorAgreementDigest != "" || body.Version > 1 && !canonicalDigestPattern.MatchString(body.PredecessorAgreementDigest) {
		return errors.New("agreement predecessor is invalid")
	}
	if len(body.Participants) < 2 || len(body.Participants) > MaxAgreementParticipants {
		return errors.New("agreement participant count is invalid")
	}
	participants := make(map[string]AgreementParticipant, len(body.Participants))
	previousParticipant := ""
	for _, participant := range body.Participants {
		if !boundedIdentifier(participant.AgentID, 256) || participant.AgentID <= previousParticipant || len(participant.Roles) == 0 ||
			validateSortedStrings(participant.Roles, 32, 128) != nil {
			return errors.New("agreement participants must be sorted, unique, and valid")
		}
		participants[participant.AgentID] = participant
		previousParticipant = participant.AgentID
	}
	if err := validateSortedDigests(body.ReferencedIntents, 128); err != nil {
		return fmt.Errorf("referenced intents: %w", err)
	}
	if err := validateSortedDigests(body.AttachmentDigests, 256); err != nil {
		return fmt.Errorf("agreement attachments: %w", err)
	}
	if err := validateSortedStrings(body.RequiredExtensions, 64, 256); err != nil || len(body.OptionalExtensions) > 64 {
		return errors.New("agreement extensions are invalid")
	}
	for name, value := range body.OptionalExtensions {
		if !boundedIdentifier(name, 256) || len(value) > MaxAgreementTermsBytes {
			return errors.New("agreement optional extension is invalid")
		}
	}
	if len(body.AuthorizationPredicates) == 0 || len(body.AuthorizationPredicates) > MaxAgreementPredicates {
		return errors.New("agreement authorization predicate count is invalid")
	}
	predicates := make(map[string]AgreementAuthorizationPredicate, len(body.AuthorizationPredicates))
	previousPredicate := ""
	for _, predicate := range body.AuthorizationPredicates {
		if !boundedIdentifier(predicate.PredicateID, 128) || predicate.PredicateID <= previousPredicate ||
			!validAuthoritySubject(predicate.AuthoritySubject) || validateSortedStrings(predicate.RoleScope, 32, 128) != nil ||
			validateSortedStrings(predicate.ObligationIDs, MaxAgreementObligations, 128) != nil || len(predicate.ObligationIDs) == 0 ||
			!boundedIdentifier(predicate.EvidenceProfileURI, 256) || predicate.EvidenceProfileVersion == 0 ||
			!canonicalDigestPattern.MatchString(predicate.EvidenceProfileDigest) || predicate.ValidFromUnix > math.MaxInt64 ||
			predicate.ExpiresAtUnix == 0 || predicate.ExpiresAtUnix > math.MaxInt64 ||
			predicate.ValidFromUnix > predicate.ExpiresAtUnix || validateSortedStrings(predicate.RequiredExtensions, 64, 256) != nil ||
			validateSortedStrings(predicate.OptionalExtensions, 64, 256) != nil {
			return errors.New("agreement authorization predicate is invalid")
		}
		if requireTargets && !canonicalDigestPattern.MatchString(predicate.EvidenceTargetProjectionDigest) ||
			!requireTargets && predicate.EvidenceTargetProjectionDigest != "" {
			return errors.New("agreement authorization target is invalid")
		}
		if predicate.EvidenceProfileURI == EvidenceProfileAgentSignature &&
			(predicate.EvidenceProfileVersion != 1 || predicate.EvidenceProfileDigest != AgentSignatureProfileDigest() || predicate.AuthoritySubject.SubjectKind != "agent") {
			return errors.New("built-in Agent-signature evidence profile descriptor mismatch")
		}
		if predicate.EvidenceProfileURI == EvidenceProfileAuthoritySignature &&
			(predicate.EvidenceProfileVersion != 1 || predicate.EvidenceProfileDigest != AuthoritySignatureProfileDigest() ||
				predicate.AuthoritySubject.SubjectKind == "agent") {
			return errors.New("built-in authority-signature evidence profile descriptor mismatch")
		}
		if retiredEvidenceProfiles[predicate.EvidenceProfileURI] {
			return errors.New("agreement names a retired evidence profile")
		}
		predicates[predicate.PredicateID] = predicate
		previousPredicate = predicate.PredicateID
	}
	if len(body.Obligations) == 0 || len(body.Obligations) > MaxAgreementObligations {
		return errors.New("agreement obligation count is invalid")
	}
	obligations := make(map[string]AgreementObligation, len(body.Obligations))
	for _, obligation := range body.Obligations {
		if _, duplicate := obligations[obligation.ObligationID]; duplicate || !boundedIdentifier(obligation.ObligationID, 128) ||
			!boundedIdentifier(obligation.Kind, 64) || participants[obligation.ObligorAgentID].AgentID == "" ||
			obligation.BeneficiaryAgentID != "" && participants[obligation.BeneficiaryAgentID].AgentID == "" ||
			!boundedIdentifier(obligation.SubjectContentType, 128) || len(obligation.Subject) == 0 || len(obligation.Subject) > MaxAgreementTermsBytes ||
			validateSortedDigests(obligation.AttachmentDigests, 256) != nil || validateSortedStrings(obligation.DependsOnObligationIDs, MaxAgreementObligations, 128) != nil ||
			validateSortedStrings(obligation.AcceptanceEvidenceRequirements, 64, 256) != nil || validateSortedStrings(obligation.AuthorizationPredicateIDs, MaxAgreementPredicates, 128) != nil ||
			len(obligation.AuthorizationPredicateIDs) == 0 || validateSortedStrings(obligation.RequiredExtensions, 64, 256) != nil ||
			validateSortedStrings(obligation.OptionalExtensions, 64, 256) != nil || !boundedIdentifier(obligation.ConfidentialityPolicy, 256) ||
			!boundedIdentifier(obligation.CancellationPolicy, 256) || !boundedIdentifier(obligation.DisputePolicy, 256) {
			return errors.New("agreement obligation is invalid")
		}
		if obligation.NotBeforeUnix != 0 && obligation.ExpiresAtUnix != 0 && obligation.NotBeforeUnix >= obligation.ExpiresAtUnix ||
			obligation.DueAtUnix != 0 && obligation.ExpiresAtUnix != 0 && obligation.DueAtUnix > obligation.ExpiresAtUnix {
			return errors.New("agreement obligation time bounds are invalid")
		}
		if obligation.Amount != nil {
			if err := validateAgreementAmount(*obligation.Amount); err != nil || !boundedIdentifier(obligation.SettlementAdapterURI, 256) || len(obligation.SettlementParameters) == 0 {
				return errors.New("value-bearing obligation lacks exact amount or settlement adapter")
			}
		} else if obligation.SettlementAdapterURI != "" || len(obligation.SettlementParameters) != 0 || obligation.BillingTerms != nil {
			return errors.New("non-value obligation carries settlement terms")
		}
		if obligation.BillingTerms != nil {
			if err := validateBillingTerms(*obligation.BillingTerms, *obligation.Amount); err != nil {
				return err
			}
		}
		obligations[obligation.ObligationID] = obligation
	}
	for _, predicate := range body.AuthorizationPredicates {
		for _, obligationID := range predicate.ObligationIDs {
			if _, found := obligations[obligationID]; !found {
				return errors.New("authorization predicate references an unknown obligation")
			}
		}
	}
	for _, obligation := range body.Obligations {
		obligorAuthorized := false
		for _, predicateID := range obligation.AuthorizationPredicateIDs {
			predicate, found := predicates[predicateID]
			if !found || !containsSorted(predicate.ObligationIDs, obligation.ObligationID) {
				return errors.New("obligation references an unknown or out-of-scope predicate")
			}
			if predicate.AuthoritySubject.SubjectKind == "agent" && predicate.AuthoritySubject.SubjectIdentifier == obligation.ObligorAgentID ||
				predicate.AuthoritySubject.SubjectKind != "agent" && predicate.AuthoritySubject.RepresentedAgentID == obligation.ObligorAgentID {
				obligorAuthorized = true
			}
		}
		if !obligorAuthorized {
			return errors.New("obligation lacks its mandatory obligor predicate")
		}
		for _, dependency := range obligation.DependsOnObligationIDs {
			if _, found := obligations[dependency]; !found || dependency == obligation.ObligationID {
				return errors.New("obligation dependency is invalid")
			}
		}
	}
	if agreementHasCycle(obligations) {
		return errors.New("agreement obligation graph contains a cycle")
	}
	if requireTargets {
		prepared := body
		prepared.AuthorizationPredicates = append([]AgreementAuthorizationPredicate(nil), body.AuthorizationPredicates...)
		for index := range prepared.AuthorizationPredicates {
			prepared.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
		}
		recomputed, err := PrepareAgreementTargets(prepared)
		if err != nil {
			return err
		}
		for index := range body.AuthorizationPredicates {
			if body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest != recomputed.AuthorizationPredicates[index].EvidenceTargetProjectionDigest {
				return errors.New("agreement authorization target digest mismatch")
			}
		}
	}
	return nil
}

func ValidateAgreementAuthorization(agreement AgentAgreement, verifier AgreementEvidenceVerifier, now time.Time) error {
	return validateAgreementEvidenceSet(agreement, verifier, now, true)
}

// ValidatePartialAgreementAuthorization validates every supplied evidence
// object and all complete-group rules but permits predicates that have not yet
// been satisfied. It is for durable negotiation inboxes; it never declares an
// Agreement authorized. Call ValidateAgreementAuthorization at promotion.
func ValidatePartialAgreementAuthorization(agreement AgentAgreement, verifier AgreementEvidenceVerifier, now time.Time) error {
	return validateAgreementEvidenceSet(agreement, verifier, now, false)
}

func validateAgreementEvidenceSet(agreement AgentAgreement, verifier AgreementEvidenceVerifier, now time.Time, requireComplete bool) error {
	if err := ValidateAgreementBody(agreement.Body); err != nil {
		return err
	}
	if verifier == nil || now.IsZero() {
		return errors.New("agreement evidence verifier is required")
	}
	now = now.UTC()
	if now.Before(time.Unix(int64(agreement.Body.ValidFromUnix), 0).UTC()) ||
		!now.Before(time.Unix(int64(agreement.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("agreement body is outside its authorization validity window")
	}
	bodyDigest, err := AgreementBodyDigest(agreement.Body)
	if err != nil {
		return err
	}
	groups := make(map[string][]AgreementAuthorizationPredicate)
	for _, predicate := range agreement.Body.AuthorizationPredicates {
		if predicate.ValidFromUnix != 0 && now.Before(time.Unix(int64(predicate.ValidFromUnix), 0).UTC()) ||
			!now.Before(time.Unix(int64(predicate.ExpiresAtUnix), 0).UTC()) {
			return errors.New("agreement authorization predicate is outside its validity window")
		}
		key := predicate.AuthoritySubject.key() + "\x00" + predicate.EvidenceProfileURI + fmt.Sprintf("\x00%d\x00", predicate.EvidenceProfileVersion) + predicate.EvidenceProfileDigest
		groups[key] = append(groups[key], predicate)
	}
	seen := make(map[string]bool, len(agreement.AuthorizationEvidence))
	for _, evidence := range agreement.AuthorizationEvidence {
		if evidence.AgreementID != agreement.Body.AgreementID || evidence.AgreementVersion != agreement.Body.Version || evidence.AgreementBodyDigest != bodyDigest ||
			!validAuthoritySubject(evidence.AuthoritySubject) || len(evidence.PredicateIDs) == 0 || len(evidence.PredicateIDs) != len(evidence.EvidenceTargetProjectionDigests) ||
			validateSortedStrings(evidence.PredicateIDs, MaxAgreementPredicates, 128) != nil || !boundedIdentifier(evidence.EvidenceProfileURI, 256) ||
			evidence.EvidenceProfileVersion == 0 || !canonicalDigestPattern.MatchString(evidence.EvidenceProfileDigest) ||
			!boundedIdentifier(evidence.EvidenceContentType, 128) || len(evidence.Evidence) == 0 || len(evidence.Evidence) > MaxAgreementEvidenceBytes {
			return errors.New("agreement authorization evidence is invalid")
		}
		key := evidence.AuthoritySubject.key() + "\x00" + evidence.EvidenceProfileURI + fmt.Sprintf("\x00%d\x00", evidence.EvidenceProfileVersion) + evidence.EvidenceProfileDigest
		if seen[key] {
			return errors.New("duplicate or partial agreement evidence group")
		}
		predicates := groups[key]
		if len(predicates) != len(evidence.PredicateIDs) {
			return errors.New("agreement evidence does not cover its complete predicate group")
		}
		for index, predicate := range predicates {
			if predicate.PredicateID != evidence.PredicateIDs[index] || predicate.EvidenceTargetProjectionDigest != evidence.EvidenceTargetProjectionDigests[index] {
				return errors.New("agreement evidence predicate or target mismatch")
			}
		}
		if evidence.EvidenceProfileURI == EvidenceProfileAgentSignature || evidence.EvidenceProfileURI == EvidenceProfileAuthoritySignature {
			acceptance, decodeErr := DecodeSignedAgreementAcceptance(evidence.Evidence)
			if decodeErr != nil || acceptance.Body.ExpiresAtUnix > agreement.Body.ExpiresAtUnix {
				return errors.New("agreement acceptance exceeds the body validity window")
			}
			for _, predicate := range predicates {
				if acceptance.Body.ExpiresAtUnix > predicate.ExpiresAtUnix {
					return errors.New("agreement acceptance exceeds its predicate validity window")
				}
			}
		}
		if err := verifier.VerifyAgreementEvidence(evidence, now); err != nil {
			return err
		}
		seen[key] = true
	}
	for key := range groups {
		if requireComplete && !seen[key] {
			return errors.New("agreement authorization predicate is unsatisfied")
		}
	}
	return nil
}

func SignAgreementAcceptance(body AgreementAcceptanceBody, privateKey ed25519.PrivateKey) (SignedAgreementAcceptance, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !validAuthoritySubject(body.AcceptingSubject) || !canonicalDigestPattern.MatchString(body.AgreementBodyDigest) ||
		body.AgreementVersion == 0 || body.ExpiresAtUnix == 0 || len(body.PredicateIDs) == 0 || len(body.PredicateIDs) != len(body.EvidenceTargetProjectionDigests) ||
		validateSortedStrings(body.PredicateIDs, MaxAgreementPredicates, 128) != nil || validateSortedStrings(body.AcceptedRoles, 32, 128) != nil {
		return SignedAgreementAcceptance{}, errors.New("agreement acceptance is invalid")
	}
	for _, target := range body.EvidenceTargetProjectionDigests {
		if !canonicalDigestPattern.MatchString(target) {
			return SignedAgreementAcceptance{}, errors.New("agreement acceptance target is invalid")
		}
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		return SignedAgreementAcceptance{}, err
	}
	message := framedSHA256("tos.agreement-acceptance-signature.v1\x00", canonical)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignedAgreementAcceptance{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(publicKey),
		Signature: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

// AgentSignatureEvidence converts one signed typed acceptance into the exact
// complete predicate group selected by the Agreement body. A caller cannot
// choose a subset, profile, or target after signing.
func AgentSignatureEvidence(body AgentAgreementBody, acceptance SignedAgreementAcceptance) (AgreementAuthorizationEvidence, error) {
	if err := ValidateAgreementBody(body); err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	digest, err := AgreementBodyDigest(body)
	if err != nil || acceptance.Body.AgreementID != body.AgreementID || acceptance.Body.AgreementVersion != body.Version ||
		acceptance.Body.AgreementBodyDigest != digest {
		return AgreementAuthorizationEvidence{}, errors.New("typed acceptance does not target this Agreement")
	}
	var predicates []AgreementAuthorizationPredicate
	for _, predicate := range body.AuthorizationPredicates {
		if predicate.AuthoritySubject == acceptance.Body.AcceptingSubject && predicate.EvidenceProfileURI == EvidenceProfileAgentSignature {
			predicates = append(predicates, predicate)
		}
	}
	if len(predicates) == 0 || len(predicates) != len(acceptance.Body.PredicateIDs) {
		return AgreementAuthorizationEvidence{}, errors.New("typed acceptance does not cover one complete Agent-signature predicate group")
	}
	profileVersion, profileDigest := predicates[0].EvidenceProfileVersion, predicates[0].EvidenceProfileDigest
	for index, predicate := range predicates {
		if predicate.EvidenceProfileVersion != profileVersion || predicate.EvidenceProfileDigest != profileDigest ||
			predicate.PredicateID != acceptance.Body.PredicateIDs[index] ||
			predicate.EvidenceTargetProjectionDigest != acceptance.Body.EvidenceTargetProjectionDigests[index] {
			return AgreementAuthorizationEvidence{}, errors.New("typed acceptance predicate group is inconsistent")
		}
	}
	canonical, err := codec.Marshal(acceptance)
	if err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	return AgreementAuthorizationEvidence{AgreementID: body.AgreementID, AgreementVersion: body.Version,
		AgreementBodyDigest: digest, AuthoritySubject: acceptance.Body.AcceptingSubject,
		PredicateIDs: append([]string(nil), acceptance.Body.PredicateIDs...), EvidenceProfileURI: EvidenceProfileAgentSignature,
		EvidenceProfileVersion: profileVersion, EvidenceProfileDigest: profileDigest,
		EvidenceTargetProjectionDigests: append([]string(nil), acceptance.Body.EvidenceTargetProjectionDigests...),
		EvidenceContentType:             AgreementAcceptanceContentType, Evidence: canonical}, nil
}

func VerifySignedAgreementAcceptance(acceptance SignedAgreementAcceptance, expected AgreementAuthorizationEvidence, resolver IntentAuthorityResolver, now time.Time) error {
	if acceptance.Body.AgreementID != expected.AgreementID || acceptance.Body.AgreementVersion != expected.AgreementVersion ||
		acceptance.Body.AgreementBodyDigest != expected.AgreementBodyDigest || acceptance.Body.AcceptingSubject != expected.AuthoritySubject ||
		!equalStrings(acceptance.Body.PredicateIDs, expected.PredicateIDs) || !equalStrings(acceptance.Body.EvidenceTargetProjectionDigests, expected.EvidenceTargetProjectionDigests) ||
		!now.UTC().Before(time.Unix(int64(acceptance.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("agreement acceptance does not match evidence")
	}
	if acceptance.Body.AcceptingSubject.SubjectKind != "agent" || resolver == nil {
		return errors.New("agent acceptance requires an Agent authority resolver")
	}
	publicKey, err := parseEd25519PublicKey(acceptance.PublicKey)
	if err != nil {
		return err
	}
	if err := resolver.AuthorizeIntentKey(acceptance.Body.AcceptingSubject.SubjectIdentifier, publicKey, now); err != nil {
		return err
	}
	signature, err := parseEd25519Signature(acceptance.Signature)
	if err != nil {
		return err
	}
	canonical, err := codec.Marshal(acceptance.Body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, framedSHA256("tos.agreement-acceptance-signature.v1\x00", canonical), signature) {
		return errors.New("agreement acceptance signature is invalid")
	}
	return nil
}

func agreementCoreBytes(body AgentAgreementBody) ([]byte, error) {
	projection := struct {
		SchemaVersion              uint16                 `json:"schema_version"`
		AgreementID                string                 `json:"agreement_id"`
		Version                    uint64                 `json:"version"`
		PredecessorAgreementDigest string                 `json:"predecessor_agreement_digest,omitempty"`
		NetworkContext             string                 `json:"network_context"`
		Participants               []AgreementParticipant `json:"participants"`
		ReferencedIntents          []string               `json:"referenced_intents,omitempty"`
		TermsContentType           string                 `json:"terms_content_type"`
		Terms                      []byte                 `json:"terms"`
		AttachmentDigests          []string               `json:"attachment_digests,omitempty"`
		Obligations                []AgreementObligation  `json:"obligations"`
		RequiredExtensions         []string               `json:"required_extensions,omitempty"`
		OptionalExtensions         map[string][]byte      `json:"optional_extensions,omitempty"`
		ValidFromUnix              uint64                 `json:"valid_from_unix"`
		ExpiresAtUnix              uint64                 `json:"expires_at_unix"`
	}{body.SchemaVersion, body.AgreementID, body.Version, body.PredecessorAgreementDigest, body.NetworkContext, body.Participants,
		body.ReferencedIntents, body.TermsContentType, body.Terms, body.AttachmentDigests, body.Obligations, body.RequiredExtensions,
		body.OptionalExtensions, body.ValidFromUnix, body.ExpiresAtUnix}
	return codec.Marshal(projection)
}

func agreementPolicyBytes(predicates []AgreementAuthorizationPredicate) ([]byte, error) {
	type predicateProjection struct {
		PredicateID            string                    `json:"predicate_id"`
		AuthoritySubject       AgreementAuthoritySubject `json:"authority_subject"`
		RoleScope              []string                  `json:"role_scope,omitempty"`
		ObligationIDs          []string                  `json:"obligation_ids"`
		EvidenceProfileURI     string                    `json:"evidence_profile_uri"`
		EvidenceProfileVersion uint32                    `json:"evidence_profile_version"`
		EvidenceProfileDigest  string                    `json:"evidence_profile_digest"`
		ValidFromUnix          uint64                    `json:"valid_from_unix,omitempty"`
		ExpiresAtUnix          uint64                    `json:"expires_at_unix"`
		RequiredExtensions     []string                  `json:"required_extensions,omitempty"`
		OptionalExtensions     []string                  `json:"optional_extensions,omitempty"`
	}
	projected := make([]predicateProjection, len(predicates))
	for index, predicate := range predicates {
		projected[index] = predicateProjection{predicate.PredicateID, predicate.AuthoritySubject, predicate.RoleScope, predicate.ObligationIDs,
			predicate.EvidenceProfileURI, predicate.EvidenceProfileVersion, predicate.EvidenceProfileDigest, predicate.ValidFromUnix,
			predicate.ExpiresAtUnix, predicate.RequiredExtensions, predicate.OptionalExtensions}
	}
	return codec.Marshal(projected)
}

func framedSHA256(domain string, canonical []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(domain))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hasher.Write(length[:])
	hasher.Write(canonical)
	return hasher.Sum(nil)
}

func validateAgreementAmount(amount AgreementAmount) error {
	if !boundedIdentifier(amount.AssetNamespace, 128) || !boundedIdentifier(amount.AssetIdentifier, 256) || !boundedIdentifier(amount.Unit, 128) ||
		(amount.AmountAtomic == "") == (amount.AmountDecimal == "") {
		return errors.New("agreement amount is incomplete or ambiguous")
	}
	if amount.AmountAtomic != "" && !canonicalUnsignedDecimal(amount.AmountAtomic) || amount.AmountDecimal != "" && !canonicalDecimal(amount.AmountDecimal) {
		return errors.New("agreement amount is not canonical")
	}
	return nil
}

// ValidateAgreementAmount exposes the exact canonical amount rules to
// settlement and accounting Adapters.  Reusing this validator prevents those
// sinks from accepting numeric spellings that the Agreement body would reject
// (leading zeroes, signs, exponents, or redundant fractional zeroes).
func ValidateAgreementAmount(amount AgreementAmount) error {
	return validateAgreementAmount(amount)
}

func validateBillingTerms(terms BillingTerms, amount AgreementAmount) error {
	switch terms.BillingKind {
	case "one_time", "deposit", "milestone", "installment", "accumulated":
		if terms.RecurrenceStartUnix != 0 || terms.RecurrenceEndUnix != 0 || terms.RecurrenceCount != 0 || terms.RecurrenceIntervalSecs != 0 {
			return errors.New("non-periodic billing carries recurrence fields")
		}
	case "periodic":
		if terms.RecurrenceStartUnix == 0 || terms.RecurrenceEndUnix <= terms.RecurrenceStartUnix || terms.RecurrenceCount == 0 ||
			terms.RecurrenceCount > 10_000 || terms.RecurrenceIntervalSecs == 0 {
			return errors.New("periodic billing is unbounded")
		}
	default:
		return errors.New("billing kind is invalid")
	}
	if terms.FirstSequence == 0 || !boundedIdentifier(terms.CancellationCutoffPolicy, 256) || validateAgreementAmount(terms.MaximumAggregateAmount) != nil ||
		terms.MaximumAggregateAmount.AssetNamespace != amount.AssetNamespace || terms.MaximumAggregateAmount.AssetIdentifier != amount.AssetIdentifier ||
		terms.MaximumAggregateAmount.Unit != amount.Unit {
		return errors.New("billing aggregate cap is invalid")
	}
	return nil
}

func validAuthoritySubject(subject AgreementAuthoritySubject) bool {
	switch subject.SubjectKind {
	case "agent", "wallet", "custody_principal", "key_owner", "data_owner", "capability_owner":
	default:
		return false
	}
	if !boundedIdentifier(subject.SubjectNamespace, 128) || !boundedIdentifier(subject.SubjectIdentifier, 256) {
		return false
	}
	if subject.SubjectKind == "agent" {
		return subject.RepresentedAgentID == ""
	}
	return boundedIdentifier(subject.RepresentedAgentID, 256)
}

func validateSortedDigests(values []string, maximum int) error {
	if len(values) > maximum {
		return errors.New("digest set is too large")
	}
	for index, value := range values {
		if !canonicalDigestPattern.MatchString(value) || index > 0 && values[index-1] >= value {
			return errors.New("digests must be canonical, sorted, and unique")
		}
	}
	return nil
}

func containsSorted(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func agreementHasCycle(obligations map[string]AgreementObligation) bool {
	const (
		unseen = iota
		visiting
		visited
	)
	state := make(map[string]int, len(obligations))
	var visit func(string) bool
	visit = func(identifier string) bool {
		if state[identifier] == visiting {
			return true
		}
		if state[identifier] == visited {
			return false
		}
		state[identifier] = visiting
		for _, dependency := range obligations[identifier].DependsOnObligationIDs {
			if visit(dependency) {
				return true
			}
		}
		state[identifier] = visited
		return false
	}
	for identifier := range obligations {
		if visit(identifier) {
			return true
		}
	}
	return false
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func DecodeSignedAgreementAcceptance(canonical []byte) (SignedAgreementAcceptance, error) {
	var acceptance SignedAgreementAcceptance
	if err := codec.Unmarshal(canonical, &acceptance); err != nil {
		return SignedAgreementAcceptance{}, err
	}
	return acceptance, nil
}

// AgentSignatureEvidenceVerifier verifies the released generic Agent evidence
// profile. Other profiles are provided by custody or chain-specific adapters.
type AgentSignatureEvidenceVerifier struct{ Resolver IntentAuthorityResolver }

func (v AgentSignatureEvidenceVerifier) VerifyAgreementEvidence(evidence AgreementAuthorizationEvidence, now time.Time) error {
	if evidence.EvidenceProfileURI != EvidenceProfileAgentSignature || evidence.EvidenceProfileVersion != 1 ||
		evidence.EvidenceProfileDigest != AgentSignatureProfileDigest() || evidence.EvidenceContentType != AgreementAcceptanceContentType || v.Resolver == nil {
		return errors.New("unsupported Agreement evidence profile")
	}
	acceptance, err := DecodeSignedAgreementAcceptance(evidence.Evidence)
	if err != nil {
		return err
	}
	return VerifySignedAgreementAcceptance(acceptance, evidence, v.Resolver, now)
}

func EncodeSignedAgreementAcceptance(acceptance SignedAgreementAcceptance) ([]byte, error) {
	return codec.Marshal(acceptance)
}

func ProfileDescriptorDigest(profileURI string, profileVersion uint32, allowedSubjectKinds, evidenceContentTypes []string,
	predicateGroupingRule, targetBindingRule, verifierProfileURI, validityPolicy string) (string, error) {
	if !boundedIdentifier(profileURI, 256) || profileVersion == 0 || validateSortedStrings(allowedSubjectKinds, 16, 64) != nil ||
		validateSortedStrings(evidenceContentTypes, 16, 128) != nil || !boundedIdentifier(predicateGroupingRule, 256) ||
		!boundedIdentifier(targetBindingRule, 256) || !boundedIdentifier(verifierProfileURI, 256) || !boundedIdentifier(validityPolicy, 256) {
		return "", errors.New("agreement acceptance profile is invalid")
	}
	profile := struct {
		ProfileURI            string   `json:"profile_uri"`
		ProfileVersion        uint32   `json:"profile_version"`
		AllowedSubjectKinds   []string `json:"allowed_subject_kinds"`
		EvidenceContentTypes  []string `json:"evidence_content_types"`
		PredicateGroupingRule string   `json:"predicate_grouping_rule"`
		TargetBindingRule     string   `json:"target_binding_rule"`
		VerifierProfileURI    string   `json:"verifier_profile_uri"`
		ValidityPolicy        string   `json:"validity_policy"`
	}{profileURI, profileVersion, allowedSubjectKinds, evidenceContentTypes, predicateGroupingRule, targetBindingRule, verifierProfileURI, validityPolicy}
	canonical, err := codec.Marshal(profile)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(framedSHA256("tos.agreement-acceptance-profile.v1\x00", canonical)), nil
}
