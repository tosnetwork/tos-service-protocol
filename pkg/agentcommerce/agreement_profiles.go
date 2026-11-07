package agentcommerce

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// AgreementAuthorityKeyResolver resolves a purpose-limited key for the exact
// non-Agent subject frozen in an Agreement predicate.
type AgreementAuthorityKeyResolver interface {
	AuthorizeAgreementAuthorityKey(AgreementAuthoritySubject, ed25519.PublicKey, time.Time) error
}

// AuthoritySignatureEvidence converts one signed typed statement into the
// complete non-Agent authority predicate group selected by the Agreement.
func AuthoritySignatureEvidence(body AgentAgreementBody, acceptance SignedAgreementAcceptance) (AgreementAuthorizationEvidence, error) {
	if err := ValidateAgreementBody(body); err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	digest, err := AgreementBodyDigest(body)
	if err != nil || acceptance.Body.AgreementID != body.AgreementID || acceptance.Body.AgreementVersion != body.Version ||
		acceptance.Body.AgreementBodyDigest != digest {
		return AgreementAuthorizationEvidence{}, errors.New("typed authority acceptance does not target this Agreement")
	}
	var predicates []AgreementAuthorizationPredicate
	for _, predicate := range body.AuthorizationPredicates {
		if predicate.AuthoritySubject == acceptance.Body.AcceptingSubject && predicate.EvidenceProfileURI == EvidenceProfileAuthoritySignature {
			predicates = append(predicates, predicate)
		}
	}
	if len(predicates) == 0 || len(predicates) != len(acceptance.Body.PredicateIDs) {
		return AgreementAuthorizationEvidence{}, errors.New("typed authority acceptance does not cover one complete predicate group")
	}
	for index, predicate := range predicates {
		if predicate.EvidenceProfileVersion != 1 || predicate.EvidenceProfileDigest != AuthoritySignatureProfileDigest() ||
			predicate.PredicateID != acceptance.Body.PredicateIDs[index] ||
			predicate.EvidenceTargetProjectionDigest != acceptance.Body.EvidenceTargetProjectionDigests[index] {
			return AgreementAuthorizationEvidence{}, errors.New("typed authority acceptance predicate group is inconsistent")
		}
	}
	canonical, err := codec.Marshal(acceptance)
	if err != nil {
		return AgreementAuthorizationEvidence{}, err
	}
	return AgreementAuthorizationEvidence{AgreementID: body.AgreementID, AgreementVersion: body.Version,
		AgreementBodyDigest: digest, AuthoritySubject: acceptance.Body.AcceptingSubject,
		PredicateIDs: append([]string(nil), acceptance.Body.PredicateIDs...), EvidenceProfileURI: EvidenceProfileAuthoritySignature,
		EvidenceProfileVersion: 1, EvidenceProfileDigest: AuthoritySignatureProfileDigest(),
		EvidenceTargetProjectionDigests: append([]string(nil), acceptance.Body.EvidenceTargetProjectionDigests...),
		EvidenceContentType:             AuthorityAcceptanceContentType, Evidence: canonical}, nil
}

type AuthoritySignatureEvidenceVerifier struct{ Resolver AgreementAuthorityKeyResolver }

func (verifier AuthoritySignatureEvidenceVerifier) VerifyAgreementEvidence(evidence AgreementAuthorizationEvidence, now time.Time) error {
	if verifier.Resolver == nil || evidence.EvidenceProfileURI != EvidenceProfileAuthoritySignature || evidence.EvidenceProfileVersion != 1 ||
		evidence.EvidenceProfileDigest != AuthoritySignatureProfileDigest() || evidence.EvidenceContentType != AuthorityAcceptanceContentType {
		return errors.New("unsupported Agreement authority evidence profile")
	}
	acceptance, err := DecodeSignedAgreementAcceptance(evidence.Evidence)
	if err != nil || acceptance.Body.AgreementID != evidence.AgreementID || acceptance.Body.AgreementVersion != evidence.AgreementVersion ||
		acceptance.Body.AgreementBodyDigest != evidence.AgreementBodyDigest || acceptance.Body.AcceptingSubject != evidence.AuthoritySubject ||
		!equalStrings(acceptance.Body.PredicateIDs, evidence.PredicateIDs) ||
		!equalStrings(acceptance.Body.EvidenceTargetProjectionDigests, evidence.EvidenceTargetProjectionDigests) ||
		!now.UTC().Before(time.Unix(int64(acceptance.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("authority acceptance does not match evidence")
	}
	publicKey, err := parseEd25519PublicKey(acceptance.PublicKey)
	if err != nil {
		return err
	}
	if err := verifier.Resolver.AuthorizeAgreementAuthorityKey(evidence.AuthoritySubject, publicKey, now); err != nil {
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
		return errors.New("Agreement authority acceptance signature is invalid")
	}
	return nil
}
