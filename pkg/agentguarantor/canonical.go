package agentguarantor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

func equalCanonical(left, right any) bool {
	leftBytes, leftErr := guarantorCodec.Marshal(left)
	rightBytes, rightErr := guarantorCodec.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const NativeAuthorizationContentType = "application/vnd.tos.service.agent-guarantor-native-authorization.v1+cbor"

// NativeAuthorizationSignaturePrefix prefixes the only text form of a native
// ML-DSA-44 signature.
const NativeAuthorizationSignaturePrefix = "mldsa44:"

// NativeAgentAuthorityResolver resolves native ML-DSA-44 Agent authority.
// ResolveNativeAgentKey proves from historicalProof, against finalized TOS
// state the resolver reads itself, that keyID named an Agent-control
// controller of scope.AuthoritySubject meeting the ordinary threshold at the
// signed time, and returns the 1,312-byte key stored for it. Verify checks
// ML-DSA-44 signatures.
type NativeAgentAuthorityResolver interface {
	ResolveNativeAgentKey(scope AuthorityResolutionScopeV1, keyID [mldsa44.KeyIDSize]byte, at time.Time,
		historicalProof []byte) ([]byte, error)
	mldsa44.Verifier
}

// AuthorityKeyResolver is the authority boundary of every Guarantor
// verifier. ResolveGuarantorAuthority authorizes the Ed25519 key of a scalar
// Action Authority for a stage admission (Semantic Action Identity scheme);
// native Agent authorization goes through NativeAgentAuthorityResolver.
type AuthorityKeyResolver interface {
	ResolveGuarantorAuthority(scope AuthorityResolutionScopeV1, publicKey string, at time.Time, historicalProof []byte) error
	NativeAgentAuthorityResolver
}

// AuthorityResolutionScopeV1 prevents a key authorized for one low-risk role
// from being replayed for a different profile, object, or signature domain.
type AuthorityResolutionScopeV1 struct {
	AuthoritySubject string
	ProfileURI       string
	ProfileVersion   uint64
	ProfileDigest    string
	AuthorizedKind   string
	AuthorizedDigest string
	SignatureDomain  string
}

// GuarantorCodecLimitsV1 are the canonical-encoding limits of every Guarantor
// V1 object. Only this profile uses them; the package-level codec limits of
// every other profile stay at codec.DefaultLimits.
//
//   - CanonicalBytes is the complete-object ceiling, MaxCanonicalObjectBytes.
//   - StringBytes equals the object ceiling: a nested string (a base64
//     canonical request inside a stage result) is part of the object that
//     carries it, so a lower string bound would be a second, arbitrary ceiling
//     that a valid history reaches first. The worst-case authorized-decision
//     receipt carries a 1,165,360-character request string.
//   - JSONBytes keeps the codec's JSON-to-CBOR ratio of 2.
var GuarantorCodecLimitsV1 = codec.Limits{CanonicalBytes: MaxCanonicalObjectBytes,
	JSONBytes: 2 * MaxCanonicalObjectBytes, StringBytes: MaxCanonicalObjectBytes}

var guarantorCodec = codec.Bounded{Limits: GuarantorCodecLimitsV1}

// Digest is codec.Digest under the Guarantor limits.
func Digest(domain string, value interface{}) (string, error) {
	return guarantorCodec.Digest(domain, value)
}

// Unmarshal is codec.Unmarshal under the Guarantor limits.
func Unmarshal(data []byte, output interface{}) error { return guarantorCodec.Unmarshal(data, output) }

// DigestCanonical is codec.DigestCanonical under the Guarantor limits.
func DigestCanonical(domain string, encoded []byte) (string, error) {
	return guarantorCodec.DigestCanonical(domain, encoded)
}

// Canonical is codec.Marshal under the Guarantor limits.
func Canonical(value interface{}) ([]byte, error) { return guarantorCodec.Marshal(value) }

func enforceCanonicalSize(value interface{}, maximum uint64, label string) error {
	if maximum == 0 || maximum > MaxCanonicalObjectBytes {
		return fmt.Errorf("%s has an invalid negotiated byte ceiling", label)
	}
	encoded, err := guarantorCodec.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", label, err)
	}
	if uint64(len(encoded)) > maximum {
		return fmt.Errorf("%s exceeds its negotiated byte ceiling", label)
	}
	return nil
}

func authorizationMessage(signatureDomain string, statement AuthorizationStatementV1) ([]byte, error) {
	if err := validateAuthorizationStatement(statement); err != nil {
		return nil, err
	}
	canonical, err := guarantorCodec.Marshal(statement)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(signatureDomain))
	h.Write([]byte{0})
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(canonical)))
	h.Write(size[:])
	h.Write(canonical)
	return h.Sum(nil), nil
}

// NativeAuthorizationMessage returns the 32-byte section 9 message a native
// authorization signs: SHA-256(domain || 0x00 || uint32_be(len) || CBOR).
func NativeAuthorizationMessage(signatureDomain string, statement AuthorizationStatementV1) ([]byte, error) {
	return authorizationMessage(signatureDomain, statement)
}

// NativeAuthorizationSignatureText renders a 2,420-byte signature in its only
// text form.
func NativeAuthorizationSignatureText(signature []byte) (string, error) {
	if len(signature) != mldsa44.SignatureSize {
		return "", errors.New("Guarantor authorization signature is not 2,420 bytes")
	}
	return NativeAuthorizationSignaturePrefix + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ParseNativeAuthorizationSignatureText accepts only mldsa44: followed by the
// unpadded URL-safe Base64 of exactly 2,420 bytes, with no padding, other
// alphabet, trailing bits or alias.
func ParseNativeAuthorizationSignatureText(value string) ([]byte, error) {
	if !strings.HasPrefix(value, NativeAuthorizationSignaturePrefix) {
		return nil, errors.New("Guarantor authorization signature has no mldsa44 prefix")
	}
	encoded := value[len(NativeAuthorizationSignaturePrefix):]
	signature, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) != mldsa44.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != encoded {
		return nil, errors.New("Guarantor authorization signature is not canonical")
	}
	return signature, nil
}

// SignObjectAuthorization signs a native authorization with the custody-held
// controller named controller, under TOS-AGENT-GUARANTOR-V1 over the section
// 9 message. historicalProof is the canonical proof the verifier will use to
// resolve the key; the signer never supplies the key.
func SignObjectAuthorization(ctx context.Context, statement AuthorizationStatementV1, signatureDomain string,
	signer mldsa44.Signer, controller string, historicalProof []byte) (ProfileQualifiedObjectAuthorizationV1, error) {
	if ctx == nil || signer == nil || len(historicalProof) == 0 || len(historicalProof) > MaxHistoricalAuthorityProofBytes {
		return ProfileQualifiedObjectAuthorizationV1{}, errors.New("Guarantor authorization signer or authority proof is invalid")
	}
	message, err := authorizationMessage(signatureDomain, statement)
	if err != nil {
		return ProfileQualifiedObjectAuthorizationV1{}, err
	}
	signed, err := signer.Sign(ctx, controller, mldsa44.UseAgentGuarantor, message)
	if err != nil {
		return ProfileQualifiedObjectAuthorizationV1{}, fmt.Errorf("Guarantor authorization signing: %w", err)
	}
	if err := mldsa44.CheckSignature(signed); err != nil {
		return ProfileQualifiedObjectAuthorizationV1{}, fmt.Errorf("Guarantor authorization custody answer: %w", err)
	}
	signatureText, err := NativeAuthorizationSignatureText(signed.Signature)
	if err != nil {
		return ProfileQualifiedObjectAuthorizationV1{}, err
	}
	return ProfileQualifiedObjectAuthorizationV1{AuthoritySubject: statement.AuthoritySubject,
		ProfileURI: statement.ProfileURI, ProfileVersion: statement.ProfileVersion,
		ProfileDigest: statement.ProfileDigest, AuthorizedObjectKind: statement.AuthorizedObjectKind,
		AuthorizedBodyDigest: statement.AuthorizedBodyDigest, ValidationTimeUnix: statement.ValidationTimeUnix,
		EvidenceContentType: NativeAuthorizationContentType,
		Evidence: NativeMLDSA44AgentAuthorizationEvidenceV1{KeyID: mldsa44.KeyIDText(signed.KeyID),
			Signature: signatureText, HistoricalAuthorityProof: append([]byte(nil), historicalProof...)}}, nil
}

// VerifyObjectAuthorization verifies one native ML-DSA-44 Agent
// authorization: exact text forms, the recomputed section 9 message, the key
// the historical authority proof resolves for key_id, and a Pure ML-DSA-44
// signature under TOS-AGENT-GUARANTOR-V1.
func VerifyObjectAuthorization(authorization ProfileQualifiedObjectAuthorizationV1, expectedObjectKind, expectedBodyDigest,
	signatureDomain string, resolver AuthorityKeyResolver, now time.Time) error {
	statement := authorization.AuthorizationStatement()
	if authorization.EvidenceContentType != NativeAuthorizationContentType ||
		statement.AuthorizedObjectKind != expectedObjectKind || statement.AuthorizedBodyDigest != expectedBodyDigest || resolver == nil ||
		len(authorization.Evidence.HistoricalAuthorityProof) == 0 ||
		len(authorization.Evidence.HistoricalAuthorityProof) > MaxHistoricalAuthorityProofBytes {
		return errors.New("Guarantor object authorization does not match the expected body")
	}
	if statement.ValidationTimeUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) {
		return errors.New("Guarantor authorization validation time is in the future")
	}
	keyID, err := mldsa44.ParseKeyIDText(authorization.Evidence.KeyID)
	if err != nil {
		return errors.New("Guarantor authorization key ID is invalid")
	}
	signature, err := ParseNativeAuthorizationSignatureText(authorization.Evidence.Signature)
	if err != nil {
		return err
	}
	message, err := authorizationMessage(signatureDomain, statement)
	if err != nil {
		return err
	}
	publicKey, err := resolver.ResolveNativeAgentKey(AuthorityResolutionScopeV1{
		AuthoritySubject: statement.AuthoritySubject, ProfileURI: statement.ProfileURI,
		ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
		AuthorizedKind: statement.AuthorizedObjectKind, AuthorizedDigest: statement.AuthorizedBodyDigest,
		SignatureDomain: signatureDomain,
	}, keyID, time.Unix(int64(statement.ValidationTimeUnix), 0).UTC(), authorization.Evidence.HistoricalAuthorityProof)
	if err != nil {
		return fmt.Errorf("Guarantor authorization authority: %w", err)
	}
	derived, err := mldsa44.KeyID(publicKey)
	if err != nil || derived != keyID {
		return errors.New("Guarantor authorization resolved key does not derive its key ID")
	}
	if err := resolver.Verify(context.Background(), mldsa44.UseAgentGuarantor, message, publicKey, signature); err != nil {
		return fmt.Errorf("Guarantor authorization signature does not verify: %w", err)
	}
	return nil
}

// StageActionAdmissionObjectKind is the only authorized object kind of a
// portable stage admission authorization.
const StageActionAdmissionObjectKind = "stage-action-admission"

// StageActionAdmissionSignatureDomain separates stage admission signatures
// from every other Action Authority signature.
const StageActionAdmissionSignatureDomain = "tos.service.agent-guarantor-stage-action-admission-signature.v1"

// ActionAuthorityEvidenceContentType tags Action Authority evidence under the
// Semantic Action Identity scheme. It is distinct from the native Agent
// evidence type, so neither can be presented as the other.
const ActionAuthorityEvidenceContentType = "application/vnd.tos.service.agent-guarantor-action-authority-mldsa44-evidence.v1+cbor"

// verifyStageActionAdmissionAuthorizationV1 verifies a stage admission under
// the scalar Action Authority's Semantic Action Identity scheme. It is never
// native Agent evidence: its kind, signature domain and content type are
// fixed, its subject and key ID are those of the admitted AuthorizedAction,
// its key ID and signature use exactly the AuthorizedAction text forms, the
// key resolves through the Action Authority resolver at the validation time,
// and the Guarantor resolver must still authorize the historical proof for the
// complete scope.
func verifyStageActionAdmissionAuthorizationV1(authorization StageActionAdmissionAuthorizationV1,
	action agentcommerce.AuthorizedAction, expectedBodyDigest string, resolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	statement := authorization.AuthorizationStatement()
	if authorization.EvidenceContentType != ActionAuthorityEvidenceContentType ||
		statement.AuthorizedObjectKind != StageActionAdmissionObjectKind || statement.AuthorizedBodyDigest != expectedBodyDigest ||
		resolver == nil || fenceResolver == nil || len(authorization.Evidence.HistoricalAuthorityProof) == 0 ||
		len(authorization.Evidence.HistoricalAuthorityProof) > MaxHistoricalAuthorityProofBytes {
		return errors.New("Guarantor stage admission authorization does not match the expected body")
	}
	if statement.AuthoritySubject != action.AuthorityID || authorization.Evidence.KeyID != action.AuthorityKeyID {
		return errors.New("Guarantor stage admission is not signed by the admitted action's authority key")
	}
	if statement.ValidationTimeUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) {
		return errors.New("Guarantor authorization validation time is in the future")
	}
	message, err := authorizationMessage(StageActionAdmissionSignatureDomain, statement)
	if err != nil {
		return errors.New("Guarantor stage admission statement is invalid")
	}
	validationTime := time.Unix(int64(statement.ValidationTimeUnix), 0).UTC()
	if err := agentcommerce.VerifyActionAuthoritySignature(fenceResolver, statement.AuthoritySubject,
		authorization.Evidence.KeyID, authorization.Evidence.Signature, message, validationTime); err != nil {
		return fmt.Errorf("Guarantor stage admission signature does not verify: %w", err)
	}
	return resolver.ResolveGuarantorAuthority(AuthorityResolutionScopeV1{
		AuthoritySubject: statement.AuthoritySubject, ProfileURI: statement.ProfileURI,
		ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
		AuthorizedKind: statement.AuthorizedObjectKind, AuthorizedDigest: statement.AuthorizedBodyDigest,
		SignatureDomain: StageActionAdmissionSignatureDomain,
	}, authorization.Evidence.KeyID, validationTime, authorization.Evidence.HistoricalAuthorityProof)
}

func ValidateAuthorizationSet(authorizations []ProfileQualifiedObjectAuthorizationV1, objectKind, bodyDigest,
	signatureDomain string, requiredSubjects []string, resolver AuthorityKeyResolver, now time.Time) error {
	if len(authorizations) == 0 || len(authorizations) > MaxAuthorizations || !sortedUnique(requiredSubjects, MaxAuthorizations, validID) {
		return errors.New("Guarantor authorization set is invalid")
	}
	seen := make(map[string]struct{}, len(authorizations))
	previous := []byte(nil)
	for _, authorization := range authorizations {
		canonical, err := guarantorCodec.Marshal(authorization)
		if err != nil || previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return errors.New("Guarantor authorizations are unsorted or duplicated")
		}
		previous = canonical
		if err := VerifyObjectAuthorization(authorization, objectKind, bodyDigest, signatureDomain, resolver, now); err != nil {
			return err
		}
		if _, duplicate := seen[authorization.AuthoritySubject]; duplicate {
			return errors.New("Guarantor authorization subject is duplicated")
		}
		seen[authorization.AuthoritySubject] = struct{}{}
	}
	for _, subject := range requiredSubjects {
		if _, found := seen[subject]; !found {
			return fmt.Errorf("required Guarantor authority %q is missing", subject)
		}
	}
	return nil
}

// QuorumThresholdV1 parses the closed V1 quorum grammar.  A quorum is part of
// the signed commercial terms, so implementations MUST NOT delegate its
// interpretation to UI text or an adapter-specific expression language.
//
// The only released forms are "all", "any", and "at-least:<n>" where n is a
// canonical base-10 positive integer no greater than the eligible subject set.
func QuorumThresholdV1(rule string, eligibleSubjects []string) (int, error) {
	if !sortedUnique(eligibleSubjects, MaxAuthorizations, validID) {
		return 0, errors.New("Guarantor quorum subject set is invalid")
	}
	switch rule {
	case "all":
		return len(eligibleSubjects), nil
	case "any":
		return 1, nil
	}
	const prefix = "at-least:"
	if !strings.HasPrefix(rule, prefix) {
		return 0, errors.New("Guarantor quorum rule is not released")
	}
	raw := strings.TrimPrefix(rule, prefix)
	if raw == "" || len(raw) > 2 || raw[0] == '0' {
		return 0, errors.New("Guarantor quorum threshold is not canonical")
	}
	value, err := strconv.ParseUint(raw, 10, 8)
	if err != nil || value == 0 || value > uint64(len(eligibleSubjects)) {
		return 0, errors.New("Guarantor quorum threshold is unsatisfiable")
	}
	return int(value), nil
}

func QuorumThresholdMustFailV1(rule string, eligibleSubjects []string) bool {
	_, err := QuorumThresholdV1(rule, eligibleSubjects)
	return err != nil
}

// ValidateAuthorizationQuorumSet verifies an exact eligible-subject domain and
// then evaluates its released quorum rule.  Signatures by subjects outside the
// Agreement-selected domain are rejected instead of being ignored.
func ValidateAuthorizationQuorumSet(authorizations []ProfileQualifiedObjectAuthorizationV1, objectKind, bodyDigest,
	signatureDomain string, eligibleSubjects []string, quorumRule string, resolver AuthorityKeyResolver, now time.Time) error {
	threshold, err := QuorumThresholdV1(quorumRule, eligibleSubjects)
	if err != nil || len(authorizations) < threshold || len(authorizations) > len(eligibleSubjects) {
		return errors.New("Guarantor authorization quorum is not satisfied")
	}
	eligible := make(map[string]struct{}, len(eligibleSubjects))
	for _, subject := range eligibleSubjects {
		eligible[subject] = struct{}{}
	}
	seen := make(map[string]struct{}, len(authorizations))
	previous := []byte(nil)
	for _, authorization := range authorizations {
		canonical, marshalErr := guarantorCodec.Marshal(authorization)
		if marshalErr != nil || previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return errors.New("Guarantor authorizations are unsorted or duplicated")
		}
		previous = canonical
		if _, ok := eligible[authorization.AuthoritySubject]; !ok {
			return errors.New("Guarantor authorization subject is outside the selected quorum")
		}
		if _, duplicate := seen[authorization.AuthoritySubject]; duplicate {
			return errors.New("Guarantor authorization subject is duplicated")
		}
		if verifyErr := VerifyObjectAuthorization(authorization, objectKind, bodyDigest, signatureDomain, resolver, now); verifyErr != nil {
			return verifyErr
		}
		seen[authorization.AuthoritySubject] = struct{}{}
	}
	return nil
}

func validateAuthorizationStatement(statement AuthorizationStatementV1) error {
	if statement.SchemaVersion != 1 || !validID(statement.AuthoritySubject) || !validID(statement.ProfileURI) ||
		statement.ProfileVersion == 0 || !digestPattern.MatchString(statement.ProfileDigest) ||
		!validToken(statement.AuthorizedObjectKind, 128) || !digestPattern.MatchString(statement.AuthorizedBodyDigest) ||
		!validUnixTimestampV1(statement.ValidationTimeUnix) {
		return errors.New("Guarantor authorization statement is invalid")
	}
	return nil
}

// validUnixTimestampV1 is the common boundary for protocol timestamps that
// are converted to time.Time. The wire representation is uint64, while Go's
// Unix conversion accepts int64. Rejecting the non-overlapping half of the
// wire domain prevents a crafted in-memory value from wrapping into the past
// before policy or historical-authority validation.
func validUnixTimestampV1(value uint64) bool {
	return value > 0 && value <= math.MaxInt64
}

func validID(value string) bool { return validToken(value, MaxObjectIDBytes) }

func validToken(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && utf8.ValidString(value) && !bytes.ContainsRune([]byte(value), 0)
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func sortedUnique(values []string, maximum int, valid func(string) bool) bool {
	if len(values) == 0 || len(values) > maximum || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func sameAsset(left, right AssetIdentityV1) bool { return left == right }

func validateAmount(amount AtomicAmountV1, positive bool) error {
	return agentcommerce.ValidateAtomicAmountV1(amount, positive)
}

func compareAmount(left, right AtomicAmountV1) (int, error) {
	if !sameAsset(left.Asset, right.Asset) || validateAmount(left, false) != nil || validateAmount(right, false) != nil {
		return 0, errors.New("amount assets differ")
	}
	if len(left.AmountAtomic) < len(right.AmountAtomic) {
		return -1, nil
	}
	if len(left.AmountAtomic) > len(right.AmountAtomic) {
		return 1, nil
	}
	return bytes.Compare([]byte(left.AmountAtomic), []byte(right.AmountAtomic)), nil
}
