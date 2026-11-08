package agentguarantor

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

const stageAuthorityController = "stage-authority"

// stageAdmissionFixture is one scalar Action Authority, the AuthorizedAction
// it signed, the stage admission statement it must sign, and the Action
// Authority resolver that authorizes exactly its key.
type stageAdmissionFixture struct {
	action        agentcommerce.AuthorizedAction
	statement     AuthorizationStatementV1
	fenceResolver mldsa44test.ActionAuthorityResolver
}

func newStageAdmissionFixture(t *testing.T) stageAdmissionFixture {
	t.Helper()
	authorityID := "authority_" + strings.Repeat("3c", 32)
	action := agentcommerce.AuthorizedAction{AuthorityID: authorityID,
		AuthorityKeyID: nativeTestFake.KeyID(stageAuthorityController)}
	statement := AuthorizationStatementV1{SchemaVersion: SchemaVersionV1, AuthoritySubject: action.AuthorityID,
		ProfileURI: ProfileURI, ProfileVersion: 1, ProfileDigest: testDigest("1"),
		AuthorizedObjectKind: StageActionAdmissionObjectKind, AuthorizedBodyDigest: testDigest("2"),
		ValidationTimeUnix: 1767225600}
	return stageAdmissionFixture{action: action, statement: statement,
		fenceResolver: mldsa44test.ActionAuthorityResolver{Verifier: nativeTestFake,
			Keys: map[string][][]byte{authorityID: {nativeTestFake.PublicKey(stageAuthorityController)}}}}
}

func (f stageAdmissionFixture) now() time.Time {
	return time.Unix(int64(f.statement.ValidationTimeUnix), 0)
}

// sign makes a valid Action Authority signature over statement under domain
// with the fixture's controller, so a refusal can only come from the check
// under test.
func (f stageAdmissionFixture) sign(t *testing.T, statement AuthorizationStatementV1, domain string) StageActionAdmissionAuthorizationV1 {
	t.Helper()
	return signStageAdmissionWith(t, statement, domain, stageAuthorityController, mldsa44.UseActionAuthority)
}

func signStageAdmissionWith(t *testing.T, statement AuthorizationStatementV1, domain, controller string,
	use mldsa44.Use) StageActionAdmissionAuthorizationV1 {
	t.Helper()
	message, err := NativeAuthorizationMessage(domain, statement)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := nativeTestFake.Sign(context.Background(), controller, use, message)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := agentcommerce.ActionAuthoritySignatureText(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return StageActionAdmissionAuthorizationV1{AuthoritySubject: statement.AuthoritySubject,
		ProfileURI: statement.ProfileURI, ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
		AuthorizedObjectKind: statement.AuthorizedObjectKind, AuthorizedBodyDigest: statement.AuthorizedBodyDigest,
		ValidationTimeUnix: statement.ValidationTimeUnix, EvidenceContentType: ActionAuthorityEvidenceContentType,
		Evidence: ActionAuthorityMLDSA44EvidenceV1{KeyID: mldsa44.KeyIDText(signed.KeyID), Signature: signature,
			HistoricalAuthorityProof: []byte("proof")}}
}

func (f stageAdmissionFixture) verify(authorization StageActionAdmissionAuthorizationV1) error {
	return f.verifyFor(authorization, f.action)
}

func (f stageAdmissionFixture) verifyFor(authorization StageActionAdmissionAuthorizationV1,
	action agentcommerce.AuthorizedAction) error {
	return verifyStageActionAdmissionAuthorizationV1(authorization, action, f.statement.AuthorizedBodyDigest,
		allowAuthorityResolver{}, f.fenceResolver, f.now())
}

func TestStageAdmissionVerifiesUnderTheActionAuthority(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	if err := fixture.verify(fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)); err != nil {
		t.Fatalf("a canonical stage admission was refused: %v", err)
	}
}

// The authorization's object kind is exactly stage-action-admission. The
// object-registry kind of the evidence envelope is not an alias for it.
func TestStageAdmissionRefusesAnotherObjectKind(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	for _, kind := range []string{"stage-action-admission-evidence", "stage-action-admission-body", "Stage-Action-Admission"} {
		statement := fixture.statement
		statement.AuthorizedObjectKind = kind
		if err := fixture.verify(fixture.sign(t, statement, StageActionAdmissionSignatureDomain)); err == nil {
			t.Fatalf("a stage admission signed for kind %q was accepted", kind)
		}
	}
	empty := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
	empty.AuthorizedObjectKind = ""
	if err := fixture.verify(empty); err == nil {
		t.Fatal("a stage admission without an object kind was accepted")
	}
	// The signature domain is fixed too.
	other := fixture.sign(t, fixture.statement, "tos.service.agent-guarantor-claim-decision-admission-signature.v1")
	if err := fixture.verify(other); err == nil {
		t.Fatal("a stage admission signed under another domain was accepted")
	}
}

// Its subject and key ID are the admitted AuthorizedAction's: a different key
// that signs correctly, and that the resolver would accept, still fails.
func TestStageAdmissionIsBoundToTheActionAuthorityKey(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	fixture.fenceResolver.Keys[fixture.action.AuthorityID] = append(fixture.fenceResolver.Keys[fixture.action.AuthorityID],
		nativeTestFake.PublicKey("other-authority"))
	if err := fixture.verify(signStageAdmissionWith(t, fixture.statement, StageActionAdmissionSignatureDomain,
		"other-authority", mldsa44.UseActionAuthority)); err == nil {
		t.Fatal("a stage admission signed by a key other than the action authority key was accepted")
	}
	statement := fixture.statement
	statement.AuthoritySubject = "authority_" + strings.Repeat("4d", 32)
	if err := fixture.verify(fixture.sign(t, statement, StageActionAdmissionSignatureDomain)); err == nil {
		t.Fatal("a stage admission naming another authority subject was accepted")
	}
}

// Both resolver gates hold independently: the Action Authority resolver must
// return the named key, the key must derive the named key ID, the signature
// must be under TOS-ACTION-AUTHORITY-V1, and the Guarantor resolver must
// still authorize the historical proof.
func TestStageAdmissionKeepsBothResolverGates(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	valid := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
	verifyWith := func(fenceResolver agentcommerce.FenceAuthorityResolver, authorityResolver AuthorityKeyResolver,
		authorization StageActionAdmissionAuthorizationV1) error {
		return verifyStageActionAdmissionAuthorizationV1(authorization, fixture.action, fixture.statement.AuthorizedBodyDigest,
			authorityResolver, fenceResolver, fixture.now())
	}
	if err := verifyWith(fixture.fenceResolver, allowAuthorityResolver{}, valid); err != nil {
		t.Fatalf("valid stage admission refused: %v", err)
	}
	refusingFence := mldsa44test.ActionAuthorityResolver{Verifier: nativeTestFake, Keys: map[string][][]byte{}}
	if err := verifyWith(refusingFence, allowAuthorityResolver{}, valid); err == nil {
		t.Fatal("a key the Action Authority resolver does not authorize was accepted")
	}
	if err := verifyWith(nil, allowAuthorityResolver{}, valid); err == nil {
		t.Fatal("a missing Action Authority resolver was accepted")
	}
	substituting := keySubstitutingResolver{ActionAuthorityResolver: fixture.fenceResolver,
		key: nativeTestFake.PublicKey("other-authority")}
	if err := verifyWith(substituting, allowAuthorityResolver{}, valid); err == nil {
		t.Fatal("a resolved key of another key ID was accepted")
	}
	guarantorContext := signStageAdmissionWith(t, fixture.statement, StageActionAdmissionSignatureDomain,
		stageAuthorityController, mldsa44.UseAgentGuarantor)
	if err := verifyWith(fixture.fenceResolver, allowAuthorityResolver{}, guarantorContext); err == nil {
		t.Fatal("a signature under TOS-AGENT-GUARANTOR-V1 was accepted as a stage admission")
	}
	if err := verifyWith(fixture.fenceResolver, refusingGuarantorResolver{}, valid); err == nil {
		t.Fatal("a stage admission the Guarantor resolver refuses was accepted")
	}
}

type keySubstitutingResolver struct {
	mldsa44test.ActionAuthorityResolver
	key []byte
}

func (r keySubstitutingResolver) ResolveActionAuthorityKey(string, [mldsa44.KeyIDSize]byte, time.Time) ([]byte, error) {
	return append([]byte(nil), r.key...), nil
}

type refusingGuarantorResolver struct{ nativeTestAuthority }

func (refusingGuarantorResolver) ResolveGuarantorAuthority(AuthorityResolutionScopeV1, string, time.Time, []byte) error {
	return errors.New("historical authority proof does not authorize this scope")
}

// The key ID and signature use exactly the AuthorizedAction text forms. Each
// case keeps the action's key ID equal to the evidence key ID, so only the
// text-form parser can refuse it.
func TestStageAdmissionRefusesNonCanonicalTextForms(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	valid := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
	encoded := strings.TrimPrefix(valid.Evidence.Signature, "mldsa44:")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	trailingBits := encoded[:len(encoded)-1] + string(alphabet[(last&^15)|((last+1)&15)])
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := strings.TrimPrefix(valid.Evidence.KeyID, "mldsa44:")
	for name, mutate := range map[string]func(*StageActionAdmissionAuthorizationV1){
		"uppercase key hex": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.KeyID = "mldsa44:" + strings.ToUpper(keyHex)
		},
		"key without prefix":      func(a *StageActionAdmissionAuthorizationV1) { a.Evidence.KeyID = keyHex },
		"key with another prefix": func(a *StageActionAdmissionAuthorizationV1) { a.Evidence.KeyID = "MLDSA44:" + keyHex },
		"Ed25519 key": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.KeyID = "ed25519:" + strings.Repeat("ab", 32)
		},
		"signature with non-zero trailing bits": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "mldsa44:" + trailingBits
		},
		"signature with an embedded newline": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "mldsa44:" + encoded[:40] + "\n" + encoded[41:]
		},
		"padded signature": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "mldsa44:" + encoded + "="
		},
		"standard base64 signature": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "mldsa44:" + strings.NewReplacer("-", "+", "_", "/").Replace(encoded) + "+"
		},
		"truncated signature": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "mldsa44:" + base64.RawURLEncoding.EncodeToString(decoded[:len(decoded)-1])
		},
		"oversized signature": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "mldsa44:" + base64.RawURLEncoding.EncodeToString(append(decoded, 0))
		},
		"Ed25519 signature": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "ed25519:" + base64.RawURLEncoding.EncodeToString(decoded[:64])
		},
		"signature without prefix": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = encoded
		},
	} {
		authorization := valid
		mutate(&authorization)
		action := fixture.action
		action.AuthorityKeyID = authorization.Evidence.KeyID
		if err := fixture.verifyFor(authorization, action); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if trailingBits == encoded {
		t.Fatal("the trailing-bit mutation did not change the signature text")
	}
}

// It is not native Agent evidence and carries only the Action Authority
// evidence content type.
func TestStageAdmissionRefusesAnotherContentType(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	if ActionAuthorityEvidenceContentType != "application/vnd.tos.service.agent-guarantor-action-authority-mldsa44-evidence.v1+cbor" {
		t.Fatalf("Action Authority evidence content type is %q", ActionAuthorityEvidenceContentType)
	}
	for _, contentType := range []string{NativeAuthorizationContentType, "",
		"application/vnd.tos.service.agent-guarantor-action-authority-ed25519-evidence.v1+cbor",
		"application/vnd.tos.service.agent-guarantor-action-authority-mldsa44-evidence.v2+cbor",
		strings.ToUpper(ActionAuthorityEvidenceContentType)} {
		authorization := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
		authorization.EvidenceContentType = contentType
		if err := fixture.verify(authorization); err == nil {
			t.Fatalf("a stage admission with content type %q was accepted", contentType)
		}
	}
}

// The historical authority proof bound is the native bound: at the bound it
// is accepted, one byte over it is refused, and an empty proof is refused.
func TestStageAdmissionHistoricalProofBound(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	for size, accepted := range map[int]bool{0: false, 1: true, MaxHistoricalAuthorityProofBytes: true,
		MaxHistoricalAuthorityProofBytes + 1: false} {
		authorization := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
		authorization.Evidence.HistoricalAuthorityProof = make([]byte, size)
		for index := range authorization.Evidence.HistoricalAuthorityProof {
			authorization.Evidence.HistoricalAuthorityProof[index] = 0x5a
		}
		if err := fixture.verify(authorization); (err == nil) != accepted {
			t.Fatalf("a %d-byte historical proof: accepted=%v, want %v (%v)", size, err == nil, accepted, err)
		}
	}
}
