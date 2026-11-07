package agentguarantor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// stageAdmissionFixture is one scalar Action Authority, the AuthorizedAction
// it signed, and the stage admission statement it must sign.
type stageAdmissionFixture struct {
	action    agentcommerce.AuthorizedAction
	private   ed25519.PrivateKey
	statement AuthorizationStatementV1
}

func newStageAdmissionFixture(t *testing.T) stageAdmissionFixture {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	action := agentcommerce.AuthorizedAction{AuthorityID: "authority_" + strings.Repeat("3c", 32),
		AuthorityPublicKey: "ed25519:" + hex.EncodeToString(public)}
	statement := AuthorizationStatementV1{SchemaVersion: SchemaVersionV1, AuthoritySubject: action.AuthorityID,
		ProfileURI: ProfileURI, ProfileVersion: 1, ProfileDigest: testDigest("1"),
		AuthorizedObjectKind: StageActionAdmissionObjectKind, AuthorizedBodyDigest: testDigest("2"),
		ValidationTimeUnix: 1767225600}
	return stageAdmissionFixture{action: action, private: private, statement: statement}
}

func (f stageAdmissionFixture) now() time.Time {
	return time.Unix(int64(f.statement.ValidationTimeUnix), 0)
}

// sign makes a valid Ed25519 signature over statement under domain with the
// fixture's key, so a refusal can only come from the check under test.
func (f stageAdmissionFixture) sign(t *testing.T, statement AuthorizationStatementV1, domain string) StageActionAdmissionAuthorizationV1 {
	t.Helper()
	return signStageAdmissionWith(t, statement, domain, f.private)
}

func signStageAdmissionWith(t *testing.T, statement AuthorizationStatementV1, domain string,
	private ed25519.PrivateKey) StageActionAdmissionAuthorizationV1 {
	t.Helper()
	message, err := NativeAuthorizationMessage(domain, statement)
	if err != nil {
		t.Fatal(err)
	}
	return StageActionAdmissionAuthorizationV1{AuthoritySubject: statement.AuthoritySubject,
		ProfileURI: statement.ProfileURI, ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
		AuthorizedObjectKind: statement.AuthorizedObjectKind, AuthorizedBodyDigest: statement.AuthorizedBodyDigest,
		ValidationTimeUnix: statement.ValidationTimeUnix, EvidenceContentType: ActionAuthorityEvidenceContentType,
		Evidence: ActionAuthorityEd25519EvidenceV1{
			PublicKey:                "ed25519:" + hex.EncodeToString(private.Public().(ed25519.PublicKey)),
			Signature:                "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message)),
			HistoricalAuthorityProof: []byte("proof")}}
}

func (f stageAdmissionFixture) verify(authorization StageActionAdmissionAuthorizationV1) error {
	return f.verifyFor(authorization, f.action)
}

func (f stageAdmissionFixture) verifyFor(authorization StageActionAdmissionAuthorizationV1,
	action agentcommerce.AuthorizedAction) error {
	return verifyStageActionAdmissionAuthorizationV1(authorization, action, f.statement.AuthorizedBodyDigest,
		allowAuthorityResolver{}, f.now())
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

// Its subject and key are the admitted AuthorizedAction's: a different key
// that signs correctly, and that the resolver would accept, still fails.
func TestStageAdmissionIsBoundToTheActionAuthorityKey(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	if err := fixture.verify(signStageAdmissionWith(t, fixture.statement, StageActionAdmissionSignatureDomain, other)); err == nil {
		t.Fatal("a stage admission signed by a key other than the action authority key was accepted")
	}
	statement := fixture.statement
	statement.AuthoritySubject = "authority_" + strings.Repeat("4d", 32)
	if err := fixture.verify(fixture.sign(t, statement, StageActionAdmissionSignatureDomain)); err == nil {
		t.Fatal("a stage admission naming another authority subject was accepted")
	}
}

// The key and signature use exactly the AuthorizedAction text forms. Each
// case keeps the action's key string equal to the evidence key, so only the
// text-form parser can refuse it.
func TestStageAdmissionRefusesNonCanonicalTextForms(t *testing.T) {
	fixture := newStageAdmissionFixture(t)
	valid := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
	encoded := strings.TrimPrefix(valid.Evidence.Signature, "ed25519:")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	trailingBits := encoded[:len(encoded)-1] + string(alphabet[last^1])
	for name, mutate := range map[string]func(*StageActionAdmissionAuthorizationV1){
		"uppercase key hex": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.PublicKey = "ed25519:" + strings.ToUpper(strings.TrimPrefix(a.Evidence.PublicKey, "ed25519:"))
		},
		"key without prefix": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.PublicKey = strings.TrimPrefix(a.Evidence.PublicKey, "ed25519:")
		},
		"key with another prefix": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.PublicKey = "ED25519:" + strings.TrimPrefix(a.Evidence.PublicKey, "ed25519:")
		},
		"signature with non-zero trailing bits": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "ed25519:" + trailingBits
		},
		"signature with an embedded newline": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "ed25519:" + encoded[:40] + "\n" + encoded[40:]
		},
		"signature with an embedded carriage return": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "ed25519:" + encoded[:40] + "\r" + encoded[40:]
		},
		"padded signature": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "ed25519:" + encoded + "=="
		},
		"standard base64 signature": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = "ed25519:" + strings.NewReplacer("-", "+", "_", "/").Replace(encoded) + "+"
		},
		"signature without prefix": func(a *StageActionAdmissionAuthorizationV1) {
			a.Evidence.Signature = encoded
		},
	} {
		authorization := valid
		mutate(&authorization)
		action := fixture.action
		action.AuthorityPublicKey = authorization.Evidence.PublicKey
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
	for _, contentType := range []string{NativeAuthorizationContentType, "",
		"application/vnd.tos.service.agent-guarantor-action-authority-ed25519-evidence.v2+cbor",
		strings.ToUpper(ActionAuthorityEvidenceContentType)} {
		authorization := fixture.sign(t, fixture.statement, StageActionAdmissionSignatureDomain)
		authorization.EvidenceContentType = contentType
		if err := fixture.verify(authorization); err == nil {
			t.Fatalf("a stage admission with content type %q was accepted", contentType)
		}
	}
}
