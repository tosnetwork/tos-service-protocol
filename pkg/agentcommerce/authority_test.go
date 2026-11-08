package agentcommerce

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// testActionAuthority is one Action Authority controller signing through the
// in-process Fake, with a resolver that authorizes exactly its key for one
// authority.
type testActionAuthority struct {
	fake        *mldsa44test.Fake
	controller  string
	authorityID string
	keyID       string
	resolver    mldsa44test.ActionAuthorityResolver
}

func newTestActionAuthority(controller, authorityID string) testActionAuthority {
	fake := &mldsa44test.Fake{}
	return testActionAuthority{fake: fake, controller: controller, authorityID: authorityID, keyID: fake.KeyID(controller),
		resolver: mldsa44test.ActionAuthorityResolver{Verifier: fake,
			Keys: map[string][][]byte{authorityID: {fake.PublicKey(controller)}}}}
}

func (a testActionAuthority) signFence(t testing.TB, body WriterFenceBody) WriterFence {
	t.Helper()
	fence, err := SignWriterFence(context.Background(), body, a.fake, a.controller)
	if err != nil {
		t.Fatal(err)
	}
	return fence
}

func (a testActionAuthority) signAction(t testing.TB, action AuthorizedAction) AuthorizedAction {
	t.Helper()
	signed, err := SignAuthorizedAction(context.Background(), action, a.keyID, a.fake, a.controller)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

type fixedCurrentFenceResolver struct {
	mldsa44test.ActionAuthorityResolver
	current WriterFenceBody
	err     error
}

func (r fixedCurrentFenceResolver) ConfirmCurrentWriterFence(fence WriterFence, _ time.Time) error {
	if r.err != nil {
		return r.err
	}
	if fence.Body.OwnerID != r.current.OwnerID || fence.Body.AgentID != r.current.AgentID ||
		fence.Body.InstanceID != r.current.InstanceID || fence.Body.LeaseID != r.current.LeaseID ||
		fence.Body.WriterGeneration != r.current.WriterGeneration || fence.Body.AuthorityID != r.current.AuthorityID {
		return errors.New("writer generation was superseded")
	}
	return nil
}

func TestConfirmCurrentWriterFenceFailsClosedAfterTakeover(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	old := WriterFence{Body: WriterFenceBody{OwnerID: "owner:test", AgentID: "agent:test", InstanceID: "instance:old",
		LeaseID: "lease:old", WriterGeneration: 7, AuthorityID: "authority:test", ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}}
	current := old.Body
	current.InstanceID = "instance:new"
	current.LeaseID = "lease:new"
	current.WriterGeneration++
	resolver := fixedCurrentFenceResolver{current: current}
	if err := ConfirmCurrentWriterFence(old, resolver, now); err == nil {
		t.Fatal("unexpired but superseded writer fence was accepted")
	}
	if err := ConfirmCurrentWriterFence(old, nil, now); err == nil {
		t.Fatal("missing current-writer authority was accepted")
	}
	currentFence := old
	currentFence.Body = current
	if err := ConfirmCurrentWriterFence(currentFence, resolver, now); err != nil {
		t.Fatalf("current writer fence was rejected: %v", err)
	}
}

type authorityFixture struct {
	authority testActionAuthority
	now       time.Time
	fence     WriterFence
	fields    map[string]SemanticValue
	request   []byte
	action    AuthorizedAction
}

func testFenceBody(now time.Time) WriterFenceBody {
	return WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test", AgentID: "agent:test",
		InstanceID: "instance:one", LeaseID: "lease:one", WriterGeneration: 3, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), AuthorityID: "authority:test", Scope: []string{"agreement.propose"}}
}

func newAuthorityFixture(t *testing.T) authorityFixture {
	t.Helper()
	authority := newTestActionAuthority("authority", "authority:test")
	now := time.Unix(2_000_000_000, 0).UTC()
	fence := authority.signFence(t, testFenceBody(now))
	fields := map[string]SemanticValue{"owner_id": ID("owner:test"), "agent_id": ID("agent:test"),
		"agreement_body_digest": Digest32("sha256:" + strings.Repeat("1", 64)),
		"recipient_set_digest":  Digest32("sha256:" + strings.Repeat("2", 64))}
	request := []byte("canonical-request")
	action, err := BuildAuthorizedAction("owner:test", "agent:test", "agreement.propose", fields, request, fence, 7,
		"sha256:"+strings.Repeat("3", 64), "", "none", uint64(now.Add(30*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return authorityFixture{authority: authority, now: now, fence: fence, fields: fields, request: request,
		action: authority.signAction(t, action)}
}

func (f authorityFixture) verify(action AuthorizedAction, fence WriterFence, resolver FenceAuthorityResolver) error {
	return VerifyAuthorizedAction(action, f.fields, f.request, fence, resolver, f.now)
}

func TestWriterFenceAndAuthorizedAction(t *testing.T) {
	f := newAuthorityFixture(t)
	if !strings.HasPrefix(f.fence.KeyID, "mldsa44:") || f.fence.KeyID != f.action.AuthorityKeyID ||
		!strings.HasPrefix(f.action.AuthorizationProof, "mldsa44:") {
		t.Fatalf("fence and action do not carry the ML-DSA-44 key ID and proof forms: %q %q", f.fence.KeyID, f.action.AuthorityKeyID)
	}
	if err := f.verify(f.action, f.fence, f.authority.resolver); err != nil {
		t.Fatal(err)
	}
	wrongPrincipalFields := map[string]SemanticValue{"owner_id": ID("owner:other"), "agent_id": ID("agent:test"),
		"agreement_body_digest": Digest32("sha256:" + strings.Repeat("1", 64)),
		"recipient_set_digest":  Digest32("sha256:" + strings.Repeat("2", 64))}
	if _, err := BuildAuthorizedAction("owner:test", "agent:test", "agreement.propose", wrongPrincipalFields, f.request, f.fence, 7,
		"sha256:"+strings.Repeat("3", 64), "", "none", uint64(f.now.Add(30*time.Second).Unix())); err == nil {
		t.Fatal("semantic owner different from AuthorizedAction owner was accepted")
	}
	mutated := append([]byte(nil), f.request...)
	mutated[0] = 'C'
	if err := VerifyAuthorizedAction(f.action, f.fields, mutated, f.fence, f.authority.resolver, f.now); err == nil {
		t.Fatal("changed request reused an AuthorizedAction")
	}
	tamperedAction := f.action
	tamperedAction.ExpectedPriorState = "different"
	if err := f.verify(tamperedAction, f.fence, f.authority.resolver); err == nil {
		t.Fatal("tampered action fields reused the authority proof")
	}
	unsignedAction := f.action
	unsignedAction.AuthorizationProof = ""
	if err := f.verify(unsignedAction, f.fence, f.authority.resolver); err == nil {
		t.Fatal("unsigned AuthorizedAction was accepted")
	}
	tampered := f.fence
	tampered.Body.WriterGeneration++
	if err := f.verify(f.action, tampered, f.authority.resolver); err == nil {
		t.Fatal("tampered writer generation was accepted")
	}
}

// The key comes only from the resolver: an unauthorized key, a resolver that
// returns a key of a different ID, and a missing resolver all refuse an
// otherwise valid fence and action.
func TestActionAuthorityKeyMustResolve(t *testing.T) {
	f := newAuthorityFixture(t)
	other := newTestActionAuthority("other", "authority:test")
	for name, resolver := range map[string]FenceAuthorityResolver{
		"unauthorized key": other.resolver,
		"another authority": mldsa44test.ActionAuthorityResolver{Verifier: f.authority.fake,
			Keys: map[string][][]byte{"authority:other": {f.authority.fake.PublicKey("authority")}}},
		"resolved key of another ID": substitutingResolver{ActionAuthorityResolver: f.authority.resolver,
			key: f.authority.fake.PublicKey("other")},
		"nil": nil,
	} {
		if err := f.verify(f.action, f.fence, resolver); err == nil {
			t.Errorf("%s: action accepted", name)
		}
		if err := VerifyWriterFence(f.fence, resolver, f.now, "agreement.propose"); err == nil {
			t.Errorf("%s: fence accepted", name)
		}
	}
}

// A fence whose proof is valid under one authorized key but whose key ID
// names another is refused because the resolved key must derive the carried
// key ID, even when the resolver returns the signing key for any ID.
func TestResolvedKeyMustDeriveTheCarriedKeyID(t *testing.T) {
	f := newAuthorityFixture(t)
	other := newTestActionAuthority("other", "authority:test")
	renamed := f.fence
	renamed.KeyID = other.keyID
	substituting := substitutingResolver{ActionAuthorityResolver: f.authority.resolver,
		key: f.authority.fake.PublicKey("authority")}
	if err := VerifyWriterFence(f.fence, substituting, f.now, "agreement.propose"); err != nil {
		t.Fatalf("the fence under its own key ID was refused: %v", err)
	}
	if err := VerifyWriterFence(renamed, substituting, f.now, "agreement.propose"); err == nil {
		t.Fatal("a fence naming another key ID verified under the resolved signing key")
	}
}

// substitutingResolver returns key for every lookup, whatever ID was asked.
type substitutingResolver struct {
	mldsa44test.ActionAuthorityResolver
	key []byte
}

func (r substitutingResolver) ResolveActionAuthorityKey(string, [mldsa44.KeyIDSize]byte, time.Time) ([]byte, error) {
	return append([]byte(nil), r.key...), nil
}

// A fence signed by one authorized key and an action signed by another
// authorized key of the same authority never combine.
func TestAuthorizedActionKeyMustEqualTheFenceKey(t *testing.T) {
	f := newAuthorityFixture(t)
	second := newTestActionAuthority("second", "authority:test")
	resolver := mldsa44test.ActionAuthorityResolver{Verifier: f.authority.fake, Keys: map[string][][]byte{
		"authority:test": {f.authority.fake.PublicKey("authority"), f.authority.fake.PublicKey("second")}}}
	unsigned := f.action
	unsigned.AuthorityKeyID, unsigned.AuthorizationProof = "", ""
	signedBySecond, err := SignAuthorizedAction(context.Background(), unsigned, second.keyID, f.authority.fake, "second")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verify(signedBySecond, f.fence, resolver); err == nil {
		t.Fatal("an action signed by a key other than the fence key was accepted")
	}
	if err := f.verify(f.action, f.fence, resolver); err != nil {
		t.Fatalf("the fence-key action was refused under a two-key resolver: %v", err)
	}
	// Custody must sign with exactly the key ID the action names.
	if _, err := SignAuthorizedAction(context.Background(), unsigned, f.authority.keyID, f.authority.fake, "second"); err == nil {
		t.Fatal("custody signed with a key other than the named key ID")
	}
}

// A real ML-DSA-44 signature over the same 32-byte message made under another
// context, or a signature of one Action Authority object kind presented as
// another, never verifies.
func TestActionAuthoritySignaturesAreContextAndDomainSeparated(t *testing.T) {
	f := newAuthorityFixture(t)
	message, err := AuthorizedActionSignatureMessage(f.action)
	if err != nil {
		t.Fatal(err)
	}
	for _, use := range []mldsa44.Use{mldsa44.UseAgentGuarantor, mldsa44.UseAgentPacket, mldsa44.UseAgentContact} {
		signed, err := f.authority.fake.Sign(context.Background(), "authority", use, message)
		if err != nil {
			t.Fatal(err)
		}
		text, err := ActionAuthoritySignatureText(signed.Signature)
		if err != nil {
			t.Fatal(err)
		}
		wrong := f.action
		wrong.AuthorizationProof = text
		if err := f.verify(wrong, f.fence, f.authority.resolver); err == nil {
			t.Fatalf("a %s signature over the action message was accepted", use)
		}
	}
	// The fence proof is a valid Action Authority signature, but over the
	// fence domain: it never authorizes the action.
	swapped := f.action
	swapped.AuthorizationProof = f.fence.Proof
	if err := f.verify(swapped, f.fence, f.authority.resolver); err == nil {
		t.Fatal("the fence proof was accepted as the action proof")
	}
}

// Ed25519 keys and signatures are refused with the dedicated error, and so
// are old field spellings and every non-canonical mldsa44: text form.
func TestActionAuthorityRefusesEd25519AndNonCanonicalText(t *testing.T) {
	f := newAuthorityFixture(t)
	ed25519Key := "ed25519:" + strings.Repeat("ab", 32)
	ed25519Proof := "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if _, err := ParseActionAuthorityKeyID(ed25519Key); !errors.Is(err, ErrEd25519ActionAuthority) {
		t.Fatalf("Ed25519 key: %v", err)
	}
	if _, err := ParseActionAuthoritySignature(ed25519Proof); !errors.Is(err, ErrEd25519ActionAuthority) {
		t.Fatalf("Ed25519 proof: %v", err)
	}
	ed25519Action := f.action
	ed25519Action.AuthorityKeyID, ed25519Action.AuthorizationProof = ed25519Key, ed25519Proof
	ed25519Fence := f.fence
	ed25519Fence.KeyID, ed25519Fence.Proof = ed25519Key, ed25519Proof
	if _, err := AuthorizedActionDigest(ed25519Action); !errors.Is(err, ErrEd25519ActionAuthority) && err == nil {
		t.Fatal("an Ed25519 action digest was computed")
	}
	if _, err := WriterFenceDigest(ed25519Fence); !errors.Is(err, ErrEd25519ActionAuthority) {
		t.Fatalf("Ed25519 fence digest: %v", err)
	}
	if err := VerifyWriterFence(ed25519Fence, f.authority.resolver, f.now, "agreement.propose"); !errors.Is(err, ErrEd25519ActionAuthority) {
		t.Fatalf("Ed25519 fence verification: %v", err)
	}
	if err := f.verify(ed25519Action, ed25519Fence, f.authority.resolver); err == nil {
		t.Fatal("an Ed25519 action was accepted")
	}

	keyHex := strings.TrimPrefix(f.fence.KeyID, "mldsa44:")
	encoded := strings.TrimPrefix(f.fence.Proof, "mldsa44:")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	trailing := encoded[:len(encoded)-1] + string(alphabet[(last&^15)|((last+1)&15)])
	decoded, _ := base64.RawURLEncoding.DecodeString(encoded)
	keyTexts := map[string]string{
		"uppercase key hex": "mldsa44:" + strings.ToUpper(keyHex),
		"63 hex":            "mldsa44:" + keyHex[:63],
		"65 hex":            "mldsa44:" + keyHex + "0",
		"all-zero key ID":   "mldsa44:" + strings.Repeat("0", 64),
		"no prefix":         keyHex,
		"uppercase prefix":  "MLDSA44:" + keyHex,
		"key CRLF":          f.fence.KeyID + "\r\n",
	}
	signatureTexts := map[string]string{
		"padding":          f.fence.Proof + "=",
		"standard base64":  "mldsa44:" + strings.NewReplacer("-", "+", "_", "/").Replace(encoded) + "+",
		"trailing bits":    "mldsa44:" + trailing,
		"embedded newline": "mldsa44:" + encoded[:40] + "\n" + encoded[41:],
		"truncated 2419":   "mldsa44:" + base64.RawURLEncoding.EncodeToString(decoded[:2419]),
		"oversized 2421":   "mldsa44:" + base64.RawURLEncoding.EncodeToString(append(decoded, 0)),
		"no prefix":        encoded,
	}
	if trailing == encoded {
		t.Fatal("the trailing-bit mutation did not change the text")
	}
	for name, text := range keyTexts {
		if _, err := ParseActionAuthorityKeyID(text); err == nil {
			t.Errorf("key ID %s was parsed", name)
		}
		mutated := f.fence
		mutated.KeyID = text
		if _, err := WriterFenceDigest(mutated); err == nil {
			t.Errorf("fence digest with key ID %s was computed", name)
		}
	}
	for name, text := range signatureTexts {
		if _, err := ParseActionAuthoritySignature(text); err == nil {
			t.Errorf("signature %s was parsed", name)
		}
		fence := f.fence
		fence.Proof = text
		if err := VerifyWriterFence(fence, f.authority.resolver, f.now, "agreement.propose"); err == nil {
			t.Errorf("fence with signature %s was accepted", name)
		}
		action := f.action
		action.AuthorizationProof = text
		if _, err := AuthorizedActionDigest(action); err == nil {
			t.Errorf("action digest with signature %s was computed", name)
		}
	}
}

func strictJSONDecode(document []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

// Strict JSON decoding refuses the removed field names, so an object written
// under the removed suite cannot be read as this one.
func TestRemovedActionAuthorityFieldNamesAreUnknown(t *testing.T) {
	f := newAuthorityFixture(t)
	for _, document := range []string{
		`{"body":{},"public_key":"` + f.fence.KeyID + `","fence_proof":"` + f.fence.Proof + `"}`,
	} {
		var fence WriterFence
		if err := strictJSONDecode([]byte(document), &fence); err == nil {
			t.Fatal("a fence with public_key was decoded")
		}
	}
	var action AuthorizedAction
	if err := strictJSONDecode([]byte(`{"authority_public_key":"`+f.action.AuthorityKeyID+`"}`), &action); err == nil {
		t.Fatal("an action with authority_public_key was decoded")
	}
}

func TestAuthorityInstanceIdentityIsRecoverable(t *testing.T) {
	zero := "sha256:" + strings.Repeat("0", 64)
	request := AuthorityInstanceAllocationRequest{OwnerID: "owner:test", AgentID: "agent:test", PurposeKind: "messenger.contact",
		MandateDigest: "sha256:" + strings.Repeat("1", 64), ApprovalDigestOrZero: zero,
		DownstreamEffectDescriptorDigest: "sha256:" + strings.Repeat("2", 64), PredecessorAuthorityInstanceID: zero}
	digest, err := AuthorityInstanceAllocationRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := AuthorityInstanceAllocationRequestDigest(request)
	if err != nil || retry != digest {
		t.Fatalf("allocation digest changed on retry: %q %v", retry, err)
	}
	first, err := DeriveAuthorityInstanceID(request, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveAuthorityInstanceID(request, 2)
	if err != nil || first == second {
		t.Fatal("distinct authority allocation sequence did not distinguish intentional repeats")
	}
}
