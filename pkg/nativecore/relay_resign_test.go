package nativecore

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"google.golang.org/protobuf/proto"
)

// hedgingFake models hedged ML-DSA-44 signing on top of the Fake: besides
// the Fake's signature it accepts one alternative encoding, so one action can
// carry two different, equally valid signature sets. It is not ML-DSA-44.
type hedgingFake struct{ *mldsa44test.Fake }

func hedged(signature []byte) []byte {
	alternative := append([]byte(nil), signature...)
	alternative[len(alternative)-1] ^= 0xff
	return alternative
}

func (h hedgingFake) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if err := h.Fake.Verify(ctx, use, payload, publicKey, signature); err == nil {
		return nil
	}
	if len(signature) != mldsa44.SignatureSize {
		return mldsa44.ErrMalformed
	}
	return h.Fake.Verify(ctx, use, payload, publicKey, hedged(signature))
}

// leaseCrash simulates a process that dies after claiming its slot and
// before acquiring the broadcast lease.
type leaseCrash struct {
	*FileRelayJournal
	crash bool
}

func (j *leaseCrash) AcquireBroadcastLease(actionIdentity string, intent RelayIntent) (bool, bool, []byte, error) {
	if j.crash {
		return false, false, nil, errors.New("process stopped before the broadcast lease")
	}
	return j.FileRelayJournal.AcquireBroadcastLease(actionIdentity, intent)
}

type resignFixture struct {
	locator   *Locator
	directory string
	first     *nativev1.SignedNativeActionV1
	second    *nativev1.SignedNativeActionV1
	built     BuiltAction
}

func newResignFixture(t *testing.T) resignFixture {
	t.Helper()
	l := testLocator(t)
	policy, controller := testPolicy(t)
	first, built := signedAgentRegistration(t, l, policy, controller, bytes32('h'), bytes32('i'))
	second := proto.Clone(first).(*nativev1.SignedNativeActionV1)
	second.AuthoritySignatures[0].Mldsa44Signature = hedged(second.AuthoritySignatures[0].Mldsa44Signature)
	bodies := make([]string, 2)
	for i, submission := range []*nativev1.SignedNativeActionV1{first, second} {
		body, err := MessageBody(built, submission.AuthoritySignatures, nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		bodies[i] = base64.StdEncoding.EncodeToString(body.ToBOC())
	}
	if bodies[0] == bodies[1] {
		t.Fatal("re-signed submission did not change the body")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return resignFixture{locator: l, directory: directory, first: first, second: second, built: built}
}

// relayer opens a fresh journal on the fixture's directory: a new process.
func (f resignFixture) relayer(t *testing.T, sender ContractCellSender, resolver RelayStateResolver, crash bool) *Relayer {
	t.Helper()
	journal, err := NewFileRelayJournal(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	relay := testRelayer(t, f.locator, sender, resolver)
	relay.Verifier = hedgingFake{fakeKeys}
	relay.Journal = &leaseCrash{FileRelayJournal: journal, crash: crash}
	return relay
}

func TestResignedBodyForCompletedActionReturnsTheCompletedResult(t *testing.T) {
	f := newResignFixture(t)
	sender := &senderStub{}
	resolver := resolverStub{states: map[string]*nativev1.NativeStateV1{}}
	hash, err := f.relayer(t, sender, resolver, false).SubmitIdempotent(context.Background(), f.first, "first-signing")
	if err != nil || hash != f.built.HashString {
		t.Fatalf("first submission = %q, %v", hash, err)
	}
	recorded := sender.body
	for _, key := range []string{"first-signing", "second-signing"} {
		// Each retry runs in a new process over the same journal.
		hash, err := f.relayer(t, sender, resolver, false).SubmitIdempotent(context.Background(), f.second, key)
		if err != nil || hash != f.built.HashString {
			t.Fatalf("re-signed submission under %s = %q, %v", key, hash, err)
		}
	}
	if sender.calls != 1 || sender.body != recorded {
		t.Fatalf("re-signed completed action caused %d broadcasts", sender.calls)
	}
}

func TestResignedBodyForPreparedSlotBroadcastsTheRecordedBodyOnce(t *testing.T) {
	f := newResignFixture(t)
	sender := &senderStub{}
	resolver := resolverStub{states: map[string]*nativev1.NativeStateV1{}}
	if _, err := f.relayer(t, sender, resolver, true).SubmitIdempotent(context.Background(), f.first, "first-signing"); err == nil {
		t.Fatal("a crash before the broadcast lease reported success")
	}
	if sender.calls != 0 {
		t.Fatal("a prepared slot was broadcast before its lease")
	}
	// After restart a re-signed body for the same action recovers the slot,
	// and the slot's recorded body is the one broadcast.
	hash, err := f.relayer(t, sender, resolver, false).SubmitIdempotent(context.Background(), f.second, "second-signing")
	if err != nil || hash != f.built.HashString {
		t.Fatalf("recovery with a re-signed body = %q, %v", hash, err)
	}
	if sender.calls != 1 {
		t.Fatalf("prepared slot caused %d broadcasts", sender.calls)
	}
	recovered := sender.body
	expected := f.expectedBody(t, f.first)
	if recovered != expected {
		t.Fatal("the recovery broadcast the re-signed body instead of the recorded one")
	}
	for _, submission := range []*nativev1.SignedNativeActionV1{f.first, f.second} {
		if _, err := f.relayer(t, sender, resolver, false).SubmitIdempotent(context.Background(), submission, "later"); err != nil {
			t.Fatal(err)
		}
	}
	if sender.calls != 1 {
		t.Fatalf("completed slot caused %d broadcasts", sender.calls)
	}
}

func TestResignedBodyForBroadcastingSlotNeverRebroadcasts(t *testing.T) {
	f := newResignFixture(t)
	sender := &senderStub{sendErr: errors.New("ambiguous transport result")}
	resolver := resolverStub{states: map[string]*nativev1.NativeStateV1{}}
	if _, err := f.relayer(t, sender, resolver, false).SubmitIdempotent(context.Background(), f.first, "first-signing"); err == nil {
		t.Fatal("ambiguous broadcast reported success")
	}
	sender.sendErr = nil
	if _, err := f.relayer(t, sender, resolver, false).SubmitIdempotent(context.Background(), f.second, "second-signing"); err == nil {
		t.Fatal("an ambiguous slot was resolved without finalized evidence")
	}
	if sender.calls != 1 || sender.body != f.expectedBody(t, f.first) {
		t.Fatalf("broadcasting slot caused %d broadcasts", sender.calls)
	}
	id := f.first.Action.TargetObjectId
	resolver.states[id] = &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{
		AgentId: id, LastActionHash: f.built.HashString}}}
	hash, err := f.relayer(t, sender, resolver, false).SubmitIdempotent(context.Background(), f.second, "third-signing")
	if err != nil || hash != f.built.HashString || sender.calls != 1 {
		t.Fatalf("finalized resolution of a re-signed body = %q, %v, %d broadcasts", hash, err, sender.calls)
	}
}

// TestHedgedResigningThroughCustodyIsOneOperation signs one registration twice
// through real tosctl custody, whose ML-DSA-44 signing is hedged, and relays
// both signature sets with the real helper as verifier.
func TestHedgedResigningThroughCustodyIsOneOperation(t *testing.T) {
	custody := mldsa44test.NewCustody(t, "relay-controller")
	l := testLocator(t)
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 60,
		Controllers: []*nativev1.ControllerV1{{KeyId: custody.KeyID(t, "relay-controller"),
			Mldsa44PublicKey: custody.PublicKeys["relay-controller"], Weight: 1, PurposeMask: knownPurposeMask, Recovery: true}}}
	objectNonce := bytes32('k')
	id, err := DeriveAgentID(l.Network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: id,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('l'),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	submissions := make([]*nativev1.SignedNativeActionV1, 2)
	for i := range submissions {
		signature, err := SignAction(ctx, custody.Signer, "relay-controller", built)
		if err != nil {
			t.Fatal(err)
		}
		submissions[i] = &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	}
	if string(submissions[0].AuthoritySignatures[0].Mldsa44Signature) == string(submissions[1].AuthoritySignatures[0].Mldsa44Signature) {
		t.Fatal("custody signed one action twice with identical bytes; this test needs hedged signing to exercise re-signed bodies")
	}
	sender := &senderStub{}
	relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{}})
	relay.Verifier = mldsa44test.RequireTosctl(t)
	for i, submission := range submissions {
		hash, err := relay.SubmitIdempotent(ctx, submission, "custody-"+string(rune('a'+i)))
		if err != nil || hash != built.HashString {
			t.Fatalf("submission %d = %q, %v", i, hash, err)
		}
	}
	if sender.calls != 1 {
		t.Fatalf("two signings of one action caused %d broadcasts", sender.calls)
	}
}

func (f resignFixture) expectedBody(t *testing.T, submission *nativev1.SignedNativeActionV1) string {
	t.Helper()
	identity := canonicalRelayActionIdentity(submission.Action, f.built.HashString)
	queryID := relayQueryID(identity)
	body, err := MessageBody(f.built, submission.AuthoritySignatures, nil, queryID)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(body.ToBOC())
}

func TestJournalRefusesASlotWhoseBodyWasAltered(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	intent := journalTestIntent("sha256:altered")
	if _, _, err := journal.Begin("altered", "sha256:altered-action", intent, []byte("another body"), journalTestLimits, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("a body that does not match its intent was recorded")
	}
	if _, _, err := journal.Begin("altered", "sha256:altered-action", intent, journalTestBody, journalTestLimits, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	slot, found, err := journal.readSlot(intent.StateSlotIdentity)
	if err != nil || !found {
		t.Fatal(err)
	}
	slot.BodyBOCBase64 = base64.StdEncoding.EncodeToString([]byte("substituted body"))
	if slot.valid() {
		t.Fatal("a slot whose recorded body does not match its hash is valid")
	}
	resigned := intent
	resigned.BodyHash = relayPayloadHash([]byte("re-signed body"))
	acquired, complete, body, err := journal.AcquireBroadcastLease("sha256:altered-action", resigned)
	if err != nil || !acquired || complete || string(body) != string(journalTestBody) {
		t.Fatalf("lease for a re-signed intent = (%v, %v, %q, %v), want the recorded body", acquired, complete, body, err)
	}
	other := intent
	other.FundingNanoTOS++
	if _, _, _, err := journal.AcquireBroadcastLease("sha256:altered-action", other); err == nil {
		t.Fatal("a different funding amount matched the recorded operation")
	}
}
