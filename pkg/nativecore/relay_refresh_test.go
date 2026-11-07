package nativecore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// refreshFixture is a Capability publication whose owner Agent's policy can
// rotate between a crash before the broadcast lease and the retry.
type refreshFixture struct {
	locator   *Locator
	directory string
	owner     string
	action    *nativev1.NativeActionV1
	built     BuiltAction
}

func ownerPolicy(names ...string) *nativev1.ControllerPolicyV1 {
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 60}
	for _, name := range names {
		policy.Controllers = append(policy.Controllers, fakeController(name, knownPurposeMask, true))
	}
	return policy
}

func ownerState(owner string, policy *nativev1.ControllerPolicyV1) map[string]*nativev1.NativeStateV1 {
	return map[string]*nativev1.NativeStateV1{owner: {State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: owner, Policy: policy}}}}
}

func newRefreshFixture(t *testing.T) refreshFixture {
	t.Helper()
	l := testLocator(t)
	owner := "agent_" + strings.Repeat("a1", 32)
	version := &nativev1.CapabilityVersionV1{Version: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	capability, err := DeriveCapabilityID(l.Network, bytes32('p'), owner, version)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: capability,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('q'),
		Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: bytes32('p'), OwnerAgentId: owner, InitialVersion: version}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return refreshFixture{locator: l, directory: directory, owner: owner, action: action, built: built}
}

func (f refreshFixture) signed(t *testing.T, names ...string) *nativev1.SignedNativeActionV1 {
	t.Helper()
	return &nativev1.SignedNativeActionV1{Action: f.action, AuthoritySignatures: fakeSign(t, f.built, names...)}
}

func (f refreshFixture) relayer(t *testing.T, sender ContractCellSender, resolver RelayStateResolver, verifier mldsa44.Verifier, crash bool) (*Relayer, *FileRelayJournal) {
	t.Helper()
	journal, err := NewFileRelayJournal(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	relay := testRelayer(t, f.locator, sender, resolver)
	relay.Verifier = verifier
	relay.Journal = &leaseCrash{FileRelayJournal: journal, crash: crash}
	return relay, journal
}

func (f refreshFixture) queryID() uint64 {
	return relayQueryID(canonicalRelayActionIdentity(f.action, f.built.HashString))
}

func (f refreshFixture) body(t *testing.T, submission *nativev1.SignedNativeActionV1, queryID uint64) []byte {
	t.Helper()
	body, err := AgentAuthorizationBody(f.built, submission.AuthoritySignatures, nil, queryID)
	if err != nil {
		t.Fatal(err)
	}
	return body.ToBOC()
}

func (f refreshFixture) slot(t *testing.T, journal *FileRelayJournal) relaySlotRecord {
	t.Helper()
	slot, found, err := journal.readSlot(canonicalRelayStateSlotIdentity(f.action))
	if err != nil || !found {
		t.Fatalf("slot: found=%v err=%v", found, err)
	}
	return slot
}

// prepare claims the slot with controller A's signature and stops before the
// broadcast lease.
func (f refreshFixture) prepare(t *testing.T, sender *senderStub) *nativev1.SignedNativeActionV1 {
	t.Helper()
	first := f.signed(t, "refresh-a")
	relay, journal := f.relayer(t, sender, resolverStub{states: ownerState(f.owner, ownerPolicy("refresh-a"))}, fakeKeys, true)
	if _, err := relay.SubmitIdempotent(context.Background(), first, "first"); err == nil {
		t.Fatal("a crash before the broadcast lease reported success")
	}
	slot := f.slot(t, journal)
	if slot.Phase != relaySlotPrepared || slot.BodyBOCBase64 != base64.StdEncoding.EncodeToString(f.body(t, first, f.queryID())) || sender.calls != 0 {
		t.Fatalf("prepared slot = %s, %d broadcasts", slot.Phase, sender.calls)
	}
	return first
}

func TestPreparedRecoveryRefreshesABodyTheRotatedPolicyRefuses(t *testing.T) {
	f := newRefreshFixture(t)
	sender := &senderStub{}
	first := f.prepare(t, sender)
	// The owner rotated from A to B before the retry.
	rotated := resolverStub{states: ownerState(f.owner, ownerPolicy("refresh-b"))}
	retry := f.signed(t, "refresh-b")
	relay, journal := f.relayer(t, sender, rotated, fakeKeys, false)
	hash, err := relay.SubmitIdempotent(context.Background(), retry, "retry")
	if err != nil || hash != f.built.HashString {
		t.Fatalf("retry after rotation = %q, %v", hash, err)
	}
	want := base64.StdEncoding.EncodeToString(f.body(t, retry, f.queryID()))
	if sender.calls != 1 || sender.body != want {
		t.Fatalf("recovery broadcast %d bodies; carries the retry's signatures: %v", sender.calls, sender.body == want)
	}
	if slot := f.slot(t, journal); slot.Phase != relaySlotComplete || slot.BodyBOCBase64 != want {
		t.Fatalf("completed slot = %s, records the broadcast body: %v", slot.Phase, slot.BodyBOCBase64 == want)
	}
	// A completed slot answers any submission of the same action with the
	// recorded result and never broadcasts again.
	relay, _ = f.relayer(t, sender, rotated, fakeKeys, false)
	if hash, err := relay.SubmitIdempotent(context.Background(), first, "first"); err != nil || hash != f.built.HashString {
		t.Fatalf("completed slot answer = %q, %v", hash, err)
	}
	if sender.calls != 1 {
		t.Fatalf("completed slot caused %d broadcasts", sender.calls)
	}
}

func TestPreparedRecoveryAuthorizesAgainstFinalizedAuthority(t *testing.T) {
	f := newRefreshFixture(t)
	sender := &senderStub{}
	first := f.prepare(t, sender)
	// Current but unfinalized state still names A; finalized state names B.
	split := resolverStub{states: ownerState(f.owner, ownerPolicy("refresh-a")), finalized: ownerState(f.owner, ownerPolicy("refresh-b"))}
	relay, journal := f.relayer(t, sender, split, fakeKeys, false)
	if _, err := relay.SubmitIdempotent(context.Background(), first, "first-again"); err == nil {
		t.Fatal("signatures were authorized against unfinalized state")
	}
	if sender.calls != 0 || f.slot(t, journal).Phase != relaySlotPrepared {
		t.Fatal("an unfinalized authorization reached the broadcast lease")
	}
	retry := f.signed(t, "refresh-b")
	if _, err := relay.SubmitIdempotent(context.Background(), retry, "retry"); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 1 || sender.body != base64.StdEncoding.EncodeToString(f.body(t, retry, f.queryID())) {
		t.Fatal("recovery did not broadcast the body finalized authority accepts")
	}
}

// selectiveVerifier answers like the Fake except for one signature, for
// which it is unavailable.
type selectiveVerifier struct {
	unavailableFor []byte
}

func (v selectiveVerifier) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if bytes.Equal(signature, v.unavailableFor) {
		return mldsa44.ErrUnavailable
	}
	return fakeKeys.Verify(ctx, use, payload, publicKey, signature)
}

func TestPreparedRecoveryFailsClosedWithoutChangingTheSlot(t *testing.T) {
	cases := map[string]func(t *testing.T, f refreshFixture, first *nativev1.SignedNativeActionV1, journal *FileRelayJournal) (resolverStub, mldsa44.Verifier){
		"authority resolution fails": func(*testing.T, refreshFixture, *nativev1.SignedNativeActionV1, *FileRelayJournal) (resolverStub, mldsa44.Verifier) {
			return resolverStub{states: map[string]*nativev1.NativeStateV1{}, unavailable: map[string]bool{"agent_" + strings.Repeat("a1", 32): true}}, fakeKeys
		},
		"authority is not found": func(*testing.T, refreshFixture, *nativev1.SignedNativeActionV1, *FileRelayJournal) (resolverStub, mldsa44.Verifier) {
			return resolverStub{states: map[string]*nativev1.NativeStateV1{}}, fakeKeys
		},
		"verifier unavailable for the recorded signatures": func(_ *testing.T, f refreshFixture, first *nativev1.SignedNativeActionV1, _ *FileRelayJournal) (resolverStub, mldsa44.Verifier) {
			return resolverStub{states: ownerState(f.owner, ownerPolicy("refresh-a", "refresh-b"))},
				selectiveVerifier{unavailableFor: first.AuthoritySignatures[0].Mldsa44Signature}
		},
		"recorded body does not decode": func(t *testing.T, f refreshFixture, first *nativev1.SignedNativeActionV1, journal *FileRelayJournal) (resolverStub, mldsa44.Verifier) {
			// A recorded body under another query ID is not this operation's body.
			slot := f.slot(t, journal)
			tampered := f.body(t, first, f.queryID()+1)
			slot.BodyBOCBase64 = base64.StdEncoding.EncodeToString(tampered)
			slot.Intent.BodyHash = relayPayloadHash(tampered)
			raw, err := json.Marshal(slot)
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.atomicReplace(journal.slotPath(slot.StateSlotIdentity), raw); err != nil {
				t.Fatal(err)
			}
			return resolverStub{states: ownerState(f.owner, ownerPolicy("refresh-b"))}, fakeKeys
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRefreshFixture(t)
			sender := &senderStub{}
			first := f.prepare(t, sender)
			journal, err := NewFileRelayJournal(f.directory)
			if err != nil {
				t.Fatal(err)
			}
			resolver, verifier := setup(t, f, first, journal)
			before := f.slot(t, journal)
			relay, _ := f.relayer(t, sender, resolver, verifier, false)
			if _, err := relay.SubmitIdempotent(context.Background(), f.signed(t, "refresh-b"), "retry"); err == nil {
				t.Fatal("recovery proceeded without a decision on the recorded body")
			} else if _, coded := ErrorCodeOf(err); coded {
				t.Fatalf("an unavailable decision carried a protocol code: %v", err)
			}
			after := f.slot(t, journal)
			if sender.calls != 0 || after.Phase != relaySlotPrepared || after.BodyBOCBase64 != before.BodyBOCBase64 || after.Intent != before.Intent {
				t.Fatalf("slot changed or broadcast: phase %s, %d broadcasts", after.Phase, sender.calls)
			}
		})
	}
}

func TestLeaseRefusesARecordedBodyThatChanged(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	intent := journalTestIntent("sha256:cas")
	if _, _, err := journal.Begin("cas", "sha256:cas-action", intent, journalTestBody, journalTestLimits, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := journal.AcquireBroadcastLease("sha256:cas-action", intent, relayPayloadHash([]byte("another")), nil); err == nil {
		t.Fatal("a lease was given against a recorded body that changed")
	}
	replacement := []byte("verified replacement body")
	if _, _, _, err := journal.AcquireBroadcastLease("sha256:cas-action", intent, intent.BodyHash, replacement); err == nil {
		t.Fatal("a replacement that is not the intent's body was accepted")
	}
	if body, prepared, err := journal.RecordedBody("sha256:cas-action", intent); err != nil || !prepared || !bytes.Equal(body, journalTestBody) {
		t.Fatal("a refused lease changed the slot")
	}
	resigned := intent
	resigned.BodyHash = relayPayloadHash(replacement)
	acquired, complete, body, err := journal.AcquireBroadcastLease("sha256:cas-action", resigned, intent.BodyHash, replacement)
	if err != nil || !acquired || complete || !bytes.Equal(body, replacement) {
		t.Fatalf("replacing lease = (%v, %v, %q, %v)", acquired, complete, body, err)
	}
	if body, prepared, err := journal.RecordedBody("sha256:cas-action", intent); err != nil || prepared || !bytes.Equal(body, replacement) {
		t.Fatal("the slot does not record the body it handed out")
	}
	if acquired, _, _, err := journal.AcquireBroadcastLease("sha256:cas-action", intent, resigned.BodyHash, journalTestBody); err != nil || acquired {
		t.Fatal("a broadcasting slot was leased or refreshed again")
	}
	if body, _, _ := journal.RecordedBody("sha256:cas-action", intent); !bytes.Equal(body, replacement) {
		t.Fatal("a broadcasting slot's body was replaced")
	}
}
