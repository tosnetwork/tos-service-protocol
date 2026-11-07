package nativecore

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type senderStub struct {
	destination, body, stateInit string
	calls                        int
	sendErr                      error
}

// resolverStub answers ResolveState from states. ResolveFinalizedState
// answers from finalized when it is set (so current and finalized state can
// differ) and fails for the objects listed in unavailable.
type resolverStub struct {
	states      map[string]*nativev1.NativeStateV1
	finalized   map[string]*nativev1.NativeStateV1
	unavailable map[string]bool
	finalizedAt time.Time
}

func (r resolverStub) ResolveState(_ context.Context, objectID, _ string) (*nativev1.NativeStateV1, bool, error) {
	state, found := r.states[objectID]
	return state, found, nil
}

func (r resolverStub) ResolveFinalizedState(_ context.Context, objectID, _ string) (*nativev1.NativeStateV1, bool, time.Time, error) {
	if r.unavailable[objectID] {
		return nil, false, time.Time{}, errors.New("finalized state is unavailable")
	}
	states := r.states
	if r.finalized != nil {
		states = r.finalized
	}
	state, found := states[objectID]
	finalizedAt := r.finalizedAt
	if finalizedAt.IsZero() {
		finalizedAt = time.Unix(1_700_000_000, 0).UTC()
	}
	return state, found, finalizedAt, nil
}

func testRelayer(t *testing.T, locator *Locator, sender ContractCellSender, resolver RelayStateResolver) *Relayer {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	return &Relayer{Locator: locator, Sender: sender, Verifier: fakeKeys, FundingNanoTOS: MinimumRelayFundingNanoTOS, Journal: journal, Resolver: resolver,
		Limits: RelaySpendLimits{Window: time.Hour, MaxActionsPerTarget: 100, MaxFundingPerTargetNanoTOS: 100 * MinimumRelayFundingNanoTOS,
			MaxActionsPerWallet: 1000, MaxFundingPerWalletNanoTOS: 1000 * MinimumRelayFundingNanoTOS},
		RecoverySafety: MinimumRecoveryRelaySafety}
}

func (s *senderStub) SendContractCell(_ context.Context, destination string, _ uint64, body, stateInit string) error {
	s.destination, s.body, s.stateInit = destination, body, stateInit
	s.calls++
	return s.sendErr
}

func signedAgentRegistration(t *testing.T, locator *Locator, policy *nativev1.ControllerPolicyV1, controller string, objectNonce, actionNonce []byte) (*nativev1.SignedNativeActionV1, BuiltAction) {
	t.Helper()
	id, err := DeriveAgentID(locator.Network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: locator.Network, TargetObjectId: id,
		TargetContractCodeHash: locator.CodeHash, Generation: 1, Sequence: 1, Nonce: actionNonce,
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(context.Background(), fakeKeys, controller, built)
	if err != nil {
		t.Fatal(err)
	}
	return &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}, built
}

func TestRelayerSubmissionFailsClosedWithoutDurableDependencies(t *testing.T) {
	relay := &Relayer{Locator: testLocator(t), Sender: &senderStub{}, FundingNanoTOS: MinimumRelayFundingNanoTOS}
	if _, err := relay.Submit(context.Background(), &nativev1.SignedNativeActionV1{Action: &nativev1.NativeActionV1{}}, 1); err == nil {
		t.Fatal("relayer accepted submission without durable journal and finalized resolver")
	}
}

func TestRecoverySafetyPolicyIsBoundedAndWholeSecond(t *testing.T) {
	for _, value := range []time.Duration{MinimumRecoveryRelaySafety, MaximumRecoveryRelaySafety, 30 * time.Minute} {
		if !validRecoverySafety(value) {
			t.Fatalf("valid recovery safety rejected: %v", value)
		}
	}
	for _, value := range []time.Duration{0, MinimumRecoveryRelaySafety - time.Second,
		MaximumRecoveryRelaySafety + time.Second, MinimumRecoveryRelaySafety + time.Nanosecond} {
		if validRecoverySafety(value) {
			t.Fatalf("invalid recovery safety accepted: %v", value)
		}
	}
}

func TestRelayerMirrorsContractCounterpartySignatureShape(t *testing.T) {
	nonempty := []*nativev1.SignatureV1{{}}
	for _, kind := range []Kind{KindUpdateAgentPolicy, KindInitiateRecovery, KindTransferCapability} {
		if err := validateSignatureShape(kind, nonempty); err != nil {
			t.Fatalf("required counterparty shape rejected for kind %d: %v", kind, err)
		}
		if err := validateSignatureShape(kind, nil); err == nil {
			t.Fatalf("empty required counterparty shape accepted for kind %d", kind)
		}
	}
	for _, kind := range []Kind{KindRegisterAgent, KindDelegateAgent, KindCompleteRecovery, KindRevokeAgent,
		KindRegisterCapability, KindAddCapabilityVersion, KindRevokeCapability} {
		if err := validateSignatureShape(kind, nil); err != nil {
			t.Fatalf("empty counterparty shape rejected for kind %d: %v", kind, err)
		}
		if err := validateSignatureShape(kind, nonempty); err == nil {
			t.Fatalf("forbidden counterparty shape accepted for kind %d", kind)
		}
	}
}

func TestRelayerDeduplicatesCanonicalActionAcrossRequestKeys(t *testing.T) {
	l := testLocator(t)
	policy, controller := testPolicy(t)
	objectNonce := bytes32('o')
	id, err := DeriveAgentID(l.Network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: id,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('a'),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(context.Background(), fakeKeys, controller, built)
	if err != nil {
		t.Fatal(err)
	}
	sender := &senderStub{}
	relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{}})
	submission := &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	forbidden := &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}, CounterpartySignatures: []*nativev1.SignatureV1{signature}}
	if _, err := relay.SubmitIdempotent(context.Background(), forbidden, "forbidden-signature-shape"); err == nil || sender.calls != 0 {
		t.Fatalf("forbidden counterparty signature reached paid broadcast: err=%v calls=%d", err, sender.calls)
	}
	hash, err := relay.SubmitIdempotent(context.Background(), submission, "audit-key-one")
	if err != nil || hash != built.HashString || sender.destination == "" || sender.body == "" || sender.stateInit == "" {
		t.Fatalf("relay: %v", err)
	}
	if _, err := relay.SubmitIdempotent(context.Background(), submission, "audit-key-two"); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 1 {
		t.Fatalf("completed intent caused %d paid broadcasts", sender.calls)
	}
}

func TestRelayerFencesConflictingRegistrationNonceVariants(t *testing.T) {
	l := testLocator(t)
	policy, controller := testPolicy(t)
	first, firstBuilt := signedAgentRegistration(t, l, policy, controller, bytes32('o'), bytes32('a'))
	second, secondBuilt := signedAgentRegistration(t, l, policy, controller, bytes32('o'), bytes32('b'))
	if firstBuilt.HashString == secondBuilt.HashString {
		t.Fatal("nonce variants unexpectedly produced one action hash")
	}
	if canonicalRelayStateSlotIdentity(first.Action) != canonicalRelayStateSlotIdentity(second.Action) {
		t.Fatal("nonce variants escaped their shared canonical state slot")
	}
	sender := &senderStub{}
	relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{}})
	if _, err := relay.SubmitIdempotent(context.Background(), first, "slot-key-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.SubmitIdempotent(context.Background(), second, "slot-key-two"); err == nil {
		t.Fatal("conflicting nonce variant acquired a second paid broadcast")
	}
	if sender.calls != 1 {
		t.Fatalf("conflicting registration actions caused %d paid broadcasts, want 1", sender.calls)
	}
}

func TestRelayerRejectsExistingRegistrationBeforePaidBroadcast(t *testing.T) {
	l := testLocator(t)
	policy, controller := testPolicy(t)
	submission, _ := signedAgentRegistration(t, l, policy, controller, bytes32('x'), bytes32('a'))
	id := submission.Action.TargetObjectId
	state := &nativev1.NativeStateV1{TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("11", 32),
		State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: id, Generation: 1, Sequence: 1, Policy: policy}}}
	sender := &senderStub{}
	relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{id: state}})
	if _, err := relay.SubmitIdempotent(context.Background(), submission, "existing-registration"); err == nil {
		t.Fatal("existing Agent registration passed finalized-state preflight")
	}
	if sender.calls != 0 {
		t.Fatalf("existing Agent registration caused %d paid broadcasts", sender.calls)
	}
}

func TestRelayerRejectsInvalidCapabilityStateBeforePaidBroadcast(t *testing.T) {
	l := testLocator(t)
	policy, controller := testPolicy(t)
	ownerNonce := bytes32('o')
	owner, err := DeriveAgentID(l.Network, ownerNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	initialVersion := &nativev1.CapabilityVersionV1{Version: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	capability, err := DeriveCapabilityID(l.Network, bytes32('c'), owner, initialVersion)
	if err != nil {
		t.Fatal(err)
	}
	predecessor := "tvm-cell-sha256:" + strings.Repeat("66", 32)
	newVersion := &nativev1.CapabilityVersionV1{Version: "2.0.0", ManifestDigest: "sha256:" + strings.Repeat("77", 32)}
	makeSubmission := func(ownerID string, generation, sequence uint64) *nativev1.SignedNativeActionV1 {
		action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: capability,
			TargetContractCodeHash: l.CodeHash, Generation: generation, Sequence: sequence,
			PredecessorTvmStateHash: predecessor, Nonce: bytes32('n'),
			Payload: &nativev1.NativeActionV1_AddCapabilityVersion{AddCapabilityVersion: &nativev1.AddCapabilityVersionV1{
				Version: newVersion, OwnerAgentId: ownerID}}}
		built, err := BuildAction(action)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := SignAction(context.Background(), fakeKeys, controller, built)
		if err != nil {
			t.Fatal(err)
		}
		return &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	}
	for _, test := range []struct {
		name       string
		owner      string
		generation uint64
		sequence   uint64
		tombstoned bool
	}{
		{name: "wrong owner", owner: "agent_" + strings.Repeat("22", 32), generation: 1, sequence: 2},
		{name: "skipped sequence", owner: owner, generation: 1, sequence: 3},
		{name: "terminal capability", owner: owner, generation: 1, sequence: 2, tombstoned: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			targetState := &nativev1.NativeStateV1{TvmStateHash: predecessor, State: &nativev1.NativeStateV1_Capability{
				Capability: &nativev1.CapabilityStateV1{CapabilityId: capability, Generation: 1, Sequence: 1,
					OwnerAgentId: owner, Versions: []*nativev1.CapabilityVersionV1{initialVersion}, Tombstoned: test.tombstoned}}}
			ownerState := &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{
				Agent: &nativev1.AgentStateV1{AgentId: owner, Policy: policy}}}
			sender := &senderStub{}
			relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{capability: targetState, owner: ownerState}})
			if _, err := relay.SubmitIdempotent(context.Background(), makeSubmission(test.owner, test.generation, test.sequence), "capability-"+test.name); err == nil {
				t.Fatal("invalid finalized Capability state passed preflight")
			}
			if sender.calls != 0 {
				t.Fatalf("invalid Capability state caused %d paid broadcasts", sender.calls)
			}
		})
	}
}

func TestCapabilityRegistrationIsAuthorizedByCanonicalOwnerAgent(t *testing.T) {
	l := testLocator(t)
	policy, controller := testPolicy(t)
	ownerNonce := bytes32('o')
	owner, err := DeriveAgentID(l.Network, ownerNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	version := &nativev1.CapabilityVersionV1{Version: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	capabilityNonce := bytes32('c')
	capability, err := DeriveCapabilityID(l.Network, capabilityNonce, owner, version)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: capability,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('a'),
		Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: capabilityNonce, OwnerAgentId: owner, InitialVersion: version}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(context.Background(), fakeKeys, controller, built)
	if err != nil {
		t.Fatal(err)
	}
	sender := &senderStub{}
	ownerState := &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: owner, Policy: policy}}}
	relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{owner: ownerState}})
	if _, err := relay.Submit(context.Background(), &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}, 10); err != nil {
		t.Fatal(err)
	}
	ownerContract, _ := l.Locate(owner)
	if sender.destination != ownerContract.Address || sender.stateInit != "" {
		t.Fatal("Capability registration bypassed owner Agent authorization")
	}
	bodyRaw, _ := base64.StdEncoding.DecodeString(sender.body)
	body, _ := cell.FromBOC(bodyRaw)
	opcode, _ := body.MustBeginParse().LoadUInt(32)
	if opcode != 0x4e560002 {
		t.Fatalf("opcode = %x", opcode)
	}
}

func TestRelayerResolvesAmbiguousIntentWithoutRebroadcast(t *testing.T) {
	l := testLocator(t)
	policy, controller := testPolicy(t)
	objectNonce := bytes32('q')
	id, err := DeriveAgentID(l.Network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: id,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('r'),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(context.Background(), fakeKeys, controller, built)
	if err != nil {
		t.Fatal(err)
	}
	sender := &senderStub{sendErr: errors.New("ambiguous transport result")}
	resolver := resolverStub{states: map[string]*nativev1.NativeStateV1{}}
	relay := testRelayer(t, l, sender, resolver)
	submission := &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	if _, err := relay.Submit(context.Background(), submission, 11); err == nil {
		t.Fatal("ambiguous transport result was reported as complete")
	}
	sender.sendErr = nil
	resolver.states[id] = &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: id, LastActionHash: built.HashString, Policy: policy}}}
	hash, err := relay.Submit(context.Background(), submission, 11)
	if err != nil || hash != built.HashString {
		t.Fatalf("read-only ambiguous recovery = %q, %v", hash, err)
	}
	if sender.calls != 1 {
		t.Fatalf("ambiguous intent caused %d paid broadcasts", sender.calls)
	}
}

func TestRecoveryInitiationUsesFinalizedChainTimeAndSafetyMargin(t *testing.T) {
	l := testLocator(t)
	policy, _ := testPolicy(t)
	agentID := "agent_" + strings.Repeat("81", 32)
	predecessor := "tvm-cell-sha256:" + strings.Repeat("82", 32)
	chainTime := time.Unix(1_700_000_000, 0).UTC()
	state := &nativev1.NativeStateV1{TvmStateHash: predecessor, State: &nativev1.NativeStateV1_Agent{
		Agent: &nativev1.AgentStateV1{AgentId: agentID, Generation: 1, Sequence: 1, Policy: policy},
	}}
	relay := testRelayer(t, l, &senderStub{}, resolverStub{states: map[string]*nativev1.NativeStateV1{agentID: state}, finalizedAt: chainTime})
	// Host time is deliberately far behind. It must not weaken the chain-time gate.
	relay.Now = func() time.Time { return chainTime.Add(-24 * time.Hour) }
	makeAction := func(executeAfter uint64) (*nativev1.NativeActionV1, BuiltAction) {
		action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: agentID,
			TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 2,
			PredecessorTvmStateHash: predecessor, Nonce: bytes32('t'),
			Payload: &nativev1.NativeActionV1_InitiateRecovery{InitiateRecovery: &nativev1.InitiateRecoveryV1{
				ExecuteAfterUnixSeconds: executeAfter, NewPolicy: policy}}}
		built, err := BuildAction(action)
		if err != nil {
			t.Fatal(err)
		}
		return action, built
	}
	minimum := uint64(chainTime.Unix()) + policy.RecoveryTimelockSeconds + uint64(relay.RecoverySafety/time.Second)
	tooSoon, tooSoonBuilt := makeAction(minimum - 1)
	if _, err := relay.preflightTargetTransition(context.Background(), tooSoon, tooSoonBuilt); err == nil {
		t.Fatal("recovery initiation below the finalized-chain safety boundary was accepted")
	}
	atBoundary, boundaryBuilt := makeAction(minimum)
	if _, err := relay.preflightTargetTransition(context.Background(), atBoundary, boundaryBuilt); err != nil {
		t.Fatalf("recovery initiation at the finalized-chain safety boundary: %v", err)
	}
}

func TestRecoveryCompletionUsesFinalizedChainTime(t *testing.T) {
	l := testLocator(t)
	policy, _ := testPolicy(t)
	agentID := "agent_" + strings.Repeat("91", 32)
	predecessor := "tvm-cell-sha256:" + strings.Repeat("92", 32)
	initiation := "sha256:" + strings.Repeat("93", 32)
	executeAfter := uint64(1_700_000_100)
	state := &nativev1.NativeStateV1{TvmStateHash: predecessor, State: &nativev1.NativeStateV1_Agent{
		Agent: &nativev1.AgentStateV1{AgentId: agentID, Generation: 1, Sequence: 2, Policy: policy,
			RecoveryPolicy: policy, RecoveryInitiationActionHash: initiation,
			RecoveryExecuteAfterUnixSeconds: executeAfter},
	}}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: agentID,
		TargetContractCodeHash: l.CodeHash, Generation: 2, Sequence: 1,
		PredecessorTvmStateHash: predecessor, Nonce: bytes32('u'),
		Payload: &nativev1.NativeActionV1_CompleteRecovery{CompleteRecovery: &nativev1.CompleteRecoveryV1{
			InitiationActionHash: initiation}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	before := resolverStub{states: map[string]*nativev1.NativeStateV1{agentID: state}, finalizedAt: time.Unix(int64(executeAfter)-1, 0)}
	relay := testRelayer(t, l, &senderStub{}, before)
	// Host time is deliberately far ahead. It must not authorize early completion.
	relay.Now = func() time.Time { return time.Unix(int64(executeAfter)+24*60*60, 0) }
	if _, err := relay.preflightTargetTransition(context.Background(), action, built); err == nil {
		t.Fatal("recovery completion before finalized chain time was accepted")
	}
	relay.Resolver = resolverStub{states: map[string]*nativev1.NativeStateV1{agentID: state}, finalizedAt: time.Unix(int64(executeAfter), 0)}
	if _, err := relay.preflightTargetTransition(context.Background(), action, built); err != nil {
		t.Fatalf("recovery completion at finalized chain time: %v", err)
	}
}
