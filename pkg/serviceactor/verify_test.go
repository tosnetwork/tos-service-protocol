package serviceactor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	tosaddress "github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	testCapability = "cap_" + "3333333333333333333333333333333333333333333333333333333333333333"
	testOwnerAgent = "agent_" + "4444444444444444444444444444444444444444444444444444444444444444"
)

var (
	testActor   = "0:" + strings.Repeat("77", 32)
	testBuyer   = "0:" + strings.Repeat("21", 32)
	testOwner   = "0:" + strings.Repeat("11", 32)
	testCode    = func() [32]byte { var v [32]byte; copy(v[:], bytes.Repeat([]byte{0x88}, 32)); return v }()
	testKey     = bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	testKeyID   = func() [32]byte { id, _ := mldsa44.KeyID(testKey); return id }()
	otherKey    = bytes.Repeat([]byte{0x5b}, mldsa44.PublicKeySize)
	otherKeyID  = func() [32]byte { id, _ := mldsa44.KeyID(otherKey); return id }()
	testRequest = func() [32]byte { var v [32]byte; copy(v[:], bytes.Repeat([]byte{0x44}, 32)); return v }()
)

type fixture struct {
	evidence *Evidence
	proposal *nativev1.QuoteProposalV1
	rail     nativecore.ServiceActorQuoteRailV1
}

func msgAddress(t *testing.T, raw string) nativecore.MsgAddressV1 {
	t.Helper()
	value, err := nativecore.StandardAddress(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	network := servicefixture.Network()
	settlement := servicefixture.Settlement{ActorAccount: bytes.Repeat([]byte{0x77}, 32), ActorCodeHash: testCode[:],
		AttestorKey: mldsa44.KeyIDText(testKeyID)}
	manifest := servicefixture.Manifest("1.0.0", settlement)
	_, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	reference := func() *nativev1.ChainReference {
		return &nativev1.ChainReference{FinalizedCheckpoint: 42, ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("aa", 32)}
	}
	capability := &nativev1.NativeStateV1{Network: network, Reference: reference(), State: &nativev1.NativeStateV1_Capability{
		Capability: &nativev1.CapabilityStateV1{CapabilityId: testCapability, OwnerAgentId: testOwnerAgent,
			Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: digest}}}}}
	agent := &nativev1.NativeStateV1{Network: network, Reference: reference(), State: &nativev1.NativeStateV1_Agent{
		Agent: &nativev1.AgentStateV1{AgentId: testOwnerAgent}}}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
		CapabilityID: testCapability, ProviderAgentID: testOwnerAgent, CapabilityVersion: "1.0.0", ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	policy := nativecore.ServiceActorPolicyV1{PolicyVersion: 2, PricePerCall: big.NewInt(300_000_000), StorageFee: big.NewInt(200_000_000),
		CleanupBounty: big.NewInt(100_000_000), ResponseSLA: 3600, RefundClaimWindow: 3600, OpenAccess: true,
		AuthorizedCaller: msgAddress(t, testOwner), MetadataHash: metadata, ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme,
		HasAttestor: true, AttestorKeyID: testKeyID, AttestorKey: testKey}
	data := &nativecore.ServiceActorDataV1{Owner: msgAddress(t, testOwner), Active: true, Policy: policy,
		Accounting: nativecore.ServiceActorAccountingV1{WithdrawableRevenue: new(big.Int), LockedStorageFees: new(big.Int),
			PendingLiability: new(big.Int), RefundableLiability: new(big.Int)},
		Pending: map[uint64]nativecore.ServiceActorPendingRequestV1{}, Refunds: map[uint64]nativecore.ServiceActorRefundV1{},
		CallerLiveCounts: map[[32]byte]uint32{}}
	evidence := &Evidence{Checkpoint: 42, ChainTime: time.Unix(1_000_100, 0), Network: network, Capability: capability, Agent: agent,
		Version: "1.0.0", ManifestDigest: digest, Manifest: manifest,
		Actor: &toschain.ActorAccount{Address: testActor, CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(testCode[:]), Data: data}}
	termsHash, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "p", CapabilityId: testCapability, CapabilityVersion: "1.0.0",
		ProviderAgentId: testOwnerAgent, ManifestDigest: digest, TransportBindingDigest: "sha256:" + strings.Repeat("66", 32),
		ExpiresAtUnixSeconds: 2_000_000, Actor: &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)},
		ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(testCode[:]), PolicyVersion: 2, TermsHash: hex.EncodeToString(termsHash[:]),
		PriceNanotos: "300000000", StorageFeeNanotos: "200000000", AttestorKeyId: mldsa44.KeyIDText(testKeyID)}
	f := &fixture{evidence: evidence, proposal: proposal}
	f.reparse(t)
	return f
}

func (f *fixture) reparse(t *testing.T) {
	t.Helper()
	rail, err := nativecore.ParseServiceActorQuoteRail(f.proposal)
	if err != nil {
		t.Fatal(err)
	}
	f.rail = rail
}

func (f *fixture) rehashManifest(t *testing.T) {
	t.Helper()
	_, digest, err := nativecore.CanonicalSoftwareWorkManifest(f.evidence.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.evidence.ManifestDigest = digest
	f.evidence.Capability.GetCapability().Versions[0].ManifestDigest = digest
	f.proposal.ManifestDigest = digest
}

func wantStep(t *testing.T, name string, err error, procedure string, step int) {
	t.Helper()
	var stepErr *StepError
	if !errors.As(err, &stepErr) {
		t.Errorf("%s: want %s step %d, got %v", name, procedure, step, err)
		return
	}
	if stepErr.Procedure != procedure || stepErr.Step != step {
		t.Errorf("%s: want %s step %d, got %s step %d (%s)", name, procedure, step, stepErr.Procedure, stepErr.Step, stepErr.Reason)
	}
}

func TestAdmissionAcceptsTheBoundOffer(t *testing.T) {
	f := newFixture(t)
	admission, err := VerifyAdmission(f.evidence, testCode, &f.rail, f.proposal, testBuyer)
	if err != nil {
		t.Fatal(err)
	}
	if admission.Binding.Actor != testActor || admission.TermsHash != f.rail.TermsHash {
		t.Fatalf("admission = %+v", admission)
	}
	if _, err := VerifyAdmission(f.evidence, testCode, nil, nil, ""); err != nil {
		t.Fatalf("discovery without a Quote: %v", err)
	}
}

func TestAdmissionRefusesEachStep(t *testing.T) {
	cases := []struct {
		name string
		step int
		edit func(*testing.T, *fixture)
	}{
		{"tombstoned Capability", 1, func(_ *testing.T, f *fixture) { f.evidence.Capability.GetCapability().Tombstoned = true }},
		{"revoked version", 1, func(_ *testing.T, f *fixture) { f.evidence.Capability.GetCapability().Versions[0].Revoked = true }},
		{"absent version", 1, func(_ *testing.T, f *fixture) { f.evidence.Version = "2.0.0" }},
		{"tombstoned owner", 1, func(_ *testing.T, f *fixture) { f.evidence.Agent.GetAgent().Tombstoned = true }},
		{"other owner Agent", 1, func(_ *testing.T, f *fixture) {
			f.evidence.Agent.GetAgent().AgentId = "agent_" + strings.Repeat("45", 32)
		}},
		{"Capability from another checkpoint", 1, func(_ *testing.T, f *fixture) { f.evidence.Capability.Reference.FinalizedCheckpoint = 41 }},
		{"Agent from another checkpoint", 1, func(_ *testing.T, f *fixture) { f.evidence.Agent.Reference.FinalizedCheckpoint = 43 }},
		{"manifest not the digest", 1, func(_ *testing.T, f *fixture) { f.evidence.Manifest.Name = "changed" }},
		{"Quote for another provider", 1, func(_ *testing.T, f *fixture) { f.proposal.ProviderAgentId = "agent_" + strings.Repeat("45", 32) }},
		{"actor substitution", 2, func(t *testing.T, f *fixture) {
			f.proposal.Actor.AccountId = bytes.Repeat([]byte{0x78}, 32)
			f.reparse(t)
		}},
		{"actor not active", 3, func(_ *testing.T, f *fixture) { f.evidence.Actor = nil }},
		{"account code hash", 3, func(_ *testing.T, f *fixture) {
			f.evidence.Actor.CodeHash = "tvm-cell-sha256:" + strings.Repeat("89", 32)
		}},
		{"manifest code hash", 3, func(t *testing.T, f *fixture) {
			f.evidence.Manifest.Settlement.ActorCodeHash = bytes.Repeat([]byte{0x89}, 32)
			f.rehashManifest(t)
		}},
		{"Quote code hash", 3, func(t *testing.T, f *fixture) {
			f.proposal.ActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("89", 32)
			f.reparse(t)
		}},
		{"Quote attestor", 4, func(t *testing.T, f *fixture) {
			f.proposal.AttestorKeyId = mldsa44.KeyIDText(otherKeyID)
			f.reparse(t)
		}},
		{"inactive actor", 5, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Active = false }},
		{"revoked attestor", 5, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.HasAttestor = false }},
		{"rotated attestor", 5, func(_ *testing.T, f *fixture) {
			f.evidence.Actor.Data.Policy.AttestorKeyID, f.evidence.Actor.Data.Policy.AttestorKey = otherKeyID, otherKey
		}},
		{"stored key mismatch", 5, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.AttestorKey = otherKey }},
		{"metadata hash", 6, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.MetadataHash[0] ^= 1 }},
		{"proof scheme", 6, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.ProofSchemeHash[0] ^= 1 }},
		{"response SLA bound", 7, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.ResponseSLA = 60 }},
		{"refund window bound", 7, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.RefundClaimWindow = 2_592_001 }},
		{"cleanup bounty bound", 7, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.CleanupBounty = big.NewInt(1) }},
		{"storage fee bound", 7, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.StorageFee = big.NewInt(199_999_999) }},
		{"closed access", 7, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.OpenAccess = false }},
		{"authorized other caller", 7, func(_ *testing.T, f *fixture) {
			f.evidence.Actor.Data.Policy.OpenAccess, f.evidence.Actor.Data.Policy.HasAuthorizedCaller = false, true
		}},
		{"terms changed", 8, func(_ *testing.T, f *fixture) { f.evidence.Actor.Data.Policy.PolicyVersion = 3 }},
		{"Quote price", 8, func(t *testing.T, f *fixture) {
			f.proposal.PriceNanotos = "300000001"
			f.reparse(t)
		}},
		{"Quote terms hash", 8, func(t *testing.T, f *fixture) {
			f.proposal.TermsHash = strings.Repeat("ab", 32)
			f.reparse(t)
		}},
	}
	for _, test := range cases {
		f := newFixture(t)
		test.edit(t, f)
		_, err := VerifyAdmission(f.evidence, testCode, &f.rail, f.proposal, testBuyer)
		procedure := "admission"
		if test.step <= 4 {
			procedure = "binding"
		}
		wantStep(t, test.name, err, procedure, test.step)
	}
	// The buyer authorized by the actor is admitted when access is closed.
	f := newFixture(t)
	f.evidence.Actor.Data.Policy.OpenAccess, f.evidence.Actor.Data.Policy.HasAuthorizedCaller = false, true
	f.evidence.Actor.Data.Policy.AuthorizedCaller = msgAddress(t, testBuyer)
	if _, err := VerifyAdmission(f.evidence, testCode, &f.rail, f.proposal, testBuyer); err != nil {
		t.Fatalf("the authorized buyer was refused: %v", err)
	}
	// The pinned release differs from the code everywhere else.
	f = newFixture(t)
	other := testCode
	other[0] ^= 1
	_, err := VerifyAdmission(f.evidence, other, &f.rail, f.proposal, testBuyer)
	wantStep(t, "pinned release", err, "binding", 3)
	// Manifest key 18 committing to the raw key id instead of the text form:
	// the canonical manifest validator already refuses it, so the manifest
	// no longer reproduces the finalized digest (step 1) before step 4's own
	// check is reached.
	f = newFixture(t)
	f.evidence.Manifest.ExecutionSignerAuthorization = "sha256:" + hex.EncodeToString(testKeyID[:])
	_, err = VerifyBinding(f.evidence, testCode, &f.rail, f.proposal, testActor, nil)
	wantStep(t, "key 18", err, "binding", 1)
}

// callFixture is a finalized call transaction and its request snapshot.
func callFixture(t *testing.T, f *fixture, now uint32, terms nativecore.ServiceActorTermsV1, edit func(*cell.Builder)) toschain.ActorTransaction {
	t.Helper()
	termsCell, err := nativecore.BuildServiceActorTermsCell(terms)
	if err != nil {
		t.Fatal(err)
	}
	termsHash := termsCell.Hash()
	responseDeadline := uint64(now) + uint64(terms.ResponseSLA)
	caller, _ := addressLib(testBuyer)
	body := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorRequestSnapshotTag, 32).MustStoreUInt(0, 64).MustStoreAddr(caller).
		MustStoreSlice(testRequest[:], 256).MustStoreUInt(responseDeadline, 64).MustStoreUInt(responseDeadline+uint64(terms.RefundClaimWindow), 64)
	if edit != nil {
		edit(body)
	}
	snapshot := body.MustStoreRef(termsCell).EndCell()
	return toschain.ActorTransaction{LT: 10, Hash: strings.Repeat("0a", 32), Now: now, Kind: toschain.ActorTxCall, Sender: testBuyer,
		Call:     &toschain.ActorCallBody{QueryID: 5, RequestHash: hex.EncodeToString(testRequest[:]), ExpectedTermsHash: hex.EncodeToString(termsHash)},
		Snapshot: &toschain.ActorSAR1{BodyBOC: base64.StdEncoding.EncodeToString(snapshot.ToBOC())}}
}

func TestExistingRequestVerifiesFromTheSnapshotAlone(t *testing.T) {
	f := newFixture(t)
	terms := nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy)
	call := callFixture(t, f, 1_000_000, terms, nil)
	// The current policy changing after the call does not affect the request.
	f.evidence.Actor.Data.Policy.PolicyVersion = 9
	f.evidence.Actor.Data.Policy.AttestorKeyID, f.evidence.Actor.Data.Policy.AttestorKey = otherKeyID, otherKey
	request, err := VerifyExistingRequest(f.evidence, testCode, &f.rail, f.proposal, testActor, call, testBuyer, testRequest,
		acceptanceFor(call))
	if err != nil {
		t.Fatal(err)
	}
	if request.Snapshot.RequestID != 0 || request.Snapshot.TermsHash != f.rail.TermsHash {
		t.Fatalf("request = %+v", request.Snapshot)
	}

	rotated := terms
	rotated.AttestorKeyID = otherKeyID
	revoked := terms
	revoked.HasAttestor, revoked.AttestorKeyID = false, [32]byte{}
	wrongMetadata := terms
	wrongMetadata.MetadataHash[0] ^= 1
	wrongScheme := terms
	wrongScheme.ProofSchemeHash[0] ^= 1
	termsHashOf := func(value nativecore.ServiceActorTermsV1) string {
		hash, err := nativecore.ServiceActorTermsHash(value)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(hash[:])
	}
	changedVersion := terms
	changedVersion.PolicyVersion = 3
	mismatchedTerms := callFixture(t, f, 1_000_000, changedVersion, nil)
	mismatchedBody := *mismatchedTerms.Call
	mismatchedBody.ExpectedTermsHash = termsHashOf(terms)
	mismatchedTerms.Call = &mismatchedBody
	cases := []struct {
		name  string
		step  int
		call  toschain.ActorTransaction
		quote string // terms hash the Quote carries; empty keeps the fixture's
		edit  func(*fixture)
	}{
		{"not a call", 5, func() toschain.ActorTransaction { c := call; c.Kind = toschain.ActorTxFailed; return c }(), "", nil},
		{"another sender", 5, func() toschain.ActorTransaction { c := call; c.Sender = testOwner; return c }(), "", nil},
		{"another request hash", 5, func() toschain.ActorTransaction {
			c := call
			copied := *c.Call
			copied.RequestHash = strings.Repeat("45", 32)
			c.Call = &copied
			return c
		}(), "", nil},
		{"Quote terms", 5, call, strings.Repeat("ab", 32), nil},
		{"rotated attestor", 7, callFixture(t, f, 1_000_000, rotated, nil), termsHashOf(rotated), nil},
		{"revoked attestor", 7, callFixture(t, f, 1_000_000, revoked, nil), termsHashOf(revoked), nil},
		{"terms cell hash", 8, mismatchedTerms, "", nil},
		{"metadata", 8, callFixture(t, f, 1_000_000, wrongMetadata, nil), termsHashOf(wrongMetadata), nil},
		{"proof scheme", 8, callFixture(t, f, 1_000_000, wrongScheme, nil), termsHashOf(wrongScheme), nil},
		{"deadline", 8, func() toschain.ActorTransaction { c := call; c.Now++; return c }(), "", nil},
		{"cleanup bounty", 8, func() toschain.ActorTransaction {
			x := terms
			x.CleanupBounty = big.NewInt(100_000_001)
			c := callFixture(t, f, 1_000_000, x, nil)
			body := *c.Call
			body.ExpectedTermsHash = termsHashOf(terms)
			c.Call = &body
			return c
		}(), "", nil},
		{"price", 8, callFixture(t, f, 1_000_000, func() nativecore.ServiceActorTermsV1 {
			x := terms
			x.PricePerCall = big.NewInt(300_000_001)
			return x
		}(), nil), termsHashOf(func() nativecore.ServiceActorTermsV1 { x := terms; x.PricePerCall = big.NewInt(300_000_001); return x }()), nil},
		{"actor substitution", 2, call, "", func(f *fixture) { f.proposal.Actor.AccountId = bytes.Repeat([]byte{0x78}, 32) }},
	}
	for _, test := range cases {
		f := newFixture(t)
		if test.quote != "" {
			f.proposal.TermsHash = test.quote
		}
		if test.edit != nil {
			test.edit(f)
		}
		f.reparse(t)
		_, err := VerifyExistingRequest(f.evidence, testCode, &f.rail, f.proposal, testActor, test.call, testBuyer, testRequest,
			acceptanceFor(test.call))
		procedure := "existing-request"
		if test.step <= 4 {
			procedure = "binding"
		}
		wantStep(t, test.name, err, procedure, test.step)
	}
	// A call found in another account's history is never attributed.
	_, err = VerifyExistingRequest(f.evidence, testCode, &f.rail, f.proposal, "0:"+strings.Repeat("78", 32), call, testBuyer, testRequest,
		acceptanceFor(call))
	wantStep(t, "other history", err, "binding", 2)
}

func addressLib(raw string) (*tosaddress.Address, error) { return tosaddress.ParseRawAddr(raw) }

// acceptanceFor is the liveness proof of a call whose Capability, version and
// owner Agent are all live: nothing to prove.
func acceptanceFor(call toschain.ActorTransaction) *Acceptance {
	return &Acceptance{Call: toschain.ActorTxID{LT: call.LT, Hash: call.Hash}}
}

const (
	capabilityLastAction = "sha256:" + "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	agentLastAction      = "sha256:" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
)

func transitionAt(lt uint64, action string) *toschain.RegistryTransitionTx {
	return &toschain.RegistryTransitionTx{LT: lt, Hash: strings.Repeat("0b", 32), ActionHash: action}
}

// Step 1's liveness is judged at the call (the call fixture is at LT 10): a
// tombstone or revocation counts against an existing request only if it is
// not proven finalized after the call.
func TestExistingRequestJudgesLivenessAtTheCall(t *testing.T) {
	type state struct{ capability, version, agent bool }
	cases := []struct {
		name  string
		state state
		proof func(*Acceptance)
		ok    bool
	}{
		{"Capability tombstoned after the call", state{capability: true},
			func(a *Acceptance) { a.CapabilityTombstone = transitionAt(11, capabilityLastAction) }, true},
		{"Capability tombstoned before the call", state{capability: true},
			func(a *Acceptance) { a.CapabilityTombstone = transitionAt(9, capabilityLastAction) }, false},
		{"Capability tombstoned at the call's logical time", state{capability: true},
			func(a *Acceptance) { a.CapabilityTombstone = transitionAt(10, capabilityLastAction) }, false},
		{"Capability tombstone unproven", state{capability: true}, func(*Acceptance) {}, false},
		{"Capability tombstone that is not the last action", state{capability: true},
			func(a *Acceptance) { a.CapabilityTombstone = transitionAt(11, agentLastAction) }, false},
		{"Capability tombstone proven only for the Agent", state{capability: true},
			func(a *Acceptance) { a.AgentTombstone = transitionAt(11, capabilityLastAction) }, false},
		{"Agent tombstoned after the call", state{agent: true},
			func(a *Acceptance) { a.AgentTombstone = transitionAt(11, agentLastAction) }, true},
		{"Agent tombstoned before the call", state{agent: true},
			func(a *Acceptance) { a.AgentTombstone = transitionAt(9, agentLastAction) }, false},
		{"Agent tombstoned at the call's logical time", state{agent: true},
			func(a *Acceptance) { a.AgentTombstone = transitionAt(10, agentLastAction) }, false},
		{"Agent tombstone unproven", state{agent: true}, func(*Acceptance) {}, false},
		{"Agent tombstone that is not the last action", state{agent: true},
			func(a *Acceptance) { a.AgentTombstone = transitionAt(11, capabilityLastAction) }, false},
		{"Agent tombstone proven only for the Capability", state{agent: true},
			func(a *Acceptance) { a.CapabilityTombstone = transitionAt(11, agentLastAction) }, false},
		{"version revoked after the call", state{version: true},
			func(a *Acceptance) { a.VersionRevocation = transitionAt(11, "sha256:"+strings.Repeat("d1", 32)) }, true},
		{"version revoked before the call", state{version: true},
			func(a *Acceptance) { a.VersionRevocation = transitionAt(9, "sha256:"+strings.Repeat("d1", 32)) }, false},
		{"version revoked at the call's logical time", state{version: true},
			func(a *Acceptance) { a.VersionRevocation = transitionAt(10, "sha256:"+strings.Repeat("d1", 32)) }, false},
		{"version revocation unproven", state{version: true}, func(*Acceptance) {}, false},
		{"version revocation proven only as a tombstone", state{version: true},
			func(a *Acceptance) { a.CapabilityTombstone = transitionAt(11, capabilityLastAction) }, false},
		{"all three after the call", state{capability: true, version: true, agent: true}, func(a *Acceptance) {
			a.CapabilityTombstone = transitionAt(11, capabilityLastAction)
			a.VersionRevocation = transitionAt(12, "sha256:"+strings.Repeat("d1", 32))
			a.AgentTombstone = transitionAt(13, agentLastAction)
		}, true},
		{"all three, the Agent before the call", state{capability: true, version: true, agent: true}, func(a *Acceptance) {
			a.CapabilityTombstone = transitionAt(11, capabilityLastAction)
			a.VersionRevocation = transitionAt(12, "sha256:"+strings.Repeat("d1", 32))
			a.AgentTombstone = transitionAt(9, agentLastAction)
		}, false},
	}
	for _, test := range cases {
		f := newFixture(t)
		capability, agent := f.evidence.Capability.GetCapability(), f.evidence.Agent.GetAgent()
		capability.LastActionHash, agent.LastActionHash = capabilityLastAction, agentLastAction
		capability.Tombstoned, capability.Versions[0].Revoked, agent.Tombstoned = test.state.capability, test.state.version, test.state.agent
		call := callFixture(t, f, 1_000_000, nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy), nil)
		acceptance := acceptanceFor(call)
		test.proof(acceptance)
		_, err := VerifyExistingRequest(f.evidence, testCode, &f.rail, f.proposal, testActor, call, testBuyer, testRequest, acceptance)
		if test.ok {
			if err != nil {
				t.Errorf("%s: refused: %v", test.name, err)
			}
			// Admission keeps the current-state check whatever the proof.
			_, err := VerifyAdmission(f.evidence, testCode, &f.rail, f.proposal, testBuyer)
			wantStep(t, test.name+" at admission", err, "binding", 1)
			continue
		}
		wantStep(t, test.name, err, "binding", 1)
	}

	// The proof must be the one made for this call transaction.
	f := newFixture(t)
	call := callFixture(t, f, 1_000_000, nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy), nil)
	for name, acceptance := range map[string]*Acceptance{
		"no proof":                 nil,
		"proof for another LT":     {Call: toschain.ActorTxID{LT: call.LT + 1, Hash: call.Hash}},
		"proof for another hash":   {Call: toschain.ActorTxID{LT: call.LT, Hash: strings.Repeat("0c", 32)}},
		"proof for no transaction": {},
	} {
		_, err := VerifyExistingRequest(f.evidence, testCode, &f.rail, f.proposal, testActor, call, testBuyer, testRequest, acceptance)
		wantStep(t, name, err, "binding", 1)
	}
}

type transitionRequest struct {
	object  string
	kind    nativecore.RegistryTransitionKind
	version string
}

type fakeTransitions struct {
	requests []transitionRequest
	proofs   map[nativecore.RegistryTransitionKind]*toschain.RegistryTransitionTx
	err      error
}

func (f *fakeTransitions) RegistryTransition(_ context.Context, object string, kind nativecore.RegistryTransitionKind,
	version string) (*toschain.RegistryTransitionTx, error) {
	f.requests = append(f.requests, transitionRequest{object, kind, version})
	if f.err != nil {
		return nil, f.err
	}
	if proof := f.proofs[kind]; proof != nil {
		return proof, nil
	}
	return nil, toschain.ErrRegistryTransitionUnproven
}

func TestProveAcceptanceAsksForExactlyTheShownTransitions(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	call := callFixture(t, f, 1_000_000, nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy), nil)
	live := &fakeTransitions{}
	acceptance, err := ProveAcceptance(ctx, live, f.evidence, call)
	if err != nil || len(live.requests) != 0 || *acceptance != *acceptanceFor(call) {
		t.Fatalf("live objects: %+v %v, asked %v", acceptance, err, live.requests)
	}

	capability, agent := f.evidence.Capability.GetCapability(), f.evidence.Agent.GetAgent()
	capability.Tombstoned, capability.Versions[0].Revoked, agent.Tombstoned = true, true, true
	tombstone, revocation := transitionAt(11, capabilityLastAction), transitionAt(12, "sha256:"+strings.Repeat("d1", 32))
	session := &fakeTransitions{proofs: map[nativecore.RegistryTransitionKind]*toschain.RegistryTransitionTx{
		nativecore.RegistryCapabilityTombstone: tombstone, nativecore.RegistryVersionRevocation: revocation}}
	acceptance, err = ProveAcceptance(ctx, session, f.evidence, call)
	if err != nil {
		t.Fatal(err)
	}
	want := []transitionRequest{{testCapability, nativecore.RegistryCapabilityTombstone, ""},
		{testCapability, nativecore.RegistryVersionRevocation, "1.0.0"}, {testOwnerAgent, nativecore.RegistryAgentTombstone, ""}}
	if len(session.requests) != len(want) {
		t.Fatalf("asked %v, want %v", session.requests, want)
	}
	for index := range want {
		if session.requests[index] != want[index] {
			t.Fatalf("asked %v, want %v", session.requests, want)
		}
	}
	// An unproven transition is left for the verification to refuse.
	if acceptance.Call != (toschain.ActorTxID{LT: call.LT, Hash: call.Hash}) || acceptance.CapabilityTombstone != tombstone ||
		acceptance.VersionRevocation != revocation || acceptance.AgentTombstone != nil {
		t.Fatalf("acceptance = %+v", acceptance)
	}

	failing := &fakeTransitions{err: errors.New("endpoint unavailable")}
	if _, err := ProveAcceptance(ctx, failing, f.evidence, call); err == nil || errors.Is(err, toschain.ErrRegistryTransitionUnproven) {
		t.Fatalf("a read failure was not returned: %v", err)
	}
	if _, err := ProveAcceptance(ctx, session, nil, call); err == nil {
		t.Fatal("missing evidence was proven")
	}
}
