package buyersdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

const (
	saCapability = "cap_3333333333333333333333333333333333333333333333333333333333333333"
	saAgent      = "agent_4444444444444444444444444444444444444444444444444444444444444444"
)

var (
	saActor    = "0:" + strings.Repeat("77", 32)
	saBuyer    = "0:" + strings.Repeat("21", 32)
	saOwner    = "0:" + strings.Repeat("11", 32)
	saCodeHash = "tvm-cell-sha256:" + strings.Repeat("88", 32)
	saKey      = bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	saKeyID    = func() [32]byte { id, _ := mldsa44.KeyID(saKey); return id }()
	saNow      = time.Unix(2_000_000_000, 0)
)

type saManifests map[string][]byte

func (m saManifests) Manifest(_ context.Context, digest string) ([]byte, error) {
	if value, ok := m[digest]; ok {
		return value, nil
	}
	return nil, errors.New("unknown manifest")
}

// saChain is a fake finalized chain for one Capability and its actor.
type saChain struct {
	mu         sync.Mutex
	checkpoint uint64
	capability *nativev1.NativeStateV1
	agent      *nativev1.NativeStateV1
	data       *nativecore.ServiceActorDataV1
	history    []toschain.ActorTransaction
	getterLie  bool
}

func (c *saChain) BeginBuyerSession(context.Context) (ServiceActorSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkpoint++
	return &saSession{checkpoint: c.checkpoint, capability: proto.Clone(c.capability).(*nativev1.NativeStateV1),
		agent: proto.Clone(c.agent).(*nativev1.NativeStateV1), data: c.data, history: append([]toschain.ActorTransaction(nil), c.history...),
		getterLie: c.getterLie}, nil
}

type saSession struct {
	checkpoint        uint64
	capability, agent *nativev1.NativeStateV1
	data              *nativecore.ServiceActorDataV1
	history           []toschain.ActorTransaction
	getterLie         bool
}

func (s *saSession) Checkpoint() uint64   { return s.checkpoint }
func (s *saSession) ChainTime() time.Time { return saNow }
func (s *saSession) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	var state *nativev1.NativeStateV1
	switch id {
	case saCapability:
		state = s.capability
	case saAgent:
		state = s.agent
	default:
		return nil, false, nil
	}
	state.Reference = &nativev1.ChainReference{FinalizedCheckpoint: s.checkpoint}
	return state, true, nil
}

func (s *saSession) head() toschain.ActorTxID {
	if len(s.history) == 0 {
		return toschain.ActorTxID{}
	}
	return toschain.ActorTxID{LT: s.history[0].LT, Hash: s.history[0].Hash}
}

func (s *saSession) ReadActor(_ context.Context, address string) (*toschain.ActorAccount, bool, error) {
	if address != saActor {
		return nil, false, nil
	}
	return &toschain.ActorAccount{Address: address, CodeHash: saCodeHash, Data: s.data, LastTransaction: s.head()}, true, nil
}

func (s *saSession) History(_ context.Context, _ string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	if anchor != nil {
		return nil, errors.New("not used")
	}
	return &toschain.ActorHistory{Result: toschain.HistoryComplete, Head: s.head(), Transactions: s.history}, nil
}

func (s *saSession) GetRequest(_ context.Context, _ string, id uint64) (*nativecore.ServiceActorRequestViewV1, error) {
	entry, ok := s.data.Pending[id]
	if !ok {
		return nil, nil
	}
	view := &nativecore.ServiceActorRequestViewV1{Caller: entry.Caller, Price: entry.Price, StorageFee: entry.StorageFee,
		CleanupBounty: entry.CleanupBounty, ResponseDeadline: entry.ResponseDeadline, RefundClaimDeadline: entry.RefundClaimDeadline,
		PolicyVersion: entry.PolicyVersion, RequestHash: entry.RequestHash, TermsHash: entry.TermsHash,
		HasAttestor: entry.HasAttestor, AttestorKeyID: entry.AttestorKeyID}
	if s.getterLie {
		view.ResponseDeadline++
	}
	return view, nil
}

func (s *saSession) GetRefund(_ context.Context, _ string, id uint64) (*nativecore.ServiceActorRefundV1, error) {
	entry, ok := s.data.Refunds[id]
	if !ok {
		return nil, nil
	}
	return &entry, nil
}

type fakeSender struct {
	mu           sync.Mutex
	preflightErr error
	sendErr      error
	sends        []ServiceActorCallIntent
}

func (f *fakeSender) Preflight(context.Context, ServiceActorCallIntent) error { return f.preflightErr }
func (f *fakeSender) SendCall(_ context.Context, intent ServiceActorCallIntent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends = append(f.sends, intent)
	return f.sendErr
}

type buyerFixture struct {
	chain   *saChain
	sender  *fakeSender
	buyer   *ServiceActorBuyer
	request *nativev1.RequestQuoteProposalRequest
	pkg     *nativev1.QuoteProposalPackageV1
	dir     string
	policy  nativecore.ServiceActorPolicyV1
}

func newBuyerFixture(t *testing.T, limits ServiceActorLimits) *buyerFixture {
	t.Helper()
	network := servicefixture.Network()
	settlement := servicefixture.Settlement{ActorAccount: bytes.Repeat([]byte{0x77}, 32), ActorCodeHash: bytes.Repeat([]byte{0x88}, 32),
		AttestorKey: mldsa44.KeyIDText(saKeyID)}
	manifest := servicefixture.Manifest("1.0.0", settlement)
	manifestCBOR, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network, CapabilityID: saCapability,
		ProviderAgentID: saAgent, CapabilityVersion: "1.0.0", ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	terms := servicefixture.Terms(saKeyID, metadata)
	policy := nativecore.ServiceActorPolicyV1{PolicyVersion: terms.PolicyVersion, PricePerCall: terms.PricePerCall, StorageFee: terms.StorageFee,
		CleanupBounty: terms.CleanupBounty, ResponseSLA: terms.ResponseSLA, RefundClaimWindow: terms.RefundClaimWindow, OpenAccess: true,
		MetadataHash: metadata, ProofSchemeHash: terms.ProofSchemeHash, HasAttestor: true, AttestorKeyID: saKeyID, AttestorKey: saKey}
	data, err := servicefixture.ActorData(saOwner, policy, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain := &saChain{checkpoint: 10, data: data,
		capability: &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
			CapabilityId: saCapability, OwnerAgentId: saAgent, Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: digest}}}}},
		agent: &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: saAgent}}}}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(nativecore.TransportBindingV1{
		SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	if err != nil {
		t.Fatal(err)
	}
	termsHash, _ := nativecore.ServiceActorTermsHash(terms)
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-1", CapabilityId: saCapability, CapabilityVersion: "1.0.0",
		ProviderAgentId: saAgent, ManifestDigest: digest, TransportBindingDigest: transportDigest,
		ExpiresAtUnixSeconds: uint64(saNow.Add(30 * time.Minute).Unix()),
		Actor:                &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)}, ActorCodeHash: saCodeHash,
		PolicyVersion: terms.PolicyVersion, TermsHash: hex.EncodeToString(termsHash[:]), PriceNanotos: "300000000",
		StorageFeeNanotos: "200000000", AttestorKeyId: mldsa44.KeyIDText(saKeyID)}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenServiceActorJournal(dir, saNow)
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{}
	counter := byte(0)
	buyer, err := NewServiceActorBuyer(ServiceActorBuyerConfig{Reader: chain, Manifests: saManifests{digest: manifestCBOR},
		Network: network, ActorCodeHash: saCodeHash, BuyerWallet: saBuyer, Sender: sender, Journal: journal, Limits: limits,
		Now: func() time.Time { return saNow }, Random: func(value []byte) error {
			counter++
			for i := range value {
				value[i] = counter
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return &buyerFixture{chain: chain, sender: sender, buyer: buyer, dir: dir, policy: policy,
		request: &nativev1.RequestQuoteProposalRequest{CapabilityId: saCapability, CapabilityVersion: "1.0.0", BuyerAddress: saBuyer},
		pkg:     &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: transport.ToBOC()}}
}

func defaultLimits() ServiceActorLimits {
	return ServiceActorLimits{Window: 24 * time.Hour, MaxCalls: 10, MaxPerCallNanoTOS: big.NewInt(1_000_000_000),
		MaxWindowNanoTOS: big.NewInt(10_000_000_000)}
}

func digest32(b byte) [32]byte {
	var v [32]byte
	copy(v[:], bytes.Repeat([]byte{b}, 32))
	return v
}

// land appends the finalized call the record describes, and the state it leaves.
func (f *buyerFixture) land(t *testing.T, record CallRecord, requestID uint64, success bool) toschain.ActorTransaction {
	t.Helper()
	var requestHash [32]byte
	raw, _ := hex.DecodeString(record.RequestHash)
	copy(requestHash[:], raw)
	terms := nativecore.TermsOfPolicy(f.policy)
	call, err := servicefixture.CallTransaction(saBuyer, requestID, requestHash, record.QueryID, uint32(saNow.Unix())-100, 10+requestID, terms)
	if err != nil {
		t.Fatal(err)
	}
	f.chain.mu.Lock()
	defer f.chain.mu.Unlock()
	if !success {
		call.Kind, call.Snapshot, call.ExitCode = toschain.ActorTxFailed, nil, 1928
		f.chain.history = append([]toschain.ActorTransaction{call}, f.chain.history...)
		return call
	}
	snapshot, _ := call.Snapshot.Decode()
	pending := map[uint64]nativecore.ServiceActorRequestSnapshotV1{requestID: snapshot}
	data, err := servicefixture.ActorData(saOwner, f.policy, requestID+1, pending, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.chain.history = append([]toschain.ActorTransaction{call}, f.chain.history...)
	f.chain.data = data
	return call
}

func TestBuyerDiscoversVerifiesCallsAndResolves(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	ctx := context.Background()
	offer, err := f.buyer.Discover(ctx, saCapability, "1.0.0")
	if err != nil || offer.Actor != saActor || offer.TermsHash != f.pkg.Proposal.TermsHash {
		t.Fatalf("offer = %+v, %v", offer, err)
	}
	record, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != PhasePrepared || record.PaymentNanoTOS != "700000000" || record.TermsHash != f.pkg.Proposal.TermsHash {
		t.Fatalf("record = %+v", record)
	}
	// The NSR1 request hash commits to the Accepted Quote, execution and input.
	quote, _, _ := nativecore.BuildAcceptedQuoteCommitment(servicefixture.Network(), f.pkg.Proposal)
	var quoteHash [32]byte
	copy(quoteHash[:], quote.Hash())
	nsr1, _ := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: quoteHash, ExecutionID: digest32(1), InputDigest: digest32(2)})
	if record.RequestHash != hex.EncodeToString(nsr1.Hash()) {
		t.Fatal("the request hash is not the NSR1 cell hash")
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2)); err == nil {
		t.Fatal("a reused request_hash was accepted")
	}
	called, err := f.buyer.Call(ctx, record.RequestHash)
	if err != nil || called.Phase != PhaseSubmitted || len(f.sender.sends) != 1 {
		t.Fatalf("call: %+v %v", called, err)
	}
	sent := f.sender.sends[0]
	if sent.QueryID != record.QueryID || hex.EncodeToString(sent.ExpectedTermsHash[:]) != f.pkg.Proposal.TermsHash || sent.Actor != saActor {
		t.Fatalf("sent intent = %+v", sent)
	}
	if _, err := f.buyer.Call(ctx, record.RequestHash); err == nil || len(f.sender.sends) != 1 {
		t.Fatal("a submitted call was sent again")
	}
	report, err := f.buyer.Resolve(ctx, record.RequestHash)
	if err != nil || report.Found {
		t.Fatalf("before landing: %+v %v", report, err)
	}
	call := f.land(t, record, 0, true)
	report, err = f.buyer.Resolve(ctx, record.RequestHash)
	if err != nil || !report.Found || report.Phase != PhaseAdmitted || *report.RequestID != 0 || report.Status != serviceactor.StatusPending {
		t.Fatalf("after landing: %+v %v", report, err)
	}
	// A respond lands for the request in a later transaction.
	respond := servicefixture.Transition(toschain.ActorTxRespond, 0, call.Now+5, 20, saOwner)
	respond.ResponseHash = strings.Repeat("cd", 32)
	f.chain.mu.Lock()
	f.chain.history = append([]toschain.ActorTransaction{respond}, f.chain.history...)
	f.chain.data, _ = servicefixture.ActorData(saOwner, f.policy, 1, nil, nil)
	f.chain.mu.Unlock()
	report, err = f.buyer.Resolve(ctx, record.RequestHash)
	if err != nil || report.State != serviceactor.StateResponded || report.ResponseHash != strings.Repeat("cd", 32) {
		t.Fatalf("after respond: %+v %v", report, err)
	}
}

func TestBuyerNeverResendsAnAmbiguousCall(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	ctx := context.Background()
	record, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	f.sender.sendErr = errors.New("tosctl exited after submitting")
	called, err := f.buyer.Call(ctx, record.RequestHash)
	if err == nil || called.Phase != PhaseAmbiguous {
		t.Fatalf("ambiguous call: %+v %v", called, err)
	}
	f.sender.sendErr = nil
	if _, err := f.buyer.Call(ctx, record.RequestHash); err == nil || len(f.sender.sends) != 1 {
		t.Fatal("an ambiguous call was sent again")
	}
	f.land(t, record, 0, true)
	report, err := f.buyer.Resolve(ctx, record.RequestHash)
	if err != nil || report.Phase != PhaseAdmitted {
		t.Fatalf("resolved ambiguous call: %+v %v", report, err)
	}

	// A call custody never started returns to prepared and may be retried.
	g := newBuyerFixture(t, defaultLimits())
	record, _ = g.buyer.Prepare(ctx, g.request, g.pkg, digest32(1), digest32(2))
	g.sender.sendErr = ErrCallNotStarted
	if called, err := g.buyer.Call(ctx, record.RequestHash); !errors.Is(err, ErrCallNotStarted) || called.Phase != PhasePrepared {
		t.Fatalf("not-started call: %+v %v", called, err)
	}
	g.sender.sendErr = nil
	if called, err := g.buyer.Call(ctx, record.RequestHash); err != nil || called.Phase != PhaseSubmitted {
		t.Fatalf("retried call: %+v %v", called, err)
	}
}

func TestBuyerRecoversAnInterruptedSendAsAmbiguous(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	record, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.config.Journal.Transition(record.RequestHash, []CallPhase{PhasePrepared}, func(r *CallRecord) error {
		r.Phase = PhaseSending
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The process stops here; a new process opens the journal.
	reopened, err := OpenServiceActorJournal(f.dir, saNow)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Read(record.RequestHash)
	if err != nil || recovered.Phase != PhaseAmbiguous {
		t.Fatalf("recovered = %+v %v", recovered, err)
	}
}

func TestBuyerReverifiesAtCallTime(t *testing.T) {
	ctx := context.Background()
	for name, edit := range map[string]func(*buyerFixture){
		"version revoked": func(f *buyerFixture) { f.chain.capability.GetCapability().Versions[0].Revoked = true },
		"terms changed":   func(f *buyerFixture) { f.chain.data.Policy.PolicyVersion = 3 },
		"attestor rotated": func(f *buyerFixture) {
			f.chain.data.Policy.HasAttestor = false
		},
		"preflight refused": func(f *buyerFixture) { f.sender.preflightErr = errors.New("payer is another wallet") },
	} {
		f := newBuyerFixture(t, defaultLimits())
		record, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
		if err != nil {
			t.Fatal(err)
		}
		edit(f)
		called, err := f.buyer.Call(ctx, record.RequestHash)
		if err == nil || called.Phase != PhasePrepared || len(f.sender.sends) != 0 {
			t.Errorf("%s: call went ahead (%+v, %v)", name, called, err)
		}
	}
	// An expired Quote is refused before anything else.
	f := newBuyerFixture(t, defaultLimits())
	record, _ := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	f.buyer.config.Now = func() time.Time { return saNow.Add(time.Hour) }
	if _, err := f.buyer.Call(ctx, record.RequestHash); err == nil || len(f.sender.sends) != 0 {
		t.Error("an expired Quote was called")
	}
	// A wrong buyer in the Quote request is refused at prepare.
	f = newBuyerFixture(t, defaultLimits())
	f.request.BuyerAddress = saOwner
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2)); err == nil {
		t.Error("a Quote request for another buyer was prepared")
	}
	// A zero execution id cannot form a request commitment.
	f = newBuyerFixture(t, defaultLimits())
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, [32]byte{}, digest32(2)); err == nil {
		t.Error("a zero execution id was prepared")
	}
}

func TestBuyerBudgetReservations(t *testing.T) {
	ctx := context.Background()
	limits := defaultLimits()
	limits.MaxCalls = 1
	f := newBuyerFixture(t, limits)
	first, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(3), digest32(4)); err == nil {
		t.Fatal("a second call within the call limit was prepared")
	}
	f.sender.sendErr = errors.New("ambiguous")
	if _, err := f.buyer.Call(ctx, first.RequestHash); err == nil {
		t.Fatal("expected an ambiguous send")
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(3), digest32(4)); err == nil {
		t.Fatal("an ambiguous call released its reservation")
	}
	f.land(t, first, 0, false)
	report, err := f.buyer.Resolve(ctx, first.RequestHash)
	if err != nil || report.Phase != PhaseRefused || report.ExitCode != 1928 {
		t.Fatalf("aborted call: %+v %v", report, err)
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(3), digest32(4)); err != nil {
		t.Fatalf("a refused call kept its reservation: %v", err)
	}
	limits = defaultLimits()
	limits.MaxPerCallNanoTOS = big.NewInt(699_999_999)
	limits.MaxWindowNanoTOS = big.NewInt(699_999_999)
	g := newBuyerFixture(t, limits)
	if _, err := g.buyer.Prepare(ctx, g.request, g.pkg, digest32(1), digest32(2)); err == nil {
		t.Fatal("a call above the per-call limit was prepared")
	}
}

func TestBuyerResolveRefusesInconsistentEvidence(t *testing.T) {
	ctx := context.Background()
	for name, edit := range map[string]func(*buyerFixture, CallRecord){
		"getter disagrees": func(f *buyerFixture, _ CallRecord) { f.chain.getterLie = true },
		"two matching calls": func(f *buyerFixture, record CallRecord) {
			f.chain.history = append([]toschain.ActorTransaction{f.chain.history[0]}, f.chain.history...)
		},
		"state unexplained": func(f *buyerFixture, _ CallRecord) {
			f.chain.data, _ = servicefixture.ActorData(saOwner, f.policy, 1, nil, nil)
		},
		"snapshot of another attestor": func(f *buyerFixture, record CallRecord) {
			var requestHash [32]byte
			raw, _ := hex.DecodeString(record.RequestHash)
			copy(requestHash[:], raw)
			terms := nativecore.TermsOfPolicy(f.policy)
			terms.AttestorKeyID[0] ^= 1
			call, _ := servicefixture.CallTransaction(saBuyer, 0, requestHash, record.QueryID, uint32(saNow.Unix())-100, 10, terms)
			call.Call.ExpectedTermsHash = record.TermsHash
			f.chain.history[0] = call
		},
	} {
		f := newBuyerFixture(t, defaultLimits())
		record, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.buyer.Call(ctx, record.RequestHash); err != nil {
			t.Fatal(err)
		}
		f.land(t, record, 0, true)
		f.chain.mu.Lock()
		edit(f, record)
		f.chain.mu.Unlock()
		if report, err := f.buyer.Resolve(ctx, record.RequestHash); err == nil {
			t.Errorf("%s resolved: %+v", name, report)
		}
	}
}

func TestJournalExcludesConcurrentStarts(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	record, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	// Separate journal handles take separate file descriptions, so their
	// locks exclude each other as two processes' would.
	var wait sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			journal, err := OpenServiceActorJournal(f.dir, saNow)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := journal.Transition(record.RequestHash, []CallPhase{PhasePrepared}, func(r *CallRecord) error {
				r.Phase = PhaseSending
				return nil
			}); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	if winners != 1 {
		t.Fatalf("%d handles started the same call", winners)
	}
	entries, _ := os.ReadDir(f.dir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".call-") {
			t.Fatalf("temporary file %s left behind", filepath.Join(f.dir, entry.Name()))
		}
	}
}
