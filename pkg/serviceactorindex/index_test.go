package serviceactorindex

import (
	"bytes"
	"context"
	"errors"
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
)

var (
	actor   = "0:" + strings.Repeat("77", 32)
	buyer   = "0:" + strings.Repeat("21", 32)
	other   = "0:" + strings.Repeat("22", 32)
	owner   = "0:" + strings.Repeat("11", 32)
	key     = bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	keyID   = func() [32]byte { id, _ := mldsa44.KeyID(key); return id }()
	callNow = uint32(1_000_000)
)

// chainState is a fake finalized chain: each checkpoint has the actor data
// and the actor's full history, newest first.
type chainState struct {
	mu         sync.Mutex
	checkpoint uint64
	data       *nativecore.ServiceActorDataV1
	history    []toschain.ActorTransaction
	readErr    error
	historyErr error
	staleHead  bool
	walks      []string
}

func (c *chainState) BeginSession(context.Context) (Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &fakeSession{chain: c, checkpoint: c.checkpoint, data: c.data, history: append([]toschain.ActorTransaction(nil), c.history...)}, nil
}

type fakeSession struct {
	chain      *chainState
	checkpoint uint64
	data       *nativecore.ServiceActorDataV1
	history    []toschain.ActorTransaction
}

func (s *fakeSession) Checkpoint() uint64   { return s.checkpoint }
func (s *fakeSession) ChainTime() time.Time { return time.Unix(int64(callNow)+100, 0) }
func (s *fakeSession) ResolveRegistry(context.Context, string) (*nativev1.NativeStateV1, bool, error) {
	return nil, false, errors.New("not used")
}

func (s *fakeSession) ReadActor(_ context.Context, address string) (*toschain.ActorAccount, bool, error) {
	if s.chain.readErr != nil {
		return nil, false, s.chain.readErr
	}
	head := toschain.ActorTxID{}
	if len(s.history) > 0 {
		head = toschain.ActorTxID{LT: s.history[0].LT, Hash: s.history[0].Hash}
	}
	return &toschain.ActorAccount{Address: address, Data: s.data, LastTransaction: head}, true, nil
}

func (s *fakeSession) History(_ context.Context, _ string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	if s.chain.historyErr != nil {
		return nil, s.chain.historyErr
	}
	s.chain.mu.Lock()
	if anchor == nil {
		s.chain.walks = append(s.chain.walks, "full")
	} else {
		s.chain.walks = append(s.chain.walks, "anchored")
	}
	s.chain.mu.Unlock()
	head := toschain.ActorTxID{}
	if len(s.history) > 0 {
		head = toschain.ActorTxID{LT: s.history[0].LT, Hash: s.history[0].Hash}
	}
	if s.chain.staleHead {
		head.LT++
	}
	if anchor == nil {
		return &toschain.ActorHistory{Result: toschain.HistoryComplete, Head: head, Transactions: s.history}, nil
	}
	for index, transaction := range s.history {
		if transaction.LT == anchor.LT && transaction.Hash == anchor.Hash {
			return &toschain.ActorHistory{Result: toschain.HistoryAnchorReached, Head: head, Transactions: s.history[:index]}, nil
		}
	}
	return nil, toschain.ErrHistoryAnchorMissing
}

func policy() nativecore.ServiceActorPolicyV1 {
	terms := servicefixture.Terms(keyID, [32]byte{0x66})
	return nativecore.ServiceActorPolicyV1{PolicyVersion: terms.PolicyVersion, PricePerCall: terms.PricePerCall,
		StorageFee: terms.StorageFee, CleanupBounty: terms.CleanupBounty, ResponseSLA: terms.ResponseSLA,
		RefundClaimWindow: terms.RefundClaimWindow, OpenAccess: true, MetadataHash: terms.MetadataHash,
		ProofSchemeHash: terms.ProofSchemeHash, HasAttestor: true, AttestorKeyID: keyID, AttestorKey: key}
}

func call(t *testing.T, caller string, id uint64, hashByte byte, lt uint64) (toschain.ActorTransaction, nativecore.ServiceActorRequestSnapshotV1) {
	t.Helper()
	var hash [32]byte
	copy(hash[:], bytes.Repeat([]byte{hashByte}, 32))
	transaction, err := servicefixture.CallTransaction(caller, id, hash, 100+id, callNow, lt, servicefixture.Terms(keyID, [32]byte{0x66}))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := transaction.Snapshot.Decode()
	if err != nil {
		t.Fatal(err)
	}
	return transaction, snapshot
}

func data(t *testing.T, next uint64, pending, refunds map[uint64]nativecore.ServiceActorRequestSnapshotV1) *nativecore.ServiceActorDataV1 {
	t.Helper()
	value, err := servicefixture.ActorData(owner, policy(), next, pending, refunds)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestIndexRebuildsAndRefreshesIncrementally(t *testing.T) {
	call0, snap0 := call(t, buyer, 0, 0x40, 10)
	call1, snap1 := call(t, other, 1, 0x41, 11)
	chain := &chainState{checkpoint: 5, data: data(t, 2, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0, 1: snap1}, nil),
		history: []toschain.ActorTransaction{call1, call0}}
	index, err := New(chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.Refresh(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	page, err := index.Requests(actor, RequestFilter{Caller: buyer}, 10, nil)
	if err != nil || len(page.Requests) != 1 || page.Requests[0].RequestID != 0 || page.Requests[0].State != serviceactor.StatePending ||
		page.Checkpoint != 5 || page.Requests[0].QueryID != 100 {
		t.Fatalf("page = %+v, %v", page, err)
	}

	// A respond lands; the next refresh walks only the new transaction.
	respond := servicefixture.Transition(toschain.ActorTxRespond, 1, callNow+10, 12, owner)
	chain.mu.Lock()
	chain.checkpoint, chain.history = 6, append([]toschain.ActorTransaction{respond}, chain.history...)
	chain.data = data(t, 2, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0}, nil)
	chain.mu.Unlock()
	if _, err := index.Refresh(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	id := uint64(1)
	page, err = index.Requests(actor, RequestFilter{RequestID: &id}, 10, nil)
	if err != nil || len(page.Requests) != 1 || page.Requests[0].State != serviceactor.StateResponded || page.Requests[0].Outcome == nil {
		t.Fatalf("after respond: %+v, %v", page, err)
	}
	if strings.Join(chain.walks, ",") != "full,anchored" {
		t.Fatalf("walks = %v", chain.walks)
	}

	// The published head disappears from history (a rebuilt fake chain):
	// the index discards its derivation and rebuilds from the origin.
	call0b, snap0b := call(t, buyer, 0, 0x50, 20)
	chain.mu.Lock()
	chain.checkpoint, chain.history = 7, []toschain.ActorTransaction{call0b}
	chain.data = data(t, 1, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0b}, nil)
	chain.mu.Unlock()
	if _, err := index.Refresh(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	if strings.Join(chain.walks, ",") != "full,anchored,anchored,full" {
		t.Fatalf("walks = %v", chain.walks)
	}
	page, err = index.Requests(actor, RequestFilter{}, 10, nil)
	if err != nil || len(page.Requests) != 1 || page.Requests[0].RequestHash != strings.Repeat("50", 32) {
		t.Fatalf("after rebuild: %+v %v", page, err)
	}
}

func TestIndexRefusesInconsistentHistoryAndKeepsThePublishedView(t *testing.T) {
	call0, snap0 := call(t, buyer, 0, 0x40, 10)
	chain := &chainState{checkpoint: 5, data: data(t, 1, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0}, nil),
		history: []toschain.ActorTransaction{call0}}
	index, _ := New(chain)
	if _, err := index.Refresh(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	_, snapGap := call(t, buyer, 2, 0x42, 12)
	callGap, _ := call(t, buyer, 2, 0x42, 12)
	cases := map[string]func(){
		"request id gap": func() {
			chain.history = []toschain.ActorTransaction{callGap, call0}
			chain.data = data(t, 3, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0, 2: snapGap}, nil)
		},
		"state not explained": func() {
			chain.history = []toschain.ActorTransaction{call0}
			chain.data = data(t, 1, nil, nil)
		},
		"terminal for unknown request": func() {
			chain.history = []toschain.ActorTransaction{servicefixture.Transition(toschain.ActorTxRespond, 9, callNow+1, 13, owner), call0}
			chain.data = data(t, 1, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0}, nil)
		},
		"history head is not the account head": func() {
			chain.history = []toschain.ActorTransaction{call0}
			chain.data = data(t, 1, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0}, nil)
			chain.staleHead = true
		},
		"read failure":    func() { chain.readErr = errors.New("quorum not reached") },
		"history failure": func() { chain.historyErr = toschain.ErrHistoryBoundExceeded },
	}
	for name, edit := range cases {
		chain.mu.Lock()
		chain.checkpoint++
		chain.readErr, chain.historyErr, chain.staleHead = nil, nil, false
		edit()
		chain.mu.Unlock()
		if _, err := index.Refresh(context.Background(), actor); err == nil {
			t.Errorf("%s was published", name)
		}
		snapshot, ok := index.Snapshot(actor)
		if !ok || snapshot.Checkpoint != 5 {
			t.Errorf("%s replaced the published view", name)
		}
	}
	// A checkpoint older than the published one is refused.
	chain.mu.Lock()
	chain.checkpoint, chain.readErr, chain.historyErr, chain.staleHead = 4, nil, nil, false
	chain.history, chain.data = []toschain.ActorTransaction{call0}, data(t, 1, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snap0}, nil)
	chain.mu.Unlock()
	if _, err := index.Refresh(context.Background(), actor); err == nil {
		t.Error("a regressed checkpoint was accepted")
	}
}

func TestIndexQueriesAreBoundedAndReadOneSnapshot(t *testing.T) {
	var history []toschain.ActorTransaction
	pending := map[uint64]nativecore.ServiceActorRequestSnapshotV1{}
	for id := uint64(0); id < 120; id++ {
		transaction, snapshot := call(t, buyer, id, byte(id), 10+id)
		history = append([]toschain.ActorTransaction{transaction}, history...)
		pending[id] = snapshot
	}
	chain := &chainState{checkpoint: 5, data: data(t, 120, pending, nil), history: history}
	index, _ := New(chain)
	if _, err := index.Refresh(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	if _, err := index.Requests(actor, RequestFilter{}, MaxPageSize+1, nil); err == nil {
		t.Fatal("an oversized page was accepted")
	}
	first, err := index.Requests(actor, RequestFilter{}, MaxPageSize, nil)
	if err != nil || len(first.Requests) != MaxPageSize || first.NextAfterID == nil || *first.NextAfterID != 99 {
		t.Fatalf("first page: %d %v", len(first.Requests), err)
	}
	second, err := index.Requests(actor, RequestFilter{}, MaxPageSize, first.NextAfterID)
	if err != nil || len(second.Requests) != 20 || second.NextAfterID != nil || second.Requests[0].RequestID != 100 {
		t.Fatalf("second page: %d %v", len(second.Requests), err)
	}
	if _, err := index.Requests("0:"+strings.Repeat("99", 32), RequestFilter{}, 10, nil); err == nil {
		t.Fatal("an unindexed actor answered")
	}

	// Concurrent queries during refreshes always see one whole snapshot.
	var wait sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < 50; i++ {
				page, err := index.Requests(actor, RequestFilter{}, MaxPageSize, nil)
				if err != nil || len(page.Requests) != MaxPageSize {
					t.Errorf("concurrent query: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 5; i++ {
		chain.mu.Lock()
		chain.checkpoint++
		chain.mu.Unlock()
		if _, err := index.Refresh(context.Background(), actor); err != nil {
			t.Fatal(err)
		}
	}
	wait.Wait()
}
