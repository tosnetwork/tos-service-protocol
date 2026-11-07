// Package serviceactorindex is a rebuildable, derived index of Service Actor
// requests and a discovery query over Capability offers settled by Service
// Actors. The index is rebuilt only from finalized transactions (request
// snapshots and lifecycle transactions) and the actor's decoded state at the
// same checkpoint; it holds no authority, and a refresh that cannot be
// reconciled completely is refused rather than published in part.
package serviceactorindex

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const (
	// MaxPageSize bounds every query page.
	MaxPageSize = 100
	// MaxTrackedActors bounds the actors one index follows.
	MaxTrackedActors = 1024
)

// Session is one finalized checkpoint the index reads through.
type Session interface {
	serviceactor.Session
	History(ctx context.Context, actor string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error)
}

// Reader opens sessions.
type Reader interface {
	BeginSession(ctx context.Context) (Session, error)
}

type chainReader struct{ reader *toschain.ServiceActorReader }

func (c chainReader) BeginSession(ctx context.Context) (Session, error) { return c.reader.Begin(ctx) }

// FromChain adapts a finalized Service Actor reader.
func FromChain(reader *toschain.ServiceActorReader) Reader { return chainReader{reader: reader} }

// ActorSnapshot is one published, immutable view of an actor's requests.
type ActorSnapshot struct {
	Actor      string
	Checkpoint uint64
	ChainTime  time.Time
	Head       toschain.ActorTxID
	Data       *nativecore.ServiceActorDataV1
	requests   map[uint64]*serviceactor.Request
	byHash     map[string][]uint64
	byCaller   map[string][]uint64
}

// Index follows a bounded set of actors.
type Index struct {
	reader    Reader
	refreshMu sync.Mutex
	mu        sync.RWMutex
	snapshots map[string]*ActorSnapshot
}

// New returns an empty index.
func New(reader Reader) (*Index, error) {
	if reader == nil {
		return nil, errors.New("Service Actor index needs a finalized reader")
	}
	return &Index{reader: reader, snapshots: map[string]*ActorSnapshot{}}, nil
}

// Refresh rebuilds one actor's view at a fresh checkpoint: incrementally from
// the published head when the finalized history still contains it, otherwise
// from the actor's first transaction. Nothing is published unless the whole
// history reconciles with the actor's state at that checkpoint.
func (x *Index) Refresh(ctx context.Context, actor string) (*ActorSnapshot, error) {
	if x == nil || ctx == nil {
		return nil, errors.New("Service Actor index is not configured")
	}
	canonical, err := toschain.CanonicalAddress(actor)
	if err != nil {
		return nil, fmt.Errorf("invalid Service Actor address: %w", err)
	}
	x.refreshMu.Lock()
	defer x.refreshMu.Unlock()
	x.mu.RLock()
	previous := x.snapshots[canonical]
	tracked := len(x.snapshots)
	x.mu.RUnlock()
	if previous == nil && tracked >= MaxTrackedActors {
		return nil, errors.New("Service Actor index tracks the maximum number of actors")
	}
	session, err := x.reader.BeginSession(ctx)
	if err != nil {
		return nil, err
	}
	if previous != nil && session.Checkpoint() < previous.Checkpoint {
		return nil, errors.New("Service Actor index checkpoint regressed")
	}
	account, found, err := session.ReadActor(ctx, canonical)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("Service Actor account is not active at the checkpoint")
	}
	var anchor *toschain.ActorTxID
	var base map[uint64]*serviceactor.Request
	if previous != nil {
		head := previous.Head
		anchor, base = &head, previous.requests
	}
	history, err := session.History(ctx, canonical, anchor)
	if errors.Is(err, toschain.ErrHistoryAnchorMissing) {
		anchor, base = nil, nil
		history, err = session.History(ctx, canonical, nil)
	}
	if err != nil {
		return nil, err
	}
	if anchor == nil && history.Result != toschain.HistoryComplete || anchor != nil && history.Result != toschain.HistoryAnchorReached {
		return nil, errors.New("Service Actor history walk ended without reaching its anchor or origin")
	}
	if history.Head != account.LastTransaction {
		return nil, errors.New("Service Actor history head is not the account's last transaction")
	}
	requests, err := serviceactor.ReplayFrom(base, history.Transactions, account.Data)
	if err != nil {
		return nil, fmt.Errorf("Service Actor history does not reconcile with state: %w", err)
	}
	snapshot := &ActorSnapshot{Actor: canonical, Checkpoint: session.Checkpoint(), ChainTime: session.ChainTime(),
		Head: history.Head, Data: account.Data, requests: requests, byHash: map[string][]uint64{}, byCaller: map[string][]uint64{}}
	for id, request := range requests {
		hash := hex.EncodeToString(request.Snapshot.RequestHash[:])
		snapshot.byHash[hash] = append(snapshot.byHash[hash], id)
		caller := request.Snapshot.Caller.Text()
		snapshot.byCaller[caller] = append(snapshot.byCaller[caller], id)
	}
	for _, ids := range snapshot.byHash {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	}
	for _, ids := range snapshot.byCaller {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	}
	x.mu.Lock()
	x.snapshots[canonical] = snapshot
	x.mu.Unlock()
	return snapshot, nil
}

// Snapshot returns the published view of an actor, if any.
func (x *Index) Snapshot(actor string) (*ActorSnapshot, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	snapshot, ok := x.snapshots[actor]
	return snapshot, ok
}

// RequestFilter selects requests; empty fields match everything.
type RequestFilter struct {
	Caller      string
	RequestHash string
	RequestID   *uint64
}

// RequestRecord is one indexed request.
type RequestRecord struct {
	RequestID           uint64                     `json:"request_id"`
	Caller              string                     `json:"caller"`
	RequestHash         string                     `json:"request_hash"`
	TermsHash           string                     `json:"terms_hash"`
	PriceNanoTOS        string                     `json:"price_nanotos"`
	StorageFeeNanoTOS   string                     `json:"storage_fee_nanotos"`
	AttestorKeyID       string                     `json:"attestor_key_id,omitempty"`
	ResponseDeadline    uint64                     `json:"response_deadline"`
	RefundClaimDeadline uint64                     `json:"refund_claim_deadline"`
	CallTransaction     toschain.ActorTxID         `json:"call_transaction"`
	QueryID             uint64                     `json:"query_id"`
	State               serviceactor.RequestState  `json:"state"`
	Status              serviceactor.Status        `json:"status"`
	Outcome             *toschain.ActorTransaction `json:"outcome,omitempty"`
	RequiredAction      string                     `json:"required_action,omitempty"`
	// RequestHashReused reports another request with the same request_hash.
	RequestHashReused bool `json:"request_hash_reused,omitempty"`
}

// RequestPage is one page of a request query from one published snapshot.
type RequestPage struct {
	Actor       string          `json:"actor"`
	Checkpoint  uint64          `json:"checkpoint"`
	Requests    []RequestRecord `json:"requests"`
	NextAfterID *uint64         `json:"next_after_request_id,omitempty"`
	Authority   string          `json:"authority"`
}

// Requests answers a bounded query from one published snapshot.
func (x *Index) Requests(actor string, filter RequestFilter, pageSize int, after *uint64) (*RequestPage, error) {
	if pageSize <= 0 || pageSize > MaxPageSize {
		return nil, fmt.Errorf("page size must be 1 to %d", MaxPageSize)
	}
	snapshot, ok := x.Snapshot(actor)
	if !ok {
		return nil, errors.New("the actor is not indexed; refresh it first")
	}
	var ids []uint64
	switch {
	case filter.RequestID != nil:
		if _, ok := snapshot.requests[*filter.RequestID]; ok {
			ids = []uint64{*filter.RequestID}
		}
	case filter.RequestHash != "":
		ids = append(ids, snapshot.byHash[filter.RequestHash]...)
	case filter.Caller != "":
		ids = append(ids, snapshot.byCaller[filter.Caller]...)
	default:
		for id := range snapshot.requests {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	}
	page := &RequestPage{Actor: snapshot.Actor, Checkpoint: snapshot.Checkpoint,
		Authority: "derived index; verify against finalized state before acting"}
	for _, id := range ids {
		if after != nil && id <= *after {
			continue
		}
		request := snapshot.requests[id]
		if filter.Caller != "" {
			if request.Snapshot.Caller.Text() != filter.Caller {
				continue
			}
		}
		if filter.RequestHash != "" && hex.EncodeToString(request.Snapshot.RequestHash[:]) != filter.RequestHash {
			continue
		}
		if len(page.Requests) == pageSize {
			last := page.Requests[len(page.Requests)-1].RequestID
			page.NextAfterID = &last
			break
		}
		page.Requests = append(page.Requests, record(snapshot, id, request))
	}
	return page, nil
}

func record(snapshot *ActorSnapshot, id uint64, request *serviceactor.Request) RequestRecord {
	s, terms := request.Snapshot, request.Snapshot.Terms
	caller := s.Caller.Text()
	hash := hex.EncodeToString(s.RequestHash[:])
	result := RequestRecord{RequestID: id, Caller: caller, RequestHash: hash, TermsHash: hex.EncodeToString(s.TermsHash[:]),
		PriceNanoTOS: terms.PricePerCall.String(), StorageFeeNanoTOS: terms.StorageFee.String(),
		ResponseDeadline: s.ResponseDeadline, RefundClaimDeadline: s.RefundClaimDeadline,
		CallTransaction: toschain.ActorTxID{LT: request.Call.LT, Hash: request.Call.Hash}, QueryID: request.Call.Call.QueryID,
		State: request.State, Status: request.StatusAt(snapshot.ChainTime), Outcome: request.Terminal,
		RequiredAction: request.RequiredAction(snapshot.ChainTime), RequestHashReused: len(snapshot.byHash[hash]) > 1}
	if terms.HasAttestor {
		result.AttestorKeyID = "mldsa44:" + hex.EncodeToString(terms.AttestorKeyID[:])
	}
	return result
}
