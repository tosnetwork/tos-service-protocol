package serviceactor

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// RequestState is a request's position in the contract lifecycle.
type RequestState string

const (
	StatePending   RequestState = "pending"
	StateExpired   RequestState = "expired"
	StateResponded RequestState = "responded"
	StateRefunded  RequestState = "refunded"
	StateSwept     RequestState = "swept"
)

// Terminal reports a state no transition leaves.
func (s RequestState) Terminal() bool {
	return s == StateResponded || s == StateRefunded || s == StateSwept
}

// Request is one request replayed from its call snapshot and its finalized
// lifecycle transactions.
type Request struct {
	Snapshot   nativecore.ServiceActorRequestSnapshotV1
	Call       toschain.ActorTransaction
	State      RequestState
	Terminal   *toschain.ActorTransaction
	Expiration *toschain.ActorTransaction
}

// NewRequest starts a request at its successful call.
func NewRequest(call toschain.ActorTransaction) (*Request, error) {
	if call.Kind != toschain.ActorTxCall || call.Snapshot == nil || call.Call == nil {
		return nil, errors.New("a request starts only at a successful call")
	}
	snapshot, err := call.Snapshot.Decode()
	if err != nil {
		return nil, err
	}
	if snapshot.Caller.Text() != call.Sender {
		return nil, errors.New("request snapshot caller is not the call sender")
	}
	if snapshot.ResponseDeadline != uint64(call.Now)+uint64(snapshot.Terms.ResponseSLA) {
		return nil, errors.New("request snapshot response deadline is not the call time plus the SLA")
	}
	if call.Call.RequestHash != hexOf(snapshot.RequestHash) || call.Call.ExpectedTermsHash != hexOf(snapshot.TermsHash) {
		return nil, errors.New("request snapshot differs from the call body")
	}
	return &Request{Snapshot: snapshot, Call: call, State: StatePending}, nil
}

// Apply moves the request through one successful lifecycle transaction,
// checking each transition's time predicate against the transaction time and
// the snapshot deadlines, the sender rules, and the payouts. owner is the
// actor's fixed owner address.
func (r *Request) Apply(transaction toschain.ActorTransaction, owner nativecore.MsgAddressV1) error {
	if r == nil {
		return errors.New("missing request")
	}
	if transaction.RequestID != r.Snapshot.RequestID {
		return errors.New("transaction names another request")
	}
	if r.State.Terminal() {
		return fmt.Errorf("request %d is already %s", r.Snapshot.RequestID, r.State)
	}
	now := uint64(transaction.Now)
	price := r.Snapshot.Terms.PricePerCall
	caller := r.Snapshot.Caller.Text()
	switch transaction.Kind {
	case toschain.ActorTxRespond:
		ownerRaw, ok := owner.RawStandard()
		if r.State != StatePending || now >= r.Snapshot.ResponseDeadline {
			return fmt.Errorf("respond to request %d outside its response window", r.Snapshot.RequestID)
		}
		if !ok || transaction.Sender != ownerRaw {
			return errors.New("respond was not sent by the actor owner")
		}
		if transaction.Signed != r.Snapshot.Terms.HasAttestor {
			return errors.New("respond signature presence disagrees with the snapshot attestor")
		}
		r.State, r.Terminal = StateResponded, &transaction
	case toschain.ActorTxExpire:
		if r.State != StatePending || now < r.Snapshot.ResponseDeadline || now >= r.Snapshot.RefundClaimDeadline {
			return fmt.Errorf("expire of request %d outside its window", r.Snapshot.RequestID)
		}
		r.State, r.Expiration = StateExpired, &transaction
	case toschain.ActorTxClaim:
		if r.State != StateExpired || now >= r.Snapshot.RefundClaimDeadline || transaction.Sender != caller {
			return fmt.Errorf("claim_refund of request %d is not the caller's claim within the window", r.Snapshot.RequestID)
		}
		if !hasPayout(transaction.Payouts, transaction.Destination, price) {
			return errors.New("claim_refund did not pay the price to its destination")
		}
		r.State, r.Terminal = StateRefunded, &transaction
	case toschain.ActorTxSweep:
		if (r.State != StatePending && r.State != StateExpired) || now < r.Snapshot.RefundClaimDeadline {
			return fmt.Errorf("sweep of request %d before its refund deadline", r.Snapshot.RequestID)
		}
		if price.Sign() > 0 && !hasPayout(transaction.Payouts, caller, price) {
			return errors.New("sweep did not return the price to the caller")
		}
		r.State, r.Terminal = StateSwept, &transaction
	default:
		return fmt.Errorf("transaction kind %s is not a request transition", transaction.Kind)
	}
	return nil
}

func hasPayout(payouts []toschain.ActorPayout, destination string, amount *big.Int) bool {
	for _, payout := range payouts {
		value, ok := new(big.Int).SetString(payout.AmountNano, 10)
		if ok && payout.Destination == destination && value.Cmp(amount) == 0 && !payout.Bounce && payout.EmptyBody {
			return true
		}
	}
	return false
}

// Status is the buyer-visible state of design section 5.1 at a checkpoint.
type Status string

const (
	StatusPending    Status = "pending"
	StatusOverdue    Status = "overdue"
	StatusRefundable Status = "refundable"
	StatusLapsed     Status = "lapsed"
	StatusResponded  Status = "responded"
	StatusRefunded   Status = "refunded"
	StatusSwept      Status = "swept"
)

// StatusAt derives the buyer-visible status at a chain time.
func (r *Request) StatusAt(chainTime time.Time) Status {
	now := uint64(chainTime.Unix())
	switch r.State {
	case StateResponded:
		return StatusResponded
	case StateRefunded:
		return StatusRefunded
	case StateSwept:
		return StatusSwept
	}
	if now >= r.Snapshot.RefundClaimDeadline {
		return StatusLapsed
	}
	if r.State == StateExpired {
		return StatusRefundable
	}
	if now >= r.Snapshot.ResponseDeadline {
		return StatusOverdue
	}
	return StatusPending
}

// RequiredAction names what the buyer must do next, if anything.
func (r *Request) RequiredAction(chainTime time.Time) string {
	switch r.StatusAt(chainTime) {
	case StatusOverdue:
		return "send expire before the refund claim deadline, then claim_refund from the caller wallet"
	case StatusRefundable:
		return "send claim_refund from the caller wallet before the refund claim deadline"
	case StatusLapsed:
		return "none: the refund window has lapsed; a sweep returns the price to the caller"
	default:
		return ""
	}
}

// MatchesPending reports whether a pending data entry equals the snapshot.
func (r *Request) MatchesPending(entry nativecore.ServiceActorPendingRequestV1) bool {
	s, terms := r.Snapshot, r.Snapshot.Terms
	return entry.Caller.Equal(s.Caller) && entry.Price.Cmp(terms.PricePerCall) == 0 && entry.StorageFee.Cmp(terms.StorageFee) == 0 &&
		entry.CleanupBounty.Cmp(terms.CleanupBounty) == 0 && entry.ResponseDeadline == s.ResponseDeadline &&
		entry.RefundClaimDeadline == s.RefundClaimDeadline && entry.PolicyVersion == terms.PolicyVersion &&
		entry.RequestHash == s.RequestHash && entry.TermsHash == s.TermsHash && entry.HasAttestor == terms.HasAttestor &&
		entry.AttestorKeyID == terms.AttestorKeyID
}

// MatchesRefund reports whether a refund data entry equals the snapshot.
func (r *Request) MatchesRefund(entry nativecore.ServiceActorRefundV1) bool {
	s, terms := r.Snapshot, r.Snapshot.Terms
	return entry.Caller.Equal(s.Caller) && entry.Price.Cmp(terms.PricePerCall) == 0 && entry.StorageFee.Cmp(terms.StorageFee) == 0 &&
		entry.CleanupBounty.Cmp(terms.CleanupBounty) == 0 && entry.RefundClaimDeadline == s.RefundClaimDeadline
}

func hexOf(value [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range value {
		out[2*i], out[2*i+1] = digits[b>>4], digits[b&15]
	}
	return string(out)
}

// Replay reconstructs every request of an actor from its complete history
// (newest first) and checks the result against the decoded account data at
// the same checkpoint: request ids from the snapshots are exactly
// 0..next_request_id-1, every transition is legal, and the pending and
// refund sets equal the data dictionaries entry for entry. Any mismatch is an
// error; a partial result is never returned.
func Replay(history []toschain.ActorTransaction, data *nativecore.ServiceActorDataV1) (map[uint64]*Request, error) {
	return ReplayFrom(nil, history, data)
}

// ReplayFrom extends previously replayed requests with newer transactions
// (newest first) and reconciles the result with data.
func ReplayFrom(previous map[uint64]*Request, newer []toschain.ActorTransaction, data *nativecore.ServiceActorDataV1) (map[uint64]*Request, error) {
	if data == nil {
		return nil, errors.New("actor data is required to reconcile requests")
	}
	requests := make(map[uint64]*Request, len(previous)+len(newer))
	for id, request := range previous {
		copied := *request
		requests[id] = &copied
	}
	next := uint64(len(requests))
	for index := len(newer) - 1; index >= 0; index-- {
		transaction := newer[index]
		switch transaction.Kind {
		case toschain.ActorTxCall:
			request, err := NewRequest(transaction)
			if err != nil {
				return nil, fmt.Errorf("call %s: %w", transaction.Hash, err)
			}
			if request.Snapshot.RequestID != next {
				return nil, fmt.Errorf("call %s assigned request %d, expected %d", transaction.Hash, request.Snapshot.RequestID, next)
			}
			requests[next] = request
			next++
		case toschain.ActorTxRespond, toschain.ActorTxExpire, toschain.ActorTxClaim, toschain.ActorTxSweep:
			request := requests[transaction.RequestID]
			if request == nil {
				return nil, fmt.Errorf("transaction %s names unknown request %d", transaction.Hash, transaction.RequestID)
			}
			if err := request.Apply(transaction, data.Owner); err != nil {
				return nil, fmt.Errorf("transaction %s: %w", transaction.Hash, err)
			}
		}
	}
	if next != data.NextRequestID {
		return nil, fmt.Errorf("history assigned %d requests, the actor reports next_request_id %d", next, data.NextRequestID)
	}
	pending, refunds := 0, 0
	for id, request := range requests {
		switch request.State {
		case StatePending:
			entry, ok := data.Pending[id]
			if !ok || !request.MatchesPending(entry) {
				return nil, fmt.Errorf("pending request %d differs from the actor data", id)
			}
			pending++
		case StateExpired:
			entry, ok := data.Refunds[id]
			if !ok || !request.MatchesRefund(entry) {
				return nil, fmt.Errorf("refundable request %d differs from the actor data", id)
			}
			refunds++
		}
	}
	if pending != len(data.Pending) || refunds != len(data.Refunds) {
		return nil, errors.New("the actor data holds entries the history does not explain")
	}
	if err := nativecore.ValidateServiceActorLiveState(data); err != nil {
		return nil, err
	}
	return requests, nil
}
