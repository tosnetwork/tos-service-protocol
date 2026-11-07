package serviceactor

import (
	"bytes"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	tosaddress "github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const callNow = 1_000_000

func lifecycleCall(t *testing.T, f *fixture, id uint64, lt uint64) toschain.ActorTransaction {
	t.Helper()
	call := rebuildWithID(t, f, nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy), id)
	call.LT = lt
	return call
}

func rebuildWithID(t *testing.T, f *fixture, terms nativecore.ServiceActorTermsV1, id uint64) toschain.ActorTransaction {
	t.Helper()
	call := callFixture(t, f, callNow, terms, nil)
	snapshot, err := call.Snapshot.Decode()
	if err != nil {
		t.Fatal(err)
	}
	termsCell, _ := nativecore.BuildServiceActorTermsCell(terms)
	caller, _ := addressLib(testBuyer)
	body := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorRequestSnapshotTag, 32).MustStoreUInt(id, 64).MustStoreAddr(caller).
		MustStoreSlice(snapshot.RequestHash[:], 256).MustStoreUInt(snapshot.ResponseDeadline, 64).
		MustStoreUInt(snapshot.RefundClaimDeadline, 64).MustStoreRef(termsCell).EndCell()
	call.Snapshot = &toschain.ActorSAR1{BodyBOC: bocBase64(body)}
	return call
}

func bocBase64(value *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(value.ToBOC())
}

func transition(kind string, id uint64, now uint32, sender string) toschain.ActorTransaction {
	return toschain.ActorTransaction{Kind: kind, RequestID: id, Now: now, Sender: sender, Signed: kind == toschain.ActorTxRespond,
		Hash: strings.Repeat("0b", 32)}
}

func withPayout(transaction toschain.ActorTransaction, destination, amount string) toschain.ActorTransaction {
	transaction.Payouts = []toschain.ActorPayout{{Destination: destination, AmountNano: amount, EmptyBody: true}}
	return transaction
}

func TestLifecycleTransitions(t *testing.T) {
	f := newFixture(t)
	owner := f.evidence.Actor.Data.Owner
	responseDeadline := uint32(callNow + 3600)
	refundDeadline := uint32(callNow + 7200)
	claim := func(now uint32) toschain.ActorTransaction {
		c := withPayout(transition(toschain.ActorTxClaim, 0, now, testBuyer), testBuyer, "300000000")
		c.Destination = testBuyer
		return c
	}
	sweep := func(now uint32) toschain.ActorTransaction {
		return withPayout(transition(toschain.ActorTxSweep, 0, now, testOwner), testBuyer, "300000000")
	}
	legal := map[string][]toschain.ActorTransaction{
		"respond":              {transition(toschain.ActorTxRespond, 0, responseDeadline-1, testOwner)},
		"expire then claim":    {transition(toschain.ActorTxExpire, 0, responseDeadline, testOwner), claim(refundDeadline - 1)},
		"expire then sweep":    {transition(toschain.ActorTxExpire, 0, responseDeadline, testOwner), sweep(refundDeadline)},
		"sweep without expire": {sweep(refundDeadline)},
	}
	for name, steps := range legal {
		request, err := NewRequest(lifecycleCall(t, f, 0, 10))
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if err := request.Apply(step, owner); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if !request.State.Terminal() {
			t.Fatalf("%s ended %s", name, request.State)
		}
	}
	illegal := map[string][]toschain.ActorTransaction{
		"respond at deadline":  {transition(toschain.ActorTxRespond, 0, responseDeadline, testOwner)},
		"respond by non-owner": {transition(toschain.ActorTxRespond, 0, responseDeadline-1, testBuyer)},
		"respond unsigned": {func() toschain.ActorTransaction {
			r := transition(toschain.ActorTxRespond, 0, 1, testOwner)
			r.Signed = false
			return r
		}()},
		"respond after respond": {transition(toschain.ActorTxRespond, 0, responseDeadline-2, testOwner), transition(toschain.ActorTxRespond, 0, responseDeadline-1, testOwner)},
		"expire early":          {transition(toschain.ActorTxExpire, 0, responseDeadline-1, testOwner)},
		"expire late":           {transition(toschain.ActorTxExpire, 0, refundDeadline, testOwner)},
		"claim without expire":  {claim(responseDeadline + 1)},
		"claim after window":    {transition(toschain.ActorTxExpire, 0, responseDeadline, testOwner), claim(refundDeadline)},
		"claim by another":      {transition(toschain.ActorTxExpire, 0, responseDeadline, testOwner), func() toschain.ActorTransaction { c := claim(refundDeadline - 1); c.Sender = testOwner; return c }()},
		"claim short payout": {transition(toschain.ActorTxExpire, 0, responseDeadline, testOwner), func() toschain.ActorTransaction {
			c := claim(refundDeadline - 1)
			c.Payouts[0].AmountNano = "299999999"
			return c
		}()},
		"sweep early":            {sweep(refundDeadline - 1)},
		"sweep to another":       {withPayout(transition(toschain.ActorTxSweep, 0, refundDeadline, testOwner), testOwner, "300000000")},
		"sweep after respond":    {transition(toschain.ActorTxRespond, 0, responseDeadline-1, testOwner), sweep(refundDeadline)},
		"refund after sweep":     {sweep(refundDeadline), claim(refundDeadline)},
		"another request":        {transition(toschain.ActorTxExpire, 1, responseDeadline, testOwner)},
		"bounceable claim":       {transition(toschain.ActorTxExpire, 0, responseDeadline, testOwner), func() toschain.ActorTransaction { c := claim(refundDeadline - 1); c.Payouts[0].Bounce = true; return c }()},
		"not a transition kind":  {transition(toschain.ActorTxOwner, 0, 1, testOwner)},
		"expire after responded": {transition(toschain.ActorTxRespond, 0, 1, testOwner), transition(toschain.ActorTxExpire, 0, responseDeadline, testOwner)},
	}
	for name, steps := range illegal {
		request, err := NewRequest(lifecycleCall(t, f, 0, 10))
		if err != nil {
			t.Fatal(err)
		}
		var failure error
		for _, step := range steps {
			if failure = request.Apply(step, owner); failure != nil {
				break
			}
		}
		if failure == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestStatusAndRequiredAction(t *testing.T) {
	f := newFixture(t)
	request, err := NewRequest(lifecycleCall(t, f, 0, 10))
	if err != nil {
		t.Fatal(err)
	}
	at := func(seconds int64) time.Time { return time.Unix(callNow+seconds, 0) }
	for seconds, want := range map[int64]Status{0: StatusPending, 3599: StatusPending, 3600: StatusOverdue, 7199: StatusOverdue, 7200: StatusLapsed} {
		if got := request.StatusAt(at(seconds)); got != want {
			t.Errorf("at +%d: %s, want %s", seconds, got, want)
		}
	}
	if request.RequiredAction(at(3600)) == "" || request.RequiredAction(at(0)) != "" {
		t.Error("required actions do not follow the status")
	}
	if err := request.Apply(transition(toschain.ActorTxExpire, 0, callNow+3600, testOwner), f.evidence.Actor.Data.Owner); err != nil {
		t.Fatal(err)
	}
	if request.StatusAt(at(3601)) != StatusRefundable || request.StatusAt(at(7200)) != StatusLapsed {
		t.Error("an expired request is refundable until the refund deadline, then lapsed")
	}
}

// replayData builds actor data holding the given pending and refundable
// requests exactly as the contract would.
func replayData(t *testing.T, f *fixture, next uint64, pending, refunds []*Request) *nativecore.ServiceActorDataV1 {
	t.Helper()
	data := *f.evidence.Actor.Data
	data.NextRequestID = next
	data.Pending = map[uint64]nativecore.ServiceActorPendingRequestV1{}
	data.Refunds = map[uint64]nativecore.ServiceActorRefundV1{}
	data.CallerLiveCounts = map[[32]byte]uint32{}
	pendingSum, refundSum, locked := new(big.Int), new(big.Int), new(big.Int)
	for _, request := range pending {
		s := request.Snapshot
		data.Pending[s.RequestID] = nativecore.ServiceActorPendingRequestV1{Caller: s.Caller, Price: s.Terms.PricePerCall,
			StorageFee: s.Terms.StorageFee, CleanupBounty: s.Terms.CleanupBounty, ResponseDeadline: s.ResponseDeadline,
			RefundClaimDeadline: s.RefundClaimDeadline, PolicyVersion: s.Terms.PolicyVersion, RequestHash: s.RequestHash,
			TermsHash: s.TermsHash, HasAttestor: s.Terms.HasAttestor, AttestorKeyID: s.Terms.AttestorKeyID}
		pendingSum.Add(pendingSum, s.Terms.PricePerCall)
		locked.Add(locked, s.Terms.StorageFee)
		key, _ := s.Caller.SliceHash()
		data.CallerLiveCounts[key]++
	}
	for _, request := range refunds {
		s := request.Snapshot
		data.Refunds[s.RequestID] = nativecore.ServiceActorRefundV1{Caller: s.Caller, Price: s.Terms.PricePerCall,
			StorageFee: s.Terms.StorageFee, CleanupBounty: s.Terms.CleanupBounty, RefundClaimDeadline: s.RefundClaimDeadline}
		refundSum.Add(refundSum, s.Terms.PricePerCall)
		locked.Add(locked, s.Terms.StorageFee)
		key, _ := s.Caller.SliceHash()
		data.CallerLiveCounts[key]++
	}
	data.PendingCount, data.LiveCount = uint32(len(pending)), uint32(len(pending)+len(refunds))
	data.Accounting.PendingLiability, data.Accounting.RefundableLiability, data.Accounting.LockedStorageFees = pendingSum, refundSum, locked
	return &data
}

func TestReplayReconcilesHistoryWithState(t *testing.T) {
	f := newFixture(t)
	call0, call1, call2 := lifecycleCall(t, f, 0, 10), lifecycleCall(t, f, 1, 11), lifecycleCall(t, f, 2, 12)
	request0, _ := NewRequest(call0)
	request2, _ := NewRequest(call2)
	expire2 := transition(toschain.ActorTxExpire, 2, callNow+3600, testOwner)
	respond1 := transition(toschain.ActorTxRespond, 1, callNow+10, testOwner)
	history := []toschain.ActorTransaction{expire2, respond1, {Kind: toschain.ActorTxFailed}, call2, call1, call0}
	expired2 := *request2
	expired2.State = StateExpired
	data := replayData(t, f, 3, []*Request{request0}, []*Request{&expired2})
	requests, err := Replay(history, data)
	if err != nil {
		t.Fatal(err)
	}
	if requests[0].State != StatePending || requests[1].State != StateResponded || requests[2].State != StateExpired {
		t.Fatalf("replayed states: %s %s %s", requests[0].State, requests[1].State, requests[2].State)
	}
	// Incremental replay from the first three transactions gives the same result.
	older, err := Replay(history[3:], replayData(t, f, 3, []*Request{request0, mustRequest(t, call1), request2}, nil))
	if err != nil {
		t.Fatal(err)
	}
	incremental, err := ReplayFrom(older, history[:3], data)
	if err != nil || incremental[1].State != StateResponded || incremental[2].State != StateExpired {
		t.Fatalf("incremental replay: %v", err)
	}
	if older[1].State != StatePending {
		t.Fatal("an incremental replay modified the previous result")
	}

	for name, test := range map[string]struct {
		history []toschain.ActorTransaction
		data    *nativecore.ServiceActorDataV1
	}{
		"id gap":           {[]toschain.ActorTransaction{call2, call0}, replayData(t, f, 2, nil, nil)},
		"duplicate id":     {[]toschain.ActorTransaction{call0, call0}, replayData(t, f, 2, nil, nil)},
		"next id mismatch": {[]toschain.ActorTransaction{call0}, replayData(t, f, 2, []*Request{request0}, nil)},
		"pending missing":  {[]toschain.ActorTransaction{call0}, replayData(t, f, 1, nil, nil)},
		"pending differs": {[]toschain.ActorTransaction{call0}, func() *nativecore.ServiceActorDataV1 {
			d := replayData(t, f, 1, []*Request{request0}, nil)
			e := d.Pending[0]
			e.RefundClaimDeadline++
			d.Pending[0] = e
			return d
		}()},
		"refund unexplained": {[]toschain.ActorTransaction{respond1, call1, call0}, replayData(t, f, 2, []*Request{request0},
			[]*Request{func() *Request { r := mustRequest(t, call1); r.State = StateExpired; return r }()})},
		"reused request id": {[]toschain.ActorTransaction{call0, call0}, replayData(t, f, 2,
			[]*Request{request0, func() *Request {
				r := mustRequest(t, call1)
				r.Snapshot = request0.Snapshot
				r.Snapshot.RequestID = 1
				return r
			}()}, nil)},
		"unknown request": {[]toschain.ActorTransaction{respond1}, replayData(t, f, 0, nil, nil)},
		"double terminal": {[]toschain.ActorTransaction{respond1, respond1, call1, call0}, replayData(t, f, 2, []*Request{request0}, nil)},
		"liabilities": {[]toschain.ActorTransaction{call0}, func() *nativecore.ServiceActorDataV1 {
			d := replayData(t, f, 1, []*Request{request0}, nil)
			d.Accounting.PendingLiability = big.NewInt(1)
			return d
		}()},
	} {
		if _, err := Replay(test.history, test.data); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func mustRequest(t *testing.T, call toschain.ActorTransaction) *Request {
	t.Helper()
	request, err := NewRequest(call)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestLifecycleAcceptsZeroPriceRefundsAndVariableOwners(t *testing.T) {
	f := newFixture(t)
	terms := nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy)
	terms.PricePerCall = big.NewInt(0)
	request, err := NewRequest(callFixture(t, f, callNow, terms, nil))
	if err != nil {
		t.Fatal(err)
	}
	owner := f.evidence.Actor.Data.Owner
	if err := request.Apply(transition(toschain.ActorTxExpire, 0, callNow+3600, testOwner), owner); err != nil {
		t.Fatal(err)
	}
	claim := transition(toschain.ActorTxClaim, 0, callNow+3601, testBuyer)
	claim.Destination = testBuyer
	if err := request.Apply(claim, owner); err != nil || request.State != StateRefunded {
		t.Fatalf("a zero-price refund without a principal payout was refused: %v", err)
	}

	variable := tosaddress.NewAddressVar(0, 3, 72, bytes.Repeat([]byte{0x2d}, 9))
	ownerCell := cell.BeginCell().MustStoreAddr(variable).EndCell()
	variableOwner, err := nativecore.DecodeMsgAddressCell(ownerCell)
	if err != nil {
		t.Fatal(err)
	}
	paid, err := NewRequest(callFixture(t, f, callNow, nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy), nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := paid.Apply(transition(toschain.ActorTxRespond, 0, callNow+1, variableOwner.Text()), variableOwner); err != nil {
		t.Fatalf("a respond from an addr_var owner was refused: %v", err)
	}
	other, _ := NewRequest(callFixture(t, f, callNow, nativecore.TermsOfPolicy(f.evidence.Actor.Data.Policy), nil))
	if err := other.Apply(transition(toschain.ActorTxRespond, 0, callNow+1, testOwner), variableOwner); err == nil {
		t.Fatal("a respond from another sender was accepted for an addr_var owner")
	}
}
