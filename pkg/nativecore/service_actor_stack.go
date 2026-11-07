package nativecore

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// TVMStackEntryV1 is one getter result value in the getter's declared return
// order: Kind is "num", "cell", "slice" or "null".
type TVMStackEntryV1 struct {
	Kind   string
	Number *big.Int
	Cell   *cell.Cell
}

func stackUint(stack []TVMStackEntryV1, index int, width uint, what string) (*big.Int, error) {
	entry := stack[index]
	if entry.Kind != "num" || entry.Number == nil || entry.Number.Sign() < 0 || uint(entry.Number.BitLen()) > width {
		return nil, fmt.Errorf("getter %s is not an unsigned %d-bit number", what, width)
	}
	return new(big.Int).Set(entry.Number), nil
}

func stackUint64(stack []TVMStackEntryV1, index int, width uint, what string) (uint64, error) {
	value, err := stackUint(stack, index, width, what)
	if err != nil {
		return 0, err
	}
	return value.Uint64(), nil
}

func stackFlag(stack []TVMStackEntryV1, index int, what string) (bool, error) {
	value, err := stackUint(stack, index, 1, what)
	if err != nil {
		return false, err
	}
	return value.Sign() == 1, nil
}

func stackHash(stack []TVMStackEntryV1, index int, what string) ([32]byte, error) {
	var out [32]byte
	value, err := stackUint(stack, index, 256, what)
	if err != nil {
		return out, err
	}
	value.FillBytes(out[:])
	return out, nil
}

func stackCoins(stack []TVMStackEntryV1, index int, what string) (*big.Int, error) {
	return stackUint(stack, index, 120, what)
}

func stackAddress(stack []TVMStackEntryV1, index int, internal bool, what string) (MsgAddressV1, error) {
	entry := stack[index]
	if entry.Kind != "slice" && entry.Kind != "cell" {
		return MsgAddressV1{}, fmt.Errorf("getter %s is not a slice", what)
	}
	s, err := beginOrdinary(entry.Cell, "getter "+what)
	if err != nil {
		return MsgAddressV1{}, err
	}
	var value MsgAddressV1
	if internal {
		value, err = loadMsgAddressInt(s)
	} else {
		value, err = loadMsgAddress(s)
	}
	if err != nil {
		return value, fmt.Errorf("getter %s: %w", what, err)
	}
	return value, exhausted(s, "getter "+what)
}

func stackZero(stack []TVMStackEntryV1, nullIndex int) error {
	for index, entry := range stack {
		if index == nullIndex {
			if entry.Kind != "null" || entry.Cell != nil || entry.Number != nil {
				return errors.New("not-found getter result has a non-null caller")
			}
			continue
		}
		if entry.Kind != "num" || entry.Number == nil || entry.Number.Sign() != 0 {
			return errors.New("not-found getter result carries values")
		}
	}
	return nil
}

// ServiceActorServiceDataViewV1 is the get_service_data result.
type ServiceActorServiceDataViewV1 struct {
	Owner         MsgAddressV1
	Active        bool
	Policy        ServiceActorPolicyV1
	NextRequestID uint64
	PendingCount  uint32
	LiveCount     uint32
	Accounting    ServiceActorAccountingV1
}

// DecodeServiceActorServiceDataStack decodes the 25 get_service_data values.
// The attestor key is not part of the getter; Policy.AttestorKey stays nil.
func DecodeServiceActorServiceDataStack(stack []TVMStackEntryV1) (ServiceActorServiceDataViewV1, error) {
	var view ServiceActorServiceDataViewV1
	if len(stack) != 25 {
		return view, fmt.Errorf("get_service_data returned %d values, not 25", len(stack))
	}
	var err error
	if view.Owner, err = stackAddress(stack, 0, false, "owner"); err != nil {
		return view, err
	}
	if view.Active, err = stackFlag(stack, 1, "active"); err != nil {
		return view, err
	}
	p := &view.Policy
	version, err := stackUint64(stack, 2, 32, "policy_version")
	if err != nil {
		return view, err
	}
	p.PolicyVersion = uint32(version)
	if p.PricePerCall, err = stackCoins(stack, 3, "price_per_call"); err != nil {
		return view, err
	}
	if p.StorageFee, err = stackCoins(stack, 4, "storage_fee"); err != nil {
		return view, err
	}
	if p.CleanupBounty, err = stackCoins(stack, 5, "cleanup_bounty"); err != nil {
		return view, err
	}
	sla, err := stackUint64(stack, 6, 32, "response_sla")
	if err != nil {
		return view, err
	}
	window, err := stackUint64(stack, 7, 32, "refund_claim_window")
	if err != nil {
		return view, err
	}
	p.ResponseSLA, p.RefundClaimWindow = uint32(sla), uint32(window)
	if p.OpenAccess, err = stackFlag(stack, 8, "open_access"); err != nil {
		return view, err
	}
	if p.HasAuthorizedCaller, err = stackFlag(stack, 9, "has_authorized_caller"); err != nil {
		return view, err
	}
	if p.AuthorizedCaller, err = stackAddress(stack, 10, false, "authorized_caller"); err != nil {
		return view, err
	}
	rate, err := stackUint64(stack, 11, 32, "rate_limit_per_day")
	if err != nil {
		return view, err
	}
	p.RateLimitPerDay = uint32(rate)
	if p.MetadataHash, err = stackHash(stack, 12, "metadata_hash"); err != nil {
		return view, err
	}
	if p.ProofSchemeHash, err = stackHash(stack, 13, "proof_scheme_hash"); err != nil {
		return view, err
	}
	if p.HasAttestor, err = stackFlag(stack, 14, "has_attestor"); err != nil {
		return view, err
	}
	if p.AttestorKeyID, err = stackHash(stack, 15, "attestor_key_id"); err != nil {
		return view, err
	}
	if view.NextRequestID, err = stackUint64(stack, 16, 64, "next_request_id"); err != nil {
		return view, err
	}
	pending, err := stackUint64(stack, 17, 32, "pending_count")
	if err != nil {
		return view, err
	}
	live, err := stackUint64(stack, 18, 32, "live_count")
	if err != nil {
		return view, err
	}
	view.PendingCount, view.LiveCount = uint32(pending), uint32(live)
	a := &view.Accounting
	if a.WithdrawableRevenue, err = stackCoins(stack, 19, "withdrawable_revenue"); err != nil {
		return view, err
	}
	if a.LockedStorageFees, err = stackCoins(stack, 20, "locked_storage_fees"); err != nil {
		return view, err
	}
	if a.PendingLiability, err = stackCoins(stack, 21, "pending_liability"); err != nil {
		return view, err
	}
	if a.RefundableLiability, err = stackCoins(stack, 22, "refundable_liability"); err != nil {
		return view, err
	}
	day, err := stackUint64(stack, 23, 32, "call_day")
	if err != nil {
		return view, err
	}
	calls, err := stackUint64(stack, 24, 32, "calls_today")
	if err != nil {
		return view, err
	}
	a.CallDay, a.CallsToday = uint32(day), uint32(calls)
	return view, nil
}

// ServiceActorRequestViewV1 is a found get_request result; the getter does
// not return the stored key.
type ServiceActorRequestViewV1 struct {
	Caller              MsgAddressV1
	Price               *big.Int
	StorageFee          *big.Int
	CleanupBounty       *big.Int
	ResponseDeadline    uint64
	RefundClaimDeadline uint64
	PolicyVersion       uint32
	RequestHash         [32]byte
	TermsHash           [32]byte
	HasAttestor         bool
	AttestorKeyID       [32]byte
}

// DecodeServiceActorGetRequestStack decodes the 12 get_request values. A
// not-found result must be exactly (0, null, 0, ...).
func DecodeServiceActorGetRequestStack(stack []TVMStackEntryV1) (*ServiceActorRequestViewV1, error) {
	if len(stack) != 12 {
		return nil, fmt.Errorf("get_request returned %d values, not 12", len(stack))
	}
	found, err := stackFlag(stack, 0, "found")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, stackZero(stack, 1)
	}
	view := &ServiceActorRequestViewV1{}
	if view.Caller, err = stackAddress(stack, 1, true, "caller"); err != nil {
		return nil, err
	}
	if view.Price, err = stackCoins(stack, 2, "price"); err != nil {
		return nil, err
	}
	if view.StorageFee, err = stackCoins(stack, 3, "storage_fee"); err != nil {
		return nil, err
	}
	if view.CleanupBounty, err = stackCoins(stack, 4, "cleanup_bounty"); err != nil {
		return nil, err
	}
	if view.ResponseDeadline, err = stackUint64(stack, 5, 64, "response_deadline"); err != nil {
		return nil, err
	}
	if view.RefundClaimDeadline, err = stackUint64(stack, 6, 64, "refund_claim_deadline"); err != nil {
		return nil, err
	}
	version, err := stackUint64(stack, 7, 32, "policy_version")
	if err != nil {
		return nil, err
	}
	view.PolicyVersion = uint32(version)
	if view.RequestHash, err = stackHash(stack, 8, "request_hash"); err != nil {
		return nil, err
	}
	if view.TermsHash, err = stackHash(stack, 9, "terms_hash"); err != nil {
		return nil, err
	}
	if view.HasAttestor, err = stackFlag(stack, 10, "has_attestor"); err != nil {
		return nil, err
	}
	if view.AttestorKeyID, err = stackHash(stack, 11, "attestor_key_id"); err != nil {
		return nil, err
	}
	return view, nil
}

// DecodeServiceActorGetRefundStack decodes the 6 get_refund values.
func DecodeServiceActorGetRefundStack(stack []TVMStackEntryV1) (*ServiceActorRefundV1, error) {
	if len(stack) != 6 {
		return nil, fmt.Errorf("get_refund returned %d values, not 6", len(stack))
	}
	found, err := stackFlag(stack, 0, "found")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, stackZero(stack, 1)
	}
	view := &ServiceActorRefundV1{}
	if view.Caller, err = stackAddress(stack, 1, true, "caller"); err != nil {
		return nil, err
	}
	if view.Price, err = stackCoins(stack, 2, "price"); err != nil {
		return nil, err
	}
	if view.StorageFee, err = stackCoins(stack, 3, "storage_fee"); err != nil {
		return nil, err
	}
	if view.CleanupBounty, err = stackCoins(stack, 4, "cleanup_bounty"); err != nil {
		return nil, err
	}
	if view.RefundClaimDeadline, err = stackUint64(stack, 5, 64, "refund_claim_deadline"); err != nil {
		return nil, err
	}
	return view, nil
}

// DecodeServiceActorGetAttestorKeyStack decodes get_attestor_key: the
// policy's canonical stored key, or nil for null.
func DecodeServiceActorGetAttestorKeyStack(stack []TVMStackEntryV1) ([]byte, error) {
	if len(stack) != 1 {
		return nil, fmt.Errorf("get_attestor_key returned %d values, not 1", len(stack))
	}
	switch stack[0].Kind {
	case "null":
		if stack[0].Cell != nil || stack[0].Number != nil {
			return nil, errors.New("get_attestor_key null carries a value")
		}
		return nil, nil
	case "cell":
		return readStoredBytes(stack[0].Cell, mldsa44.PublicKeySize)
	default:
		return nil, errors.New("get_attestor_key is not a cell or null")
	}
}

// SameRequestView reports whether a pending entry decoded from data equals
// the get_request view of it.
func SameRequestView(entry ServiceActorPendingRequestV1, view *ServiceActorRequestViewV1) bool {
	return view != nil && entry.Caller.Equal(view.Caller) && entry.Price.Cmp(view.Price) == 0 &&
		entry.StorageFee.Cmp(view.StorageFee) == 0 && entry.CleanupBounty.Cmp(view.CleanupBounty) == 0 &&
		entry.ResponseDeadline == view.ResponseDeadline && entry.RefundClaimDeadline == view.RefundClaimDeadline &&
		entry.PolicyVersion == view.PolicyVersion && entry.RequestHash == view.RequestHash &&
		entry.TermsHash == view.TermsHash && entry.HasAttestor == view.HasAttestor && entry.AttestorKeyID == view.AttestorKeyID
}

// SameRefundView reports whether a refund decoded from data equals the
// get_refund view of it.
func SameRefundView(entry ServiceActorRefundV1, view *ServiceActorRefundV1) bool {
	return view != nil && entry.Caller.Equal(view.Caller) && entry.Price.Cmp(view.Price) == 0 &&
		entry.StorageFee.Cmp(view.StorageFee) == 0 && entry.CleanupBounty.Cmp(view.CleanupBounty) == 0 &&
		entry.RefundClaimDeadline == view.RefundClaimDeadline
}
