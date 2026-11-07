package nativecore

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// Service Actor inbound opcodes, the request snapshot tag and the protocol
// constants the contract enforces (SERVICE_ACTOR_TVM_V1 sections 2 and 7).
const (
	ServiceActorCallOpcode         = 0x53564301
	ServiceActorRespondOpcode      = 0x53564302
	ServiceActorExpireOpcode       = 0x53564303
	ServiceActorClaimRefundOpcode  = 0x53564304
	ServiceActorSweepOpcode        = 0x53564305
	ServiceActorUpdatePolicyOpcode = 0x53564306
	ServiceActorRotateKeyOpcode    = 0x53564307
	ServiceActorRevokeOpcode       = 0x53564308
	ServiceActorWithdrawOpcode     = 0x53564309

	ServiceActorRequestSnapshotTag = 0x53415231 // SAR1

	ServiceActorMinimumCleanupBounty    = 100_000_000
	ServiceActorMaximumCleanupBounty    = 1_000_000_000
	ServiceActorMinimumStorageFee       = 100_000_000
	ServiceActorMinimumOperatingReserve = 1_000_000_000
	ServiceActorAdmissionGasAllowance   = 200_000_000
	ServiceActorPayoutGasAllowance      = 200_000_000
	ServiceActorMinimumWindowSeconds    = 3_600
	ServiceActorMaximumWindowSeconds    = 2_592_000
	ServiceActorMaxLiveGlobal           = 100_000
	ServiceActorMaxLivePerCaller        = 1_000

	// ServiceActorRespondContext is the ML-DSA-44 context of an attestor
	// response signature.
	ServiceActorRespondContext = "TOS-SERVICE-ACTOR-RESPOND-V1"
	// ServiceActorRail names the settlement rail in manifest key 21.
	ServiceActorRail = "tos.service.service-actor.v1"

	serviceActorMetadataMagic = 0x4e534d31 // NSM1
	serviceRequestMagic       = 0x4e535231 // NSR1
)

// ServiceActorSoftwareWorkProofScheme is the proof_scheme_hash of the
// software-work profile: SHA-256 of its ASCII scheme name.
var ServiceActorSoftwareWorkProofScheme = sha256.Sum256([]byte("tos.service.service-actor.receipt.software-work-v1"))

// ServiceActorPolicyV1 is the policy cell and its commitments cell.
type ServiceActorPolicyV1 struct {
	PolicyVersion       uint32
	PricePerCall        *big.Int
	StorageFee          *big.Int
	CleanupBounty       *big.Int
	ResponseSLA         uint32
	RefundClaimWindow   uint32
	OpenAccess          bool
	HasAuthorizedCaller bool
	AuthorizedCaller    MsgAddressV1
	RateLimitPerDay     uint32
	MetadataHash        [32]byte
	ProofSchemeHash     [32]byte
	HasAttestor         bool
	AttestorKeyID       [32]byte
	// AttestorKey is the 1,312-byte stored key when HasAttestor.
	AttestorKey []byte
}

// ServiceActorAccountingV1 is the accounting cell.
type ServiceActorAccountingV1 struct {
	WithdrawableRevenue *big.Int
	LockedStorageFees   *big.Int
	PendingLiability    *big.Int
	RefundableLiability *big.Int
	CallDay             uint32
	CallsToday          uint32
}

// ServiceActorPendingRequestV1 is one pending_requests entry.
type ServiceActorPendingRequestV1 struct {
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
	AttestorKey         []byte
}

// ServiceActorRefundV1 is one refunds entry.
type ServiceActorRefundV1 struct {
	Caller              MsgAddressV1
	Price               *big.Int
	StorageFee          *big.Int
	CleanupBounty       *big.Int
	RefundClaimDeadline uint64
}

// ServiceActorDataV1 is the complete decoded persistent data of an actor.
type ServiceActorDataV1 struct {
	Owner            MsgAddressV1
	Active           bool
	NextRequestID    uint64
	PendingCount     uint32
	LiveCount        uint32
	Policy           ServiceActorPolicyV1
	Accounting       ServiceActorAccountingV1
	Pending          map[uint64]ServiceActorPendingRequestV1
	Refunds          map[uint64]ServiceActorRefundV1
	CallerLiveCounts map[[32]byte]uint32
}

// DecodeServiceActorData decodes the account data cell exactly as load_state
// reads it and refuses any trailing bit or reference in every cell, a
// non-minimal Coins value, and an attestor encoding that call would refuse.
func DecodeServiceActorData(data *cell.Cell) (*ServiceActorDataV1, error) {
	root, err := beginOrdinary(data, "Service Actor data")
	if err != nil {
		return nil, err
	}
	result := &ServiceActorDataV1{}
	if result.Owner, err = loadMsgAddress(root); err != nil {
		return nil, fmt.Errorf("Service Actor owner: %w", err)
	}
	if result.Active, err = root.LoadBoolBit(); err != nil {
		return nil, errors.New("Service Actor active flag is missing")
	}
	if result.NextRequestID, err = root.LoadUInt(64); err != nil {
		return nil, errors.New("Service Actor next_request_id is missing")
	}
	pendingCount, err := root.LoadUInt(32)
	if err != nil {
		return nil, errors.New("Service Actor pending_count is missing")
	}
	liveCount, err := root.LoadUInt(32)
	if err != nil {
		return nil, errors.New("Service Actor live_count is missing")
	}
	result.PendingCount, result.LiveCount = uint32(pendingCount), uint32(liveCount)
	policyCell, err := loadRefCell(root, "Service Actor policy")
	if err != nil {
		return nil, err
	}
	accountingCell, err := loadRefCell(root, "Service Actor accounting")
	if err != nil {
		return nil, err
	}
	dictsCell, err := loadRefCell(root, "Service Actor dictionaries")
	if err != nil {
		return nil, err
	}
	if err := exhausted(root, "Service Actor data"); err != nil {
		return nil, err
	}
	if result.Policy, err = decodeServiceActorPolicy(policyCell); err != nil {
		return nil, err
	}
	if result.Accounting, err = decodeServiceActorAccounting(accountingCell); err != nil {
		return nil, err
	}
	if err := decodeServiceActorDicts(dictsCell, result); err != nil {
		return nil, err
	}
	return result, nil
}

func decodeServiceActorPolicy(value *cell.Cell) (ServiceActorPolicyV1, error) {
	var policy ServiceActorPolicyV1
	s, err := beginOrdinary(value, "Service Actor policy")
	if err != nil {
		return policy, err
	}
	version, err := s.LoadUInt(32)
	if err != nil {
		return policy, errors.New("policy_version is missing")
	}
	policy.PolicyVersion = uint32(version)
	if policy.PricePerCall, err = loadServiceActorCoins(s); err != nil {
		return policy, fmt.Errorf("price_per_call: %w", err)
	}
	if policy.StorageFee, err = loadServiceActorCoins(s); err != nil {
		return policy, fmt.Errorf("storage_fee: %w", err)
	}
	if policy.CleanupBounty, err = loadServiceActorCoins(s); err != nil {
		return policy, fmt.Errorf("cleanup_bounty: %w", err)
	}
	sla, err := s.LoadUInt(32)
	if err != nil {
		return policy, errors.New("response_sla is missing")
	}
	window, err := s.LoadUInt(32)
	if err != nil {
		return policy, errors.New("refund_claim_window is missing")
	}
	policy.ResponseSLA, policy.RefundClaimWindow = uint32(sla), uint32(window)
	if policy.OpenAccess, err = s.LoadBoolBit(); err != nil {
		return policy, errors.New("open_access is missing")
	}
	if policy.HasAuthorizedCaller, err = s.LoadBoolBit(); err != nil {
		return policy, errors.New("has_authorized_caller is missing")
	}
	if policy.AuthorizedCaller, err = loadMsgAddress(s); err != nil {
		return policy, fmt.Errorf("authorized_caller: %w", err)
	}
	rate, err := s.LoadUInt(32)
	if err != nil {
		return policy, errors.New("rate_limit_per_day is missing")
	}
	policy.RateLimitPerDay = uint32(rate)
	commitmentsCell, err := loadRefCell(s, "policy commitments")
	if err != nil {
		return policy, err
	}
	if err := exhausted(s, "Service Actor policy"); err != nil {
		return policy, err
	}
	c, err := beginOrdinary(commitmentsCell, "policy commitments")
	if err != nil {
		return policy, err
	}
	if policy.MetadataHash, err = loadHash(c); err != nil {
		return policy, err
	}
	if policy.ProofSchemeHash, err = loadHash(c); err != nil {
		return policy, err
	}
	if policy.HasAttestor, err = c.LoadBoolBit(); err != nil {
		return policy, errors.New("has_attestor is missing")
	}
	if policy.AttestorKeyID, err = loadHash(c); err != nil {
		return policy, err
	}
	key, err := loadAttestorCommitment(c, policy.HasAttestor, policy.AttestorKeyID, "policy")
	if err != nil {
		return policy, err
	}
	policy.AttestorKey = key
	if err := exhausted(c, "policy commitments"); err != nil {
		return policy, err
	}
	return policy, nil
}

// loadAttestorCommitment reads attestor_key:(Maybe ^StoredKey) and enforces
// the one-encoding rule of SERVICE_ACTOR_TVM_V1 section 4.1: an attestor
// carries its canonical stored key whose derived id equals the stored id;
// no attestor carries a zero id and no key.
func loadAttestorCommitment(s *cell.Slice, hasAttestor bool, keyID [32]byte, what string) ([]byte, error) {
	present, err := s.LoadBoolBit()
	if err != nil {
		return nil, fmt.Errorf("%s attestor key flag is missing", what)
	}
	if !hasAttestor {
		if present || keyID != ([32]byte{}) {
			return nil, fmt.Errorf("%s names no attestor but carries a key or key id", what)
		}
		return nil, nil
	}
	if !present {
		return nil, fmt.Errorf("%s names an attestor without its stored key", what)
	}
	stored, err := loadRefCell(s, what+" attestor key")
	if err != nil {
		return nil, err
	}
	key, err := readStoredBytes(stored, mldsa44.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("%s attestor key: %w", what, err)
	}
	derived, err := mldsa44.KeyID(key)
	if err != nil || derived != keyID {
		return nil, fmt.Errorf("%s attestor key does not derive its key id", what)
	}
	return key, nil
}

func decodeServiceActorAccounting(value *cell.Cell) (ServiceActorAccountingV1, error) {
	var accounting ServiceActorAccountingV1
	s, err := beginOrdinary(value, "Service Actor accounting")
	if err != nil {
		return accounting, err
	}
	for _, field := range []struct {
		target **big.Int
		name   string
	}{{&accounting.WithdrawableRevenue, "withdrawable_revenue"}, {&accounting.LockedStorageFees, "locked_storage_fees"},
		{&accounting.PendingLiability, "pending_liability"}, {&accounting.RefundableLiability, "refundable_liability"}} {
		if *field.target, err = loadServiceActorCoins(s); err != nil {
			return accounting, fmt.Errorf("%s: %w", field.name, err)
		}
	}
	day, err := s.LoadUInt(32)
	if err != nil {
		return accounting, errors.New("call_day is missing")
	}
	calls, err := s.LoadUInt(32)
	if err != nil {
		return accounting, errors.New("calls_today is missing")
	}
	accounting.CallDay, accounting.CallsToday = uint32(day), uint32(calls)
	return accounting, exhausted(s, "Service Actor accounting")
}

func decodeServiceActorDicts(value *cell.Cell, result *ServiceActorDataV1) error {
	s, err := beginOrdinary(value, "Service Actor dictionaries")
	if err != nil {
		return err
	}
	pending, err := walkHashmapE(s, 64, ServiceActorMaxLiveGlobal, "pending_requests")
	if err != nil {
		return err
	}
	refunds, err := walkHashmapE(s, 64, ServiceActorMaxLiveGlobal, "refunds")
	if err != nil {
		return err
	}
	counts, err := walkHashmapE(s, 256, ServiceActorMaxLiveGlobal, "caller_live_counts")
	if err != nil {
		return err
	}
	if err := exhausted(s, "Service Actor dictionaries"); err != nil {
		return err
	}
	result.Pending = make(map[uint64]ServiceActorPendingRequestV1, len(pending))
	for _, leaf := range pending {
		entry, err := loadDictRefValue(leaf.value, "pending request")
		if err != nil {
			return err
		}
		decoded, err := decodeServiceActorPendingRequest(entry)
		if err != nil {
			return err
		}
		result.Pending[new(big.Int).SetBytes(leaf.key).Uint64()] = decoded
	}
	result.Refunds = make(map[uint64]ServiceActorRefundV1, len(refunds))
	for _, leaf := range refunds {
		entry, err := loadDictRefValue(leaf.value, "refund")
		if err != nil {
			return err
		}
		decoded, err := decodeServiceActorRefund(entry)
		if err != nil {
			return err
		}
		id := new(big.Int).SetBytes(leaf.key).Uint64()
		if _, overlap := result.Pending[id]; overlap {
			return fmt.Errorf("request %d is both pending and refundable", id)
		}
		result.Refunds[id] = decoded
	}
	result.CallerLiveCounts = make(map[[32]byte]uint32, len(counts))
	for _, leaf := range counts {
		count, err := leaf.value.LoadUInt(32)
		if err != nil {
			return errors.New("caller live count is truncated")
		}
		if err := exhausted(leaf.value, "caller live count"); err != nil {
			return err
		}
		if count == 0 {
			return errors.New("caller live count is zero")
		}
		var key [32]byte
		copy(key[:], leaf.key)
		result.CallerLiveCounts[key] = uint32(count)
	}
	return nil
}

func loadDictRefValue(s *cell.Slice, what string) (*cell.Cell, error) {
	if s.BitsLeft() != 0 || s.RefsNum() != 1 {
		return nil, fmt.Errorf("%s value is not exactly one reference", what)
	}
	return loadRefCell(s, what)
}

func decodeServiceActorPendingRequest(value *cell.Cell) (ServiceActorPendingRequestV1, error) {
	var entry ServiceActorPendingRequestV1
	s, err := beginOrdinary(value, "pending request")
	if err != nil {
		return entry, err
	}
	if entry.Caller, err = loadMsgAddressInt(s); err != nil {
		return entry, fmt.Errorf("pending request caller: %w", err)
	}
	if entry.Price, err = loadServiceActorCoins(s); err != nil {
		return entry, fmt.Errorf("pending request price: %w", err)
	}
	if entry.StorageFee, err = loadServiceActorCoins(s); err != nil {
		return entry, fmt.Errorf("pending request storage fee: %w", err)
	}
	if entry.CleanupBounty, err = loadServiceActorCoins(s); err != nil {
		return entry, fmt.Errorf("pending request cleanup bounty: %w", err)
	}
	if entry.ResponseDeadline, err = s.LoadUInt(64); err != nil {
		return entry, errors.New("pending request response deadline is missing")
	}
	if entry.RefundClaimDeadline, err = s.LoadUInt(64); err != nil {
		return entry, errors.New("pending request refund deadline is missing")
	}
	version, err := s.LoadUInt(32)
	if err != nil {
		return entry, errors.New("pending request policy version is missing")
	}
	entry.PolicyVersion = uint32(version)
	commitments, err := loadRefCell(s, "pending request commitments")
	if err != nil {
		return entry, err
	}
	if err := exhausted(s, "pending request"); err != nil {
		return entry, err
	}
	c, err := beginOrdinary(commitments, "pending request commitments")
	if err != nil {
		return entry, err
	}
	if entry.RequestHash, err = loadHash(c); err != nil {
		return entry, err
	}
	if entry.TermsHash, err = loadHash(c); err != nil {
		return entry, err
	}
	if entry.HasAttestor, err = c.LoadBoolBit(); err != nil {
		return entry, errors.New("pending request has_attestor is missing")
	}
	if entry.AttestorKeyID, err = loadHash(c); err != nil {
		return entry, err
	}
	if entry.AttestorKey, err = loadAttestorCommitment(c, entry.HasAttestor, entry.AttestorKeyID, "pending request"); err != nil {
		return entry, err
	}
	return entry, exhausted(c, "pending request commitments")
}

func decodeServiceActorRefund(value *cell.Cell) (ServiceActorRefundV1, error) {
	var entry ServiceActorRefundV1
	s, err := beginOrdinary(value, "refund")
	if err != nil {
		return entry, err
	}
	if entry.Caller, err = loadMsgAddressInt(s); err != nil {
		return entry, fmt.Errorf("refund caller: %w", err)
	}
	if entry.Price, err = loadServiceActorCoins(s); err != nil {
		return entry, fmt.Errorf("refund price: %w", err)
	}
	if entry.StorageFee, err = loadServiceActorCoins(s); err != nil {
		return entry, fmt.Errorf("refund storage fee: %w", err)
	}
	if entry.CleanupBounty, err = loadServiceActorCoins(s); err != nil {
		return entry, fmt.Errorf("refund cleanup bounty: %w", err)
	}
	if entry.RefundClaimDeadline, err = s.LoadUInt(64); err != nil {
		return entry, errors.New("refund deadline is missing")
	}
	return entry, exhausted(s, "refund")
}

// ValidateServiceActorLiveState checks the invariants that hold after every
// contract transition: counts, per-caller live counts, liabilities and the
// storage lock all equal what the live entries imply.
func ValidateServiceActorLiveState(data *ServiceActorDataV1) error {
	if data == nil {
		return errors.New("Service Actor data is missing")
	}
	if uint64(len(data.Pending)) != uint64(data.PendingCount) {
		return fmt.Errorf("pending_count %d differs from %d pending entries", data.PendingCount, len(data.Pending))
	}
	if uint64(len(data.Pending))+uint64(len(data.Refunds)) != uint64(data.LiveCount) {
		return fmt.Errorf("live_count %d differs from %d live entries", data.LiveCount, len(data.Pending)+len(data.Refunds))
	}
	pendingSum, refundSum, lockedSum := new(big.Int), new(big.Int), new(big.Int)
	callers := map[[32]byte]uint32{}
	countCaller := func(caller MsgAddressV1) error {
		key, err := caller.SliceHash()
		if err != nil {
			return err
		}
		callers[key]++
		return nil
	}
	for id, entry := range data.Pending {
		if id >= data.NextRequestID {
			return fmt.Errorf("pending request %d is at or above next_request_id", id)
		}
		pendingSum.Add(pendingSum, entry.Price)
		lockedSum.Add(lockedSum, entry.StorageFee)
		if err := countCaller(entry.Caller); err != nil {
			return err
		}
	}
	for id, entry := range data.Refunds {
		if id >= data.NextRequestID {
			return fmt.Errorf("refund %d is at or above next_request_id", id)
		}
		refundSum.Add(refundSum, entry.Price)
		lockedSum.Add(lockedSum, entry.StorageFee)
		if err := countCaller(entry.Caller); err != nil {
			return err
		}
	}
	if pendingSum.Cmp(data.Accounting.PendingLiability) != 0 || refundSum.Cmp(data.Accounting.RefundableLiability) != 0 ||
		lockedSum.Cmp(data.Accounting.LockedStorageFees) != 0 {
		return errors.New("Service Actor liabilities differ from the live entries")
	}
	if len(callers) != len(data.CallerLiveCounts) {
		return errors.New("caller live counts differ from the live entries")
	}
	for key, count := range callers {
		if data.CallerLiveCounts[key] != count {
			return errors.New("caller live counts differ from the live entries")
		}
	}
	return nil
}

// ServiceActorTermsV1 is the terms_hash preimage of SERVICE_ACTOR_TVM_V1
// section 5.
type ServiceActorTermsV1 struct {
	PolicyVersion     uint32
	PricePerCall      *big.Int
	StorageFee        *big.Int
	CleanupBounty     *big.Int
	ResponseSLA       uint32
	RefundClaimWindow uint32
	MetadataHash      [32]byte
	ProofSchemeHash   [32]byte
	HasAttestor       bool
	AttestorKeyID     [32]byte
}

// TermsOfPolicy returns the terms a call admitted under policy commits to.
func TermsOfPolicy(policy ServiceActorPolicyV1) ServiceActorTermsV1 {
	return ServiceActorTermsV1{PolicyVersion: policy.PolicyVersion, PricePerCall: policy.PricePerCall,
		StorageFee: policy.StorageFee, CleanupBounty: policy.CleanupBounty, ResponseSLA: policy.ResponseSLA,
		RefundClaimWindow: policy.RefundClaimWindow, MetadataHash: policy.MetadataHash,
		ProofSchemeHash: policy.ProofSchemeHash, HasAttestor: policy.HasAttestor, AttestorKeyID: policy.AttestorKeyID}
}

// BuildServiceActorTermsCell builds terms_cell: the key id is written as zero
// when there is no attestor.
func BuildServiceActorTermsCell(terms ServiceActorTermsV1) (*cell.Cell, error) {
	keyID := terms.AttestorKeyID
	if !terms.HasAttestor {
		keyID = [32]byte{}
	}
	tail := cell.BeginCell().MustStoreSlice(terms.MetadataHash[:], 256).MustStoreSlice(terms.ProofSchemeHash[:], 256).
		MustStoreBoolBit(terms.HasAttestor).MustStoreSlice(keyID[:], 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(uint64(terms.PolicyVersion), 32)
	for _, value := range []*big.Int{terms.PricePerCall, terms.StorageFee, terms.CleanupBounty} {
		if err := storeServiceActorCoins(root, value); err != nil {
			return nil, err
		}
	}
	return root.MustStoreUInt(uint64(terms.ResponseSLA), 32).MustStoreUInt(uint64(terms.RefundClaimWindow), 32).
		MustStoreRef(tail).EndCell(), nil
}

// ServiceActorTermsHash is cell_hash(terms_cell).
func ServiceActorTermsHash(terms ServiceActorTermsV1) ([32]byte, error) {
	var out [32]byte
	root, err := BuildServiceActorTermsCell(terms)
	if err != nil {
		return out, err
	}
	copy(out[:], root.Hash())
	return out, nil
}

// DecodeServiceActorTermsCell decodes a terms cell exactly, refusing the
// attestor encodings decode_request_snapshot refuses.
func DecodeServiceActorTermsCell(value *cell.Cell) (ServiceActorTermsV1, error) {
	var terms ServiceActorTermsV1
	s, err := beginOrdinary(value, "terms")
	if err != nil {
		return terms, err
	}
	version, err := s.LoadUInt(32)
	if err != nil {
		return terms, errors.New("terms policy_version is missing")
	}
	terms.PolicyVersion = uint32(version)
	if terms.PricePerCall, err = loadServiceActorCoins(s); err != nil {
		return terms, fmt.Errorf("terms price: %w", err)
	}
	if terms.StorageFee, err = loadServiceActorCoins(s); err != nil {
		return terms, fmt.Errorf("terms storage fee: %w", err)
	}
	if terms.CleanupBounty, err = loadServiceActorCoins(s); err != nil {
		return terms, fmt.Errorf("terms cleanup bounty: %w", err)
	}
	sla, err := s.LoadUInt(32)
	if err != nil {
		return terms, errors.New("terms response_sla is missing")
	}
	window, err := s.LoadUInt(32)
	if err != nil {
		return terms, errors.New("terms refund_claim_window is missing")
	}
	terms.ResponseSLA, terms.RefundClaimWindow = uint32(sla), uint32(window)
	tailCell, err := loadRefCell(s, "terms tail")
	if err != nil {
		return terms, err
	}
	if err := exhausted(s, "terms"); err != nil {
		return terms, err
	}
	t, err := beginOrdinary(tailCell, "terms tail")
	if err != nil {
		return terms, err
	}
	if terms.MetadataHash, err = loadHash(t); err != nil {
		return terms, err
	}
	if terms.ProofSchemeHash, err = loadHash(t); err != nil {
		return terms, err
	}
	if terms.HasAttestor, err = t.LoadBoolBit(); err != nil {
		return terms, errors.New("terms has_attestor is missing")
	}
	if terms.AttestorKeyID, err = loadHash(t); err != nil {
		return terms, err
	}
	if err := exhausted(t, "terms tail"); err != nil {
		return terms, err
	}
	zero := terms.AttestorKeyID == [32]byte{}
	if terms.HasAttestor && zero {
		return terms, errors.New("terms name an attestor with a zero key id")
	}
	if !terms.HasAttestor && !zero {
		return terms, errors.New("terms carry a key id without an attestor")
	}
	return terms, nil
}

// ServiceActorRequestSnapshotV1 is the decoded request_snapshot#53415231
// external out-message body of a successful call.
type ServiceActorRequestSnapshotV1 struct {
	RequestID           uint64
	Caller              MsgAddressV1
	RequestHash         [32]byte
	ResponseDeadline    uint64
	RefundClaimDeadline uint64
	// TermsHash is the cell hash of the terms preimage.
	TermsHash [32]byte
	Terms     ServiceActorTermsV1
}

// DecodeServiceActorRequestSnapshot mirrors decode_request_snapshot: tag,
// fields, exhaustion of all three cells, terms_hash as the terms cell hash,
// the attestor encoding, and response_deadline + window ==
// refund_claim_deadline with checked addition.
func DecodeServiceActorRequestSnapshot(body *cell.Cell) (ServiceActorRequestSnapshotV1, error) {
	var snapshot ServiceActorRequestSnapshotV1
	s, err := beginOrdinary(body, "request snapshot")
	if err != nil {
		return snapshot, err
	}
	tag, err := s.LoadUInt(32)
	if err != nil || tag != ServiceActorRequestSnapshotTag {
		return snapshot, errors.New("not a Service Actor request snapshot")
	}
	if snapshot.RequestID, err = s.LoadUInt(64); err != nil {
		return snapshot, errors.New("request snapshot request_id is missing")
	}
	if snapshot.Caller, err = loadMsgAddressInt(s); err != nil {
		return snapshot, fmt.Errorf("request snapshot caller: %w", err)
	}
	if snapshot.RequestHash, err = loadHash(s); err != nil {
		return snapshot, err
	}
	if snapshot.ResponseDeadline, err = s.LoadUInt(64); err != nil {
		return snapshot, errors.New("request snapshot response deadline is missing")
	}
	if snapshot.RefundClaimDeadline, err = s.LoadUInt(64); err != nil {
		return snapshot, errors.New("request snapshot refund deadline is missing")
	}
	termsCell, err := loadRefCell(s, "request snapshot terms")
	if err != nil {
		return snapshot, err
	}
	if err := exhausted(s, "request snapshot"); err != nil {
		return snapshot, err
	}
	if snapshot.Terms, err = DecodeServiceActorTermsCell(termsCell); err != nil {
		return snapshot, err
	}
	copy(snapshot.TermsHash[:], termsCell.Hash())
	sum := snapshot.ResponseDeadline + uint64(snapshot.Terms.RefundClaimWindow)
	if sum < snapshot.ResponseDeadline || sum != snapshot.RefundClaimDeadline {
		return snapshot, errors.New("request snapshot deadlines disagree with its refund claim window")
	}
	return snapshot, nil
}

// ServiceActorInboundV1 is a decoded inbound body.
type ServiceActorInboundV1 struct {
	Opcode            uint32
	QueryID           uint64
	RequestHash       [32]byte // call
	ExpectedTermsHash [32]byte // call
	RequestID         uint64   // respond, expire, claim_refund, sweep
	ResponseHash      [32]byte // respond
	Signed            bool     // respond: a signature reference is present
	Destination       MsgAddressV1
}

// DecodeServiceActorInbound decodes a lifecycle body strictly. Owner-only
// configuration operations are recognised by opcode and query id only.
func DecodeServiceActorInbound(body *cell.Cell) (ServiceActorInboundV1, error) {
	var result ServiceActorInboundV1
	s, err := beginOrdinary(body, "Service Actor message body")
	if err != nil {
		return result, err
	}
	opcode, err := s.LoadUInt(32)
	if err != nil {
		return result, errors.New("Service Actor opcode is missing")
	}
	query, err := s.LoadUInt(64)
	if err != nil {
		return result, errors.New("Service Actor query_id is missing")
	}
	result.Opcode, result.QueryID = uint32(opcode), query
	switch result.Opcode {
	case ServiceActorCallOpcode:
		if result.RequestHash, err = loadHash(s); err != nil {
			return result, err
		}
		if result.ExpectedTermsHash, err = loadHash(s); err != nil {
			return result, err
		}
		return result, exhausted(s, "call body")
	case ServiceActorRespondOpcode:
		if result.RequestID, err = s.LoadUInt(64); err != nil {
			return result, errors.New("respond request_id is missing")
		}
		if result.ResponseHash, err = loadHash(s); err != nil {
			return result, err
		}
		switch {
		case s.BitsLeft() == 0 && s.RefsNum() == 0:
		case s.BitsLeft() == 0 && s.RefsNum() == 1:
			result.Signed = true
		default:
			return result, errors.New("respond body has trailing data")
		}
		return result, nil
	case ServiceActorExpireOpcode, ServiceActorSweepOpcode:
		if result.RequestID, err = s.LoadUInt(64); err != nil {
			return result, errors.New("request_id is missing")
		}
		return result, exhausted(s, "expire or sweep body")
	case ServiceActorClaimRefundOpcode:
		if result.RequestID, err = s.LoadUInt(64); err != nil {
			return result, errors.New("claim_refund request_id is missing")
		}
		if result.Destination, err = loadMsgAddressInt(s); err != nil {
			return result, fmt.Errorf("claim_refund destination: %w", err)
		}
		return result, exhausted(s, "claim_refund body")
	case ServiceActorUpdatePolicyOpcode, ServiceActorRotateKeyOpcode, ServiceActorRevokeOpcode, ServiceActorWithdrawOpcode:
		return result, nil
	default:
		return result, fmt.Errorf("unknown Service Actor opcode %#x", result.Opcode)
	}
}

// BuildServiceActorCallBody builds call#53564301 query_id request_hash
// expected_terms_hash.
func BuildServiceActorCallBody(queryID uint64, requestHash, expectedTermsHash [32]byte) *cell.Cell {
	return cell.BeginCell().MustStoreUInt(ServiceActorCallOpcode, 32).MustStoreUInt(queryID, 64).
		MustStoreSlice(requestHash[:], 256).MustStoreSlice(expectedTermsHash[:], 256).EndCell()
}

// ServiceActorMetadataInputV1 names what the NSM1 metadata_hash binds.
type ServiceActorMetadataInputV1 struct {
	Network           *nativev1.NetworkDomain
	CapabilityID      string
	ProviderAgentID   string
	CapabilityVersion string
	ManifestDigest    string
}

// BuildServiceActorMetadataCell builds the NSM1 cell of the settlement design
// section 2.3; metadata_hash is its cell hash.
func BuildServiceActorMetadataCell(input ServiceActorMetadataInputV1) (*cell.Cell, error) {
	domain, err := domainCell(input.Network)
	if err != nil {
		return nil, err
	}
	capability, kind, err := objectID(input.CapabilityID)
	if err != nil || kind != 2 {
		return nil, errors.New("invalid Service Actor metadata Capability")
	}
	provider, kind, err := objectID(input.ProviderAgentID)
	if err != nil || kind != 1 {
		return nil, errors.New("invalid Service Actor metadata provider")
	}
	if !validProtocolText(input.CapabilityVersion, 128) {
		return nil, errors.New("invalid Service Actor metadata version")
	}
	manifest, err := digestBytes(input.ManifestDigest, "sha256:", false)
	if err != nil {
		return nil, errors.New("invalid Service Actor metadata manifest digest")
	}
	versionHash := sha256.Sum256([]byte(input.CapabilityVersion))
	version := cell.BeginCell().MustStoreSlice(versionHash[:], 256).MustStoreSlice(manifest, 256).EndCell()
	return cell.BeginCell().MustStoreUInt(serviceActorMetadataMagic, 32).MustStoreUInt(1, 16).
		MustStoreSlice(capability, 256).MustStoreSlice(provider, 256).MustStoreRef(domain).MustStoreRef(version).EndCell(), nil
}

// ServiceActorMetadataHash is cell_hash(NSM1).
func ServiceActorMetadataHash(input ServiceActorMetadataInputV1) ([32]byte, error) {
	var out [32]byte
	root, err := BuildServiceActorMetadataCell(input)
	if err != nil {
		return out, err
	}
	copy(out[:], root.Hash())
	return out, nil
}

// MinimumServiceActorCallPayment is price + storage_fee + the admission
// allowance, the least value a call must attach.
func MinimumServiceActorCallPayment(price, storageFee *big.Int) (*big.Int, error) {
	if price == nil || storageFee == nil || price.Sign() < 0 || storageFee.Sign() < 0 {
		return nil, errors.New("invalid Service Actor call terms")
	}
	return new(big.Int).Add(new(big.Int).Add(price, storageFee), big.NewInt(ServiceActorAdmissionGasAllowance)), nil
}

// ServiceActorRespondDomainTag is the SRP2 statement tag.
const ServiceActorRespondDomainTag = 0x53525032

// ServiceActorResponseDomainHash is cell_hash(SRP2) of SERVICE_ACTOR_TVM_V1
// section 6: the signing domain (tag, global_id, actor workchain and
// address) with request_id, request_hash and response_hash, and a tail of
// the snapshot caller, terms_hash, price and both deadlines. Every input but
// response_hash comes from the request snapshot.
func ServiceActorResponseDomainHash(globalID int32, actor string, snapshot ServiceActorRequestSnapshotV1, responseHash [32]byte) ([32]byte, error) {
	var out [32]byte
	parsed, err := parseServiceActorRawAddress(actor, false)
	if err != nil {
		return out, errors.New("the actor is not a raw standard address")
	}
	tail := cell.BeginCell()
	if err := tail.StoreSlice(snapshot.Caller.Bits, snapshot.Caller.BitLen); err != nil {
		return out, err
	}
	tail.MustStoreSlice(snapshot.TermsHash[:], 256)
	if err := storeServiceActorCoins(tail, snapshot.Terms.PricePerCall); err != nil {
		return out, err
	}
	tail.MustStoreUInt(snapshot.ResponseDeadline, 64).MustStoreUInt(snapshot.RefundClaimDeadline, 64)
	root := cell.BeginCell().MustStoreUInt(ServiceActorRespondDomainTag, 32).MustStoreInt(int64(globalID), 32).
		MustStoreInt(int64(parsed.workchain), 8).MustStoreSlice(parsed.account, 256).MustStoreUInt(snapshot.RequestID, 64).
		MustStoreSlice(snapshot.RequestHash[:], 256).MustStoreSlice(responseHash[:], 256).MustStoreRef(tail.EndCell()).EndCell()
	copy(out[:], root.Hash())
	return out, nil
}
