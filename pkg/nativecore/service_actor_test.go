package nativecore

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func testNetworkDomain() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
}

func hash32(b byte) [32]byte {
	var out [32]byte
	copy(out[:], fill(b))
	return out
}

func coins(t *testing.T, builder *cell.Builder, value uint64) *cell.Builder {
	t.Helper()
	if err := storeServiceActorCoins(builder, new(big.Int).SetUint64(value)); err != nil {
		t.Fatal(err)
	}
	return builder
}

func stdAddress(builder *cell.Builder, workchain int64, fillByte byte) *cell.Builder {
	return builder.MustStoreUInt(2, 2).MustStoreBoolBit(false).MustStoreInt(workchain, 8).MustStoreSlice(fill(fillByte), 256)
}

// snapshotCase reproduces the Rust SnapshotCase of service_actor.rs
// (request_snapshots_decode_exactly_and_refuse_every_inconsistency): the same
// field values, written in the FunC emit_request_snapshot / terms_cell layout.
type snapshotCase struct {
	tag           uint64
	hasAttestor   bool
	keyID         []byte
	deadlines     [2]uint64
	window        uint64
	trailing      bool
	trailingRoot  bool
	trailingTail  bool
	extraRootRef  bool
	nonMinimalFee bool
}

func defaultSnapshotCase() snapshotCase {
	return snapshotCase{tag: ServiceActorRequestSnapshotTag, hasAttestor: true, keyID: fill(9), deadlines: [2]uint64{10, 20}, window: 10}
}

func snapshotBody(t *testing.T, c snapshotCase) (*cell.Cell, []byte) {
	t.Helper()
	tail := cell.BeginCell().MustStoreSlice(fill(0x66), 256).MustStoreSlice(fill(0x77), 256).
		MustStoreBoolBit(c.hasAttestor).MustStoreSlice(c.keyID, 256)
	if c.trailingTail {
		tail.MustStoreBoolBit(true)
	}
	terms := cell.BeginCell().MustStoreUInt(3, 32)
	coins(t, terms, 7)
	if c.nonMinimalFee {
		terms.MustStoreUInt(2, 4).MustStoreUInt(8, 16)
	} else {
		coins(t, terms, 8)
	}
	coins(t, terms, 2)
	terms.MustStoreUInt(3600, 32).MustStoreUInt(c.window, 32)
	if c.trailing {
		terms.MustStoreBoolBit(true)
	}
	termsCell := terms.MustStoreRef(tail.EndCell()).EndCell()
	body := cell.BeginCell().MustStoreUInt(c.tag, 32).MustStoreUInt(5, 64)
	stdAddress(body, 0, 0x33).MustStoreSlice(fill(0x44), 256).MustStoreUInt(c.deadlines[0], 64).
		MustStoreUInt(c.deadlines[1], 64).MustStoreRef(termsCell)
	if c.trailingRoot {
		body.MustStoreBoolBit(false)
	}
	if c.extraRootRef {
		body.MustStoreRef(cell.BeginCell().EndCell())
	}
	return body.EndCell(), termsCell.Hash()
}

func TestRequestSnapshotMatchesTheRustDecoder(t *testing.T) {
	body, termsHash := snapshotBody(t, defaultSnapshotCase())
	got, err := DecodeServiceActorRequestSnapshot(body)
	if err != nil {
		t.Fatal(err)
	}
	caller, ok := got.Caller.RawStandard()
	if got.RequestID != 5 || !ok || caller != "0:"+strings.Repeat("33", 32) || got.RequestHash != hash32(0x44) ||
		!bytes.Equal(got.TermsHash[:], termsHash) {
		t.Fatalf("identity fields differ: %+v", got)
	}
	terms := got.Terms
	if terms.PolicyVersion != 3 || terms.PricePerCall.Int64() != 7 || terms.StorageFee.Int64() != 8 || terms.CleanupBounty.Int64() != 2 ||
		terms.ResponseSLA != 3600 || terms.RefundClaimWindow != 10 || terms.MetadataHash != hash32(0x66) ||
		terms.ProofSchemeHash != hash32(0x77) || !terms.HasAttestor || terms.AttestorKeyID != hash32(9) ||
		got.ResponseDeadline != 10 || got.RefundClaimDeadline != 20 {
		t.Fatalf("terms differ: %+v", got)
	}
	open := defaultSnapshotCase()
	open.hasAttestor, open.keyID = false, make([]byte, 32)
	openBody, _ := snapshotBody(t, open)
	if decoded, err := DecodeServiceActorRequestSnapshot(openBody); err != nil || decoded.Terms.HasAttestor {
		t.Fatalf("open snapshot: %+v %v", decoded, err)
	}
	// The terms hash a decoder reports equals the terms cell the builder
	// writes for the same values.
	rebuilt, err := ServiceActorTermsHash(got.Terms)
	if err != nil || rebuilt != got.TermsHash {
		t.Fatalf("terms builder disagrees with the snapshot terms cell: %v", err)
	}

	mutate := func(edit func(*snapshotCase)) snapshotCase {
		c := defaultSnapshotCase()
		edit(&c)
		return c
	}
	for name, c := range map[string]snapshotCase{
		"tag":               mutate(func(c *snapshotCase) { c.tag ^= 1 }),
		"trailing":          mutate(func(c *snapshotCase) { c.trailing = true }),
		"zero key":          mutate(func(c *snapshotCase) { c.keyID = make([]byte, 32) }),
		"orphan key":        mutate(func(c *snapshotCase) { c.hasAttestor = false }),
		"deadlines":         mutate(func(c *snapshotCase) { c.deadlines = [2]uint64{10, 21} }),
		"window":            mutate(func(c *snapshotCase) { c.window = 11 }),
		"trailing root bit": mutate(func(c *snapshotCase) { c.trailingRoot = true }),
		"trailing root ref": mutate(func(c *snapshotCase) { c.extraRootRef = true }),
		"trailing tail bit": mutate(func(c *snapshotCase) { c.trailingTail = true }),
		"non-minimal coins": mutate(func(c *snapshotCase) { c.nonMinimalFee = true }),
		"deadline overflow": mutate(func(c *snapshotCase) { c.deadlines = [2]uint64{^uint64(0) - 5, 4}; c.window = 10 }),
	} {
		body, _ := snapshotBody(t, c)
		if _, err := DecodeServiceActorRequestSnapshot(body); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// Truncation at every field boundary is refused.
	full, _ := snapshotBody(t, defaultSnapshotCase())
	s := full.MustBeginParse()
	for _, size := range []uint{0, 31, 32 + 63, 32 + 64 + 266, 32 + 64 + 267 + 255, 32 + 64 + 267 + 256 + 127} {
		raw := s.Copy().MustLoadSlice(size)
		truncated := cell.BeginCell().MustStoreSlice(raw, size).MustStoreRef(full.MustPeekRef(0)).EndCell()
		if _, err := DecodeServiceActorRequestSnapshot(truncated); err == nil {
			t.Errorf("snapshot truncated to %d bits was accepted", size)
		}
	}
}

func TestCallBodyMatchesTheRustLayout(t *testing.T) {
	body := BuildServiceActorCallBody(1, hash32(0xAA), hash32(0xBB))
	s := body.MustBeginParse()
	if s.MustLoadUInt(32) != ServiceActorCallOpcode || s.MustLoadUInt(64) != 1 ||
		!bytes.Equal(s.MustLoadSlice(256), fill(0xAA)) || !bytes.Equal(s.MustLoadSlice(256), fill(0xBB)) ||
		s.BitsLeft() != 0 || s.RefsNum() != 0 {
		t.Fatal("call body does not match call#53564301 query_id request_hash expected_terms_hash")
	}
	decoded, err := DecodeServiceActorInbound(body)
	if err != nil || decoded.Opcode != ServiceActorCallOpcode || decoded.QueryID != 1 ||
		decoded.RequestHash != hash32(0xAA) || decoded.ExpectedTermsHash != hash32(0xBB) {
		t.Fatalf("call decode: %+v %v", decoded, err)
	}
	trailing := cell.BeginCell().MustStoreBuilder(body.ToBuilder()).MustStoreBoolBit(false).EndCell()
	if _, err := DecodeServiceActorInbound(trailing); err == nil {
		t.Fatal("call body with trailing data was accepted")
	}
}

func TestInboundBodiesDecodeExactly(t *testing.T) {
	head := func(op uint64) *cell.Builder { return cell.BeginCell().MustStoreUInt(op, 32).MustStoreUInt(7, 64) }
	respond := head(ServiceActorRespondOpcode).MustStoreUInt(9, 64).MustStoreSlice(fill(0xCC), 256)
	unsigned := respond.Copy().EndCell()
	signed := respond.Copy().MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	if got, err := DecodeServiceActorInbound(unsigned); err != nil || got.Signed || got.RequestID != 9 || got.ResponseHash != hash32(0xCC) {
		t.Fatalf("unsigned respond: %+v %v", got, err)
	}
	if got, err := DecodeServiceActorInbound(signed); err != nil || !got.Signed {
		t.Fatalf("signed respond: %+v %v", got, err)
	}
	claim := head(ServiceActorClaimRefundOpcode).MustStoreUInt(9, 64)
	stdAddress(claim, 0, 0x55)
	if got, err := DecodeServiceActorInbound(claim.EndCell()); err != nil || got.RequestID != 9 {
		t.Fatalf("claim: %+v %v", got, err)
	}
	for name, body := range map[string]*cell.Cell{
		"respond trailing bit":    respond.Copy().MustStoreBoolBit(true).EndCell(),
		"respond two refs":        respond.Copy().MustStoreRef(cell.BeginCell().EndCell()).MustStoreRef(cell.BeginCell().EndCell()).EndCell(),
		"expire trailing":         head(ServiceActorExpireOpcode).MustStoreUInt(9, 64).MustStoreBoolBit(false).EndCell(),
		"sweep truncated":         head(ServiceActorSweepOpcode).MustStoreUInt(9, 32).EndCell(),
		"claim none destination":  head(ServiceActorClaimRefundOpcode).MustStoreUInt(9, 64).MustStoreUInt(0, 2).EndCell(),
		"unknown opcode":          head(0x53564310).EndCell(),
		"missing query":           cell.BeginCell().MustStoreUInt(ServiceActorExpireOpcode, 32).EndCell(),
		"claim trailing":          claim.Copy().MustStoreBoolBit(false).EndCell(),
		"respond truncated hash":  head(ServiceActorRespondOpcode).MustStoreUInt(9, 64).MustStoreSlice(fill(1), 255).EndCell(),
		"call missing terms hash": head(ServiceActorCallOpcode).MustStoreSlice(fill(1), 256).EndCell(),
	} {
		if _, err := DecodeServiceActorInbound(body); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// actorFixture writes Service Actor data in the FunC save_state layout. The
// dictionaries are built with the tosutils dictionary builder, not with the
// walker under test.
type actorFixture struct {
	t           *testing.T
	key         []byte
	keyID       [32]byte
	hasAttestor bool
	pending     map[uint64]*cell.Cell
	refunds     map[uint64]*cell.Cell
	counts      map[[32]byte]uint64
	nextID      uint64
	pendingN    uint64
	liveN       uint64
	pendingSum  uint64
	refundSum   uint64
	lockedSum   uint64
	mutate      func(*actorCells)
}

type actorCells struct {
	root, policy, commitments, accounting, dicts *cell.Builder
}

func newActorFixture(t *testing.T) *actorFixture {
	key := bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	id, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	return &actorFixture{t: t, key: key, keyID: id, hasAttestor: true, pending: map[uint64]*cell.Cell{},
		refunds: map[uint64]*cell.Cell{}, counts: map[[32]byte]uint64{}}
}

func (f *actorFixture) callerHash(fillByte byte) [32]byte {
	var out [32]byte
	copy(out[:], stdAddress(cell.BeginCell(), 0, fillByte).EndCell().Hash())
	return out
}

func (f *actorFixture) addPending(id uint64, callerByte byte, price, fee uint64) {
	commitments := cell.BeginCell().MustStoreSlice(fill(0x44), 256).MustStoreSlice(fill(0x45), 256).
		MustStoreBoolBit(true).MustStoreSlice(f.keyID[:], 256).MustStoreMaybeRef(storedBytesCell(f.key)).EndCell()
	entry := stdAddress(cell.BeginCell(), 0, callerByte)
	coins(f.t, entry, price)
	coins(f.t, entry, fee)
	coins(f.t, entry, 100_000_000)
	f.pending[id] = entry.MustStoreUInt(1000, 64).MustStoreUInt(2000, 64).MustStoreUInt(4, 32).MustStoreRef(commitments).EndCell()
	f.counts[f.callerHash(callerByte)]++
	f.pendingN++
	f.liveN++
	f.pendingSum += price
	f.lockedSum += fee
	if id >= f.nextID {
		f.nextID = id + 1
	}
}

func (f *actorFixture) addRefund(id uint64, callerByte byte, price, fee uint64) {
	entry := stdAddress(cell.BeginCell(), 0, callerByte)
	coins(f.t, entry, price)
	coins(f.t, entry, fee)
	coins(f.t, entry, 100_000_000)
	f.refunds[id] = entry.MustStoreUInt(2000, 64).EndCell()
	f.counts[f.callerHash(callerByte)]++
	f.liveN++
	f.refundSum += price
	f.lockedSum += fee
	if id >= f.nextID {
		f.nextID = id + 1
	}
}

func refDict(t *testing.T, width uint, entries map[uint64]*cell.Cell) *cell.Dictionary {
	dict := cell.NewDict(width)
	for id, entry := range entries {
		if err := dict.SetIntKey(new(big.Int).SetUint64(id), cell.BeginCell().MustStoreRef(entry).EndCell()); err != nil {
			t.Fatal(err)
		}
	}
	return dict
}

func (f *actorFixture) build() *cell.Cell {
	t := f.t
	cells := &actorCells{}
	cells.commitments = cell.BeginCell().MustStoreSlice(fill(0x66), 256).MustStoreSlice(ServiceActorSoftwareWorkProofScheme[:], 256)
	if f.hasAttestor {
		cells.commitments.MustStoreBoolBit(true).MustStoreSlice(f.keyID[:], 256).MustStoreMaybeRef(storedBytesCell(f.key))
	} else {
		cells.commitments.MustStoreBoolBit(false).MustStoreSlice(make([]byte, 32), 256).MustStoreMaybeRef(nil)
	}
	cells.policy = cell.BeginCell().MustStoreUInt(4, 32)
	coins(t, cells.policy, 300_000_000)
	coins(t, cells.policy, 200_000_000)
	coins(t, cells.policy, 100_000_000)
	cells.policy.MustStoreUInt(3600, 32).MustStoreUInt(3600, 32).MustStoreBoolBit(true).MustStoreBoolBit(false)
	stdAddress(cells.policy, 0, 0x11).MustStoreUInt(0, 32)
	cells.accounting = cell.BeginCell()
	coins(t, cells.accounting, 5)
	coins(t, cells.accounting, f.lockedSum)
	coins(t, cells.accounting, f.pendingSum)
	coins(t, cells.accounting, f.refundSum)
	cells.accounting.MustStoreUInt(20000, 32).MustStoreUInt(3, 32)
	counts := cell.NewDict(256)
	for key, count := range f.counts {
		if err := counts.SetIntKey(new(big.Int).SetBytes(key[:]), cell.BeginCell().MustStoreUInt(count, 32).EndCell()); err != nil {
			t.Fatal(err)
		}
	}
	cells.dicts = cell.BeginCell().MustStoreDict(refDict(t, 64, f.pending)).MustStoreDict(refDict(t, 64, f.refunds)).MustStoreDict(counts)
	cells.root = stdAddress(cell.BeginCell(), 0, 0x11).MustStoreBoolBit(true).MustStoreUInt(f.nextID, 64).
		MustStoreUInt(f.pendingN, 32).MustStoreUInt(f.liveN, 32)
	if f.mutate != nil {
		f.mutate(cells)
	}
	policy := cells.policy.MustStoreRef(cells.commitments.EndCell()).EndCell()
	return cells.root.MustStoreRef(policy).MustStoreRef(cells.accounting.EndCell()).MustStoreRef(cells.dicts.EndCell()).EndCell()
}

func populatedFixture(t *testing.T) *actorFixture {
	f := newActorFixture(t)
	f.addPending(0, 0x21, 300_000_000, 200_000_000)
	f.addPending(2, 0x22, 300_000_000, 200_000_000)
	f.addRefund(1, 0x21, 300_000_000, 200_000_000)
	return f
}

func TestServiceActorDataDecodesTheSaveStateLayout(t *testing.T) {
	data, err := DecodeServiceActorData(populatedFixture(t).build())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateServiceActorLiveState(data); err != nil {
		t.Fatal(err)
	}
	f := newActorFixture(t)
	if !data.Active || data.NextRequestID != 3 || data.PendingCount != 2 || data.LiveCount != 3 ||
		data.Policy.PolicyVersion != 4 || data.Policy.PricePerCall.Int64() != 300_000_000 || !data.Policy.HasAttestor ||
		data.Policy.AttestorKeyID != f.keyID || !bytes.Equal(data.Policy.AttestorKey, f.key) ||
		len(data.Pending) != 2 || len(data.Refunds) != 1 || len(data.CallerLiveCounts) != 2 ||
		data.Pending[2].RequestHash != hash32(0x44) || data.Refunds[1].RefundClaimDeadline != 2000 {
		t.Fatalf("decoded data differs: %+v", data)
	}
	empty := newActorFixture(t)
	empty.hasAttestor = false
	decoded, err := DecodeServiceActorData(empty.build())
	if err != nil || decoded.Policy.HasAttestor || ValidateServiceActorLiveState(decoded) != nil {
		t.Fatalf("empty actor: %+v %v", decoded, err)
	}
}

func TestServiceActorDataRefusesEveryMalformedCell(t *testing.T) {
	appendBit := func(b *cell.Builder) { b.MustStoreBoolBit(false) }
	appendRef := func(b *cell.Builder) { b.MustStoreRef(cell.BeginCell().EndCell()) }
	cases := map[string]func(*actorCells){
		"root trailing bit":        func(c *actorCells) { appendBit(c.root) },
		"policy trailing bit":      func(c *actorCells) { appendBit(c.policy) },
		"policy extra ref":         func(c *actorCells) { appendRef(c.policy) },
		"commitments trailing bit": func(c *actorCells) { appendBit(c.commitments) },
		"commitments extra ref":    func(c *actorCells) { appendRef(c.commitments) },
		"accounting trailing bit":  func(c *actorCells) { appendBit(c.accounting) },
		"accounting extra ref":     func(c *actorCells) { appendRef(c.accounting) },
		"dicts trailing bit":       func(c *actorCells) { appendBit(c.dicts) },
	}
	for name, mutate := range cases {
		f := populatedFixture(t)
		f.mutate = mutate
		if _, err := DecodeServiceActorData(f.build()); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	extraRootRef := populatedFixture(t).build().ToBuilder()
	extraRootRef.MustStoreRef(cell.BeginCell().EndCell())
	if _, err := DecodeServiceActorData(extraRootRef.EndCell()); err == nil {
		t.Error("root with a fourth reference was accepted")
	}

	attestor := map[string]func(*actorFixture){
		"attestor without key": func(f *actorFixture) {
			f.mutate = func(c *actorCells) {
				c.commitments = cell.BeginCell().MustStoreSlice(fill(0x66), 256).MustStoreSlice(fill(0x77), 256).
					MustStoreBoolBit(true).MustStoreSlice(f.keyID[:], 256).MustStoreMaybeRef(nil)
			}
		},
		"key id mismatch": func(f *actorFixture) { f.keyID[0] ^= 1 },
		"no attestor with key id": func(f *actorFixture) {
			f.mutate = func(c *actorCells) {
				c.commitments = cell.BeginCell().MustStoreSlice(fill(0x66), 256).MustStoreSlice(fill(0x77), 256).
					MustStoreBoolBit(false).MustStoreSlice(fill(1), 256).MustStoreMaybeRef(nil)
			}
		},
		"no attestor with key": func(f *actorFixture) {
			f.mutate = func(c *actorCells) {
				c.commitments = cell.BeginCell().MustStoreSlice(fill(0x66), 256).MustStoreSlice(fill(0x77), 256).
					MustStoreBoolBit(false).MustStoreSlice(make([]byte, 32), 256).MustStoreMaybeRef(storedBytesCell(f.key))
			}
		},
		"short stored key": func(f *actorFixture) {
			f.key = f.key[:mldsa44.PublicKeySize-1]
			f.mutate = func(c *actorCells) {
				c.commitments = cell.BeginCell().MustStoreSlice(fill(0x66), 256).MustStoreSlice(fill(0x77), 256).
					MustStoreBoolBit(true).MustStoreSlice(f.keyID[:], 256).MustStoreMaybeRef(storedBytesCell(f.key))
			}
		},
	}
	for name, edit := range attestor {
		f := newActorFixture(t)
		edit(f)
		if _, err := DecodeServiceActorData(f.build()); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	nonMinimal := newActorFixture(t)
	nonMinimal.mutate = func(c *actorCells) {
		c.accounting = cell.BeginCell().MustStoreUInt(1, 4).MustStoreUInt(0, 8)
		coins(t, c.accounting, 0)
		coins(t, c.accounting, 0)
		coins(t, c.accounting, 0)
		c.accounting.MustStoreUInt(0, 32).MustStoreUInt(0, 32)
	}
	if _, err := DecodeServiceActorData(nonMinimal.build()); err == nil {
		t.Error("non-minimal Coins was accepted")
	}
}

func TestServiceActorDictionariesAreWalkedStrictly(t *testing.T) {
	f := populatedFixture(t)
	pending := f.pending[0]
	cases := map[string]func(*actorFixture){
		"pending entry trailing bit": func(f *actorFixture) {
			f.pending[0] = pending.ToBuilder().MustStoreBoolBit(true).EndCell()
		},
		"pending wrapper bits": func(f *actorFixture) {
			f.mutate = func(c *actorCells) {
				dict := cell.NewDict(64)
				_ = dict.SetIntKey(big.NewInt(0), cell.BeginCell().MustStoreBoolBit(true).MustStoreRef(pending).EndCell())
				c.dicts = cell.BeginCell().MustStoreDict(dict).MustStoreDict(refDict(t, 64, f.refunds)).MustStoreDict(nil)
			}
		},
		"refund trailing ref": func(f *actorFixture) {
			f.refunds[1] = f.refunds[1].ToBuilder().MustStoreRef(cell.BeginCell().EndCell()).EndCell()
		},
		"caller count width": func(f *actorFixture) {
			f.mutate = func(c *actorCells) {
				counts := cell.NewDict(256)
				for key, count := range f.counts {
					_ = counts.SetIntKey(new(big.Int).SetBytes(key[:]), cell.BeginCell().MustStoreUInt(count, 33).EndCell())
				}
				c.dicts = cell.BeginCell().MustStoreDict(refDict(t, 64, f.pending)).MustStoreDict(refDict(t, 64, f.refunds)).MustStoreDict(counts)
			}
		},
		"overlapping ids": func(f *actorFixture) {
			f.refunds[0] = f.refunds[1]
		},
	}
	for name, edit := range cases {
		f := populatedFixture(t)
		edit(f)
		if _, err := DecodeServiceActorData(f.build()); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// A fork cell with a trailing bit or a third reference, built by hand.
	leaf := func(key uint64) *cell.Cell {
		// hml_long$10 n:(#<= 63) bits: the remaining 63 key bits, then ^value.
		return cell.BeginCell().MustStoreUInt(0b10, 2).MustStoreUInt(63, 6).MustStoreUInt(key, 63).
			MustStoreRef(pending).EndCell()
	}
	fork := func(extra func(*cell.Builder)) *cell.Cell {
		// hml_short$0 with an empty label (unary zero), then two branches.
		b := cell.BeginCell().MustStoreUInt(0b00, 2)
		if extra != nil {
			extra(b)
		}
		return b.MustStoreRef(leaf(0)).MustStoreRef(leaf(0)).EndCell()
	}
	for name, root := range map[string]*cell.Cell{
		"fork trailing bit": fork(func(b *cell.Builder) { b.MustStoreBoolBit(true) }),
		"fork third ref": cell.BeginCell().MustStoreUInt(0b00, 2).MustStoreRef(leaf(0)).MustStoreRef(leaf(0)).
			MustStoreRef(leaf(0)).EndCell(),
		"label too long": cell.BeginCell().MustStoreUInt(0b10, 2).MustStoreUInt(65, 7).MustStoreUInt(0, 65).MustStoreRef(pending).EndCell(),
	} {
		holder := cell.BeginCell().MustStoreBoolBit(true).MustStoreRef(root).EndCell()
		if _, err := walkHashmapE(holder.MustBeginParse(), 64, 10, "test"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	good := cell.BeginCell().MustStoreBoolBit(true).MustStoreRef(fork(nil)).EndCell()
	leaves, err := walkHashmapE(good.MustBeginParse(), 64, 10, "test")
	if err != nil || len(leaves) != 2 || leaves[1].key[0] != 0x80 {
		t.Fatalf("hand-built dictionary: %d leaves, %v", len(leaves), err)
	}
	if _, err := walkHashmapE(good.MustBeginParse(), 64, 1, "test"); err == nil {
		t.Error("dictionary above its entry bound was accepted")
	}
}

func TestServiceActorLiveStateInvariants(t *testing.T) {
	for name, edit := range map[string]func(*actorFixture){
		"pending count": func(f *actorFixture) { f.pendingN++ },
		"live count":    func(f *actorFixture) { f.liveN-- },
		"liability":     func(f *actorFixture) { f.pendingSum++ },
		"locked fees":   func(f *actorFixture) { f.lockedSum-- },
		"refundable":    func(f *actorFixture) { f.refundSum++ },
		"caller count":  func(f *actorFixture) { f.counts[f.callerHash(0x21)]++ },
		"next id":       func(f *actorFixture) { f.nextID = 2 },
	} {
		f := populatedFixture(t)
		edit(f)
		data, err := DecodeServiceActorData(f.build())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := ValidateServiceActorLiveState(data); err == nil {
			t.Errorf("%s inconsistency was accepted", name)
		}
	}
}

func stackNum(value uint64) TVMStackEntryV1 {
	return TVMStackEntryV1{Kind: "num", Number: new(big.Int).SetUint64(value)}
}

func stackHashNum(fillByte byte) TVMStackEntryV1 {
	return TVMStackEntryV1{Kind: "num", Number: new(big.Int).SetBytes(fill(fillByte))}
}

func stackSlice(cellValue *cell.Cell) TVMStackEntryV1 { return TVMStackEntryV1{Kind: "slice", Cell: cellValue} }

// The values of the Rust decodes_pending_request_stack and
// decodes_refund_stack cases, with the caller on workchain -1 as there.
func TestGetterStacksMatchTheRustCases(t *testing.T) {
	caller := stdAddress(cell.BeginCell(), -1, 0x22).EndCell()
	request := []TVMStackEntryV1{stackNum(1), stackSlice(caller), stackNum(100000000), stackNum(150000000),
		stackNum(100000000), stackNum(1700000000), stackNum(1703600000), stackNum(3), stackHashNum(0xAA),
		stackHashNum(0xBB), stackNum(1), stackHashNum(0x99)}
	view, err := DecodeServiceActorGetRequestStack(request)
	if err != nil || view.Price.Int64() != 100000000 || view.StorageFee.Int64() != 150000000 ||
		view.ResponseDeadline != 1700000000 || view.RefundClaimDeadline != 1703600000 || view.PolicyVersion != 3 ||
		view.RequestHash != hash32(0xAA) || view.TermsHash != hash32(0xBB) || !view.HasAttestor ||
		view.AttestorKeyID != hash32(0x99) || view.Caller.Workchain != -1 {
		t.Fatalf("get_request: %+v %v", view, err)
	}
	refund := []TVMStackEntryV1{stackNum(1), stackSlice(caller), stackNum(100000000), stackNum(150000000),
		stackNum(100000000), stackNum(1703600000)}
	if got, err := DecodeServiceActorGetRefundStack(refund); err != nil || got.RefundClaimDeadline != 1703600000 {
		t.Fatalf("get_refund: %+v %v", got, err)
	}
	notFound := []TVMStackEntryV1{stackNum(0), {Kind: "null"}, stackNum(0), stackNum(0), stackNum(0), stackNum(0)}
	if got, err := DecodeServiceActorGetRefundStack(notFound); err != nil || got != nil {
		t.Fatalf("not found refund: %+v %v", got, err)
	}

	clone := func(stack []TVMStackEntryV1) []TVMStackEntryV1 { return append([]TVMStackEntryV1(nil), stack...) }
	bad := map[string][]TVMStackEntryV1{
		"short":           request[:11],
		"long":            append(clone(request), stackNum(0)),
		"flag two":        func() []TVMStackEntryV1 { s := clone(request); s[10] = stackNum(2); return s }(),
		"found two":       func() []TVMStackEntryV1 { s := clone(request); s[0] = stackNum(2); return s }(),
		"negative":        func() []TVMStackEntryV1 { s := clone(request); s[7] = TVMStackEntryV1{Kind: "num", Number: big.NewInt(-1)}; return s }(),
		"wide version":    func() []TVMStackEntryV1 { s := clone(request); s[7] = stackNum(1 << 32); return s }(),
		"caller trailing": func() []TVMStackEntryV1 { s := clone(request); s[1] = stackSlice(stdAddress(cell.BeginCell(), 0, 1).MustStoreBoolBit(true).EndCell()); return s }(),
		"caller none":     func() []TVMStackEntryV1 { s := clone(request); s[1] = stackSlice(cell.BeginCell().MustStoreUInt(0, 2).EndCell()); return s }(),
		"coins too wide":  func() []TVMStackEntryV1 { s := clone(request); s[2] = TVMStackEntryV1{Kind: "num", Number: MaxServiceActorCoins}; return s }(),
		"not found value": {stackNum(0), {Kind: "null"}, stackNum(1), stackNum(0), stackNum(0), stackNum(0), stackNum(0), stackNum(0), stackNum(0), stackNum(0), stackNum(0), stackNum(0)},
		"not found caller": {stackNum(0), stackSlice(caller), stackNum(0), stackNum(0), stackNum(0), stackNum(0), stackNum(0),
			stackNum(0), stackNum(0), stackNum(0), stackNum(0), stackNum(0)},
	}
	for name, stack := range bad {
		if _, err := DecodeServiceActorGetRequestStack(stack); err == nil {
			t.Errorf("get_request %s was accepted", name)
		}
	}

	key := bytes.Repeat([]byte{7}, mldsa44.PublicKeySize)
	if got, err := DecodeServiceActorGetAttestorKeyStack([]TVMStackEntryV1{{Kind: "cell", Cell: storedBytesCell(key)}}); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("get_attestor_key: %v", err)
	}
	if got, err := DecodeServiceActorGetAttestorKeyStack([]TVMStackEntryV1{{Kind: "null"}}); err != nil || got != nil {
		t.Fatalf("null get_attestor_key: %v", err)
	}
	for name, stack := range map[string][]TVMStackEntryV1{
		"number":    {stackNum(0)},
		"short key": {{Kind: "cell", Cell: storedBytesCell(key[:100])}},
		"two":       {{Kind: "null"}, {Kind: "null"}},
	} {
		if _, err := DecodeServiceActorGetAttestorKeyStack(stack); err == nil {
			t.Errorf("get_attestor_key %s was accepted", name)
		}
	}
}

func TestServiceDataStackMatchesTheRustCase(t *testing.T) {
	owner := stdAddress(cell.BeginCell(), -1, 0x11).EndCell()
	authorized := stdAddress(cell.BeginCell(), -1, 0x22).EndCell()
	stack := []TVMStackEntryV1{stackSlice(owner), stackNum(1), stackNum(3), stackNum(100000000), stackNum(150000000),
		stackNum(100000000), stackNum(3600), stackNum(3600), stackNum(0), stackNum(1), stackSlice(authorized),
		stackNum(1000), stackHashNum(0x33), stackHashNum(0x44), stackNum(1), stackHashNum(0x99), stackNum(42),
		stackNum(2), stackNum(5), stackNum(1500000000), stackNum(450000000), stackNum(300000000), stackNum(700000000),
		stackNum(19700), stackNum(3)}
	view, err := DecodeServiceActorServiceDataStack(stack)
	if err != nil || !view.Active || view.Policy.PolicyVersion != 3 || view.Policy.OpenAccess || !view.Policy.HasAuthorizedCaller ||
		view.Policy.RateLimitPerDay != 1000 || view.Policy.AttestorKeyID != hash32(0x99) || view.NextRequestID != 42 ||
		view.PendingCount != 2 || view.LiveCount != 5 || view.Accounting.RefundableLiability.Int64() != 700000000 ||
		view.Accounting.CallDay != 19700 || view.Accounting.CallsToday != 3 {
		t.Fatalf("get_service_data: %+v %v", view, err)
	}
	if _, err := DecodeServiceActorServiceDataStack(stack[:24]); err == nil {
		t.Fatal("short get_service_data was accepted")
	}
}

func TestMetadataHashBindsEveryInput(t *testing.T) {
	input := ServiceActorMetadataInputV1{Network: testNetworkDomain(), CapabilityID: "cap_" + strings.Repeat("02", 32),
		ProviderAgentID: "agent_" + strings.Repeat("01", 32), CapabilityVersion: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("03", 32)}
	base, err := ServiceActorMetadataHash(input)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := BuildServiceActorMetadataCell(input)
	s := root.MustBeginParse()
	if s.MustLoadUInt(32) != serviceActorMetadataMagic || s.MustLoadUInt(16) != 1 || s.BitsLeft() != 512 || s.RefsNum() != 2 {
		t.Fatal("NSM1 root is not magic schema capability provider ^network ^version (560 bits, two refs)")
	}
	for name, edit := range map[string]func(*ServiceActorMetadataInputV1){
		"capability": func(v *ServiceActorMetadataInputV1) { v.CapabilityID = "cap_" + strings.Repeat("04", 32) },
		"provider":   func(v *ServiceActorMetadataInputV1) { v.ProviderAgentID = "agent_" + strings.Repeat("05", 32) },
		"version":    func(v *ServiceActorMetadataInputV1) { v.CapabilityVersion = "1.0.1" },
		"manifest":   func(v *ServiceActorMetadataInputV1) { v.ManifestDigest = "sha256:" + strings.Repeat("06", 32) },
		"network": func(v *ServiceActorMetadataInputV1) {
			network := testNetworkDomain()
			network.NetworkId = "tos:other"
			v.Network = network
		},
	} {
		changed := input
		edit(&changed)
		if other, err := ServiceActorMetadataHash(changed); err != nil || other == base {
			t.Errorf("%s does not change metadata_hash: %v", name, err)
		}
	}
}
