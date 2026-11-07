package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	transitionAgent      = "agent_" + "4444444444444444444444444444444444444444444444444444444444444444"
	transitionCapability = "cap_" + "3333333333333333333333333333333333333333333333333333333333333333"
	transitionCodeHash   = "tvm-cell-sha256:" + "5555555555555555555555555555555555555555555555555555555555555555"
	transitionPrevious   = "tvm-cell-sha256:" + "6666666666666666666666666666666666666666666666666666666666666666"
)

func bocCell(t *testing.T, value string) *cell.Cell {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	root, err := cell.FromBOC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// The production builder, the independent reference encoder and the decoder
// agree on every revocation: the action cell hash is the same, and the
// reference body (with the opcode the contract receives) decodes to the
// transition it encodes.
func TestRegistryTransitionMatchesTheIndependentEncoder(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	nonce := bytes.Repeat([]byte{0x6e}, 32)
	longVersion := strings.Repeat("v", 128)
	cases := []struct {
		name    string
		action  *nativev1.NativeActionV1
		ref     referencecodec.Revocation
		kind    RegistryTransitionKind
		object  string
		version string
	}{
		{"agent tombstone", &nativev1.NativeActionV1{TargetObjectId: transitionAgent,
			Payload: &nativev1.NativeActionV1_RevokeAgent{RevokeAgent: &nativev1.RevokeAgentV1{}}},
			referencecodec.Revocation{Target: transitionAgent}, RegistryAgentTombstone, transitionAgent, ""},
		{"capability tombstone", &nativev1.NativeActionV1{TargetObjectId: transitionCapability,
			Payload: &nativev1.NativeActionV1_RevokeCapability{RevokeCapability: &nativev1.RevokeCapabilityV1{OwnerAgentId: transitionAgent}}},
			referencecodec.Revocation{Target: transitionCapability, OwnerAgentID: transitionAgent}, RegistryCapabilityTombstone, transitionCapability, ""},
		{"version revocation", &nativev1.NativeActionV1{TargetObjectId: transitionCapability,
			Payload: &nativev1.NativeActionV1_RevokeCapability{RevokeCapability: &nativev1.RevokeCapabilityV1{OwnerAgentId: transitionAgent, Version: "1.0.0"}}},
			referencecodec.Revocation{Target: transitionCapability, OwnerAgentID: transitionAgent, Version: "1.0.0"},
			RegistryVersionRevocation, transitionCapability, "1.0.0"},
		{"long version revocation", &nativev1.NativeActionV1{TargetObjectId: transitionCapability,
			Payload: &nativev1.NativeActionV1_RevokeCapability{RevokeCapability: &nativev1.RevokeCapabilityV1{OwnerAgentId: transitionAgent, Version: longVersion}}},
			referencecodec.Revocation{Target: transitionCapability, OwnerAgentID: transitionAgent, Version: longVersion},
			RegistryVersionRevocation, transitionCapability, longVersion},
	}
	for _, c := range cases {
		c.action.Protocol, c.action.Network, c.action.TargetContractCodeHash = Protocol, network, transitionCodeHash
		c.action.Generation, c.action.Sequence, c.action.PredecessorTvmStateHash, c.action.Nonce = 3, 7, transitionPrevious, nonce
		built, err := BuildAction(c.action)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		c.ref.Network = referencecodec.Network{NetworkID: network.NetworkId, GenesisRootHash: network.GenesisRootHash,
			GenesisFileHash: network.GenesisFileHash}
		c.ref.ContractCodeHash, c.ref.Generation, c.ref.Sequence = transitionCodeHash, 3, 7
		c.ref.Predecessor, c.ref.NonceHex = transitionPrevious, strings.Repeat("6e", 32)
		reference, err := referencecodec.EncodeRevocation(c.ref)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if reference.ActionHash != built.HashString {
			t.Fatalf("%s: reference action %s, production %s", c.name, reference.ActionHash, built.HashString)
		}
		decoded, err := DecodeRegistryTransition(bocCell(t, reference.BodyBOC))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		want := RegistryTransitionV1{Kind: c.kind, ObjectID: c.object, ActionHash: built.HashString, Version: c.version}
		if decoded != want {
			t.Fatalf("%s: decoded %+v, want %+v", c.name, decoded, want)
		}
	}
}

// actionFields is a hand-built Registry action, written field by field from
// the contract layout, so the refusal tests share no code with BuildAction.
type actionFields struct {
	magic, version, kind, targetKind, generation, sequence uint64
	target, predecessor, nonce                             []byte
	payload                                                *cell.Cell
	trailing                                               bool
}

func (f actionFields) cell() *cell.Cell {
	b := cell.BeginCell().MustStoreUInt(f.magic, 32).MustStoreUInt(f.version, 16).MustStoreUInt(f.kind, 8).
		MustStoreUInt(f.targetKind, 8).MustStoreUInt(f.generation, 64).MustStoreUInt(f.sequence, 64).
		MustStoreSlice(f.target, 256).MustStoreSlice(f.predecessor, 256).MustStoreSlice(f.nonce, 256).
		MustStoreRef(cell.BeginCell().MustStoreUInt(9, 8).EndCell()).MustStoreRef(f.payload)
	if f.trailing {
		b.MustStoreBoolBit(false)
	}
	return b.EndCell()
}

func inboundBody(opcode uint64, action *cell.Cell, edit func(*cell.Builder)) *cell.Cell {
	empty := cell.BeginCell().MustStoreUInt(0, 8).EndCell()
	b := cell.BeginCell().MustStoreUInt(opcode, 32).MustStoreUInt(5, 64).MustStoreRef(action).MustStoreRef(empty).MustStoreRef(empty)
	if edit != nil {
		edit(b)
	}
	return b.EndCell()
}

func textCell(raw []byte) *cell.Cell {
	return cell.BeginCell().MustStoreSlice(raw, uint(len(raw))*8).EndCell()
}

func revocationPayload(version []byte, hash []byte, name *cell.Cell, trailing bool) *cell.Cell {
	b := cell.BeginCell().MustStoreSlice(bytes.Repeat([]byte{0x44}, 32), 256)
	if version == nil && name == nil {
		b.MustStoreBoolBit(false)
	} else {
		if hash == nil {
			digest := sha256.Sum256(version)
			hash = digest[:]
		}
		b.MustStoreBoolBit(true).MustStoreSlice(hash, 256).MustStoreRef(name)
	}
	if trailing {
		b.MustStoreBoolBit(false)
	}
	return b.EndCell()
}

func TestRegistryTransitionRefusesEveryOtherBody(t *testing.T) {
	base := func(kind, targetKind uint64, target byte, payload *cell.Cell) actionFields {
		return actionFields{magic: actionMagic, version: 1, kind: kind, targetKind: targetKind, generation: 3, sequence: 7,
			target: bytes.Repeat([]byte{target}, 32), predecessor: bytes.Repeat([]byte{0x66}, 32),
			nonce: bytes.Repeat([]byte{0x6e}, 32), payload: payload}
	}
	agent := func() actionFields { return base(6, 1, 0x44, cell.BeginCell().EndCell()) }
	capability := func() actionFields { return base(10, 2, 0x33, revocationPayload(nil, nil, nil, false)) }
	version := func() actionFields {
		return base(10, 2, 0x33, revocationPayload([]byte("1.0.0"), nil, textCell([]byte("1.0.0")), false))
	}
	// The three accepted shapes, so every refusal below differs from an
	// accepted body by the one mutation it names.
	for name, body := range map[string]*cell.Cell{
		"agent":      inboundBody(0x4e560001, agent().cell(), nil),
		"capability": inboundBody(0x4e560003, capability().cell(), nil),
		"version":    inboundBody(0x4e560003, version().cell(), nil),
	} {
		if _, err := DecodeRegistryTransition(body); err != nil {
			t.Fatalf("%s: the accepted shape was refused: %v", name, err)
		}
	}
	mutate := func(f actionFields, edit func(*actionFields)) actionFields { edit(&f); return f }
	versionWith := func(raw []byte, name *cell.Cell, hash []byte) *cell.Cell {
		return inboundBody(0x4e560003, base(10, 2, 0x33, revocationPayload(raw, hash, name, false)).cell(), nil)
	}
	refused := map[string]*cell.Cell{
		"capability revocation submitted directly":          inboundBody(0x4e560001, capability().cell(), nil),
		"capability revocation as an Agent authorization":   inboundBody(0x4e560002, capability().cell(), nil),
		"agent revocation forwarded as a Capability action": inboundBody(0x4e560003, agent().cell(), nil),
		"agent revocation as an Agent authorization":        inboundBody(0x4e560002, agent().cell(), nil),
		"unknown action version":                            inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.version = 2 }).cell(), nil),
		"wrong action magic":                                inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.magic = 0x4e564132 }).cell(), nil),
		"another action kind":                               inboundBody(0x4e560003, mutate(capability(), func(f *actionFields) { f.kind = 9 }).cell(), nil),
		"agent kind on a Capability target":                 inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.targetKind = 2 }).cell(), nil),
		"capability kind on an Agent target":                inboundBody(0x4e560003, mutate(capability(), func(f *actionFields) { f.targetKind = 1 }).cell(), nil),
		"zero generation":                                   inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.generation = 0 }).cell(), nil),
		"zero sequence":                                     inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.sequence = 0 }).cell(), nil),
		"zero target":                                       inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.target = make([]byte, 32) }).cell(), nil),
		"zero predecessor":                                  inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.predecessor = make([]byte, 32) }).cell(), nil),
		"zero nonce":                                        inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.nonce = make([]byte, 32) }).cell(), nil),
		"trailing bit on the body":                          inboundBody(0x4e560001, agent().cell(), func(b *cell.Builder) { b.MustStoreBoolBit(true) }),
		"extra reference on the body": inboundBody(0x4e560001, agent().cell(), func(b *cell.Builder) {
			b.MustStoreRef(cell.BeginCell().EndCell())
		}),
		"trailing bit on the action": inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) { f.trailing = true }).cell(), nil),
		"agent payload not empty": inboundBody(0x4e560001, mutate(agent(), func(f *actionFields) {
			f.payload = cell.BeginCell().MustStoreBoolBit(false).EndCell()
		}).cell(), nil),
		"trailing bit after the tombstone flag": inboundBody(0x4e560003, mutate(capability(), func(f *actionFields) {
			f.payload = revocationPayload(nil, nil, nil, true)
		}).cell(), nil),
		"trailing bit after the version": inboundBody(0x4e560003, mutate(version(), func(f *actionFields) {
			f.payload = revocationPayload([]byte("1.0.0"), nil, textCell([]byte("1.0.0")), true)
		}).cell(), nil),
		"zero owner": inboundBody(0x4e560003, mutate(capability(), func(f *actionFields) {
			f.payload = cell.BeginCell().MustStoreSlice(make([]byte, 32), 256).MustStoreBoolBit(false).EndCell()
		}).cell(), nil),
		"version hash of another name":  versionWith([]byte("1.0.0"), textCell([]byte("1.0.0")), bytes.Repeat([]byte{0x01}, 32)),
		"empty version name":            versionWith([]byte{}, textCell(nil), nil),
		"non-printable version name":    versionWith([]byte("1.0 0"), textCell([]byte("1.0 0")), nil),
		"version name not byte-aligned": versionWith([]byte("1"), cell.BeginCell().MustStoreUInt(0x31, 7).EndCell(), nil),
		"version name over 128 bytes": versionWith(bytes.Repeat([]byte("v"), 129),
			cell.BeginCell().MustStoreSlice(bytes.Repeat([]byte("v"), 127), 127*8).MustStoreRef(textCell([]byte("vv"))).EndCell(), nil),
		"version name chain cell not full": versionWith([]byte("vv"),
			cell.BeginCell().MustStoreSlice([]byte("v"), 8).MustStoreRef(textCell([]byte("v"))).EndCell(), nil),
		"empty body": cell.BeginCell().EndCell(),
	}
	for name, body := range refused {
		if decoded, err := DecodeRegistryTransition(body); err == nil {
			t.Errorf("%s: decoded as %+v", name, decoded)
		}
	}
	if _, err := DecodeRegistryTransition(nil); err == nil {
		t.Error("a missing body was decoded")
	}
}
