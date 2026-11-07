package nativecore

import (
	"bytes"
	"context"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

func twoControllerPolicy() *nativev1.ControllerPolicyV1 {
	return &nativev1.ControllerPolicyV1{Threshold: 2, RecoveryThreshold: 1, RecoveryTimelockSeconds: 60,
		Controllers: []*nativev1.ControllerV1{fakeController("cells-a", knownPurposeMask, true), fakeController("cells-b", knownPurposeMask, true)}}
}

// readChain is an independent reader of the stored layout used to check what
// the builders write: the spec's len:uint32 ^chain of 127-byte cells.
func readChain(t *testing.T, stored *cell.Cell) []byte {
	t.Helper()
	s := stored.MustBeginParse()
	length := s.MustLoadUInt(32)
	if s.RefsNum() != 1 || s.BitsLeft() != 0 {
		t.Fatal("stored wrapper is not len:uint32 ^chain")
	}
	var out []byte
	for current := s.MustLoadRef().MustToCell(); current != nil; {
		cs := current.MustBeginParse()
		bits := cs.BitsLeft()
		out = append(out, cs.MustLoadSlice(bits)...)
		if cs.RefsNum() == 1 {
			if bits != 127*8 {
				t.Fatalf("non-final chain cell holds %d bits", bits)
			}
			current = cs.MustLoadRef().MustToCell()
		} else {
			current = nil
		}
	}
	if uint64(len(out)) != length {
		t.Fatalf("stored length %d, chain carries %d", length, len(out))
	}
	return out
}

func TestPolicyAndSignatureCellsFollowTheRegistryLayout(t *testing.T) {
	policy := twoControllerPolicy()
	built := wideAction(t, policy)
	root, err := PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	ordered := SortSignatures([]*nativev1.SignatureV1{
		{KeyId: policy.Controllers[0].KeyId}, {KeyId: policy.Controllers[1].KeyId},
	})
	keys := map[string][]byte{policy.Controllers[0].KeyId: policy.Controllers[0].Mldsa44PublicKey,
		policy.Controllers[1].KeyId: policy.Controllers[1].Mldsa44PublicKey}

	s := root.MustBeginParse()
	if s.MustLoadUInt(32) != policyMagic || s.MustLoadUInt(16) != 1 || s.MustLoadUInt(32) != 2 ||
		s.MustLoadUInt(32) != 1 || s.MustLoadUInt(64) != 60 || s.MustLoadUInt(8) != 2 || s.RefsNum() != 1 || s.BitsLeft() != 0 {
		t.Fatal("policy header layout")
	}
	controller := s.MustLoadRef().MustToCell()
	for i, signature := range ordered {
		cs := controller.MustBeginParse()
		if cs.BitsLeft() != 256+32+16+1 {
			t.Fatalf("controller %d holds %d bits", i, cs.BitsLeft())
		}
		id := cs.MustLoadSlice(256)
		if mldsa44.KeyIDText([32]byte(id)) != signature.KeyId {
			t.Fatalf("controller %d is out of key-ID order", i)
		}
		cs.MustLoadUInt(32)
		cs.MustLoadUInt(16)
		cs.MustLoadBoolBit()
		if !bytes.Equal(readChain(t, cs.MustLoadRef().MustToCell()), keys[signature.KeyId]) {
			t.Fatalf("controller %d does not store its key", i)
		}
		if i+1 < len(ordered) {
			controller = cs.MustLoadRef().MustToCell()
		} else if cs.RefsNum() != 0 {
			t.Fatal("last controller links onward")
		}
	}

	signatures := fakeSign(t, built, "cells-a", "cells-b")
	set, err := SignatureCell(signatures)
	if err != nil {
		t.Fatal(err)
	}
	ss := set.MustBeginParse()
	if ss.MustLoadUInt(8) != 2 || ss.RefsNum() != 1 || ss.BitsLeft() != 0 {
		t.Fatal("signature set header layout")
	}
	entry := ss.MustLoadRef().MustToCell()
	for i, signature := range signatures {
		es := entry.MustBeginParse()
		if es.BitsLeft() != 256 || mldsa44.KeyIDText([32]byte(es.MustLoadSlice(256))) != signature.KeyId {
			t.Fatalf("signature entry %d layout", i)
		}
		if got := readChain(t, es.MustLoadRef().MustToCell()); len(got) != mldsa44.SignatureSize || !bytes.Equal(got, signature.Mldsa44Signature) {
			t.Fatalf("signature entry %d does not store its signature", i)
		}
		if i+1 < len(signatures) {
			entry = es.MustLoadRef().MustToCell()
		} else if es.RefsNum() != 0 {
			t.Fatal("last signature entry links onward")
		}
	}
	empty := EmptySignatureCell().MustBeginParse()
	if empty.MustLoadUInt(8) != 0 || empty.BitsLeft() != 0 || empty.RefsNum() != 0 {
		t.Fatal("the empty signature set is not exactly count = 0 with no reference")
	}
}

func TestRegistryLocatorIsWorkchainZeroOnly(t *testing.T) {
	vectors := loadFrozenVectors(t)
	network := vectorNetwork(vectors.Network)
	if _, err := NewLocator(network, 0, vectors.ContractCodeBOCBase64, vectors.ContractCodeHash); err != nil {
		t.Fatalf("workchain 0 refused: %v", err)
	}
	for _, workchain := range []int32{-1, 1} {
		if _, err := NewLocator(network, workchain, vectors.ContractCodeBOCBase64, vectors.ContractCodeHash); err == nil {
			t.Fatalf("workchain %d accepted", workchain)
		}
	}
}

func TestSignatureSetsFailClosed(t *testing.T) {
	policy := twoControllerPolicy()
	built := wideAction(t, policy)
	ctx := context.Background()
	signatures := fakeSign(t, built, "cells-a", "cells-b")
	if err := VerifySignatures(ctx, fakeKeys, policy, signatures, PurposeAgentControl, false, built); err != nil {
		t.Fatal(err)
	}
	expect := func(name string, want ErrorCode, err error) {
		t.Helper()
		if code, ok := ErrorCodeOf(err); !ok || code != want {
			t.Fatalf("%s: code %v, want %v (%v)", name, code, want, err)
		}
	}
	reversed := []*nativev1.SignatureV1{signatures[1], signatures[0]}
	expect("unsorted", ErrDuplicateSignature, VerifySignatures(ctx, fakeKeys, policy, reversed, PurposeAgentControl, false, built))
	duplicate := []*nativev1.SignatureV1{signatures[0], signatures[0]}
	expect("duplicate", ErrDuplicateSignature, VerifySignatures(ctx, fakeKeys, policy, duplicate, PurposeAgentControl, false, built))
	_, err := SignatureCell(reversed)
	expect("unsorted cell", ErrDuplicateSignature, err)
	expect("below threshold", ErrThreshold, VerifySignatures(ctx, fakeKeys, policy, signatures[:1], PurposeAgentControl, false, built))

	short := proto.Clone(signatures[0]).(*nativev1.SignatureV1)
	short.Mldsa44Signature = short.Mldsa44Signature[:mldsa44.SignatureSize-1]
	expect("short signature", ErrBadSignature, VerifySignatures(ctx, fakeKeys, policy, []*nativev1.SignatureV1{short, signatures[1]}, PurposeAgentControl, false, built))
	_, err = SignatureCell([]*nativev1.SignatureV1{short})
	expect("short signature cell", ErrBadSignature, err)
	flipped := proto.Clone(signatures[0]).(*nativev1.SignatureV1)
	flipped.Mldsa44Signature[7] ^= 1
	expect("flipped signature", ErrBadSignature, VerifySignatures(ctx, fakeKeys, policy, []*nativev1.SignatureV1{flipped, signatures[1]}, PurposeAgentControl, false, built))
	for _, keyID := range []string{"ed25519:" + strings.Repeat("11", 32), strings.ToUpper(signatures[0].KeyId), "mldsa44:" + strings.Repeat("00", 32)} {
		other := proto.Clone(signatures[0]).(*nativev1.SignatureV1)
		other.KeyId = keyID
		expect("key ID "+keyID, ErrBadSignature, VerifySignatures(ctx, fakeKeys, policy, []*nativev1.SignatureV1{other}, PurposeAgentControl, false, built))
	}
	stranger := fakeSign(t, built, "cells-stranger")
	expect("unknown controller", ErrBadSignature, VerifySignatures(ctx, fakeKeys, policy, stranger, PurposeAgentControl, false, built))

	// Possession: exactly every controller, in key order.
	if err := VerifyPolicyPossession(ctx, fakeKeys, policy, signatures, built); err != nil {
		t.Fatal(err)
	}
	expect("missing possession", ErrBadSignature, VerifyPolicyPossession(ctx, fakeKeys, policy, signatures[:1], built))
	expect("unordered possession", ErrBadSignature, VerifyPolicyPossession(ctx, fakeKeys, policy, reversed, built))
	expect("flipped possession", ErrBadSignature, VerifyPolicyPossession(ctx, fakeKeys, policy, []*nativev1.SignatureV1{flipped, signatures[1]}, built))

	// A policy whose declared key ID does not match its key is refused.
	mismatch := twoControllerPolicy()
	mismatch.Controllers[0].KeyId = mismatch.Controllers[1].KeyId
	mismatch.Controllers[1].KeyId = fakeKeys.KeyID("cells-a")
	_, err = PolicyCell(mismatch)
	expect("swapped key IDs", ErrBadPolicy, err)
	wrongLength := twoControllerPolicy()
	wrongLength.Controllers[0].Mldsa44PublicKey = wrongLength.Controllers[0].Mldsa44PublicKey[:32]
	_, err = PolicyCell(wrongLength)
	expect("32-byte key", ErrBadPolicy, err)
	duplicateKey := twoControllerPolicy()
	duplicateKey.Controllers[1] = proto.Clone(duplicateKey.Controllers[0]).(*nativev1.ControllerV1)
	_, err = PolicyCell(duplicateKey)
	expect("duplicate controller", ErrBadPolicy, err)

	// An unavailable verifier is never a protocol decision.
	unavailable := VerifySignatures(ctx, unavailableVerifier{}, policy, signatures, PurposeAgentControl, false, built)
	if unavailable == nil {
		t.Fatal("an unavailable verifier authorized signatures")
	}
	if _, ok := ErrorCodeOf(unavailable); ok {
		t.Fatalf("an unavailable verifier produced a protocol code: %v", unavailable)
	}
	if err := VerifySignatures(ctx, nil, policy, signatures, PurposeAgentControl, false, built); err == nil {
		t.Fatal("verification without a verifier passed")
	}
}

type unavailableVerifier struct{}

func (unavailableVerifier) Verify(context.Context, mldsa44.Use, []byte, []byte, []byte) error {
	return mldsa44.ErrUnavailable
}

// policyWithStoredKey builds a one-controller policy cell whose controller
// carries the given stored-key cell, keeping every other field canonical.
func policyWithStoredKey(t *testing.T, stored *cell.Cell) *cell.Cell {
	t.Helper()
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1,
		Controllers: []*nativev1.ControllerV1{fakeController("decoder", knownPurposeMask, true)}}
	root, err := PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	s := root.MustBeginParse()
	header := cell.BeginCell().MustStoreSlice(s.MustLoadSlice(32+16+32+32+64+8), 32+16+32+32+64+8)
	controller := s.MustLoadRef().MustToCell().MustBeginParse()
	rebuilt := cell.BeginCell().MustStoreSlice(controller.MustLoadSlice(256+32+16+1), 256+32+16+1).MustStoreRef(stored).EndCell()
	return header.MustStoreRef(rebuilt).EndCell()
}

func chainCell(parts [][]byte, extraRef bool) *cell.Cell {
	var next *cell.Cell
	for i := len(parts) - 1; i >= 0; i-- {
		builder := cell.BeginCell().MustStoreSlice(parts[i], uint(8*len(parts[i])))
		if next != nil {
			builder.MustStoreRef(next)
		}
		if extraRef && i == len(parts)-1 {
			builder.MustStoreRef(cell.BeginCell().EndCell())
		}
		next = builder.EndCell()
	}
	return next
}

func split(data []byte, sizes ...int) [][]byte {
	var parts [][]byte
	for _, size := range sizes {
		parts = append(parts, data[:size])
		data = data[size:]
	}
	return parts
}

func libraryCell(t *testing.T) *cell.Cell {
	t.Helper()
	library, err := cell.BeginCell().MustStoreUInt(2, 8).MustStoreSlice(bytes.Repeat([]byte{0x42}, 32), 256).EndCellSpecial(true)
	if err != nil || !library.IsSpecial() {
		t.Fatalf("library cell: %v", err)
	}
	return library
}

func TestPolicyDecoderRefusesNonCanonicalStoredKeys(t *testing.T) {
	key := fakeKeys.PublicKey("decoder")
	canonical := make([]int, 0, 11)
	for range 10 {
		canonical = append(canonical, 127)
	}
	canonical = append(canonical, mldsa44.PublicKeySize-1270)
	wrap := func(length uint64, chain *cell.Cell, trailing bool) *cell.Cell {
		builder := cell.BeginCell().MustStoreUInt(length, 32).MustStoreRef(chain)
		if trailing {
			builder.MustStoreBoolBit(false)
		}
		return builder.EndCell()
	}
	good := policyWithStoredKey(t, wrap(mldsa44.PublicKeySize, chainCell(split(key, canonical...), false), false))
	decoded, err := DecodePolicyCell(good)
	if err != nil {
		t.Fatalf("canonical stored key refused: %v", err)
	}
	if !bytes.Equal(decoded.Controllers[0].Mldsa44PublicKey, key) || decoded.Controllers[0].KeyId != fakeKeys.KeyID("decoder") {
		t.Fatal("decoded controller differs from the stored key")
	}
	reference, err := PolicyCell(decoded)
	if err != nil || !bytes.Equal(reference.Hash(), good.Hash()) {
		t.Fatal("the independently assembled policy differs from the builder's")
	}

	library := libraryCell(t)
	wrongTail := append(append([]int(nil), canonical[:10]...), 21, 21)
	unaligned := cell.BeginCell().MustStoreSlice(key[:127], 127*8).MustStoreBoolBit(false).
		MustStoreRef(chainCell(split(key[127:], canonical[1:]...), false)).EndCell()
	cases := map[string]*cell.Cell{
		"wrong length":           wrap(mldsa44.PublicKeySize-1, chainCell(split(key, canonical...), false), false),
		"short chain":            wrap(mldsa44.PublicKeySize, chainCell(split(key[:mldsa44.PublicKeySize-1], append(canonical[:10:10], 41)...), false), false),
		"short non-final cell":   wrap(mldsa44.PublicKeySize, chainCell(split(key, append([]int{100, 27}, canonical[1:]...)...), false), false),
		"unaligned cell":         wrap(mldsa44.PublicKeySize, unaligned, false),
		"split final cell":       wrap(mldsa44.PublicKeySize, chainCell(split(key, wrongTail...), false), false),
		"extra reference":        wrap(mldsa44.PublicKeySize, chainCell(split(key, canonical...), true), false),
		"trailing wrapper bit":   wrap(mldsa44.PublicKeySize, chainCell(split(key, canonical...), false), true),
		"library chain cell":     wrap(mldsa44.PublicKeySize, library, false),
		"library stored wrapper": library,
	}
	for name, stored := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicyCell(policyWithStoredKey(t, stored)); err == nil {
				t.Fatal("non-canonical stored key accepted")
			}
		})
	}

	// A declared key ID that differs from the stored key's is refused.
	other := fakeKeys.PublicKey("decoder-other")
	if _, err := DecodePolicyCell(policyWithStoredKey(t, wrap(mldsa44.PublicKeySize, chainCell(split(other, canonical...), false), false))); err == nil {
		t.Fatal("key ID mismatch accepted")
	} else if code, _ := ErrorCodeOf(err); code != ErrBadPolicy {
		t.Fatalf("key ID mismatch code %v", code)
	}
	if _, err := DecodePolicyCell(library); err == nil {
		t.Fatal("exotic policy root accepted")
	}
	// An exotic controller cell is refused.
	s := good.MustBeginParse()
	exoticController := cell.BeginCell().MustStoreSlice(s.MustLoadSlice(32+16+32+32+64+8), 32+16+32+32+64+8).MustStoreRef(library).EndCell()
	if _, err := DecodePolicyCell(exoticController); err == nil {
		t.Fatal("exotic controller cell accepted")
	}
}
