package nativecore

import (
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func decoderFixture(t *testing.T) (BuiltAction, BuiltAction, []*nativev1.SignatureV1) {
	t.Helper()
	policy := ownerPolicy("decode-a", "decode-b")
	built := wideAction(t, policy)
	other := wideAction(t, ownerPolicy("decode-c"))
	return built, other, fakeSign(t, built, "decode-a", "decode-b")
}

func TestSubmissionBodyDecoderReturnsTheSignatureSets(t *testing.T) {
	built, _, signatures := decoderFixture(t)
	body, err := MessageBody(built, signatures, signatures[:1], 9)
	if err != nil {
		t.Fatal(err)
	}
	authority, counterparty, err := decodeSubmissionBody(body.ToBOC(), built, opSubmit, 9)
	if err != nil || len(authority) != 2 || len(counterparty) != 1 {
		t.Fatalf("decode = %d/%d, %v", len(authority), len(counterparty), err)
	}
	for i, signature := range signatures {
		if authority[i].KeyId != signature.KeyId || string(authority[i].Mldsa44Signature) != string(signature.Mldsa44Signature) {
			t.Fatalf("authority entry %d differs", i)
		}
	}
	empty, err := MessageBody(built, signatures, nil, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, counterparty, err := decodeSubmissionBody(empty.ToBOC(), built, opSubmit, 9); err != nil || counterparty != nil {
		t.Fatalf("empty counterparty set = %v, %v", counterparty, err)
	}
}

func TestSubmissionBodyDecoderRefusesNonCanonicalBodies(t *testing.T) {
	built, other, signatures := decoderFixture(t)
	authority, err := SignatureCell(signatures)
	if err != nil {
		t.Fatal(err)
	}
	body := func(opcode, query uint64, action *cell.Cell, extraBit, extraRef bool) []byte {
		builder := cell.BeginCell().MustStoreUInt(opcode, 32).MustStoreUInt(query, 64).MustStoreRef(action).
			MustStoreRef(authority).MustStoreRef(EmptySignatureCell())
		if extraBit {
			builder.MustStoreBoolBit(false)
		}
		if extraRef {
			builder.MustStoreRef(cell.BeginCell().EndCell())
		}
		return builder.EndCell().ToBOC()
	}
	good := body(opSubmit, 9, built.Cell, false, false)
	if _, _, err := decodeSubmissionBody(good, built, opSubmit, 9); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	goodCell, err := cell.FromBOC(good)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"unknown opcode":  body(opAuthorizeCapability, 9, built.Cell, false, false),
		"wrong query ID":  body(opSubmit, 10, built.Cell, false, false),
		"another action":  body(opSubmit, 9, other.Cell, false, false),
		"trailing bits":   body(opSubmit, 9, built.Cell, true, false),
		"extra reference": body(opSubmit, 9, built.Cell, false, true),
		"two BOC roots":   cell.ToBOCWithFlags([]*cell.Cell{goodCell, cell.BeginCell().EndCell()}),
		"not a BOC":       []byte("not a bag of cells"),
	} {
		if _, _, err := decodeSubmissionBody(raw, built, opSubmit, 9); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSignatureSetDecoderRefusesNonCanonicalSets(t *testing.T) {
	_, _, signatures := decoderFixture(t)
	set, err := SignatureCell(signatures)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeSignatureCell(set, false); err != nil || len(decoded) != 2 {
		t.Fatalf("positive control: %v", err)
	}
	entry := func(signature *nativev1.SignatureV1, stored *cell.Cell, next *cell.Cell, extraRef bool) *cell.Cell {
		builder := cell.BeginCell().MustStoreSlice(keyIDBytes(signature.KeyId), 256).MustStoreRef(stored)
		if next != nil {
			builder.MustStoreRef(next)
		}
		if extraRef {
			builder.MustStoreRef(cell.BeginCell().EndCell())
		}
		return builder.EndCell()
	}
	root := func(count uint64, first *cell.Cell) *cell.Cell {
		return cell.BeginCell().MustStoreUInt(count, 8).MustStoreRef(first).EndCell()
	}
	stored := func(signature *nativev1.SignatureV1) *cell.Cell { return storedBytesCell(signature.Mldsa44Signature) }
	a, b := signatures[0], signatures[1]
	library := libraryCell(t)
	shortSignature := storedBytesCell(a.Mldsa44Signature[:len(a.Mldsa44Signature)-1])
	longSignature := storedBytesCell(append(append([]byte(nil), a.Mldsa44Signature...), 0))
	// All 2,420 bytes, but the first chain cell holds 126 instead of 127: only
	// the canonical-chain check can refuse it, not the length check.
	unaligned := func() *cell.Cell {
		data := a.Mldsa44Signature
		bounds := []int{0, 126}
		for bounds[len(bounds)-1] < len(data) {
			bounds = append(bounds, min(bounds[len(bounds)-1]+127, len(data)))
		}
		var chain *cell.Cell
		for i := len(bounds) - 2; i >= 0; i-- {
			part := data[bounds[i]:bounds[i+1]]
			builder := cell.BeginCell().MustStoreSlice(part, uint(len(part))*8)
			if chain != nil {
				builder.MustStoreRef(chain)
			}
			chain = builder.EndCell()
		}
		return cell.BeginCell().MustStoreUInt(uint64(len(data)), 32).MustStoreRef(chain).EndCell()
	}()
	for name, value := range map[string]*cell.Cell{
		"count above entries":  root(3, entry(a, stored(a), entry(b, stored(b), nil, false), false)),
		"count below entries":  root(1, entry(a, stored(a), entry(b, stored(b), nil, false), false)),
		"unsorted":             root(2, entry(b, stored(b), entry(a, stored(a), nil, false), false)),
		"duplicate":            root(2, entry(a, stored(a), entry(a, stored(a), nil, false), false)),
		"short signature":      root(1, entry(a, shortSignature, nil, false)),
		"long signature":       root(1, entry(a, longSignature, nil, false)),
		"non-canonical chain":  root(1, entry(a, unaligned, nil, false)),
		"library entry":        root(1, library),
		"library signature":    root(1, entry(a, library, nil, false)),
		"extra entry ref":      root(1, entry(a, stored(a), nil, true)),
		"empty with reference": cell.BeginCell().MustStoreUInt(0, 8).MustStoreRef(cell.BeginCell().EndCell()).EndCell(),
		"nine entries":         cell.BeginCell().MustStoreUInt(9, 8).MustStoreRef(entry(a, stored(a), nil, false)).EndCell(),
	} {
		if _, err := decodeSignatureCell(value, true); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Nine well-formed, ascending entries are still one more than a set holds.
	nine := fakeSign(t, wideAction(t, ownerPolicy("decode-a")), "n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8")
	var chain *cell.Cell
	for i := len(nine) - 1; i >= 0; i-- {
		chain = entry(nine[i], stored(nine[i]), chain, false)
	}
	if _, err := decodeSignatureCell(root(9, chain), true); err == nil {
		t.Fatal("a nine-entry signature set accepted")
	}
	first := chain.MustBeginParse()
	first.MustLoadRef() // the first entry's stored signature
	eight := cell.BeginCell().MustStoreUInt(8, 8).MustStoreRef(first.MustLoadRef().MustToCell()).EndCell()
	if _, err := decodeSignatureCell(eight, true); err != nil {
		t.Fatalf("positive control: an eight-entry set refused: %v", err)
	}
	if _, err := decodeSignatureCell(EmptySignatureCell(), false); err == nil {
		t.Fatal("an empty authority set accepted")
	}
}
