package nativecore

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func testRawAddress(t *testing.T, friendly string) string {
	t.Helper()
	value, err := address.ParseAddr(friendly)
	if err != nil {
		t.Fatal(err)
	}
	return value.StringRaw()
}

func testEscrowTransport() TransportBindingV1 {
	return TransportBindingV1{SecurityMode: TransportLoopbackHTTP, MaxRequestBytes: 16 << 20, BaseURL: "http://127.0.0.1:8080"}
}

func testEscrowV2Code(t *testing.T) *cell.Cell {
	t.Helper()
	code, err := EscrowV2Code()
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestEscrowDecoderRejectsForgedRootCommitment(t *testing.T) {
	vector := loadEscrowV2ContractVector(t)
	s := vectorCell(t, vector.Funded.DataBOC).MustBeginParse()
	magic := s.MustLoadUInt(32)
	version := s.MustLoadUInt(16)
	status := s.MustLoadUInt(8)
	quoteHash := s.MustLoadSlice(256)
	termsHash := s.MustLoadSlice(256)
	authHash := s.MustLoadSlice(256)
	refs := make([]*cell.Cell, 4)
	for i := range refs {
		refs[i] = s.MustLoadRef().MustToCell()
	}
	forged := []byte(strings.Repeat("x", 32))
	for name, hashes := range map[string][][]byte{
		"quote":         {forged, termsHash, authHash},
		"terms":         {quoteHash, forged, authHash},
		"authorization": {quoteHash, termsHash, forged},
	} {
		builder := cell.BeginCell().MustStoreUInt(magic, 32).MustStoreUInt(version, 16).MustStoreUInt(status, 8)
		for _, hash := range hashes {
			builder.MustStoreSlice(hash, 256)
		}
		for _, ref := range refs {
			builder.MustStoreRef(ref)
		}
		if _, err := DecodeEscrowDataV2(builder.EndCell(), vector.Input.Network); err == nil ||
			!strings.Contains(err.Error(), "commitment mismatch") {
			t.Fatalf("%s: expected commitment mismatch, got %v", name, err)
		}
	}
}
