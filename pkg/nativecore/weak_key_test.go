package nativecore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The keys the TOS contracts' weak-key predicate refuses, in the byte order a
// contract loads them: the eight canonical torsion encodings, four encodings
// with y >= 2^255 - 19, and the identity and order-2 point with the sign bit
// set. The escrow contracts refuse each of them as an execution signer. The
// Native Registry no longer admits Ed25519 controllers at all.
var contractWeakEd25519Keys = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// Keys next to the refused set that the predicate must admit.
var admittedNearWeakEd25519Keys = []string{
	"ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecfffffffffffffffffffffffffffffffffffffffffffffffeffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e",
	"0200000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000001",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc84",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fb",
}

func mustDecodeKey(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("invalid test key %s", value)
	}
	return raw
}

func TestWeakEd25519PublicKeyMatchesTheContracts(t *testing.T) {
	for _, value := range contractWeakEd25519Keys {
		if !WeakEd25519PublicKey(mustDecodeKey(t, value)) {
			t.Fatalf("contract-refused key %s admitted", value)
		}
	}
	for _, value := range admittedNearWeakEd25519Keys {
		if WeakEd25519PublicKey(mustDecodeKey(t, value)) {
			t.Fatalf("key %s refused", value)
		}
	}
	for i := range 64 {
		seed := sha256.Sum256([]byte(fmt.Sprintf("strong-key-%d", i)))
		public, ok := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		if !ok || WeakEd25519PublicKey(public) {
			t.Fatalf("generated key %x refused", public)
		}
	}
	if !WeakEd25519PublicKey(make([]byte, 31)) {
		t.Fatal("a short key was admitted")
	}
}

func TestEscrowAuthorizationRefusesWeakExecutionSigners(t *testing.T) {
	strong := mustDecodeKey(t, admittedNearWeakEd25519Keys[0])
	if _, err := BuildEscrowAuthorizationCellV1(strong); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for _, value := range contractWeakEd25519Keys {
		weak := mustDecodeKey(t, value)
		if _, err := BuildEscrowAuthorizationCellV1(weak); err == nil {
			t.Fatalf("escrow authorization built for weak key %s", value)
		}
		stored := cell.BeginCell().MustStoreUInt(escrowAuthorizationMagic, 32).MustStoreUInt(escrowAuthorizationVersion, 16).
			MustStoreSlice(weak, 256).EndCell()
		if _, err := decodeEscrowAuthorization(stored); err == nil {
			t.Fatalf("escrow authorization decoded for weak key %s", value)
		}
	}
}
