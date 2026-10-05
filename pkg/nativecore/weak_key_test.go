package nativecore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The keys the TOS contracts' weak-key predicate refuses, in the byte order a
// contract loads them: the eight canonical torsion encodings, four encodings
// with y >= 2^255 - 19, and the identity and order-2 point with the sign bit
// set. The Native Registry sandbox registers each of them and the contract
// refuses every one with exit code 2214, except the all-zero key, which its
// earlier policy check refuses with 2207.
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

func weakKeyPolicy(t *testing.T, weak []byte) *nativev1.ControllerPolicyV1 {
	t.Helper()
	policy := widePolicy(t, 1)
	policy.Controllers = append(policy.Controllers, &nativev1.ControllerV1{KeyId: "ed25519:" + hex.EncodeToString(weak),
		Ed25519PublicKey: weak, Weight: 1, PurposeMask: knownPurposeMask, Recovery: true})
	return policy
}

func TestNativePolicyRefusesWeakControllerKeys(t *testing.T) {
	if _, err := PolicyCell(widePolicy(t, 2)); err != nil {
		t.Fatalf("positive control: strong policy refused: %v", err)
	}
	strongCell, err := PolicyCell(widePolicy(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range contractWeakEd25519Keys {
		weak := mustDecodeKey(t, value)
		want := ErrWeakKey
		if value == "0000000000000000000000000000000000000000000000000000000000000000" {
			want = ErrBadPolicy
		}
		_, err := PolicyCell(weakKeyPolicy(t, weak))
		if code, ok := ErrorCodeOf(err); !ok || code != want {
			t.Fatalf("policy naming %s: code %v, want %v (%v)", value, code, want, err)
		}
		err = VerifySignatures(weakKeyPolicy(t, weak), nil, PurposeAgentControl, false, make([]byte, 32))
		if code, ok := ErrorCodeOf(err); !ok || code != want {
			t.Fatalf("verification under a policy naming %s: code %v, want %v", value, code, want)
		}
	}
	// A stored policy whose only controller is weak is refused on decode.
	s := strongCell.MustBeginParse()
	header := cell.BeginCell().MustStoreUInt(s.MustLoadUInt(32), 32).MustStoreUInt(s.MustLoadUInt(16), 16).
		MustStoreUInt(s.MustLoadUInt(32), 32).MustStoreUInt(s.MustLoadUInt(32), 32).MustStoreUInt(s.MustLoadUInt(64), 64).
		MustStoreUInt(s.MustLoadUInt(8), 8)
	controller := s.MustLoadRef()
	weak := mustDecodeKey(t, contractWeakEd25519Keys[1])
	controller.MustLoadSlice(512)
	stored := header.MustStoreRef(cell.BeginCell().MustStoreSlice(weak, 256).MustStoreSlice(weak, 256).
		MustStoreUInt(controller.MustLoadUInt(32), 32).MustStoreUInt(controller.MustLoadUInt(16), 16).
		MustStoreBoolBit(controller.MustLoadBoolBit()).EndCell()).EndCell()
	_, err = DecodePolicyCell(stored)
	if code, ok := ErrorCodeOf(err); !ok || code != ErrWeakKey {
		t.Fatalf("a stored policy naming a weak key: code %v, %v", code, err)
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
