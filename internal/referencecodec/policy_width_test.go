package referencecodec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func referencePolicy(t *testing.T, width int) Policy {
	t.Helper()
	policy := Policy{Threshold: 1, RecoveryThreshold: 1}
	for i := range width {
		seed := sha256.Sum256([]byte(fmt.Sprintf("reference-policy-width-%d", i)))
		public, ok := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		if !ok {
			t.Fatal("invalid test key")
		}
		policy.Controllers = append(policy.Controllers, Controller{PublicKeyHex: hex.EncodeToString(public),
			Weight: 1, PurposeMask: 15, Recovery: true})
	}
	return policy
}

// The Native Registry admits at most 20 controllers and refuses a wider
// policy with exit code 2215.
func TestReferencePolicyWidthMatchesTheRegistry(t *testing.T) {
	if _, err := policyCell(referencePolicy(t, 20)); err != nil {
		t.Fatalf("a policy at the Registry width was refused: %v", err)
	}
	_, err := policyCell(referencePolicy(t, 21))
	if code, ok := ErrorCodeOf(err); !ok || code != 2215 {
		t.Fatalf("a policy one controller too wide: code %d, %v", code, err)
	}
}

// The keys the Registry contract refuses with exit code 2214, and neighbours
// it admits. The all-zero key is refused earlier as an invalid controller.
func TestReferencePolicyRefusesWeakControllerKeys(t *testing.T) {
	weak := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	admitted := []string{
		"ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecfffffffffffffffffffffffffffffffffffffffffffffffeffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e",
		"0200000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc84",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fb",
	}
	withKey := func(key string) Policy {
		policy := referencePolicy(t, 1)
		policy.Controllers = append(policy.Controllers, Controller{PublicKeyHex: key, Weight: 1, PurposeMask: 15, Recovery: true})
		return policy
	}
	for _, key := range admitted {
		if _, err := policyCell(withKey(key)); err != nil {
			t.Fatalf("admissible key %s refused: %v", key, err)
		}
	}
	for _, key := range weak {
		_, err := policyCell(withKey(key))
		if code, ok := ErrorCodeOf(err); !ok || code != 2214 {
			t.Fatalf("weak key %s: code %d, %v", key, code, err)
		}
	}
	if _, err := policyCell(withKey(strings.Repeat("00", 32))); err == nil {
		t.Fatal("the all-zero key was admitted")
	}
}
