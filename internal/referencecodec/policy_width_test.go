package referencecodec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
