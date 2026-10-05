package nativecore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The Native Registry contract admits at most 20 controllers in a policy and
// refuses a wider one with exit code 2215 before reading any controller.
func widePolicy(t *testing.T, width int) *nativev1.ControllerPolicyV1 {
	t.Helper()
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1}
	for i := range width {
		seed := sha256.Sum256([]byte(fmt.Sprintf("policy-width-%d", i)))
		public, ok := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		if !ok {
			t.Fatal("invalid test key")
		}
		policy.Controllers = append(policy.Controllers, &nativev1.ControllerV1{KeyId: fmt.Sprintf("ed25519:%x", []byte(public)),
			Ed25519PublicKey: public, Weight: 1, PurposeMask: knownPurposeMask, Recovery: true})
	}
	return policy
}

func TestNativePolicyWidthMatchesTheRegistry(t *testing.T) {
	if MaxControllers != 20 || MaxSignatures != MaxControllers || ErrPolicyTooWide != 2215 || ErrWeakKey != 2214 {
		t.Fatalf("Registry width %d/%d or codes %d/%d drifted from the contract", MaxControllers, MaxSignatures, ErrPolicyTooWide, ErrWeakKey)
	}
	if ErrPolicyTooWide.String() != "NATIVE_POLICY_TOO_WIDE" {
		t.Fatalf("unexpected name %s", ErrPolicyTooWide)
	}
	widest, err := PolicyCell(widePolicy(t, MaxControllers))
	if err != nil {
		t.Fatalf("a policy at the Registry width was refused: %v", err)
	}
	if decoded, err := DecodePolicyCell(widest); err != nil || len(decoded.Controllers) != MaxControllers {
		t.Fatalf("a policy cell at the Registry width did not decode: %v", err)
	}
	_, err = PolicyCell(widePolicy(t, MaxControllers+1))
	if code, ok := ErrorCodeOf(err); !ok || code != ErrPolicyTooWide {
		t.Fatalf("a policy one controller too wide: code %v, %v", code, err)
	}
	err = VerifySignatures(widePolicy(t, MaxControllers+1), nil, PurposeAgentControl, false, make([]byte, 32))
	if code, ok := ErrorCodeOf(err); !ok || code != ErrPolicyTooWide {
		t.Fatalf("signature verification under a too-wide policy: code %v, %v", code, err)
	}

	// A stored policy cell whose count is one over the width is refused with
	// the same code before any controller is read.
	s := widest.MustBeginParse()
	header := cell.BeginCell().MustStoreUInt(s.MustLoadUInt(32), 32).MustStoreUInt(s.MustLoadUInt(16), 16).
		MustStoreUInt(s.MustLoadUInt(32), 32).MustStoreUInt(s.MustLoadUInt(32), 32).MustStoreUInt(s.MustLoadUInt(64), 64)
	s.MustLoadUInt(8)
	tooWide := header.MustStoreUInt(MaxControllers+1, 8).MustStoreRef(s.MustLoadRef().MustToCell()).EndCell()
	_, err = DecodePolicyCell(tooWide)
	if code, ok := ErrorCodeOf(err); !ok || code != ErrPolicyTooWide {
		t.Fatalf("a stored policy one controller too wide: code %v, %v", code, err)
	}
}
