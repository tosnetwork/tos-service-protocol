package nativecore

import (
	"context"
	"fmt"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The Native Registry contract admits at most 8 controllers in a policy and
// refuses a wider one with exit code 2215 before reading any controller; an
// authorizing signature set of more than 8 entries is refused with 2209
// before any entry is read.
func widePolicy(width int) (*nativev1.ControllerPolicyV1, []string) {
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1}
	names := make([]string, 0, width)
	for i := range width {
		name := fmt.Sprintf("policy-width-%d", i)
		names = append(names, name)
		policy.Controllers = append(policy.Controllers, fakeController(name, knownPurposeMask, true))
	}
	return policy, names
}

func wideAction(t *testing.T, policy *nativev1.ControllerPolicyV1) BuiltAction {
	t.Helper()
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	id, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildAction(&nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 1,
		Nonce:   []byte(strings.Repeat("n", 32)),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}})
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func TestNativePolicyWidthMatchesTheRegistry(t *testing.T) {
	if MaxControllers != 8 || MaxSignatures != MaxControllers || ErrPolicyTooWide != 2215 || ErrThreshold != 2209 {
		t.Fatalf("Registry width %d/%d or codes %d/%d drifted from the contract", MaxControllers, MaxSignatures, ErrPolicyTooWide, ErrThreshold)
	}
	if ErrPolicyTooWide.String() != "NATIVE_POLICY_TOO_WIDE" {
		t.Fatalf("unexpected name %s", ErrPolicyTooWide)
	}
	if name := ErrorCode(2214).String(); name != "NATIVE_ERROR_2214" {
		t.Fatalf("retired code 2214 still has a name: %s", name)
	}
	widestPolicy, names := widePolicy(MaxControllers)
	widest, err := PolicyCell(widestPolicy)
	if err != nil {
		t.Fatalf("a policy at the Registry width was refused: %v", err)
	}
	if decoded, err := DecodePolicyCell(widest); err != nil || len(decoded.Controllers) != MaxControllers {
		t.Fatalf("a policy cell at the Registry width did not decode: %v", err)
	}
	tooWidePolicy, tooWideNames := widePolicy(MaxControllers + 1)
	_, err = PolicyCell(tooWidePolicy)
	if code, ok := ErrorCodeOf(err); !ok || code != ErrPolicyTooWide {
		t.Fatalf("a policy one controller too wide: code %v, %v", code, err)
	}
	built := wideAction(t, widestPolicy)
	ctx := context.Background()
	err = VerifySignatures(ctx, fakeKeys, tooWidePolicy, nil, PurposeAgentControl, false, built)
	if code, ok := ErrorCodeOf(err); !ok || code != ErrPolicyTooWide {
		t.Fatalf("signature verification under a too-wide policy: code %v, %v", code, err)
	}

	// Eight signatures, one per controller, are accepted; a ninth entry is
	// refused with the threshold code before any entry is checked.
	signatures := fakeSign(t, built, names...)
	if err := VerifySignatures(ctx, fakeKeys, widestPolicy, signatures, PurposeAgentControl, false, built); err != nil {
		t.Fatalf("eight signatures refused: %v", err)
	}
	if err := VerifyPolicyPossession(ctx, fakeKeys, widestPolicy, signatures, built); err != nil {
		t.Fatalf("eight possession signatures refused: %v", err)
	}
	if _, err := SignatureCell(signatures); err != nil {
		t.Fatalf("an eight-entry signature cell was refused: %v", err)
	}
	nine := fakeSign(t, built, tooWideNames...)
	calls := fakeKeys.Calls()
	err = VerifySignatures(ctx, fakeKeys, widestPolicy, nine, PurposeAgentControl, false, built)
	if code, ok := ErrorCodeOf(err); !ok || code != ErrThreshold || fakeKeys.Calls() != calls {
		t.Fatalf("nine signatures: code %v, %v, verifier called %d times", code, err, fakeKeys.Calls()-calls)
	}
	if _, err := SignatureCell(nine); err == nil {
		t.Fatal("a nine-entry signature cell was built")
	} else if code, _ := ErrorCodeOf(err); code != ErrThreshold {
		t.Fatalf("nine-entry signature cell code %v", code)
	}
	err = VerifySignatures(ctx, fakeKeys, widestPolicy, nil, PurposeAgentControl, false, built)
	if code, ok := ErrorCodeOf(err); !ok || code != ErrThreshold {
		t.Fatalf("an empty signature set: code %v, %v", code, err)
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
