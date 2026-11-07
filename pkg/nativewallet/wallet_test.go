package nativewallet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

func registration(t *testing.T, policy *nativev1.ControllerPolicyV1) *nativev1.NativeActionV1 {
	t.Helper()
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	id, err := nativecore.DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	return &nativev1.NativeActionV1{Protocol: nativecore.Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 1,
		Nonce: []byte(strings.Repeat("a", 32)), Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{
			ObjectNonce: objectNonce, InitialPolicy: policy}}}
}

func controller(keyID string, key []byte) *nativev1.ControllerV1 {
	return &nativev1.ControllerV1{KeyId: keyID, Mldsa44PublicKey: key, Weight: 1, PurposeMask: 15, Recovery: true}
}

// TestReviewConfirmAndSignThroughCustody signs a two-controller registration
// with keys held in a real tosctl vault and checks the result with the real
// helper exactly as the relayer's preflight does.
func TestReviewConfirmAndSignThroughCustody(t *testing.T) {
	custody := mldsa44test.NewCustody(t, "wallet-a", "wallet-b")
	policy := &nativev1.ControllerPolicyV1{Threshold: 2, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{
		controller(custody.KeyID(t, "wallet-a"), custody.PublicKeys["wallet-a"]),
		controller(custody.KeyID(t, "wallet-b"), custody.PublicKeys["wallet-b"]),
	}}
	action := registration(t, policy)
	review, built, err := ReviewAction(action)
	if err != nil || review.Action != "register_agent" || review.ActionHash != built.HashString {
		t.Fatalf("review = %+v, err = %v", review, err)
	}
	if !strings.Contains(string(review.SignedAction), `"initial_policy"`) ||
		!strings.Contains(string(review.SignedAction), base64.StdEncoding.EncodeToString(action.GetRegisterAgent().ObjectNonce)) {
		t.Fatalf("review omitted signed payload semantics: %s", review.SignedAction)
	}
	if err := ConfirmHash(bufio.NewReader(strings.NewReader(review.ActionHash+"\n")), review.ActionHash); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Names are given in both orders; the set is always ascending by key ID.
	for _, names := range [][]string{{"wallet-a", "wallet-b"}, {"wallet-b", "wallet-a"}} {
		signatures, err := Sign(ctx, custody.Signer, built, names)
		if err != nil || len(signatures) != 2 {
			t.Fatalf("signatures = %v, err = %v", signatures, err)
		}
		first, _ := mldsa44.ParseKeyIDText(signatures[0].KeyId)
		second, _ := mldsa44.ParseKeyIDText(signatures[1].KeyId)
		if bytes.Compare(first[:], second[:]) >= 0 {
			t.Fatal("wallet signatures are not ascending by key ID")
		}
		helper := mldsa44test.RequireTosctl(t)
		if err := nativecore.VerifyPolicyPossession(ctx, helper, policy, signatures, built); err != nil {
			t.Fatalf("wallet signatures do not prove possession: %v", err)
		}
		if err := nativecore.VerifySignatures(ctx, helper, policy, signatures, nativecore.PurposeAgentControl, false, built); err != nil {
			t.Fatalf("wallet signatures do not authorize the action: %v", err)
		}
	}
	if _, err := Sign(ctx, custody.Signer, built, []string{"wallet-a", "missing"}); err == nil {
		t.Fatal("a controller missing from custody signed")
	}
}

func TestSigningRequestsAndConfirmationFailClosed(t *testing.T) {
	fake := &mldsa44test.Fake{}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1,
		Controllers: []*nativev1.ControllerV1{controller(fake.KeyID("only"), fake.PublicKey("only"))}}
	_, built, err := ReviewAction(registration(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	nine := make([]string, nativecore.MaxSignatures+1)
	for i := range nine {
		nine[i] = "controller-" + string(rune('a'+i))
	}
	for name, controllers := range map[string][]string{
		"empty": nil, "too many": nine, "repeated": {"only", "only"}, "blank": {" "},
	} {
		if _, err := Sign(ctx, fake, built, controllers); err == nil {
			t.Fatalf("%s controller list was signed", name)
		}
	}
	if _, err := Sign(ctx, sameKey{fake}, built, []string{"one", "two"}); err == nil {
		t.Fatal("two names for one key were signed")
	}
	if err := ConfirmHash(bufio.NewReader(strings.NewReader("sha256:wrong\n")), "sha256:expected"); err == nil {
		t.Fatal("wrong semantic confirmation was accepted")
	}
}

// sameKey maps every controller name to one fake key.
type sameKey struct{ fake *mldsa44test.Fake }

func (s sameKey) Sign(ctx context.Context, _ string, use mldsa44.Use, payload []byte) (mldsa44.Signature, error) {
	return s.fake.Sign(ctx, "shared", use, payload)
}
