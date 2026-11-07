package nativecore

import (
	"context"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// fakeKeys stands in for the ML-DSA-44 helper in pure-logic tests. It is not
// ML-DSA-44; tests of real signature bytes use mldsa44test.RequireTosctl.
var fakeKeys = &mldsa44test.Fake{}

func fakeController(name string, purposes uint32, recovery bool) *nativev1.ControllerV1 {
	return &nativev1.ControllerV1{KeyId: fakeKeys.KeyID(name), Mldsa44PublicKey: fakeKeys.PublicKey(name),
		Weight: 1, PurposeMask: purposes, Recovery: recovery}
}

func fakeSign(t *testing.T, built BuiltAction, names ...string) []*nativev1.SignatureV1 {
	t.Helper()
	signatures := make([]*nativev1.SignatureV1, 0, len(names))
	for _, name := range names {
		signature, err := SignAction(context.Background(), fakeKeys, name, built)
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	return SortSignatures(signatures)
}
