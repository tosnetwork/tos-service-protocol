package agentguarantor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// nativeTestAuthority is the native authority of the pure-logic tests: keys
// and signatures come from mldsa44test.Fake, and a key ID resolves only after
// testSignAuthorization registered its controller. Tests of real ML-DSA-44
// bytes and of historical resolution use the helper and
// NativeAgentAuthorityResolverV1 instead.
type nativeTestAuthority struct{}

var (
	nativeTestFake = &mldsa44test.Fake{}
	nativeTestKeys sync.Map // [32]byte -> []byte
)

func (nativeTestAuthority) ResolveNativeAgentKey(_ AuthorityResolutionScopeV1, keyID [mldsa44.KeyIDSize]byte, _ time.Time,
	proof []byte) ([]byte, error) {
	if len(proof) == 0 {
		return nil, errTestAuthority
	}
	key, ok := nativeTestKeys.Load(keyID)
	if !ok {
		return nil, errors.New("test native key is not registered")
	}
	return append([]byte(nil), key.([]byte)...), nil
}

func (nativeTestAuthority) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	return nativeTestFake.Verify(ctx, use, payload, publicKey, signature)
}

func testSignAuthorization(t testing.TB, statement AuthorizationStatementV1, signatureDomain, controller string,
	proof []byte) ProfileQualifiedObjectAuthorizationV1 {
	t.Helper()
	key := nativeTestFake.PublicKey(controller)
	id, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	nativeTestKeys.Store(id, key)
	authorization, err := SignObjectAuthorization(context.Background(), statement, signatureDomain, nativeTestFake,
		controller, proof)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}
