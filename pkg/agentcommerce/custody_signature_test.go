package agentcommerce

import (
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// testCustodyKey is a custody authorization controller for logic tests. Its
// signatures come from mldsa44test.Fake, so only Fake verifies them; the real
// ML-DSA-44 bytes are covered by the helper-backed tests.
type testCustodyKey struct {
	fake       *mldsa44test.Fake
	controller string
}

func newTestCustodyKey(controller string) testCustodyKey {
	return testCustodyKey{fake: &mldsa44test.Fake{}, controller: controller}
}

func (k testCustodyKey) publicKey() []byte { return k.fake.PublicKey(k.controller) }

func (k testCustodyKey) signPayment(body CustodyActionAuthorization) (CustodyActionAuthorization, error) {
	return SignCustodyActionAuthorization(context.Background(), body, k.fake, k.controller)
}

func (k testCustodyKey) signEffect(body CustodyEffectAuthorization) (CustodyEffectAuthorization, error) {
	return SignCustodyEffectAuthorization(context.Background(), body, k.fake, k.controller)
}

func (k testCustodyKey) signPrediction(body PredictionCustodyEffectAuthorizationV1) (PredictionCustodyEffectAuthorizationV1, error) {
	return SignPredictionCustodyEffectAuthorizationV1(context.Background(), body, k.fake, k.controller)
}

// pinnedFor pins the key for exactly one principal.
func (k testCustodyKey) pinnedFor(authorityID, ownerID, agentID string) mldsa44test.CustodyAuthorizationResolver {
	return mldsa44test.CustodyAuthorizationResolver{Verifier: k.fake, Keys: map[mldsa44test.CustodyPrincipal][]byte{
		{AuthorityID: authorityID, OwnerID: ownerID, AgentID: agentID}: k.publicKey()}}
}

// pinnedForAny pins the key for every principal; tests that are about other
// bindings use it.
func (k testCustodyKey) pinnedForAny() anyPrincipalCustodyKey {
	return anyPrincipalCustodyKey{Verifier: k.fake, key: k.publicKey()}
}

type anyPrincipalCustodyKey struct {
	mldsa44.Verifier
	key []byte
}

func (r anyPrincipalCustodyKey) ResolveCustodyAuthorizationKey(_, _, _ string, keyID [mldsa44.KeyIDSize]byte,
	_ time.Time) ([]byte, error) {
	if id, err := mldsa44.KeyID(r.key); err != nil || id != keyID {
		return nil, errors.New("custody authorization key ID is not the pinned key")
	}
	return append([]byte(nil), r.key...), nil
}
