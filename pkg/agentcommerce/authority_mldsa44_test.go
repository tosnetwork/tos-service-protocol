package agentcommerce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/internal/actionauthorityvector"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

const actionAuthorityVectorPath = "testdata/action-authority-signature-vector.json"

// The shared vector's four Action Authority signatures verify through the
// real helper, each only for its own object kind, and every refusal entry (a
// valid signature in its own mode, context or domain) is refused.
func TestActionAuthorityVectorVerifiesThroughTheHelper(t *testing.T) {
	vector, err := actionauthorityvector.Load(actionAuthorityVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	helper := mldsa44test.RequireTosctl(t)
	ctx := context.Background()
	messages := make([][]byte, len(vector.Messages))
	for index, entry := range vector.Messages {
		messages[index], _ = hex.DecodeString(entry.MessageHex)
	}
	for index, entry := range vector.Messages {
		signature, _ := hex.DecodeString(entry.SignatureHex)
		if err := helper.Verify(ctx, mldsa44.UseActionAuthority, messages[index], vector.PublicKey(), signature); err != nil {
			t.Fatalf("%s does not verify: %v", entry.Name, err)
		}
		for other := range messages {
			if other != index {
				if err := helper.Verify(ctx, mldsa44.UseActionAuthority, messages[other], vector.PublicKey(), signature); err == nil {
					t.Fatalf("%s verified as %s", entry.Name, vector.Messages[other].Name)
				}
			}
		}
		if err := helper.Verify(ctx, mldsa44.UseAgentGuarantor, messages[index], vector.PublicKey(), signature); err == nil {
			t.Fatalf("%s verified under the Guarantor context", entry.Name)
		}
	}
	// One pre-hash, seven other contexts, three other domains.
	if len(vector.Refusals) != 11 {
		t.Fatalf("the vector carries %d refusals, want every other context and domain", len(vector.Refusals))
	}
	for _, refusal := range vector.Refusals {
		signature, _ := hex.DecodeString(refusal.SignatureHex)
		if err := helper.Verify(ctx, mldsa44.UseActionAuthority, messages[0], vector.PublicKey(), signature); err == nil {
			t.Fatalf("refusal %s verified as the Writer Fence signature", refusal.Name)
		}
	}
}

// The vector inputs are the canonical objects this implementation builds:
// the Writer Fence body decodes to a valid body whose message is the
// recorded one, and the AuthorizedAction names the vector key.
func TestActionAuthorityVectorObjectsAreCanonical(t *testing.T) {
	vector, err := actionauthorityvector.Load(actionAuthorityVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	fenceEntry, _ := vector.Message("writer_fence_body")
	canonical, _ := hex.DecodeString(fenceEntry.CanonicalCBORHex)
	var body WriterFenceBody
	if err := codec.Unmarshal(canonical, &body); err != nil {
		t.Fatal(err)
	}
	message, err := WriterFenceSignatureMessage(body)
	if err != nil || hex.EncodeToString(message) != fenceEntry.MessageHex {
		t.Fatalf("the fence message is not the vector message: %v", err)
	}
	actionEntry, _ := vector.Message("authorized_action")
	canonical, _ = hex.DecodeString(actionEntry.CanonicalCBORHex)
	var action AuthorizedAction
	if err := codec.Unmarshal(canonical, &action); err != nil {
		t.Fatal(err)
	}
	if action.AuthorityKeyID != vector.KeyIDText() || action.AuthorizationProof != "" {
		t.Fatalf("the vector action names %q", action.AuthorityKeyID)
	}
	message, err = AuthorizedActionSignatureMessage(action)
	if err != nil || hex.EncodeToString(message) != actionEntry.MessageHex {
		t.Fatalf("the action message is not the vector message: %v", err)
	}
	fence, err := SignWriterFence(context.Background(), body, vector, "vector")
	if err != nil {
		t.Fatal(err)
	}
	fenceDigest, err := WriterFenceDigest(fence)
	if err != nil || fenceDigest != action.WriterFenceDigest {
		t.Fatalf("the vector action does not commit to the vector fence: %v", err)
	}
	signed, err := SignAuthorizedAction(context.Background(), action.unsigned(), vector.KeyIDText(), vector, "vector")
	if err != nil {
		t.Fatal(err)
	}
	resolver := vector.Resolver(body.AuthorityID, mldsa44test.RequireTosctl(t))
	if err := VerifyWriterFence(fence, resolver, time.Unix(int64(body.IssuedAtUnix), 0), body.Scope[0]); err != nil {
		t.Fatalf("the vector fence does not verify: %v", err)
	}
	actionMessage, _ := AuthorizedActionSignatureMessage(signed)
	if err := VerifyActionAuthoritySignature(resolver, signed.AuthorityID, signed.AuthorityKeyID, signed.AuthorizationProof,
		actionMessage, time.Unix(int64(body.IssuedAtUnix), 0)); err != nil {
		t.Fatalf("the vector action proof does not verify: %v", err)
	}
}

func (action AuthorizedAction) unsigned() AuthorizedAction {
	action.AuthorityKeyID, action.AuthorizationProof = "", ""
	return action
}

// A Writer Fence and an AuthorizedAction signed by a real custody controller
// verify through the real helper; a wrong-context signature, a fence proof in
// the action and a flipped byte are refused.
func TestRealCustodySignsAndVerifiesFenceAndAction(t *testing.T) {
	custody := mldsa44test.NewCustody(t, "authority")
	helper := mldsa44test.RequireTosctl(t)
	resolver := mldsa44test.ActionAuthorityResolver{Verifier: helper,
		Keys: map[string][][]byte{"authority:test": {custody.PublicKeys["authority"]}}}
	now := time.Unix(2_000_000_000, 0).UTC()
	ctx := context.Background()
	fence, err := SignWriterFence(ctx, testFenceBody(now), custody.Signer, "authority")
	if err != nil {
		t.Fatal(err)
	}
	if fence.KeyID != custody.KeyID(t, "authority") {
		t.Fatalf("fence key ID %s is not the custody key", fence.KeyID)
	}
	fields := map[string]SemanticValue{"owner_id": ID("owner:test"), "agent_id": ID("agent:test"),
		"agreement_body_digest": Digest32("sha256:" + strings.Repeat("1", 64)),
		"recipient_set_digest":  Digest32("sha256:" + strings.Repeat("2", 64))}
	request := []byte("canonical-request")
	action, err := BuildAuthorizedAction("owner:test", "agent:test", "agreement.propose", fields, request, fence, 7,
		"sha256:"+strings.Repeat("3", 64), "", "none", uint64(now.Add(30*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = SignAuthorizedAction(ctx, action, fence.KeyID, custody.Signer, "authority")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorizedAction(action, fields, request, fence, resolver, now); err != nil {
		t.Fatalf("real custody action refused: %v", err)
	}
	message, _ := AuthorizedActionSignatureMessage(action)
	foreign, err := custody.Signer.Sign(ctx, "authority", mldsa44.UseAgentGuarantor, message)
	if err != nil {
		t.Fatal(err)
	}
	wrongContext := action
	wrongContext.AuthorizationProof, _ = ActionAuthoritySignatureText(foreign.Signature)
	swapped := action
	swapped.AuthorizationProof = fence.Proof
	proof, _ := ParseActionAuthoritySignature(action.AuthorizationProof)
	proof[100] ^= 1
	flipped := action
	flipped.AuthorizationProof, _ = ActionAuthoritySignatureText(proof)
	for name, candidate := range map[string]AuthorizedAction{"guarantor context": wrongContext,
		"fence proof": swapped, "flipped byte": flipped} {
		if err := VerifyAuthorizedAction(candidate, fields, request, fence, resolver, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// The custody authorization key and the Action Authority key are both
// ML-DSA-44 but separately pinned and separated by context. One owner holds
// both: a custody effect authorization that binds the Writer Fence digest
// verifies under the custody resolver; the custody key is not an Action
// Authority key; and even one key that is trusted for both refuses a custody
// proof as an Action Authority signature and the reverse.
func TestCustodyKeyAndActionAuthorityKeyAreSeparate(t *testing.T) {
	f := newAuthorityFixture(t)
	fenceDigest, err := WriterFenceDigest(f.fence)
	if err != nil {
		t.Fatal(err)
	}
	custodyKey := newTestCustodyKey("custody-72")
	domain := &CustodyNetworkDomain{NetworkID: "tos:test", GlobalID: -3,
		ZeroStateRootHash: "sha256:" + strings.Repeat("a", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: 0}
	value := CustodyEffectAuthorization{SchemaVersion: 2, AuthorityID: "authority:test", OwnerID: "owner:test", AgentID: "agent:test",
		SourceAccount: "0:" + strings.Repeat("1", 64), NetworkID: domain.NetworkID, NetworkGlobalID: domain.GlobalID,
		NetworkDomain: domain, ActionKind: "escrow.accept", StableActionID: f.action.StableActionID,
		ExactRequestDigest: f.action.ExactRequestDigest, WriterGeneration: f.fence.Body.WriterGeneration,
		WriterFenceDigest: fenceDigest, PolicyRevision: f.action.PolicyRevision,
		MandateDigest: f.action.MandateDigest, ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("6", 64), ObligationID: "payment:one",
		Destination: "0:" + strings.Repeat("7", 64), AmountNanoTOS: 100_000_000,
		BodyHash: "tvm-cell-sha256:" + strings.Repeat("8", 64), StateInitHashOrZero: custodyNoStateInit,
		ExpiresAtUnix: uint64(f.now.Add(time.Minute).Unix())}
	signed, err := custodyKey.signEffect(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayCustodyEffectAuthorization(signed, custodyKey.pinnedForAny(), f.now); err != nil {
		t.Fatalf("custody authorization under the separate custody key was refused: %v", err)
	}
	if err := f.verify(f.action, f.fence, f.authority.resolver); err != nil {
		t.Fatalf("the ML-DSA-44 action of the same owner was refused: %v", err)
	}
	if signed.KeyID == f.fence.KeyID {
		t.Fatal("the custody key and the Action Authority key are the same key")
	}
	fence := f.fence
	fence.KeyID = signed.KeyID
	if err := VerifyWriterFence(fence, f.authority.resolver, f.now, "agreement.propose"); err == nil {
		t.Fatal("a fence naming the custody key was accepted by the Action Authority resolver")
	}
	preimage, err := CustodyEffectAuthorizationPreimage(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(preimage)
	both := mldsa44test.ActionAuthorityResolver{Verifier: custodyKey.fake,
		Keys: map[string][][]byte{"authority:test": {custodyKey.publicKey()}}}
	if err := VerifyActionAuthoritySignature(both, "authority:test", signed.KeyID, signed.Proof, digest[:], f.now); err == nil {
		t.Fatal("a custody proof verified as an Action Authority signature")
	}
	actionSigned, err := custodyKey.fake.Sign(context.Background(), custodyKey.controller, mldsa44.UseActionAuthority, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	swapped := signed
	if swapped.Proof, err = mldsa44.SignatureText(actionSigned.Signature); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayCustodyEffectAuthorization(swapped, custodyKey.pinnedForAny(), f.now); err == nil {
		t.Fatal("an Action Authority signature verified as a custody authorization")
	}
}
