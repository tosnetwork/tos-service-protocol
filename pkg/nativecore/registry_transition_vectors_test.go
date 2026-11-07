package nativecore

import (
	"encoding/base64"
	"fmt"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
)

// TestRevocationsMatchContractExecution pins the revocation codec to the
// contract: the frozen vectors record three revocations the release code
// executed (one version, the Capability, the Agent) and the exact inbound body
// each revoked account received. The production builder and the independent
// reference encoder must reproduce the contract's action cell from the
// recorded inputs, and the decoder must read the contract-delivered body,
// signature sets included, as the same transition.
func TestRevocationsMatchContractExecution(t *testing.T) {
	vectors := loadFrozenVectors(t)
	if len(vectors.Revocations) != 3 {
		t.Fatalf("the vectors record %d revocations, want 3", len(vectors.Revocations))
	}
	network := vectorNetwork(vectors.Network)
	agentID := vectors.AgentRegistration.Expected.ObjectID
	type want struct {
		kind    RegistryTransitionKind
		target  string
		version string
		opcode  uint64
		payload func() *nativev1.NativeActionV1
	}
	cases := map[string]want{
		"revoke_version": {RegistryVersionRevocation, vectors.CapabilityRegistration.Expected.ObjectID, "1.0.0", referencecodec.OpAuthorizedCapability,
			func() *nativev1.NativeActionV1 {
				return &nativev1.NativeActionV1{Payload: &nativev1.NativeActionV1_RevokeCapability{
					RevokeCapability: &nativev1.RevokeCapabilityV1{OwnerAgentId: agentID, Version: "1.0.0"}}}
			}},
		"revoke_capability": {RegistryCapabilityTombstone, vectors.CapabilityRegistration.Expected.ObjectID, "", referencecodec.OpAuthorizedCapability,
			func() *nativev1.NativeActionV1 {
				return &nativev1.NativeActionV1{Payload: &nativev1.NativeActionV1_RevokeCapability{
					RevokeCapability: &nativev1.RevokeCapabilityV1{OwnerAgentId: agentID}}}
			}},
		"revoke_agent": {RegistryAgentTombstone, agentID, "", referencecodec.OpSubmit,
			func() *nativev1.NativeActionV1 {
				return &nativev1.NativeActionV1{Payload: &nativev1.NativeActionV1_RevokeAgent{RevokeAgent: &nativev1.RevokeAgentV1{}}}
			}},
	}
	seen := map[string]bool{}
	for _, v := range vectors.Revocations {
		c, ok := cases[v.Name]
		if !ok || seen[v.Name] {
			t.Fatalf("unexpected or repeated revocation vector %q", v.Name)
		}
		seen[v.Name] = true
		if v.ObjectID != c.target {
			t.Fatalf("%s: vector object %s, want %s", v.Name, v.ObjectID, c.target)
		}
		predecessor := "tvm-cell-sha256:" + v.Predecessor

		// Production builder, from the recorded inputs only.
		action := c.payload()
		action.Protocol, action.Network, action.TargetObjectId = Protocol, network, v.ObjectID
		action.TargetContractCodeHash, action.Generation, action.Sequence = vectors.ContractCodeHash, v.Generation, v.Sequence
		action.PredecessorTvmStateHash, action.Nonce = predecessor, mustVectorHex(t, v.Nonce)
		built, err := BuildAction(action)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if built.HashString != v.ActionHash {
			t.Fatalf("%s: production action %s, contract executed %s", v.Name, built.HashString, v.ActionHash)
		}
		if got := base64.StdEncoding.EncodeToString(built.Cell.ToBOC()); got != rebocNoCRC(t, v.ActionBOCBase64) {
			t.Fatalf("%s: production action bytes differ from the contract-executed action", v.Name)
		}

		// Independent reference encoder, from the same inputs.
		reference, err := referencecodec.EncodeRevocation(referencecodec.Revocation{
			Network: referencecodec.Network{NetworkID: network.NetworkId, GenesisRootHash: network.GenesisRootHash,
				GenesisFileHash: network.GenesisFileHash},
			ContractCodeHash: vectors.ContractCodeHash, Target: v.ObjectID, Generation: v.Generation, Sequence: v.Sequence,
			Predecessor: predecessor, NonceHex: v.Nonce, OwnerAgentID: map[bool]string{true: agentID}[c.kind != RegistryAgentTombstone],
			Version: c.version})
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if reference.ActionHash != v.ActionHash || reference.ActionBOC != rebocNoCRC(t, v.ActionBOCBase64) {
			t.Fatalf("%s: reference action differs from the contract-executed action", v.Name)
		}
		if fmt.Sprintf("0x%08x", reference.Opcode) != v.ObjectInboundOpcode || reference.Opcode != c.opcode {
			t.Fatalf("%s: reference opcode 0x%08x, contract delivered %s", v.Name, reference.Opcode, v.ObjectInboundOpcode)
		}

		// The decoder reads the body the contract delivered, signatures included.
		decoded, err := DecodeRegistryTransition(bocCell(t, v.ObjectInboundBodyBOCBase64))
		if err != nil {
			t.Fatalf("%s: the contract-delivered body does not decode: %v", v.Name, err)
		}
		expected := RegistryTransitionV1{Kind: c.kind, ObjectID: v.ObjectID, ActionHash: v.ActionHash, Version: c.version}
		if decoded != expected {
			t.Fatalf("%s: decoded %+v, want %+v", v.Name, decoded, expected)
		}
		if !v.TombstoneAfter && c.kind != RegistryVersionRevocation {
			t.Fatalf("%s: the contract did not tombstone the object", v.Name)
		}
	}
}

// rebocNoCRC re-serializes a recorded BOC in this codec's default form, so a
// CRC trailer in the recorded encoding does not decide byte equality; the
// cell tree itself must be identical.
func rebocNoCRC(t *testing.T, value string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(bocCell(t, value).ToBOC())
}
