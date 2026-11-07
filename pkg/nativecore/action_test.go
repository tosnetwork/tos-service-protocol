package nativecore

import (
	"context"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func testPolicy(t *testing.T) (*nativev1.ControllerPolicyV1, string) {
	t.Helper()
	return &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 60,
		Controllers: []*nativev1.ControllerV1{fakeController("test-controller", knownPurposeMask, true)}}, "test-controller"
}

func TestBuildSignAndVerifyDirectNativeAction(t *testing.T) {
	policy, controller := testPolicy(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	agentID, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol,
		Network:        network,
		TargetObjectId: agentID, TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32),
		Generation: 1, Sequence: 1, Nonce: []byte(strings.Repeat("n", 32)),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(context.Background(), fakeKeys, controller, built)
	if err != nil {
		t.Fatal(err)
	}
	if signature.KeyId != policy.Controllers[0].KeyId {
		t.Fatalf("signature key ID = %s", signature.KeyId)
	}
	if err := VerifySignatures(context.Background(), fakeKeys, policy, []*nativev1.SignatureV1{signature}, PurposeAgentControl, false, built); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyPossession(context.Background(), fakeKeys, policy, []*nativev1.SignatureV1{signature}, built); err != nil {
		t.Fatal(err)
	}
	body, err := MessageBody(built, []*nativev1.SignatureV1{signature}, nil, 7)
	if err != nil || len(body.ToBOC()) == 0 {
		t.Fatalf("body: %v", err)
	}
}

func TestNativePolicyEncodingIsIndependentOfInputOrder(t *testing.T) {
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{
		fakeController("order-a", knownPurposeMask, true), fakeController("order-b", knownPurposeMask, true),
	}}
	first, err := PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Controllers[0], policy.Controllers[1] = policy.Controllers[1], policy.Controllers[0]
	second, err := PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Hash()) != string(second.Hash()) {
		t.Fatal("policy input order changed canonical Cell")
	}
}

func TestNativePolicyPreservesPurposeIsolationAndReachability(t *testing.T) {
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{
		fakeController("isolated-agent", PurposeAgentControl|PurposeRecovery, true),
		fakeController("isolated-delegation", PurposeDelegation, false),
		fakeController("isolated-capability", PurposeCapabilityControl, false),
	}}
	if _, err := PolicyCell(policy); err != nil {
		t.Fatalf("reachable purpose-isolated policy was rejected: %v", err)
	}
	policy.Controllers[2].PurposeMask = PurposeDelegation
	if _, err := PolicyCell(policy); err == nil {
		t.Fatal("policy with unreachable Capability purpose was accepted")
	}
	policy.Controllers[2].PurposeMask = PurposeCapabilityControl
	policy.Controllers[0].Recovery = false
	if _, err := PolicyCell(policy); err == nil {
		t.Fatal("recovery purpose without recovery designation was accepted")
	}
	policy.Controllers[0].PurposeMask &^= PurposeRecovery
	policy.Controllers[0].Recovery = true
	if _, err := PolicyCell(policy); err == nil {
		t.Fatal("recovery designation without recovery purpose was accepted")
	}
}

func TestRegistrationRejectsCallerSelectedIdentity(t *testing.T) {
	policy, _ := testPolicy(t)
	action := &nativev1.NativeActionV1{Protocol: Protocol,
		Network:        &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		TargetObjectId: "agent_" + strings.Repeat("33", 32), TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32),
		Generation: 1, Sequence: 1, Nonce: []byte(strings.Repeat("n", 32)),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: []byte(strings.Repeat("o", 32)), InitialPolicy: policy}}}
	if _, err := BuildAction(action); err == nil {
		t.Fatal("caller-selected registration identity accepted")
	}
}

func TestGenerationResetRetainsNonzeroPredecessor(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	base := func(target string) *nativev1.NativeActionV1 {
		return &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: target,
			TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 2, Sequence: 1,
			PredecessorTvmStateHash: "tvm-cell-sha256:" + strings.Repeat("55", 32), Nonce: []byte(strings.Repeat("n", 32))}
	}
	recovery := base("agent_" + strings.Repeat("33", 32))
	recovery.Payload = &nativev1.NativeActionV1_CompleteRecovery{CompleteRecovery: &nativev1.CompleteRecoveryV1{InitiationActionHash: "sha256:" + strings.Repeat("66", 32)}}
	if _, err := BuildAction(recovery); err != nil {
		t.Fatalf("canonical recovery reset rejected: %v", err)
	}
	recovery.PredecessorTvmStateHash = ""
	if _, err := BuildAction(recovery); err == nil {
		t.Fatal("recovery reset with zero predecessor was accepted")
	} else if code, ok := ErrorCodeOf(err); !ok || code != ErrBadPredecessor {
		t.Fatalf("recovery reset with zero predecessor error = %v", err)
	}
	transfer := base("cap_" + strings.Repeat("77", 32))
	transfer.Payload = &nativev1.NativeActionV1_TransferCapability{TransferCapability: &nativev1.TransferCapabilityV1{
		CurrentOwnerAgentId: "agent_" + strings.Repeat("88", 32), NewOwnerAgentId: "agent_" + strings.Repeat("99", 32)}}
	if _, err := BuildAction(transfer); err != nil {
		t.Fatalf("canonical transfer reset rejected: %v", err)
	}
}

func TestMutationPredecessorRules(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: "agent_" + strings.Repeat("33", 32),
		TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 2,
		Nonce: []byte(strings.Repeat("n", 32)), Payload: &nativev1.NativeActionV1_DelegateAgent{DelegateAgent: &nativev1.DelegateAgentV1{DelegationDigest: "sha256:" + strings.Repeat("66", 32)}}}
	if _, err := BuildAction(action); err == nil {
		t.Fatal("ordinary mutation without predecessor was accepted")
	} else if code, ok := ErrorCodeOf(err); !ok || code != ErrBadPredecessor {
		t.Fatalf("ordinary mutation without predecessor error = %v", err)
	}
	action.PredecessorTvmStateHash = "tvm-cell-sha256:" + strings.Repeat("55", 32)
	action.Sequence = 1
	if _, err := BuildAction(action); err == nil {
		t.Fatal("ordinary mutation with reset sequence was accepted")
	} else if code, ok := ErrorCodeOf(err); !ok || code != ErrBadSequence {
		t.Fatalf("ordinary mutation with reset sequence error = %v", err)
	}
}

func TestCapabilityRegistrationFitsCanonicalCellAndUsesDerivedID(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	version := &nativev1.CapabilityVersionV1{Version: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	owner := "agent_" + strings.Repeat("66", 32)
	objectNonce := []byte(strings.Repeat("c", 32))
	id, err := DeriveCapabilityID(network, objectNonce, owner, version)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 1,
		Nonce: []byte(strings.Repeat("a", 32)), Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: objectNonce, OwnerAgentId: owner, InitialVersion: version}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	if built.Cell.BitsSize() > 1023 {
		t.Fatalf("action root exceeds TVM Cell limit: %d", built.Cell.BitsSize())
	}
}

func TestNativeActionHasNoAnchorOrPortableStateCommitment(t *testing.T) {
	policy, _ := testPolicy(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	agentID, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol,
		Network:        network,
		TargetObjectId: agentID, TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 1,
		Nonce: []byte(strings.Repeat("n", 32)), Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	s := built.Cell.MustBeginParse()
	if s.RefsNum() != 2 {
		t.Fatalf("action refs = %d, want domain+payload only", s.RefsNum())
	}
}
