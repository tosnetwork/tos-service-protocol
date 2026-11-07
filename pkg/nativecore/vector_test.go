package nativecore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type frozenVectorSet struct {
	Schema                 string                       `json:"schema"`
	Protocol               string                       `json:"protocol"`
	ContractCodeHash       string                       `json:"contract_code_hash"`
	ContractCodeBOCBase64  string                       `json:"contract_code_boc_base64"`
	Network                frozenNetwork                `json:"network"`
	Signature              frozenSignature              `json:"signature"`
	AgentRegistration      frozenAgentRegistration      `json:"agent_registration"`
	CapabilityRegistration frozenCapabilityRegistration `json:"capability_registration"`
	Revocations            []frozenRevocation           `json:"revocations"`
	NegativeMutations      []frozenNegativeMutation     `json:"negative_mutations"`
}

// frozenRevocation is one revocation the contract executed, with the exact
// inbound body the revoked object's own account received.
type frozenRevocation struct {
	Name                       string `json:"name"`
	ObjectID                   string `json:"object_id"`
	ContractAddress            string `json:"contract_address"`
	Generation                 uint64 `json:"generation"`
	Sequence                   uint64 `json:"sequence"`
	Predecessor                string `json:"predecessor"`
	Nonce                      string `json:"nonce"`
	ActionHash                 string `json:"action_hash"`
	ActionBOCBase64            string `json:"action_boc_base64"`
	SignatureSHA256            string `json:"signature_sha256"`
	SubmissionBodyHash         string `json:"submission_body_hash"`
	ObjectInboundOpcode        string `json:"object_inbound_opcode"`
	ObjectInboundBodyBOCBase64 string `json:"object_inbound_body_boc_base64"`
	StateHashAfter             string `json:"state_hash_after"`
	TombstoneAfter             bool   `json:"tombstone_after"`
}

type frozenNetwork struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

type frozenSignature struct {
	Suite   string `json:"suite"`
	Context string `json:"context"`
	Signing string `json:"signing"`
}

type frozenController struct {
	PublicKeyHex string `json:"public_key_hex"`
	KeyID        string `json:"key_id"`
	Weight       uint32 `json:"weight"`
	PurposeMask  uint32 `json:"purpose_mask"`
	Recovery     bool   `json:"recovery"`
}

type frozenPolicy struct {
	Threshold               uint32             `json:"threshold"`
	RecoveryThreshold       uint32             `json:"recovery_threshold"`
	RecoveryTimelockSeconds uint64             `json:"recovery_timelock_seconds"`
	Controllers             []frozenController `json:"controllers"`
}

type frozenExpected struct {
	ObjectID        string `json:"object_id"`
	ContractAddress string `json:"contract_address"`
	ActionHash      string `json:"action_hash"`
	ActionBOCBase64 string `json:"action_boc_base64"`
	SignatureHex    string `json:"signature_hex"`
	SubmissionBody  string `json:"submission_body_hash"`
}

type frozenAgentRegistration struct {
	PrivateSeedHex string         `json:"private_seed_hex"`
	ObjectNonceHex string         `json:"object_nonce_hex"`
	ActionNonceHex string         `json:"action_nonce_hex"`
	Policy         frozenPolicy   `json:"policy"`
	Expected       frozenExpected `json:"expected"`
}

type frozenCapabilityRegistration struct {
	OwnerAgentID   string         `json:"owner_agent_id"`
	ObjectNonceHex string         `json:"object_nonce_hex"`
	ActionNonceHex string         `json:"action_nonce_hex"`
	Version        string         `json:"version"`
	ManifestDigest string         `json:"manifest_digest"`
	Expected       frozenExpected `json:"expected"`
}

type frozenNegativeMutation struct {
	Registration string    `json:"registration"`
	Mutation     string    `json:"mutation"`
	ExpectedCode ErrorCode `json:"expected_code"`
}

func TestFrozenRegistrationVectors(t *testing.T) {
	vectors := loadFrozenVectors(t)
	if vectors.ContractCodeHash != "tvm-cell-sha256:d3bb66d0011a1f362dd0be8408ed688f4e740d096a0e2dc2a79fc0ffc628b28a" {
		t.Fatalf("frozen vectors pin another Registry code: %s", vectors.ContractCodeHash)
	}
	if vectors.Signature.Suite != "ML-DSA-44" || vectors.Signature.Context != "TOS-NATIVE-REGISTRY" {
		t.Fatalf("frozen vectors use another signature scheme: %+v", vectors.Signature)
	}
	helper := mldsa44test.RequireTosctl(t)
	ctx := context.Background()
	network := vectorNetwork(vectors.Network)
	policy := vectorPolicy(t, vectors.AgentRegistration)

	agent := vectorAgentAction(t, vectors, network, policy)
	assertFrozenAction(t, "Agent", agent, vectors.AgentRegistration.Expected)
	assertFrozenLocation(t, vectors, network, vectors.AgentRegistration.Expected)
	agentSignatures := assertFrozenSignature(t, policy, agent, vectors.AgentRegistration.Expected.SignatureHex)
	assertFrozenSubmission(t, "Agent", MessageBody, agent, agentSignatures, vectors.AgentRegistration.Expected)
	// The relayer's registration preflight admits the frozen registration.
	if err := VerifyPolicyPossession(ctx, helper, policy, agentSignatures, agent); err != nil {
		t.Fatalf("frozen registration possession refused: %v", err)
	}
	if err := VerifyRegistrationConsent(policy); err != nil {
		t.Fatal(err)
	}

	capability := vectorCapabilityAction(t, vectors, network)
	assertFrozenAction(t, "Capability", capability, vectors.CapabilityRegistration.Expected)
	assertFrozenLocation(t, vectors, network, vectors.CapabilityRegistration.Expected)
	capabilitySignatures := assertFrozenSignature(t, policy, capability, vectors.CapabilityRegistration.Expected.SignatureHex)
	assertFrozenSubmission(t, "Capability", AgentAuthorizationBody, capability, capabilitySignatures, vectors.CapabilityRegistration.Expected)
	if err := VerifySignatures(ctx, helper, policy, capabilitySignatures, PurposeCapabilityControl, false, capability); err != nil {
		t.Fatalf("frozen Capability authorization refused: %v", err)
	}
	// A signature over one action never authorizes the other.
	err := VerifySignatures(ctx, helper, policy, agentSignatures, PurposeCapabilityControl, false, capability)
	if code, _ := ErrorCodeOf(err); code != ErrBadSignature {
		t.Fatalf("the Agent registration signature over the Capability action: code %v, %v", code, err)
	}
}

type submissionBuilder func(BuiltAction, []*nativev1.SignatureV1, []*nativev1.SignatureV1, uint64) (*cell.Cell, error)

func assertFrozenSubmission(t *testing.T, name string, build submissionBuilder, built BuiltAction,
	signatures []*nativev1.SignatureV1, expected frozenExpected) {
	t.Helper()
	// The executed vectors submit with query ID 1 and no counterparty set.
	body, err := build(built, signatures, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if hash := "tvm-cell-sha256:" + hex.EncodeToString(body.Hash()); hash != expected.SubmissionBody {
		t.Fatalf("%s submission body hash = %s", name, hash)
	}
}

func assertFrozenLocation(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain, expected frozenExpected) {
	t.Helper()
	locator, err := NewLocator(network, 0, vectors.ContractCodeBOCBase64, vectors.ContractCodeHash)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := locator.Locate(expected.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Address != expected.ContractAddress {
		t.Fatalf("contract address = %q", identity.Address)
	}
}

func TestFrozenNegativeRegistrationMutations(t *testing.T) {
	vectors := loadFrozenVectors(t)
	network := vectorNetwork(vectors.Network)
	policy := vectorPolicy(t, vectors.AgentRegistration)
	agent := vectorAgentProto(t, vectors, network, policy)
	capability := vectorCapabilityProto(t, vectors, network)

	for _, mutation := range vectors.NegativeMutations {
		mutation := mutation
		t.Run(mutation.Registration+"/"+mutation.Mutation, func(t *testing.T) {
			var action *nativev1.NativeActionV1
			switch mutation.Registration {
			case "agent":
				action = proto.Clone(agent).(*nativev1.NativeActionV1)
			case "capability":
				action = proto.Clone(capability).(*nativev1.NativeActionV1)
			default:
				t.Fatalf("unknown registration %q", mutation.Registration)
			}
			applyFrozenMutation(t, action, mutation.Mutation)
			_, err := BuildAction(action)
			if err == nil {
				t.Fatal("negative mutation was accepted")
			}
			code, ok := ErrorCodeOf(err)
			if !ok || code != mutation.ExpectedCode {
				t.Fatalf("error = %v, code = %v, want %v", err, code, mutation.ExpectedCode)
			}
		})
	}
}

func loadFrozenVectors(t *testing.T) frozenVectorSet {
	t.Helper()
	raw, err := os.ReadFile("testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors frozenVectorSet
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Protocol != Protocol {
		t.Fatalf("protocol = %q", vectors.Protocol)
	}
	return vectors
}

func vectorNetwork(network frozenNetwork) *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: network.NetworkID, GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash}
}

// vectorPolicy builds the frozen policy from its public keys alone. The
// vectors also publish the key-generation seed of their deliberately public
// test controller; this module never derives keys and does not use it.
func vectorPolicy(t *testing.T, registration frozenAgentRegistration) *nativev1.ControllerPolicyV1 {
	t.Helper()
	policy := &nativev1.ControllerPolicyV1{Threshold: registration.Policy.Threshold, RecoveryThreshold: registration.Policy.RecoveryThreshold,
		RecoveryTimelockSeconds: registration.Policy.RecoveryTimelockSeconds}
	for _, controller := range registration.Policy.Controllers {
		publicKey := mustVectorHex(t, controller.PublicKeyHex)
		if len(publicKey) != mldsa44.PublicKeySize {
			t.Fatalf("frozen controller key is %d bytes", len(publicKey))
		}
		id, err := mldsa44.KeyID(publicKey)
		if err != nil || mldsa44.KeyIDText(id) != controller.KeyID {
			t.Fatalf("frozen key ID %s does not derive from its key", controller.KeyID)
		}
		policy.Controllers = append(policy.Controllers, &nativev1.ControllerV1{KeyId: controller.KeyID,
			Mldsa44PublicKey: publicKey, Weight: controller.Weight, PurposeMask: controller.PurposeMask, Recovery: controller.Recovery})
	}
	if len(policy.Controllers) != 1 || len(registration.PrivateSeedHex) != 64 {
		t.Fatal("frozen registration must name exactly one public test controller")
	}
	return policy
}

func vectorAgentProto(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain, policy *nativev1.ControllerPolicyV1) *nativev1.NativeActionV1 {
	t.Helper()
	objectNonce := mustVectorHex(t, vectors.AgentRegistration.ObjectNonceHex)
	id, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	if id != vectors.AgentRegistration.Expected.ObjectID {
		t.Fatalf("Agent object ID = %q", id)
	}
	return &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: vectors.ContractCodeHash, Generation: 1, Sequence: 1,
		Nonce:   mustVectorHex(t, vectors.AgentRegistration.ActionNonceHex),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
}

func vectorCapabilityProto(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain) *nativev1.NativeActionV1 {
	t.Helper()
	registration := vectors.CapabilityRegistration
	objectNonce := mustVectorHex(t, registration.ObjectNonceHex)
	version := &nativev1.CapabilityVersionV1{Version: registration.Version, ManifestDigest: registration.ManifestDigest}
	id, err := DeriveCapabilityID(network, objectNonce, registration.OwnerAgentID, version)
	if err != nil {
		t.Fatal(err)
	}
	if id != registration.Expected.ObjectID {
		t.Fatalf("Capability object ID = %q", id)
	}
	return &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: vectors.ContractCodeHash, Generation: 1, Sequence: 1,
		Nonce: mustVectorHex(t, registration.ActionNonceHex),
		Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: objectNonce, OwnerAgentId: registration.OwnerAgentID, InitialVersion: version}}}
}

func vectorAgentAction(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain, policy *nativev1.ControllerPolicyV1) BuiltAction {
	t.Helper()
	built, err := BuildAction(vectorAgentProto(t, vectors, network, policy))
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func vectorCapabilityAction(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain) BuiltAction {
	t.Helper()
	built, err := BuildAction(vectorCapabilityProto(t, vectors, network))
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func assertFrozenAction(t *testing.T, name string, built BuiltAction, expected frozenExpected) {
	t.Helper()
	prefix := map[uint8]string{1: "agent_", 2: "cap_"}[built.TargetKind]
	if !strings.HasPrefix(expected.ObjectID, prefix) {
		t.Fatalf("%s object ID = %q", name, expected.ObjectID)
	}
	if built.HashString != expected.ActionHash {
		t.Fatalf("%s action hash = %q", name, built.HashString)
	}
	if boc := base64.StdEncoding.EncodeToString(built.Cell.ToBOC()); boc != expected.ActionBOCBase64 {
		t.Fatalf("%s action BOC = %q", name, boc)
	}
}

// assertFrozenSignature verifies the recorded deterministic signature
// through the real ML-DSA-44 helper. Signing may be hedged, so the vector's
// signature is data to verify, not bytes to reproduce.
func assertFrozenSignature(t *testing.T, policy *nativev1.ControllerPolicyV1, built BuiltAction, expected string) []*nativev1.SignatureV1 {
	t.Helper()
	signature := mustVectorHex(t, expected)
	if len(signature) != mldsa44.SignatureSize {
		t.Fatalf("frozen signature is %d bytes", len(signature))
	}
	signatures := []*nativev1.SignatureV1{{KeyId: policy.Controllers[0].KeyId, Mldsa44Signature: signature}}
	helper := mldsa44test.RequireTosctl(t)
	if err := VerifySignatures(context.Background(), helper, policy, signatures, PurposeAgentControl, false, built); err != nil {
		t.Fatalf("frozen signature refused: %v", err)
	}
	flipped := append([]byte(nil), signature...)
	flipped[len(flipped)-1] ^= 0x80
	err := VerifySignatures(context.Background(), helper, policy,
		[]*nativev1.SignatureV1{{KeyId: policy.Controllers[0].KeyId, Mldsa44Signature: flipped}}, PurposeAgentControl, false, built)
	if code, _ := ErrorCodeOf(err); code != ErrBadSignature {
		t.Fatalf("flipped frozen signature: code %v, %v", code, err)
	}
	return signatures
}

func applyFrozenMutation(t *testing.T, action *nativev1.NativeActionV1, mutation string) {
	t.Helper()
	switch mutation {
	case "wrong_protocol":
		action.Protocol = "tos_service_v0"
	case "empty_network_id":
		action.Network.NetworkId = ""
	case "zero_genesis_root":
		action.Network.GenesisRootHash = "sha256:" + strings.Repeat("00", 32)
	case "wrong_contract_hash":
		action.TargetContractCodeHash = "sha256:" + strings.Repeat("44", 32)
	case "zero_action_nonce":
		action.Nonce = make([]byte, 32)
	case "zero_target_id":
		prefix := "agent_"
		if action.GetRegisterCapability() != nil {
			prefix = "cap_"
		}
		action.TargetObjectId = prefix + strings.Repeat("00", 32)
	case "zero_object_nonce":
		if registration := action.GetRegisterAgent(); registration != nil {
			registration.ObjectNonce = make([]byte, 32)
		} else {
			action.GetRegisterCapability().ObjectNonce = make([]byte, 32)
		}
	case "unattainable_policy":
		action.GetRegisterAgent().InitialPolicy.Threshold = 2
	case "caller_selected_id":
		prefix := "agent_"
		if action.GetRegisterCapability() != nil {
			prefix = "cap_"
		}
		action.TargetObjectId = prefix + strings.Repeat("33", 32)
	case "generation_zero":
		action.Generation = 0
	case "registration_generation_two":
		action.Generation = 2
	case "wrong_owner_kind":
		action.GetRegisterCapability().OwnerAgentId = "cap_" + strings.Repeat("44", 32)
	case "revoked_initial_version":
		action.GetRegisterCapability().InitialVersion.Revoked = true
	case "version_too_long":
		action.GetRegisterCapability().InitialVersion.Version = strings.Repeat("v", 129)
	case "version_non_printable":
		action.GetRegisterCapability().InitialVersion.Version = "1.0.0\n"
	case "registration_sequence_two":
		action.Sequence = 2
		action.PredecessorTvmStateHash = "tvm-cell-sha256:" + strings.Repeat("33", 32)
	default:
		t.Fatalf("unknown mutation %q", mutation)
	}
}

func mustVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
