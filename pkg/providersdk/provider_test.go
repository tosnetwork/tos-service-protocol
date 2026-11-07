package providersdk

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

type fakeNativeClient struct {
	ownerID    string
	owner      *nativev1.NativeStateV1
	capability *nativev1.NativeStateV1
	submitted  *nativev1.SubmitNativeActionRequest
	manifest   *nativev1.PublishSoftwareWorkManifestRequest
	resolves   int
}

func (f *fakeNativeClient) PublishSoftwareWorkManifest(_ context.Context, request *nativev1.PublishSoftwareWorkManifestRequest) (*nativev1.PublishSoftwareWorkManifestResponse, error) {
	f.manifest = proto.Clone(request).(*nativev1.PublishSoftwareWorkManifestRequest)
	return &nativev1.PublishSoftwareWorkManifestResponse{ManifestDigest: f.capability.GetCapability().Versions[0].ManifestDigest,
		Capability: proto.Clone(f.capability).(*nativev1.NativeStateV1)}, nil
}

func (f *fakeNativeClient) SubmitNativeAction(_ context.Context, request *nativev1.SubmitNativeActionRequest) (*nativev1.SubmitNativeActionResponse, error) {
	f.submitted = proto.Clone(request).(*nativev1.SubmitNativeActionRequest)
	built, err := nativecore.BuildAction(request.Submission.Action)
	if err != nil {
		return nil, err
	}
	return &nativev1.SubmitNativeActionResponse{ActionHash: built.HashString, RelayAccepted: true}, nil
}

func (f *fakeNativeClient) ResolveNativeState(_ context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	if request.ObjectId == f.ownerID {
		return &nativev1.ResolveNativeStateResponse{Found: true, State: proto.Clone(f.owner).(*nativev1.NativeStateV1)}, nil
	}
	f.resolves++
	if f.resolves == 1 {
		return &nativev1.ResolveNativeStateResponse{}, nil
	}
	return &nativev1.ResolveNativeStateResponse{Found: true, State: proto.Clone(f.capability).(*nativev1.NativeStateV1)}, nil
}

func TestProviderPreparesSignsAndFinalizesCapabilityPublication(t *testing.T) {
	manifestJSON, err := os.ReadFile("../nativecore/testdata/software_work_manifest_v1_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	// The vector file wraps the positive manifest and negative corpus.
	manifestJSON = extractManifest(t, manifestJSON)
	network := &nativev1.NetworkDomain{NetworkId: "provider-sdk-test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	codeHash := "tvm-cell-sha256:" + strings.Repeat("33", 32)
	// Real ML-DSA-44: the controller key is held by tosctl custody and the
	// SDK verifies through the pinned helper.
	custody := mldsa44test.NewCustody(t, "provider")
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 60,
		Controllers: []*nativev1.ControllerV1{{KeyId: custody.KeyID(t, "provider"), Mldsa44PublicKey: custody.PublicKeys["provider"], Weight: 1,
			PurposeMask: nativecore.PurposeAgentControl | nativecore.PurposeDelegation | nativecore.PurposeRecovery | nativecore.PurposeCapabilityControl, Recovery: true}}}
	ownerID, err := nativecore.DeriveAgentID(network, bytes32(0x44), policy)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeNativeClient{ownerID: ownerID, owner: agentState(network, codeHash, ownerID, policy)}
	provider, err := New(Config{Client: fake, Verifier: mldsa44test.RequireTosctl(t), Network: network, RegistryCodeHash: codeHash, CallerID: ownerID,
		PollInterval: time.Millisecond * 10, FinalityTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := provider.PrepareCapabilityPublication(manifestJSON, ownerID, bytes32(0x55), bytes32(0x66))
	if err != nil {
		t.Fatal(err)
	}
	built, err := nativecore.BuildAction(prepared.Action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := nativecore.SignAction(context.Background(), custody.Signer, "provider", built)
	if err != nil {
		t.Fatal(err)
	}
	version := prepared.Action.GetRegisterCapability().InitialVersion
	fake.capability = &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("77", 32), Reference: &nativev1.ChainReference{
			ContractCodeHash: codeHash, FinalizedCheckpoint: 42}, State: &nativev1.NativeStateV1_Capability{
			Capability: &nativev1.CapabilityStateV1{CapabilityId: prepared.CapabilityID, Generation: 1, Sequence: 1,
				LastActionHash: prepared.ActionHash, OwnerAgentId: ownerID,
				Versions: []*nativev1.CapabilityVersionV1{proto.Clone(version).(*nativev1.CapabilityVersionV1)}}}}
	state, err := provider.PublishCapability(context.Background(), prepared, []*nativev1.SignatureV1{signature}, "publish-one")
	if err != nil {
		t.Fatal(err)
	}
	if state.GetCapability().CapabilityId != prepared.CapabilityID || fake.submitted.Context.IdempotencyKey != "publish-one" || fake.resolves != 2 {
		t.Fatal("provider SDK did not bind submission to finalized Capability state")
	}
	if _, err := provider.PublishManifest(context.Background(), prepared, "manifest-one"); err != nil {
		t.Fatal(err)
	}
	if fake.manifest == nil || fake.manifest.Context.IdempotencyKey != "manifest-one" ||
		!bytes.Equal(fake.manifest.CanonicalCbor, prepared.ManifestCBOR) {
		t.Fatal("provider SDK did not publish exact canonical manifest bytes")
	}
}

func TestProviderRejectsChangedPublicationBeforeRelay(t *testing.T) {
	provider, prepared, signature, fake := publicationFixture(t)
	prepared.Action.Nonce[0] ^= 0xff
	if _, err := provider.PublishCapability(context.Background(), prepared, []*nativev1.SignatureV1{signature}, "changed"); err == nil {
		t.Fatal("changed reviewed publication was relayed")
	}
	if fake.submitted != nil {
		t.Fatal("unsafe publication reached the gateway")
	}
}

func TestProviderRejectsChangedManifestBeforeRelay(t *testing.T) {
	provider, prepared, signature, fake := publicationFixture(t)
	prepared.ManifestCBOR[0] ^= 0xff
	if _, err := provider.PublishCapability(context.Background(), prepared, []*nativev1.SignatureV1{signature}, "changed-manifest"); err == nil {
		t.Fatal("changed canonical manifest was relayed")
	}
	if fake.submitted != nil {
		t.Fatal("changed manifest reached the gateway")
	}
}

func publicationFixture(t *testing.T) (*Provider, *PreparedPublication, *nativev1.SignatureV1, *fakeNativeClient) {
	t.Helper()
	manifestJSON, err := os.ReadFile("../nativecore/testdata/software_work_manifest_v1_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	network := &nativev1.NetworkDomain{NetworkId: "fixture", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 1,
		Controllers: []*nativev1.ControllerV1{{KeyId: fakeKeys.KeyID("fixture"), Mldsa44PublicKey: fakeKeys.PublicKey("fixture"), Weight: 1,
			PurposeMask: 15, Recovery: true}}}
	ownerID, _ := nativecore.DeriveAgentID(network, bytes32(1), policy)
	codeHash := "tvm-cell-sha256:" + strings.Repeat("33", 32)
	fake := &fakeNativeClient{ownerID: ownerID, owner: agentState(network, codeHash, ownerID, policy)}
	provider, err := New(Config{Client: fake, Verifier: fakeKeys, Network: network, RegistryCodeHash: codeHash, CallerID: ownerID, PollInterval: 10 * time.Millisecond, FinalityTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := provider.PrepareCapabilityPublication(extractManifest(t, manifestJSON), ownerID, bytes32(2), bytes32(3))
	if err != nil {
		t.Fatal(err)
	}
	built, err := nativecore.BuildAction(prepared.Action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := nativecore.SignAction(context.Background(), fakeKeys, "fixture", built)
	if err != nil {
		t.Fatal(err)
	}
	return provider, prepared, signature, fake
}

// fakeKeys stands in for the ML-DSA-44 helper in the pure-logic fixtures; it
// is not ML-DSA-44.
var fakeKeys = &mldsa44test.Fake{}

func TestProviderRefusesSignaturesOutsideTheOwnerPolicyBeforeRelay(t *testing.T) {
	provider, prepared, _, fake := publicationFixture(t)
	built, err := nativecore.BuildAction(prepared.Action)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := nativecore.SignAction(context.Background(), fakeKeys, "stranger", built)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.PublishCapability(context.Background(), prepared, []*nativev1.SignatureV1{stranger}, "stranger"); err == nil {
		t.Fatal("a signature by a key outside the owner policy was relayed")
	}
	if fake.submitted != nil {
		t.Fatal("an unauthorized publication reached the gateway")
	}
	if _, err := New(Config{Client: fake, Network: prepared.Action.Network, RegistryCodeHash: prepared.Action.TargetContractCodeHash,
		CallerID: "caller"}); err == nil {
		t.Fatal("a provider without a signature verifier was configured")
	}
}

func extractManifest(t *testing.T, raw []byte) []byte {
	t.Helper()
	// Keep the SDK test bound to the frozen repository vector without copying
	// its large manifest fixture into this module.
	var vector struct {
		Manifest any `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(vector.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func bytes32(value byte) []byte { return []byte(strings.Repeat(string([]byte{value}), 32)) }

func agentState(network *nativev1.NetworkDomain, codeHash, ownerID string, policy *nativev1.ControllerPolicyV1) *nativev1.NativeStateV1 {
	return &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("88", 32),
		Reference:    &nativev1.ChainReference{ContractCodeHash: codeHash, FinalizedCheckpoint: 41},
		State:        &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: ownerID, Policy: policy}}}
}
