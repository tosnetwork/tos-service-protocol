package capabilitycatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

type catalogResolverFake struct {
	states map[string]*nativev1.NativeStateV1
}

func (f *catalogResolverFake) ResolveNativeState(_ context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	state := f.states[request.ObjectId]
	if state == nil {
		return &nativev1.ResolveNativeStateResponse{}, nil
	}
	return &nativev1.ResolveNativeStateResponse{Found: true, State: proto.Clone(state).(*nativev1.NativeStateV1)}, nil
}

func TestCatalogPublishesLinkedManifestAndListsFreshFinalizedState(t *testing.T) {
	catalog, resolver, manifest, digest, state := newCatalogFixture(t, 10)
	resolved, gotDigest, err := catalog.PublishManifest(context.Background(), state.GetCapability().CapabilityId, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != digest || resolved.Reference.FinalizedCheckpoint != 20 {
		t.Fatal("catalog did not return exact finalized publication")
	}
	stored, err := catalog.Manifest(digest)
	if err != nil || !bytes.Equal(stored, manifest) {
		t.Fatalf("stored manifest mismatch: %v", err)
	}
	resolver.states[state.GetCapability().CapabilityId].Reference.FinalizedCheckpoint = 21
	resolver.states[state.GetCapability().CapabilityId].GetCapability().Sequence = 2
	page, err := catalog.List(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Capabilities) != 1 || page.Capabilities[0].Reference.FinalizedCheckpoint != 21 ||
		page.Capabilities[0].GetCapability().Sequence != 2 || page.NextToken != "" {
		t.Fatal("catalog served a cached state instead of a fresh finalized resolution")
	}
}

func TestCatalogRejectsManifestWithoutFinalizedCommitment(t *testing.T) {
	catalog, _, manifest, _, state := newCatalogFixture(t, 10)
	state.GetCapability().Versions[0].ManifestDigest = "sha256:" + strings.Repeat("44", 32)
	if _, _, err := catalog.PublishManifest(context.Background(), state.GetCapability().CapabilityId, manifest); err == nil {
		t.Fatal("catalog accepted a manifest not committed by finalized Capability state")
	}
}

func TestCatalogFencesFinalityRollback(t *testing.T) {
	catalog, resolver, manifest, _, state := newCatalogFixture(t, 10)
	capabilityID := state.GetCapability().CapabilityId
	if _, _, err := catalog.PublishManifest(context.Background(), capabilityID, manifest); err != nil {
		t.Fatal(err)
	}
	resolver.states[capabilityID].Reference.FinalizedCheckpoint = 21
	if _, err := catalog.List(context.Background(), 10, ""); err != nil {
		t.Fatal(err)
	}
	resolver.states[capabilityID].Reference.FinalizedCheckpoint = 20
	if _, err := catalog.List(context.Background(), 10, ""); err == nil {
		t.Fatal("catalog accepted finalized-state rollback behind its observation fence")
	}
}

func TestCatalogExcludesFreshlyTombstonedCapability(t *testing.T) {
	catalog, resolver, manifest, _, state := newCatalogFixture(t, 10)
	capabilityID := state.GetCapability().CapabilityId
	if _, _, err := catalog.PublishManifest(context.Background(), capabilityID, manifest); err != nil {
		t.Fatal(err)
	}
	resolver.states[capabilityID].Reference.FinalizedCheckpoint++
	resolver.states[capabilityID].GetCapability().Tombstoned = true
	page, err := catalog.List(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Capabilities) != 0 || page.NextToken != "" {
		t.Fatal("catalog listed a tombstoned Capability")
	}
}

func TestCatalogRejectsTamperedManifestFile(t *testing.T) {
	catalog, _, manifest, digest, state := newCatalogFixture(t, 10)
	if _, _, err := catalog.PublishManifest(context.Background(), state.GetCapability().CapabilityId, manifest); err != nil {
		t.Fatal(err)
	}
	path, _ := catalog.store.manifestPath(digest)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Manifest(digest); err == nil {
		t.Fatal("catalog served a manifest with weakened file permissions")
	}
}

func TestCatalogEnforcesEntryBound(t *testing.T) {
	catalog, resolver, manifest, _, first := newCatalogFixture(t, 1)
	if _, _, err := catalog.PublishManifest(context.Background(), first.GetCapability().CapabilityId, manifest); err != nil {
		t.Fatal(err)
	}
	second := proto.Clone(first).(*nativev1.NativeStateV1)
	second.GetCapability().CapabilityId = "cap_" + strings.Repeat("bb", 32)
	second.TvmStateHash = "tvm-cell-sha256:" + strings.Repeat("cc", 32)
	resolver.states[second.GetCapability().CapabilityId] = second
	if _, _, err := catalog.PublishManifest(context.Background(), second.GetCapability().CapabilityId, manifest); err == nil {
		t.Fatal("catalog exceeded its configured discovery bound")
	}
}

func TestCatalogSearchSeparatesFinalizedAndGatewayLocalFields(t *testing.T) {
	catalog, resolver, manifest, digest, state := newCatalogFixture(t, 10)
	capabilityID := state.GetCapability().CapabilityId
	if _, _, err := catalog.PublishManifest(context.Background(), capabilityID, manifest); err != nil {
		t.Fatal(err)
	}
	resolver.states[capabilityID].Reference.FinalizedCheckpoint = 21
	page, err := catalog.Search(context.Background(), "deterministic test", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Results) != 1 || page.NextToken != "" {
		t.Fatal("search did not return the one local match")
	}
	result := page.Results[0]
	if result.Capability.Reference.FinalizedCheckpoint != 21 || result.ManifestDigest != digest ||
		result.CapabilityVersion == "" || result.GatewayLocal == nil ||
		result.GatewayLocal.Name != "Deterministic Go test" || result.GatewayLocal.MatchScore == 0 {
		t.Fatal("search mixed or omitted finalized and gateway-local fields")
	}
	if _, err := catalog.Search(context.Background(), "not-present", 10, ""); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogSearchRejectsRevokedVersionAndCorruptManifest(t *testing.T) {
	catalog, resolver, manifest, digest, state := newCatalogFixture(t, 10)
	capabilityID := state.GetCapability().CapabilityId
	if _, _, err := catalog.PublishManifest(context.Background(), capabilityID, manifest); err != nil {
		t.Fatal(err)
	}
	resolver.states[capabilityID].GetCapability().Versions[0].Revoked = true
	page, err := catalog.Search(context.Background(), "deterministic", 10, "")
	if err != nil || len(page.Results) != 0 {
		t.Fatal("search returned a revoked Capability version")
	}
	resolver.states[capabilityID].GetCapability().Versions[0].Revoked = false
	path, _ := catalog.store.manifestPath(digest)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Search(context.Background(), "deterministic", 10, ""); err == nil {
		t.Fatal("search ignored corrupted local manifest storage")
	}
}

func newCatalogFixture(t *testing.T, maxEntries uint32) (*Catalog, *catalogResolverFake, []byte, string, *nativev1.NativeStateV1) {
	t.Helper()
	raw, err := servicefixture.ManifestDocumentJSON()
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	decoded, err := nativecore.DecodeSoftwareWorkManifestJSON(vector.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest, digest, err := nativecore.CanonicalSoftwareWorkManifest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	network := &nativev1.NetworkDomain{NetworkId: "catalog-test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	codeHash := "tvm-cell-sha256:" + strings.Repeat("33", 32)
	capabilityID := "cap_" + strings.Repeat("aa", 32)
	state := &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("55", 32),
		Reference:    &nativev1.ChainReference{FinalizedCheckpoint: 20, ContractCodeHash: codeHash},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
			CapabilityId: capabilityID, Generation: 1, Sequence: 1,
			LastActionHash: "sha256:" + strings.Repeat("66", 32), OwnerAgentId: "agent_" + strings.Repeat("77", 32),
			Versions: []*nativev1.CapabilityVersionV1{{Version: decoded.Version, ManifestDigest: digest}}}}}
	resolver := &catalogResolverFake{states: map[string]*nativev1.NativeStateV1{capabilityID: state}}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	catalog, err := New(Config{Directory: directory, Resolver: resolver, Network: network,
		RegistryCodeHash: codeHash, CallerID: "catalog-test", ResolveTimeout: time.Second,
		MaxEntries: maxEntries, Now: func() time.Time { return time.Unix(2_000_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return catalog, resolver, manifest, digest, state
}
