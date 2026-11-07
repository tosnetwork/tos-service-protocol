package serviceactorindex

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

var codeHash = "tvm-cell-sha256:" + strings.Repeat("88", 32)

type manifests map[string][]byte

func (m manifests) Manifest(_ context.Context, digest string) ([]byte, error) {
	value, ok := m[digest]
	if !ok {
		return nil, errors.New("unknown manifest")
	}
	return value, nil
}

// registryChain serves Capabilities, their owner Agents and actors at one
// checkpoint per session.
type registryChain struct {
	checkpoint uint64
	states     map[string]*nativev1.NativeStateV1
	actors     map[string]*nativecore.ServiceActorDataV1
	failActor  bool
	sessions   int
}

func (r *registryChain) BeginSession(context.Context) (Session, error) {
	r.sessions++
	return &registrySession{chain: r, checkpoint: r.checkpoint}, nil
}

type registrySession struct {
	chain      *registryChain
	checkpoint uint64
}

func (s *registrySession) Checkpoint() uint64   { return s.checkpoint }
func (s *registrySession) ChainTime() time.Time { return time.Unix(1_000_000, 0) }
func (s *registrySession) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	state, ok := s.chain.states[id]
	if !ok {
		return nil, false, nil
	}
	copied := proto.Clone(state).(*nativev1.NativeStateV1)
	copied.Reference = &nativev1.ChainReference{FinalizedCheckpoint: s.checkpoint}
	return copied, true, nil
}

func (s *registrySession) ReadActor(_ context.Context, address string) (*toschain.ActorAccount, bool, error) {
	if s.chain.failActor {
		return nil, false, errors.New("quorum not reached")
	}
	data, ok := s.chain.actors[address]
	if !ok {
		return nil, false, nil
	}
	return &toschain.ActorAccount{Address: address, CodeHash: codeHash, Data: data}, true, nil
}

func (s *registrySession) History(context.Context, string, *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	return nil, errors.New("not used")
}

func offerFixture(t *testing.T, count int) (*registryChain, manifests, []Candidate) {
	t.Helper()
	network := servicefixture.Network()
	chain := &registryChain{checkpoint: 9, states: map[string]*nativev1.NativeStateV1{}, actors: map[string]*nativecore.ServiceActorDataV1{}}
	sources := manifests{}
	var candidates []Candidate
	for index := 0; index < count; index++ {
		capability := "cap_" + strings.Repeat(hex.EncodeToString([]byte{byte(0x30 + index)}), 32)
		agent := "agent_" + strings.Repeat(hex.EncodeToString([]byte{byte(0x60 + index)}), 32)
		actorAccount := bytes.Repeat([]byte{byte(0x70 + index)}, 32)
		settlement := servicefixture.Settlement{ActorAccount: actorAccount, ActorCodeHash: bytes.Repeat([]byte{0x88}, 32),
			AttestorKey: mldsa44.KeyIDText(keyID)}
		manifest := servicefixture.Manifest("1.0.0", settlement)
		encoded, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		sources[digest] = encoded
		chain.states[capability] = &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Capability{
			Capability: &nativev1.CapabilityStateV1{CapabilityId: capability, OwnerAgentId: agent,
				Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: digest}}}}}
		chain.states[agent] = &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Agent{
			Agent: &nativev1.AgentStateV1{AgentId: agent}}}
		metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
			CapabilityID: capability, ProviderAgentID: agent, CapabilityVersion: "1.0.0", ManifestDigest: digest})
		if err != nil {
			t.Fatal(err)
		}
		actorPolicy := policy()
		actorPolicy.MetadataHash = metadata
		actorData, err := servicefixture.ActorData(owner, actorPolicy, 0, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		chain.actors["0:"+hex.EncodeToString(actorAccount)] = actorData
		candidates = append(candidates, Candidate{CapabilityID: capability, Version: "1.0.0"})
	}
	return chain, sources, candidates
}

func TestDiscoverOfferVerifiesTheBindingAtOneCheckpoint(t *testing.T) {
	chain, sources, candidates := offerFixture(t, 1)
	discovery, err := NewDiscovery(chain, servicefixture.Network(), sources, codeHash)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := discovery.DiscoverOffer(context.Background(), candidates[0], buyer)
	if err != nil {
		t.Fatal(err)
	}
	if offer.Checkpoint != 9 || offer.Actor != "0:"+strings.Repeat("70", 32) || offer.AttestorKeyID != mldsa44.KeyIDText(keyID) ||
		offer.PriceNanoTOS != "300000000" || offer.StorageFeeRefundable || offer.ActorCodeHash != codeHash {
		t.Fatalf("offer = %+v", offer)
	}
	if _, err := NewDiscovery(chain, servicefixture.Network(), sources, ""); err == nil {
		t.Fatal("discovery without a pinned release was configured")
	}
	// A manifest source serving other bytes for the digest is refused.
	for digest := range sources {
		sources[digest] = append([]byte(nil), sources[digest]...)
		sources[digest][len(sources[digest])-1] ^= 1
	}
	if _, err := discovery.DiscoverOffer(context.Background(), candidates[0], buyer); err == nil {
		t.Fatal("tampered manifest bytes were accepted")
	}
}

func TestListOffersReadsOnePageAtOneCheckpoint(t *testing.T) {
	chain, sources, candidates := offerFixture(t, 3)
	discovery, _ := NewDiscovery(chain, servicefixture.Network(), sources, codeHash)
	// Break the second candidate's actor binding: its actor is inactive.
	delete(chain.actors, "0:"+strings.Repeat("71", 32))
	page, err := discovery.ListOffers(context.Background(), append(candidates, candidates[0]), 2, nil, buyer)
	if err != nil {
		t.Fatal(err)
	}
	if chain.sessions != 1 || page.Checkpoint != 9 || len(page.Results) != 2 || page.NextAfter == nil ||
		page.Results[0].Offer == nil || page.Results[1].Offer != nil || page.Results[1].Error == "" {
		t.Fatalf("page = %+v (sessions %d)", page, chain.sessions)
	}
	rest, err := discovery.ListOffers(context.Background(), candidates, 2, page.NextAfter, buyer)
	if err != nil || len(rest.Results) != 1 || rest.Results[0].Offer == nil || rest.NextAfter != nil {
		t.Fatalf("rest = %+v %v", rest, err)
	}
	if _, err := discovery.ListOffers(context.Background(), candidates, MaxPageSize+1, nil, buyer); err == nil {
		t.Fatal("an oversized page was accepted")
	}
	chain.failActor = true
	if _, err := discovery.ListOffers(context.Background(), candidates, 2, nil, buyer); err == nil {
		t.Fatal("a read failure was reported as a per-offer verdict")
	}
}
