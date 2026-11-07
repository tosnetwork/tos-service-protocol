package serviceactorindex

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"google.golang.org/protobuf/proto"
)

// Offer is a Capability version whose manifest names a Service Actor that,
// at one finalized checkpoint, passes binding steps 1-4 and admission steps
// 5-7. Step 8 needs a Quote and is run by the buyer before calling.
type Offer struct {
	Checkpoint          uint64 `json:"checkpoint"`
	CapabilityID        string `json:"capability_id"`
	CapabilityVersion   string `json:"capability_version"`
	ProviderAgentID     string `json:"provider_agent_id"`
	ManifestDigest      string `json:"manifest_digest"`
	Actor               string `json:"actor"`
	ActorCodeHash       string `json:"actor_code_hash"`
	AttestorKeyID       string `json:"attestor_key_id"`
	PolicyVersion       uint32 `json:"policy_version"`
	TermsHash           string `json:"terms_hash"`
	PriceNanoTOS        string `json:"price_nanotos"`
	StorageFeeNanoTOS   string `json:"storage_fee_nanotos"`
	CleanupBountyNano   string `json:"cleanup_bounty_nanotos"`
	ResponseSLASeconds  uint32 `json:"response_sla_seconds"`
	RefundWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	OpenAccess          bool   `json:"open_access"`
	// StorageFeeRefundable is always false: the storage fee is not refunded.
	StorageFeeRefundable bool `json:"storage_fee_refundable"`
}

// Discovery answers offer queries from finalized state.
type Discovery struct {
	reader   Reader
	network  *nativev1.NetworkDomain
	manifest serviceactor.ManifestSource
	codeHash [32]byte
}

// NewDiscovery pins the network, the Service Actor release code hash and
// the manifest source.
func NewDiscovery(reader Reader, network *nativev1.NetworkDomain, manifests serviceactor.ManifestSource, actorCodeHash string) (*Discovery, error) {
	if reader == nil || network == nil || manifests == nil {
		return nil, errors.New("incomplete Service Actor discovery configuration")
	}
	codeHash, err := codeHashBytes(actorCodeHash)
	if err != nil {
		return nil, err
	}
	return &Discovery{reader: reader, network: proto.Clone(network).(*nativev1.NetworkDomain), manifest: manifests, codeHash: codeHash}, nil
}

func codeHashBytes(value string) ([32]byte, error) {
	var out [32]byte
	const prefix = "tvm-cell-sha256:"
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix {
		return out, errors.New("the Service Actor code hash must be pinned as tvm-cell-sha256:<hex>")
	}
	raw, err := hex.DecodeString(value[len(prefix):])
	if err != nil || hex.EncodeToString(raw) != value[len(prefix):] {
		return out, errors.New("the Service Actor code hash must be pinned as tvm-cell-sha256:<hex>")
	}
	copy(out[:], raw)
	return out, nil
}

// Candidate names one Capability version to discover.
type Candidate struct {
	CapabilityID string
	Version      string
}

// DiscoverOffer verifies one candidate at a fresh checkpoint. buyer, when
// set, must be admitted by the actor's access gate.
func (d *Discovery) DiscoverOffer(ctx context.Context, candidate Candidate, buyer string) (*Offer, error) {
	session, err := d.reader.BeginSession(ctx)
	if err != nil {
		return nil, err
	}
	return d.discoverAt(ctx, session, candidate, buyer)
}

func (d *Discovery) discoverAt(ctx context.Context, session Session, candidate Candidate, buyer string) (*Offer, error) {
	evidence, err := serviceactor.Gather(ctx, session, d.network, d.manifest, candidate.CapabilityID, candidate.Version)
	if err != nil {
		return nil, err
	}
	admission, err := serviceactor.VerifyAdmission(evidence, d.codeHash, nil, nil, buyer)
	if err != nil {
		return nil, err
	}
	policy := admission.Policy
	capability := evidence.Capability.GetCapability()
	return &Offer{Checkpoint: evidence.Checkpoint, CapabilityID: capability.CapabilityId, CapabilityVersion: evidence.Version,
		ProviderAgentID: capability.OwnerAgentId, ManifestDigest: evidence.ManifestDigest, Actor: admission.Binding.Actor,
		ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(admission.Binding.ActorCodeHash[:]),
		AttestorKeyID: mldsa44.KeyIDText(admission.Binding.AttestorKeyID), PolicyVersion: policy.PolicyVersion,
		TermsHash: hex.EncodeToString(admission.TermsHash[:]), PriceNanoTOS: policy.PricePerCall.String(),
		StorageFeeNanoTOS: policy.StorageFee.String(), CleanupBountyNano: policy.CleanupBounty.String(),
		ResponseSLASeconds: policy.ResponseSLA, RefundWindowSeconds: policy.RefundClaimWindow, OpenAccess: policy.OpenAccess}, nil
}

// OfferResult is one entry of an offer page: an offer or the reason the
// candidate failed verification.
type OfferResult struct {
	Candidate Candidate `json:"candidate"`
	Offer     *Offer    `json:"offer,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// OfferPage is a page of offers, every entry read at one checkpoint.
type OfferPage struct {
	Checkpoint uint64        `json:"checkpoint"`
	Results    []OfferResult `json:"results"`
	NextAfter  *Candidate    `json:"next_after,omitempty"`
}

// ListOffers verifies a sorted, bounded page of candidates at one checkpoint.
func (d *Discovery) ListOffers(ctx context.Context, candidates []Candidate, pageSize int, after *Candidate, buyer string) (*OfferPage, error) {
	if pageSize <= 0 || pageSize > MaxPageSize {
		return nil, fmt.Errorf("page size must be 1 to %d", MaxPageSize)
	}
	sorted := append([]Candidate(nil), candidates...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CapabilityID != sorted[j].CapabilityID {
			return sorted[i].CapabilityID < sorted[j].CapabilityID
		}
		return sorted[i].Version < sorted[j].Version
	})
	session, err := d.reader.BeginSession(ctx)
	if err != nil {
		return nil, err
	}
	page := &OfferPage{Checkpoint: session.Checkpoint()}
	for index, candidate := range sorted {
		if index > 0 && candidate == sorted[index-1] {
			continue
		}
		if after != nil && (candidate.CapabilityID < after.CapabilityID ||
			candidate.CapabilityID == after.CapabilityID && candidate.Version <= after.Version) {
			continue
		}
		if len(page.Results) == pageSize {
			last := page.Results[len(page.Results)-1].Candidate
			page.NextAfter = &last
			break
		}
		offer, err := d.discoverAt(ctx, session, candidate, buyer)
		result := OfferResult{Candidate: candidate, Offer: offer}
		if err != nil {
			var step *serviceactor.StepError
			if !errors.As(err, &step) {
				// A read failure is not a per-offer verdict: refuse the page.
				return nil, err
			}
			result.Offer, result.Error = nil, err.Error()
		}
		page.Results = append(page.Results, result)
	}
	return page, nil
}
