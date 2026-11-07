// Package quoteprovider constructs non-canonical, complete-preimage Quote
// Proposal packages from freshly finalized Capability state and the finalized
// policy of the Service Actor that manifest key 21 names. The proposal is a
// convenience; a buyer verifies every rail field itself before calling.
package quoteprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

type NativeResolver interface {
	ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error)
}

// ActorPolicySource reads the decoded current policy of a Service Actor
// from finalized state.
type ActorPolicySource interface {
	ResolveActorPolicy(ctx context.Context, actor string) (nativecore.ServiceActorPolicyV1, error)
}

type Config struct {
	Resolver          NativeResolver
	Network           *nativev1.NetworkDomain
	RegistryCodeHash  string
	ProviderAgentID   string
	Actors            ActorPolicySource
	ManifestCBOR      []byte
	Transport         nativecore.TransportBindingV1
	ProposalTTL       time.Duration
	ResolutionTimeout time.Duration
	CallerID          string
	Now               func() time.Time
	Random            func([]byte) error
}

type Provider struct {
	config         Config
	manifestDigest string
	version        string
	settlement     nativecore.SoftwareWorkSettlementV1
}

func New(config Config) (*Provider, error) {
	if config.Resolver == nil || config.Actors == nil || config.Network == nil || config.Network.NetworkId == "" ||
		config.RegistryCodeHash == "" || config.ProviderAgentID == "" ||
		len(config.ManifestCBOR) == 0 || config.CallerID == "" || len(config.CallerID) > 256 {
		return nil, errors.New("invalid Quote provider configuration")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(config.ManifestCBOR)
	if err != nil {
		return nil, errors.New("Quote provider manifest is not canonical")
	}
	canonical, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, config.ManifestCBOR) {
		return nil, errors.New("Quote provider manifest cannot be reproduced")
	}
	if _, _, err := nativecore.BuildTransportBindingCellV1(config.Transport); err != nil || !cellDigest(config.RegistryCodeHash) {
		return nil, errors.New("invalid Quote provider policy preimage")
	}
	if config.ProposalTTL == 0 {
		config.ProposalTTL = 15 * time.Minute
	}
	if config.ResolutionTimeout == 0 {
		config.ResolutionTimeout = 30 * time.Second
	}
	if config.ProposalTTL < time.Minute || config.ProposalTTL > time.Hour ||
		config.ResolutionTimeout < time.Second || config.ResolutionTimeout > time.Minute {
		return nil, errors.New("invalid Quote provider timing policy")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	config.Network = proto.Clone(config.Network).(*nativev1.NetworkDomain)
	config.ManifestCBOR = append([]byte(nil), config.ManifestCBOR...)
	return &Provider{config: config, manifestDigest: digest, version: manifest.Version, settlement: manifest.Settlement}, nil
}

func cellDigest(value string) bool {
	if len(value) != len("tvm-cell-sha256:")+64 || !strings.HasPrefix(value, "tvm-cell-sha256:") || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "tvm-cell-sha256:"))
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}

func (p *Provider) RequestQuoteProposal(ctx context.Context, request *nativev1.RequestQuoteProposalRequest) (*nativev1.QuoteProposalPackageV1, error) {
	if p == nil || ctx == nil || request == nil || request.Context == nil || request.Context.RequestId == "" ||
		request.CapabilityId == "" || request.CapabilityVersion != p.version || request.BuyerAddress == "" {
		return nil, errors.New("invalid provider Quote request")
	}
	call, cancel := context.WithTimeout(ctx, p.config.ResolutionTimeout)
	defer cancel()
	resolved, err := p.config.Resolver.ResolveNativeState(call, &nativev1.ResolveNativeStateRequest{Context: &nativev1.RequestContext{
		RequestId: request.Context.RequestId + "-quote-state", CallerId: p.config.CallerID,
		DeadlineUnixMillis: p.config.Now().Add(p.config.ResolutionTimeout).UnixMilli()}, ObjectId: request.CapabilityId})
	if err != nil || resolved == nil || !resolved.Found || resolved.State == nil {
		return nil, errors.New("Quote Capability is not available from finalized state")
	}
	state := resolved.State
	capability := state.GetCapability()
	if !proto.Equal(state.Network, p.config.Network) || state.Reference == nil || state.Reference.FinalizedCheckpoint == 0 ||
		state.Reference.ContractCodeHash != p.config.RegistryCodeHash || capability == nil || capability.Tombstoned ||
		capability.CapabilityId != request.CapabilityId || capability.OwnerAgentId != p.config.ProviderAgentID {
		return nil, errors.New("Quote Capability does not match provider authority")
	}
	active := false
	for _, version := range capability.Versions {
		if version != nil && version.Version == p.version && version.ManifestDigest == p.manifestDigest && !version.Revoked {
			active = true
		}
	}
	if !active {
		return nil, errors.New("Quote Capability version is not active")
	}
	actor := "0:" + hex.EncodeToString(p.settlement.ActorAccountID)
	policy, err := p.config.Actors.ResolveActorPolicy(call, actor)
	if err != nil {
		return nil, errors.New("Quote Service Actor policy is not available from finalized state")
	}
	attestor, err := mldsa44.ParseKeyIDText(p.settlement.AttestorKey)
	if err != nil || !policy.HasAttestor || policy.AttestorKeyID != attestor {
		return nil, errors.New("Quote Service Actor attestor differs from manifest key 21")
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: p.config.Network,
		CapabilityID: request.CapabilityId, ProviderAgentID: p.config.ProviderAgentID, CapabilityVersion: p.version,
		ManifestDigest: p.manifestDigest})
	if err != nil || policy.MetadataHash != metadata || policy.ProofSchemeHash != nativecore.ServiceActorSoftwareWorkProofScheme {
		return nil, errors.New("Quote Service Actor is not configured for this Capability version")
	}
	termsHash, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(policy))
	if err != nil || policy.PricePerCall.Sign() <= 0 {
		return nil, errors.New("Quote Service Actor policy cannot be quoted")
	}
	now := p.config.Now()
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(p.config.Transport)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if err := p.config.Random(nonce); err != nil {
		return nil, errors.New("generate Quote Proposal identity")
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-" + hex.EncodeToString(nonce),
		CapabilityId: request.CapabilityId, CapabilityVersion: p.version, ProviderAgentId: p.config.ProviderAgentID,
		ManifestDigest: p.manifestDigest, TransportBindingDigest: transportDigest,
		ExpiresAtUnixSeconds: uint64(now.Add(p.config.ProposalTTL).Unix()),
		Actor:                &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: append([]byte(nil), p.settlement.ActorAccountID...)},
		ActorCodeHash:        "tvm-cell-sha256:" + hex.EncodeToString(p.settlement.ActorCodeHash),
		PolicyVersion:        policy.PolicyVersion, TermsHash: hex.EncodeToString(termsHash[:]),
		PriceNanotos: policy.PricePerCall.String(), StorageFeeNanotos: policy.StorageFee.String(),
		AttestorKeyId: p.settlement.AttestorKey}
	value := &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: append([]byte(nil), p.config.ManifestCBOR...),
		TransportBindingBoc: transport.ToBOC()}
	if _, err := quoteexchange.Validate(p.config.Network, request, value, now); err != nil {
		return nil, errors.New("constructed Quote Proposal package failed validation")
	}
	return value, nil
}
