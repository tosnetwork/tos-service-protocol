// Package providersdk implements the first Gate E provider workflow over the
// canonical Native Submit/Resolve API. It prepares Capability publication,
// accepts externally produced controller signatures, and waits for finalized
// typed TOS state. It owns neither keys nor a provider database.
package providersdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

const MaxManifestJSONBytes = 1 << 20

type NativeClient interface {
	SubmitNativeAction(context.Context, *nativev1.SubmitNativeActionRequest) (*nativev1.SubmitNativeActionResponse, error)
	ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error)
	PublishSoftwareWorkManifest(context.Context, *nativev1.PublishSoftwareWorkManifestRequest) (*nativev1.PublishSoftwareWorkManifestResponse, error)
}

// PublishManifest sends immutable canonical bytes to the gateway's derived
// catalog only after Capability publication has finalized. Catalog admission
// re-resolves the Capability and cannot create a canonical registry fact.
func (p *Provider) PublishManifest(ctx context.Context, prepared *PreparedPublication, idempotencyKey string) (*nativev1.NativeStateV1, error) {
	if p == nil || ctx == nil || prepared == nil || prepared.Action == nil || idempotencyKey == "" || len(idempotencyKey) > 256 {
		return nil, errors.New("invalid provider manifest publication request")
	}
	manifestHash := sha256.Sum256(prepared.ManifestCBOR)
	registration := prepared.Action.GetRegisterCapability()
	built, err := nativecore.BuildAction(prepared.Action)
	if err != nil || registration == nil || registration.InitialVersion == nil ||
		"sha256:"+hex.EncodeToString(manifestHash[:]) != prepared.ManifestDigest ||
		built.HashString != prepared.ActionHash || prepared.CapabilityID != prepared.Action.TargetObjectId ||
		registration.InitialVersion.ManifestDigest != prepared.ManifestDigest {
		return nil, errors.New("prepared Capability manifest changed after review")
	}
	requestContext, err := p.requestContext(idempotencyKey)
	if err != nil {
		return nil, err
	}
	response, err := p.client.PublishSoftwareWorkManifest(ctx, &nativev1.PublishSoftwareWorkManifestRequest{
		Context: requestContext, CapabilityId: prepared.CapabilityID, CanonicalCbor: append([]byte(nil), prepared.ManifestCBOR...),
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.ManifestDigest != prepared.ManifestDigest || !p.validStateEnvelope(response.Capability) {
		return nil, errors.New("gateway did not admit manifest against exact finalized Capability state")
	}
	capability := response.Capability.GetCapability()
	if capability == nil || capability.CapabilityId != prepared.CapabilityID || capability.Tombstoned {
		return nil, errors.New("gateway manifest admission returned conflicting Capability state")
	}
	for _, version := range capability.Versions {
		if version != nil && version.Version == registration.InitialVersion.Version &&
			version.ManifestDigest == prepared.ManifestDigest && !version.Revoked {
			return proto.Clone(response.Capability).(*nativev1.NativeStateV1), nil
		}
	}
	return nil, errors.New("gateway manifest admission omitted the committed Capability version")
}

type Config struct {
	Client NativeClient
	// Verifier checks controller signatures against the finalized owner
	// policy before anything is relayed. It is required.
	Verifier         mldsa44.Verifier
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	CallerID         string
	PollInterval     time.Duration
	FinalityTimeout  time.Duration
	Now              func() time.Time
}

type Provider struct {
	client           NativeClient
	verifier         mldsa44.Verifier
	network          *nativev1.NetworkDomain
	registryCodeHash string
	callerID         string
	pollInterval     time.Duration
	finalityTimeout  time.Duration
	now              func() time.Time
}

type PreparedPublication struct {
	CapabilityID   string                   `json:"capability_id"`
	ManifestDigest string                   `json:"manifest_digest"`
	ManifestCBOR   []byte                   `json:"manifest_cbor"`
	ActionHash     string                   `json:"action_hash"`
	Action         *nativev1.NativeActionV1 `json:"action"`
}

func New(config Config) (*Provider, error) {
	if config.Client == nil || config.Verifier == nil || config.Network == nil || config.CallerID == "" ||
		len(config.CallerID) > 256 || config.RegistryCodeHash == "" {
		return nil, errors.New("invalid provider SDK configuration")
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.FinalityTimeout == 0 {
		config.FinalityTimeout = 5 * time.Minute
	}
	if config.PollInterval < 10*time.Millisecond || config.PollInterval > time.Minute ||
		config.FinalityTimeout <= config.PollInterval || config.FinalityTimeout > time.Hour {
		return nil, errors.New("invalid provider finality policy")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	// BuildAction below validates the code hash, but validate it at construction
	// so a malformed deployment configuration cannot survive until publication.
	probeOwner := "agent_" + string(bytes.Repeat([]byte{'1'}, 64))
	probeVersion := &nativev1.CapabilityVersionV1{Version: "probe", ManifestDigest: "sha256:" + string(bytes.Repeat([]byte{'1'}, 64))}
	probeObjectNonce := bytes.Repeat([]byte{1}, 32)
	probeID, err := nativecore.DeriveCapabilityID(config.Network, probeObjectNonce, probeOwner, probeVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid provider Native domain: %w", err)
	}
	probe := &nativev1.NativeActionV1{Protocol: nativecore.Protocol, Network: config.Network,
		TargetObjectId:         probeID,
		TargetContractCodeHash: config.RegistryCodeHash, Generation: 1, Sequence: 1,
		Nonce: bytes.Repeat([]byte{1}, 32), Payload: &nativev1.NativeActionV1_RegisterCapability{
			RegisterCapability: &nativev1.RegisterCapabilityV1{ObjectNonce: probeObjectNonce,
				OwnerAgentId: probeOwner, InitialVersion: probeVersion}}}
	if _, err := nativecore.BuildAction(probe); err != nil {
		return nil, fmt.Errorf("invalid provider Native domain: %w", err)
	}
	return &Provider{client: config.Client, verifier: config.Verifier, network: proto.Clone(config.Network).(*nativev1.NetworkDomain),
		registryCodeHash: config.RegistryCodeHash, callerID: config.CallerID,
		pollInterval: config.PollInterval, finalityTimeout: config.FinalityTimeout, now: config.Now}, nil
}

func (p *Provider) PrepareCapabilityPublication(manifestJSON []byte, ownerAgentID string, objectNonce, actionNonce []byte) (*PreparedPublication, error) {
	if p == nil || len(manifestJSON) == 0 || len(manifestJSON) > MaxManifestJSONBytes {
		return nil, errors.New("invalid provider manifest input")
	}
	manifest, err := nativecore.DecodeSoftwareWorkManifestJSON(manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("decode provider manifest: %w", err)
	}
	manifestCBOR, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode provider manifest: %w", err)
	}
	version := &nativev1.CapabilityVersionV1{Version: manifest.Version, ManifestDigest: digest}
	capabilityID, err := nativecore.DeriveCapabilityID(p.network, objectNonce, ownerAgentID, version)
	if err != nil {
		return nil, fmt.Errorf("derive Capability identity: %w", err)
	}
	action := &nativev1.NativeActionV1{Protocol: nativecore.Protocol, Network: proto.Clone(p.network).(*nativev1.NetworkDomain),
		TargetObjectId: capabilityID, TargetContractCodeHash: p.registryCodeHash,
		Generation: 1, Sequence: 1, Nonce: append([]byte(nil), actionNonce...),
		Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: append([]byte(nil), objectNonce...), OwnerAgentId: ownerAgentID, InitialVersion: version}}}
	built, err := nativecore.BuildAction(action)
	if err != nil {
		return nil, fmt.Errorf("build Capability registration: %w", err)
	}
	return &PreparedPublication{CapabilityID: capabilityID, ManifestDigest: digest,
		ManifestCBOR: manifestCBOR, ActionHash: built.HashString, Action: action}, nil
}

func (p *Provider) PublishCapability(ctx context.Context, prepared *PreparedPublication, signatures []*nativev1.SignatureV1, idempotencyKey string) (*nativev1.NativeStateV1, error) {
	if p == nil || ctx == nil || prepared == nil || prepared.Action == nil || idempotencyKey == "" || len(idempotencyKey) > 256 {
		return nil, errors.New("invalid provider publication request")
	}
	manifestHash := sha256.Sum256(prepared.ManifestCBOR)
	if "sha256:"+hex.EncodeToString(manifestHash[:]) != prepared.ManifestDigest {
		return nil, errors.New("prepared Capability manifest changed after review")
	}
	built, err := nativecore.BuildAction(prepared.Action)
	registration := prepared.Action.GetRegisterCapability()
	if err != nil || built.Kind != nativecore.KindRegisterCapability || registration == nil ||
		built.HashString != prepared.ActionHash || prepared.CapabilityID != prepared.Action.TargetObjectId ||
		registration.InitialVersion == nil || registration.InitialVersion.ManifestDigest != prepared.ManifestDigest {
		return nil, errors.New("prepared Capability publication changed after review")
	}
	owner, err := p.resolve(ctx, registration.OwnerAgentId)
	if err != nil {
		return nil, fmt.Errorf("resolve Capability owner: %w", err)
	}
	if owner.GetAgent() == nil || owner.GetAgent().AgentId != registration.OwnerAgentId ||
		owner.GetAgent().Tombstoned || owner.GetAgent().Policy == nil ||
		!p.validStateEnvelope(owner) {
		return nil, errors.New("Capability owner is not a live finalized Agent")
	}
	if err := nativecore.VerifySignatures(ctx, p.verifier, owner.GetAgent().Policy, signatures,
		nativecore.PurposeCapabilityControl, false, built); err != nil {
		return nil, fmt.Errorf("verify Capability controller signatures: %w", err)
	}
	requestContext, err := p.requestContext(idempotencyKey)
	if err != nil {
		return nil, err
	}
	request := &nativev1.SubmitNativeActionRequest{Context: requestContext,
		Submission: &nativev1.SignedNativeActionV1{Action: proto.Clone(prepared.Action).(*nativev1.NativeActionV1),
			AuthoritySignatures: cloneSignatures(signatures)}}
	response, err := p.client.SubmitNativeAction(ctx, request)
	if err != nil {
		return nil, err
	}
	if response == nil || !response.RelayAccepted || response.ActionHash != built.HashString {
		return nil, errors.New("gateway did not acknowledge the exact Capability action")
	}
	return p.waitForPublication(ctx, prepared, registration, built.HashString)
}

func (p *Provider) waitForPublication(ctx context.Context, prepared *PreparedPublication, registration *nativev1.RegisterCapabilityV1, actionHash string) (*nativev1.NativeStateV1, error) {
	waitCtx, cancel := context.WithTimeout(ctx, p.finalityTimeout)
	defer cancel()
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()
	for {
		state, found, err := p.resolveFound(waitCtx, prepared.CapabilityID)
		if err != nil {
			return nil, err
		}
		if found {
			capability := state.GetCapability()
			if capability == nil || capability.LastActionHash != actionHash {
				return nil, errors.New("finalized Capability state conflicts with publication")
			}
			if err := p.validatePublishedState(state, registration, prepared); err != nil {
				return nil, err
			}
			return state, nil
		}
		select {
		case <-waitCtx.Done():
			return nil, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func (p *Provider) validatePublishedState(state *nativev1.NativeStateV1, registration *nativev1.RegisterCapabilityV1, prepared *PreparedPublication) error {
	capability := state.GetCapability()
	if !p.validStateEnvelope(state) ||
		capability == nil || capability.CapabilityId != prepared.CapabilityID || capability.Generation != 1 ||
		capability.Sequence != 1 || capability.OwnerAgentId != registration.OwnerAgentId || capability.Tombstoned ||
		len(capability.Versions) != 1 || capability.Versions[0].Version != registration.InitialVersion.Version ||
		capability.Versions[0].ManifestDigest != prepared.ManifestDigest || capability.Versions[0].Revoked {
		return errors.New("finalized Capability state does not match publication")
	}
	return nil
}

func (p *Provider) validStateEnvelope(state *nativev1.NativeStateV1) bool {
	return state != nil && proto.Equal(state.Network, p.network) && state.TvmStateHash != "" &&
		state.Reference != nil && state.Reference.FinalizedCheckpoint != 0 &&
		state.Reference.ContractCodeHash == p.registryCodeHash
}

func (p *Provider) resolve(ctx context.Context, objectID string) (*nativev1.NativeStateV1, error) {
	state, found, err := p.resolveFound(ctx, objectID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("finalized Native object was not found")
	}
	return state, nil
}

func (p *Provider) resolveFound(ctx context.Context, objectID string) (*nativev1.NativeStateV1, bool, error) {
	requestContext, err := p.requestContext("")
	if err != nil {
		return nil, false, err
	}
	response, err := p.client.ResolveNativeState(ctx, &nativev1.ResolveNativeStateRequest{
		Context: requestContext, ObjectId: objectID,
	})
	if err != nil {
		return nil, false, err
	}
	if response == nil || response.Found != (response.State != nil) {
		return nil, false, errors.New("gateway returned an incoherent Native resolution")
	}
	return response.State, response.Found, nil
}

func (p *Provider) requestContext(idempotencyKey string) (*nativev1.RequestContext, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("generate Native request identity")
	}
	return &nativev1.RequestContext{RequestId: hex.EncodeToString(nonce[:]), CallerId: p.callerID,
		IdempotencyKey: idempotencyKey, DeadlineUnixMillis: p.now().Add(p.finalityTimeout).UnixMilli()}, nil
}

func cloneSignatures(values []*nativev1.SignatureV1) []*nativev1.SignatureV1 {
	result := make([]*nativev1.SignatureV1, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = proto.Clone(value).(*nativev1.SignatureV1)
		}
	}
	return result
}
