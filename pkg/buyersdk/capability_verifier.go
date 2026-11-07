package buyersdk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

// NativeClient resolves finalized typed Native Registry state.
type NativeClient interface {
	ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error)
}

type CapabilityVerifierConfig struct {
	NativeClient     NativeClient
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	CallerID         string
	Timeout          time.Duration
	Now              func() time.Time
}

type CapabilityExpectation struct {
	CapabilityID   string
	OwnerAgentID   string
	Version        string
	ManifestDigest string
}

type CapabilityObservation struct {
	State               *nativev1.NativeStateV1
	FinalizedCheckpoint uint64
}

type CapabilityVerifier struct {
	client           NativeClient
	network          *nativev1.NetworkDomain
	registryCodeHash string
	callerID         string
	timeout          time.Duration
	now              func() time.Time
}

var (
	ErrCapabilityRejected = errors.New("finalized Capability does not match expectation")
	capabilityIDPattern   = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	agentIDPattern        = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	digest256Pattern      = regexp.MustCompile(`^(sha256|tvm-cell-sha256):[0-9a-f]{64}$`)
	capVersionPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

func NewCapabilityVerifier(config CapabilityVerifierConfig) (*CapabilityVerifier, error) {
	if config.NativeClient == nil || config.Network == nil || config.Network.NetworkId == "" ||
		!digest256Pattern.MatchString(config.Network.GenesisRootHash) ||
		!digest256Pattern.MatchString(config.Network.GenesisFileHash) ||
		!strings.HasPrefix(config.RegistryCodeHash, "tvm-cell-sha256:") ||
		!digest256Pattern.MatchString(config.RegistryCodeHash) || config.CallerID == "" || len(config.CallerID) > 128 {
		return nil, errors.New("invalid finalized Capability verifier authority")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < time.Second || config.Timeout > 5*time.Minute {
		return nil, errors.New("finalized Capability verifier timeout is outside bounds")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &CapabilityVerifier{client: config.NativeClient, network: proto.Clone(config.Network).(*nativev1.NetworkDomain),
		registryCodeHash: config.RegistryCodeHash, callerID: config.CallerID, timeout: config.Timeout, now: config.Now}, nil
}

func (v *CapabilityVerifier) Verify(ctx context.Context, expected CapabilityExpectation) (CapabilityObservation, error) {
	if v == nil || ctx == nil || !capabilityIDPattern.MatchString(expected.CapabilityID) ||
		!agentIDPattern.MatchString(expected.OwnerAgentID) || !capVersionPattern.MatchString(expected.Version) ||
		len(expected.ManifestDigest) < len("sha256:") || expected.ManifestDigest[:len("sha256:")] != "sha256:" ||
		!digest256Pattern.MatchString(expected.ManifestDigest) {
		return CapabilityObservation{}, errors.New("invalid finalized Capability expectation")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return CapabilityObservation{}, errors.New("generate Capability verification request")
	}
	now := v.now()
	if now.IsZero() || now.Unix() <= 0 {
		return CapabilityObservation{}, errors.New("invalid Capability verifier clock")
	}
	call, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	response, err := v.client.ResolveNativeState(call, &nativev1.ResolveNativeStateRequest{
		Context: &nativev1.RequestContext{RequestId: hex.EncodeToString(nonce[:]), CallerId: v.callerID,
			DeadlineUnixMillis: now.Add(v.timeout).UnixMilli()}, ObjectId: expected.CapabilityID,
	})
	if err != nil {
		return CapabilityObservation{}, err
	}
	if err := validateCapabilityResponse(response, v.network, v.registryCodeHash, expected); err != nil {
		return CapabilityObservation{}, err
	}
	return CapabilityObservation{State: proto.Clone(response.State).(*nativev1.NativeStateV1),
		FinalizedCheckpoint: response.State.Reference.FinalizedCheckpoint}, nil
}

func validateCapabilityResponse(response *nativev1.ResolveNativeStateResponse, network *nativev1.NetworkDomain,
	registryCodeHash string, expected CapabilityExpectation) error {
	if response == nil || !response.Found || response.State == nil || !proto.Equal(response.State.Network, network) ||
		response.State.TvmStateHash == "" || response.State.Reference == nil || response.State.Reference.FinalizedCheckpoint == 0 ||
		response.State.Reference.ContractCodeHash != registryCodeHash {
		return fmt.Errorf("%w: unavailable typed state", ErrCapabilityRejected)
	}
	capability := response.State.GetCapability()
	if capability == nil || capability.CapabilityId != expected.CapabilityID ||
		capability.OwnerAgentId != expected.OwnerAgentID || capability.Tombstoned {
		return fmt.Errorf("%w: provider ownership or lifecycle", ErrCapabilityRejected)
	}
	for _, version := range capability.Versions {
		if version != nil && version.Version == expected.Version && version.ManifestDigest == expected.ManifestDigest && !version.Revoked {
			return nil
		}
	}
	return fmt.Errorf("%w: version absent or revoked", ErrCapabilityRejected)
}
