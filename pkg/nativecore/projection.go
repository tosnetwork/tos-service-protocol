package nativecore

import (
	"encoding/hex"
	"errors"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// PortableProjection is an off-chain interchange view. It is never accepted
// by BuildAction, MessageBody, or the contract as a consensus input.
type PortableProjection struct {
	Protocol     string                   `json:"protocol"`
	Network      PortableNetwork          `json:"network"`
	TVMStateHash string                   `json:"tvm_state_hash"`
	Agent        *PortableAgentState      `json:"agent,omitempty"`
	Capability   *PortableCapabilityState `json:"capability,omitempty"`
}
type PortableNetwork struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}
type PortableController struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"mldsa44_public_key"`
	Weight      uint32 `json:"weight"`
	PurposeMask uint32 `json:"purpose_mask"`
	Recovery    bool   `json:"recovery"`
}
type PortablePolicy struct {
	Threshold               uint32               `json:"threshold"`
	RecoveryThreshold       uint32               `json:"recovery_threshold"`
	RecoveryTimelockSeconds uint64               `json:"recovery_timelock_seconds"`
	Controllers             []PortableController `json:"controllers"`
}
type PortableAgentState struct {
	AgentID                         string          `json:"agent_id"`
	Generation                      uint64          `json:"generation"`
	Sequence                        uint64          `json:"sequence"`
	LastActionHash                  string          `json:"last_action_hash"`
	Policy                          PortablePolicy  `json:"policy"`
	DelegationDigests               []string        `json:"delegation_digests"`
	RecoveryExecuteAfterUnixSeconds uint64          `json:"recovery_execute_after_unix_seconds"`
	RecoveryInitiationActionHash    string          `json:"recovery_initiation_action_hash"`
	RecoveryInitiatingPolicyHash    string          `json:"recovery_initiating_policy_hash"`
	RecoveryPolicy                  *PortablePolicy `json:"recovery_policy,omitempty"`
	Tombstoned                      bool            `json:"tombstoned"`
}
type PortableCapabilityVersion struct {
	Version        string `json:"version"`
	ManifestDigest string `json:"manifest_digest"`
	Revoked        bool   `json:"revoked"`
}
type PortableCapabilityState struct {
	CapabilityID   string                      `json:"capability_id"`
	Generation     uint64                      `json:"generation"`
	Sequence       uint64                      `json:"sequence"`
	LastActionHash string                      `json:"last_action_hash"`
	OwnerAgentID   string                      `json:"owner_agent_id"`
	Versions       []PortableCapabilityVersion `json:"versions"`
	Tombstoned     bool                        `json:"tombstoned"`
}

// DecodePortable derives deterministic CBOR exclusively from typed TVM data.
func (l *Locator) DecodePortable(data *cell.Cell, objectID string) ([]byte, bool, error) {
	state, found, err := l.DecodeData(data, objectID)
	if err != nil || !found {
		return nil, found, err
	}
	projection := PortableProjection{Protocol: Protocol, TVMStateHash: state.TvmStateHash,
		Network: PortableNetwork{NetworkID: state.Network.NetworkId, GenesisRootHash: state.Network.GenesisRootHash, GenesisFileHash: state.Network.GenesisFileHash}}
	if agent := state.GetAgent(); agent != nil {
		policy, err := projectPolicy(agent.Policy)
		if err != nil {
			return nil, false, err
		}
		value := &PortableAgentState{AgentID: agent.AgentId, Generation: agent.Generation, Sequence: agent.Sequence,
			LastActionHash: agent.LastActionHash, Policy: policy, DelegationDigests: append([]string(nil), agent.DelegationDigests...),
			RecoveryExecuteAfterUnixSeconds: agent.RecoveryExecuteAfterUnixSeconds, RecoveryInitiationActionHash: agent.RecoveryInitiationActionHash,
			RecoveryInitiatingPolicyHash: agent.RecoveryInitiatingPolicyHash, Tombstoned: agent.Tombstoned}
		if agent.RecoveryPolicy != nil {
			p, err := projectPolicy(agent.RecoveryPolicy)
			if err != nil {
				return nil, false, err
			}
			value.RecoveryPolicy = &p
		}
		projection.Agent = value
	} else if capability := state.GetCapability(); capability != nil {
		versions := make([]PortableCapabilityVersion, len(capability.Versions))
		for i, v := range capability.Versions {
			if v == nil {
				return nil, false, errors.New("nil Native Capability version")
			}
			versions[i] = PortableCapabilityVersion{Version: v.Version, ManifestDigest: v.ManifestDigest, Revoked: v.Revoked}
		}
		projection.Capability = &PortableCapabilityState{CapabilityID: capability.CapabilityId, Generation: capability.Generation,
			Sequence: capability.Sequence, LastActionHash: capability.LastActionHash, OwnerAgentID: capability.OwnerAgentId,
			Versions: versions, Tombstoned: capability.Tombstoned}
	} else {
		return nil, false, errors.New("missing Native typed state")
	}
	encoded, err := codec.Marshal(projection)
	return encoded, true, err
}

func projectPolicy(value interface {
	GetThreshold() uint32
	GetRecoveryThreshold() uint32
	GetRecoveryTimelockSeconds() uint64
	GetControllers() []*nativev1.ControllerV1
}) (PortablePolicy, error) {
	controllers := value.GetControllers()
	result := make([]PortableController, len(controllers))
	for i, controller := range controllers {
		if controller == nil {
			return PortablePolicy{}, errors.New("nil Native controller")
		}
		result[i] = PortableController{KeyID: controller.KeyId, PublicKey: hex.EncodeToString(controller.Mldsa44PublicKey), Weight: controller.Weight, PurposeMask: controller.PurposeMask, Recovery: controller.Recovery}
	}
	return PortablePolicy{Threshold: value.GetThreshold(), RecoveryThreshold: value.GetRecoveryThreshold(), RecoveryTimelockSeconds: value.GetRecoveryTimelockSeconds(), Controllers: result}, nil
}
