// Package nativewallet provides local, review-before-signing support for
// tos_service_v1 actions. Controller keys are ML-DSA-44 keys held in tosctl
// custody: this package names controllers and receives signatures, and it
// never reads, holds or passes private key material. It never submits a
// transaction or grants a gateway access to controller keys.
package nativewallet

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
)

type Review struct {
	Protocol               string          `json:"protocol"`
	NetworkID              string          `json:"network_id"`
	GenesisRootHash        string          `json:"genesis_root_hash"`
	GenesisFileHash        string          `json:"genesis_file_hash"`
	TargetObjectID         string          `json:"target_object_id"`
	TargetContractCodeHash string          `json:"target_contract_code_hash"`
	Generation             uint64          `json:"generation"`
	Sequence               uint64          `json:"sequence"`
	PredecessorStateHash   string          `json:"predecessor_tvm_state_hash,omitempty"`
	Action                 string          `json:"action"`
	ActionHash             string          `json:"action_hash"`
	SignedAction           json.RawMessage `json:"signed_action"`
}

func ReviewAction(action *nativev1.NativeActionV1) (Review, nativecore.BuiltAction, error) {
	built, err := nativecore.BuildAction(action)
	if err != nil {
		return Review{}, nativecore.BuiltAction{}, err
	}
	signedAction, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(action)
	if err != nil {
		return Review{}, nativecore.BuiltAction{}, err
	}
	return Review{Protocol: action.Protocol, NetworkID: action.Network.NetworkId,
		GenesisRootHash: action.Network.GenesisRootHash, GenesisFileHash: action.Network.GenesisFileHash,
		TargetObjectID: action.TargetObjectId, TargetContractCodeHash: action.TargetContractCodeHash,
		Generation: action.Generation, Sequence: action.Sequence, PredecessorStateHash: action.PredecessorTvmStateHash,
		Action: actionName(action), ActionHash: built.HashString, SignedAction: signedAction}, built, nil
}

// Sign asks custody to sign the reviewed action once with each named
// controller and returns the signature set in ascending key-ID byte order,
// the only order the Registry accepts. It refuses an empty set, more than
// the Registry's signature width, a repeated controller name, and two names
// that resolve to the same key.
func Sign(ctx context.Context, signer mldsa44.Signer, built nativecore.BuiltAction, controllers []string) ([]*nativev1.SignatureV1, error) {
	if ctx == nil || signer == nil || built.Cell == nil || len(controllers) == 0 || len(controllers) > nativecore.MaxSignatures {
		return nil, errors.New("invalid Native wallet signing request")
	}
	names := make(map[string]struct{}, len(controllers))
	keys := make(map[string]string, len(controllers))
	result := make([]*nativev1.SignatureV1, 0, len(controllers))
	for _, controller := range controllers {
		if strings.TrimSpace(controller) == "" {
			return nil, errors.New("empty Native wallet controller name")
		}
		if _, duplicate := names[controller]; duplicate {
			return nil, fmt.Errorf("Native wallet controller %q is named twice", controller)
		}
		names[controller] = struct{}{}
		signature, err := nativecore.SignAction(ctx, signer, controller, built)
		if err != nil {
			return nil, err
		}
		if other, duplicate := keys[signature.KeyId]; duplicate {
			return nil, fmt.Errorf("Native wallet controllers %q and %q hold the same key", other, controller)
		}
		keys[signature.KeyId] = controller
		result = append(result, signature)
	}
	return nativecore.SortSignatures(result), nil
}

func actionName(action *nativev1.NativeActionV1) string {
	switch action.Payload.(type) {
	case *nativev1.NativeActionV1_RegisterAgent:
		return "register_agent"
	case *nativev1.NativeActionV1_UpdateAgentPolicy:
		return "update_agent_policy"
	case *nativev1.NativeActionV1_DelegateAgent:
		return "delegate_agent"
	case *nativev1.NativeActionV1_InitiateRecovery:
		return "initiate_recovery"
	case *nativev1.NativeActionV1_CompleteRecovery:
		return "complete_recovery"
	case *nativev1.NativeActionV1_RevokeAgent:
		return "revoke_agent"
	case *nativev1.NativeActionV1_RegisterCapability:
		return "register_capability"
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		return "add_capability_version"
	case *nativev1.NativeActionV1_TransferCapability:
		return "transfer_capability"
	case *nativev1.NativeActionV1_RevokeCapability:
		return "revoke_capability"
	default:
		return "unknown"
	}
}

// ConfirmHash requires the operator to type the complete action hash. A simple
// yes/no prompt is intentionally insufficient for a value-bearing mutation.
func ConfirmHash(input *bufio.Reader, expected string) error {
	if input == nil || expected == "" {
		return errors.New("invalid Native semantic confirmation")
	}
	value, err := input.ReadString('\n')
	if err != nil && value == "" {
		return err
	}
	if strings.TrimSpace(value) != expected {
		return errors.New("Native action hash confirmation mismatch")
	}
	return nil
}
