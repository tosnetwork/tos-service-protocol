package nativecore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// opAuthorizedCapability is the opcode an owner Agent account uses to forward
// an authorized Capability action to the Capability account.
const opAuthorizedCapability = 0x4e560003

// RegistryTransitionKind names a terminal Registry liveness transition.
type RegistryTransitionKind uint8

const (
	// RegistryAgentTombstone is a revoke_agent action on an Agent account.
	RegistryAgentTombstone RegistryTransitionKind = iota + 1
	// RegistryCapabilityTombstone is a revoke_capability action without a
	// version on a Capability account.
	RegistryCapabilityTombstone
	// RegistryVersionRevocation is a revoke_capability action naming one
	// version on a Capability account.
	RegistryVersionRevocation
)

// RegistryTransitionV1 is a Registry inbound body that tombstones an object
// or revokes one Capability version.
type RegistryTransitionV1 struct {
	Kind RegistryTransitionKind
	// ObjectID is the target object, agent_<hex> or cap_<hex>.
	ObjectID string
	// ActionHash is the action cell hash, sha256:<hex>, the value a Registry
	// state records as last_action_hash once the action is applied.
	ActionHash string
	// Version is the revoked version name, for a version revocation only.
	Version string
}

// DecodeRegistryTransition decodes a Registry inbound body exactly as the
// contract reads it, opcode:uint32 query_id:uint64 ^action ^authority
// ^counterparty, and accepts only the three liveness transitions: a
// revoke_agent action submitted to an Agent account, and a revoke_capability
// action forwarded by the owner Agent to a Capability account, with or without
// a version. Any other body, including any other action, is an error.
func DecodeRegistryTransition(body *cell.Cell) (RegistryTransitionV1, error) {
	if body == nil || body.IsSpecial() {
		return RegistryTransitionV1{}, errors.New("Registry body is not an ordinary cell")
	}
	s, err := body.BeginParse()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("invalid Registry body")
	}
	opcode, err := s.LoadUInt(32)
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry body has no opcode")
	}
	if _, err := s.LoadUInt(64); err != nil {
		return RegistryTransitionV1{}, errors.New("Registry body has no query ID")
	}
	action, err := s.LoadRefCell()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry body has no action")
	}
	for _, name := range []string{"authority", "counterparty"} {
		if _, err := s.LoadRefCell(); err != nil {
			return RegistryTransitionV1{}, errors.New("Registry body has no " + name + " set")
		}
	}
	if err := endSlice(s); err != nil {
		return RegistryTransitionV1{}, err
	}
	if action.IsSpecial() {
		return RegistryTransitionV1{}, errors.New("Registry action is not an ordinary cell")
	}
	a, err := action.BeginParse()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("invalid Registry action")
	}
	magic, err := a.LoadUInt(32)
	if err != nil || magic != actionMagic {
		return RegistryTransitionV1{}, errors.New("Registry action magic is not NVA1")
	}
	version, err := a.LoadUInt(16)
	if err != nil || version != 1 {
		return RegistryTransitionV1{}, errors.New("unknown Registry action version")
	}
	kind, err := a.LoadUInt(8)
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no kind")
	}
	targetKind, err := a.LoadUInt(8)
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no target kind")
	}
	generation, err := a.LoadUInt(64)
	if err != nil || generation == 0 {
		return RegistryTransitionV1{}, errors.New("invalid Registry action generation")
	}
	sequence, err := a.LoadUInt(64)
	if err != nil || sequence == 0 {
		return RegistryTransitionV1{}, errors.New("invalid Registry action sequence")
	}
	target, err := a.LoadSlice(256)
	if err != nil || equalBytes(target, make([]byte, 32)) {
		return RegistryTransitionV1{}, errors.New("invalid Registry action target")
	}
	predecessor, err := a.LoadSlice(256)
	if err != nil || equalBytes(predecessor, make([]byte, 32)) {
		return RegistryTransitionV1{}, errors.New("a Registry revocation has no predecessor")
	}
	nonce, err := a.LoadSlice(256)
	if err != nil || equalBytes(nonce, make([]byte, 32)) {
		return RegistryTransitionV1{}, errors.New("invalid Registry action nonce")
	}
	if _, err := a.LoadRefCell(); err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no domain")
	}
	payload, err := a.LoadRefCell()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no payload")
	}
	if err := endSlice(a); err != nil {
		return RegistryTransitionV1{}, err
	}
	if payload.IsSpecial() {
		return RegistryTransitionV1{}, errors.New("Registry payload is not an ordinary cell")
	}
	p, err := payload.BeginParse()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("invalid Registry payload")
	}
	result := RegistryTransitionV1{ActionHash: "sha256:" + hex.EncodeToString(action.Hash())}
	switch {
	case Kind(kind) == KindRevokeAgent && targetKind == 1 && opcode == opSubmit:
		if err := endSlice(p); err != nil {
			return RegistryTransitionV1{}, err
		}
		result.Kind, result.ObjectID = RegistryAgentTombstone, "agent_"+hex.EncodeToString(target)
		return result, nil
	case Kind(kind) == KindRevokeCapability && targetKind == 2 && opcode == opAuthorizedCapability:
		owner, err := p.LoadSlice(256)
		if err != nil || equalBytes(owner, make([]byte, 32)) {
			return RegistryTransitionV1{}, errors.New("invalid Capability revocation owner")
		}
		hasVersion, err := p.LoadBoolBit()
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation has no version flag")
		}
		result.ObjectID = "cap_" + hex.EncodeToString(target)
		if !hasVersion {
			if err := endSlice(p); err != nil {
				return RegistryTransitionV1{}, err
			}
			result.Kind = RegistryCapabilityTombstone
			return result, nil
		}
		versionHash, err := p.LoadSlice(256)
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation has no version hash")
		}
		nameCell, err := p.LoadRefCell()
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation has no version name")
		}
		if err := endSlice(p); err != nil {
			return RegistryTransitionV1{}, err
		}
		name, err := decodeProtocolText(nameCell, 128)
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation version name is not protocol text")
		}
		digest := sha256.Sum256([]byte(name))
		if !equalBytes(digest[:], versionHash) {
			return RegistryTransitionV1{}, errors.New("Capability revocation version hash does not match its name")
		}
		result.Kind, result.Version = RegistryVersionRevocation, name
		return result, nil
	}
	return RegistryTransitionV1{}, errors.New("Registry body is not a tombstone or version revocation")
}
