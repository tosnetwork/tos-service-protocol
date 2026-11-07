package referencecodec

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// Registry opcodes and action kinds as the Native Registry contract defines
// them: a revoke_agent action is submitted to the Agent account, and a
// revoke_capability action reaches the Capability account forwarded by its
// owner Agent account.
const (
	OpSubmit               = 0x4e560001
	OpAuthorizedCapability = 0x4e560003
	kindRevokeAgent        = 6
	kindRevokeCapability   = 10
)

// Revocation is one revoke_agent or revoke_capability action. Target is
// agent_<hex> for an Agent tombstone and cap_<hex> for a Capability
// tombstone or, with Version set, a version revocation.
type Revocation struct {
	Network          Network
	ContractCodeHash string
	Target           string
	Generation       uint64
	Sequence         uint64
	// Predecessor is the tvm-cell-sha256 state hash the action follows.
	Predecessor string
	NonceHex    string
	// OwnerAgentID is the Capability owner, for a Capability action only.
	OwnerAgentID string
	Version      string
}

// RevocationResult is the action cell and the inbound body the target
// account receives, query ID 1, with an empty authority and counterparty set.
type RevocationResult struct {
	ActionHash string
	ActionBOC  string
	Opcode     uint64
	BodyBOC    string
}

// EncodeRevocation writes the action cell and inbound body from the contract
// layout: magic:uint32 version:uint16 kind:uint8 target_kind:uint8
// generation:uint64 sequence:uint64 target:uint256 predecessor:uint256
// nonce:uint256 ^domain ^payload, with the payload empty for revoke_agent and
// owner:uint256 has_version:uint1 [version_hash:uint256 ^name] for
// revoke_capability.
func EncodeRevocation(v Revocation) (RevocationResult, error) {
	targetKind, prefix, kind, opcode := uint64(1), "agent_", uint64(kindRevokeAgent), uint64(OpSubmit)
	if len(v.Target) > 4 && v.Target[:4] == "cap_" {
		targetKind, prefix, kind, opcode = 2, "cap_", kindRevokeCapability, OpAuthorizedCapability
	}
	target, err := objectID(v.Target, prefix)
	if err != nil {
		return RevocationResult{}, err
	}
	predecessor, err := digest(v.Predecessor, "tvm-cell-sha256:")
	if err != nil || zero(predecessor) {
		return RevocationResult{}, errors.New("a revocation needs a nonzero predecessor")
	}
	nonce, err := hex32(v.NonceHex)
	if err != nil || zero(nonce) {
		return RevocationResult{}, errors.New("invalid action nonce")
	}
	if v.Generation == 0 || v.Sequence == 0 {
		return RevocationResult{}, errors.New("generation and sequence must be positive")
	}
	domain, err := actionDomain(v.Network, v.ContractCodeHash)
	if err != nil {
		return RevocationResult{}, err
	}
	payload := cell.BeginCell()
	if targetKind == 2 {
		owner, err := objectID(v.OwnerAgentID, "agent_")
		if err != nil {
			return RevocationResult{}, err
		}
		payload.MustStoreSlice(owner, 256)
		if v.Version == "" {
			payload.MustStoreUInt(0, 1)
		} else {
			if !validText(v.Version, 128) {
				return RevocationResult{}, errors.New("invalid version name")
			}
			name := sha256.Sum256([]byte(v.Version))
			payload.MustStoreUInt(1, 1).MustStoreSlice(name[:], 256).MustStoreRef(snakeText(v.Version))
		}
	} else if v.OwnerAgentID != "" || v.Version != "" {
		return RevocationResult{}, errors.New("an Agent revocation names no owner or version")
	}
	action := cell.BeginCell().MustStoreUInt(actionMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(kind, 8).MustStoreUInt(targetKind, 8).
		MustStoreUInt(v.Generation, 64).MustStoreUInt(v.Sequence, 64).MustStoreSlice(target, 256).
		MustStoreSlice(predecessor, 256).MustStoreSlice(nonce, 256).
		MustStoreRef(domain).MustStoreRef(payload.EndCell()).EndCell()
	empty := cell.BeginCell().MustStoreUInt(0, 8).EndCell()
	body := cell.BeginCell().MustStoreUInt(opcode, 32).MustStoreUInt(1, 64).MustStoreRef(action).
		MustStoreRef(empty).MustStoreRef(empty).EndCell()
	return RevocationResult{ActionHash: "sha256:" + hex.EncodeToString(action.Hash()),
		ActionBOC: base64.StdEncoding.EncodeToString(action.ToBOC()), Opcode: opcode,
		BodyBOC: base64.StdEncoding.EncodeToString(body.ToBOC())}, nil
}

// snakeText stores text as a chain of cells of at most 127 bytes each.
func snakeText(value string) *cell.Cell {
	raw := []byte(value)
	if len(raw) <= 127 {
		return cell.BeginCell().MustStoreSlice(raw, uint(len(raw))*8).EndCell()
	}
	return cell.BeginCell().MustStoreSlice(raw[:127], 127*8).MustStoreRef(snakeText(string(raw[127:]))).EndCell()
}
