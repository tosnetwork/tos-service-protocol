package nativecore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const stateMagic = 0x4e565331 // NVS1

// DecodeData decodes only the typed TVM state stored in the deterministic
// object account. Portable representations must be derived from this result.
func (l *Locator) DecodeData(data *cell.Cell, expectedObjectID string) (*nativev1.NativeStateV1, bool, error) {
	if l == nil || data == nil {
		return nil, false, errors.New("missing simplified Native account data")
	}
	rawExpected, expectedKind, err := objectID(expectedObjectID)
	if err != nil {
		return nil, false, err
	}
	s, err := data.BeginParse()
	if err != nil {
		return nil, false, errors.New("invalid simplified Native account data cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != dataMagic {
		return nil, false, errors.New("invalid simplified Native data magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, false, errors.New("invalid simplified Native data schema")
	}
	kind, err := s.LoadUInt(8)
	if err != nil || uint8(kind) != expectedKind {
		return nil, false, errors.New("simplified Native object kind mismatch")
	}
	rawID, err := s.LoadSlice(256)
	if err != nil || !equalBytes(rawID, rawExpected) {
		return nil, false, errors.New("simplified Native object identity mismatch")
	}
	config, err := s.LoadRefCell()
	if err != nil {
		return nil, false, errors.New("missing simplified Native config")
	}
	if err := l.validateConfig(config); err != nil {
		return nil, false, err
	}
	found, err := s.LoadBoolBit()
	if err != nil {
		return nil, false, errors.New("missing simplified Native state flag")
	}
	if !found {
		if err := endSlice(s); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	state, err := s.LoadRefCell()
	if err != nil {
		return nil, false, errors.New("missing simplified Native typed state")
	}
	if err := endSlice(s); err != nil {
		return nil, false, err
	}
	result, err := decodeState(state, expectedObjectID, expectedKind)
	if err != nil {
		return nil, false, err
	}
	result.Network = &nativev1.NetworkDomain{NetworkId: l.Network.NetworkId, GenesisRootHash: l.Network.GenesisRootHash, GenesisFileHash: l.Network.GenesisFileHash}
	result.TvmStateHash = "tvm-cell-sha256:" + hex.EncodeToString(state.Hash())
	return result, true, nil
}

// DecodeDataAny recovers the object ID committed by an authenticated Registry
// account before applying the ordinary expected-ID decoder. It is intended for
// DNS aliases, where the account address is known before its Native object ID.
func (l *Locator) DecodeDataAny(data *cell.Cell) (*nativev1.NativeStateV1, bool, string, error) {
	if l == nil || data == nil {
		return nil, false, "", errors.New("missing simplified Native account data")
	}
	s, err := data.BeginParse()
	if err != nil {
		return nil, false, "", errors.New("invalid simplified Native account data cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != dataMagic {
		return nil, false, "", errors.New("invalid simplified Native data magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, false, "", errors.New("invalid simplified Native data schema")
	}
	kind, err := s.LoadUInt(8)
	if err != nil || (kind != 1 && kind != 2) {
		return nil, false, "", errors.New("invalid simplified Native object kind")
	}
	rawID, err := s.LoadSlice(256)
	if err != nil || equalBytes(rawID, make([]byte, 32)) {
		return nil, false, "", errors.New("invalid simplified Native object identity")
	}
	prefix := "agent_"
	if kind == 2 {
		prefix = "cap_"
	}
	objectID := prefix + hex.EncodeToString(rawID)
	state, found, err := l.DecodeData(data, objectID)
	return state, found, objectID, err
}

func (l *Locator) validateConfig(config *cell.Cell) error {
	want, err := l.configCell()
	if err != nil {
		return err
	}
	if !equalBytes(config.Hash(), want.Hash()) {
		return errors.New("simplified Native account config mismatch")
	}
	return nil
}

func decodeState(state *cell.Cell, object string, expectedKind uint8) (*nativev1.NativeStateV1, error) {
	s, err := state.BeginParse()
	if err != nil {
		return nil, errors.New("invalid simplified Native state cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != stateMagic {
		return nil, errors.New("invalid simplified Native state magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, errors.New("invalid simplified Native state schema")
	}
	kind, err := s.LoadUInt(8)
	if err != nil || uint8(kind) != expectedKind {
		return nil, errors.New("simplified Native state kind mismatch")
	}
	tombstoned, err := s.LoadBoolBit()
	if err != nil {
		return nil, err
	}
	generation, err := s.LoadUInt(64)
	if err != nil || generation == 0 {
		return nil, errors.New("invalid simplified Native generation")
	}
	sequence, err := s.LoadUInt(64)
	if err != nil || sequence == 0 {
		return nil, errors.New("invalid simplified Native sequence")
	}
	lastAction, err := s.LoadSlice(256)
	if err != nil || equalBytes(lastAction, make([]byte, 32)) {
		return nil, errors.New("invalid simplified Native action hash")
	}
	last := "sha256:" + hex.EncodeToString(lastAction)
	if expectedKind == 1 {
		policyCell, err := s.LoadRefCell()
		if err != nil {
			return nil, err
		}
		delegationsCell, err := s.LoadRefCell()
		if err != nil {
			return nil, err
		}
		recoveryCell, err := s.LoadRefCell()
		if err != nil {
			return nil, err
		}
		if err := endSlice(s); err != nil {
			return nil, err
		}
		policy, err := DecodePolicyCell(policyCell)
		if err != nil {
			return nil, err
		}
		delegations, err := decodeDelegations(delegationsCell)
		if err != nil {
			return nil, err
		}
		recoveryAt, recoveryAction, recoveryPolicyHash, recoveryPolicy, err := decodeRecovery(recoveryCell)
		if err != nil {
			return nil, err
		}
		if recoveryPolicy != nil && recoveryPolicyHash != "tvm-cell-sha256:"+hex.EncodeToString(policyCell.Hash()) {
			return nil, errors.New("pending Native recovery is not bound to the live policy")
		}
		return &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{
			AgentId: object, Generation: generation, Sequence: sequence, LastActionHash: last, Policy: policy,
			DelegationDigests: delegations, RecoveryExecuteAfterUnixSeconds: recoveryAt,
			RecoveryInitiationActionHash: recoveryAction, RecoveryInitiatingPolicyHash: recoveryPolicyHash,
			RecoveryPolicy: recoveryPolicy, Tombstoned: tombstoned}}}, nil
	}
	owner, err := s.LoadSlice(256)
	if err != nil || equalBytes(owner, make([]byte, 32)) {
		return nil, errors.New("invalid Capability owner")
	}
	versionsCell, err := s.LoadRefCell()
	if err != nil {
		return nil, err
	}
	if err := endSlice(s); err != nil {
		return nil, err
	}
	versions, err := decodeVersions(versionsCell)
	if err != nil {
		return nil, err
	}
	return &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{
		CapabilityId: object, Generation: generation, Sequence: sequence, LastActionHash: last,
		OwnerAgentId: "agent_" + hex.EncodeToString(owner), Versions: versions, Tombstoned: tombstoned}}}, nil
}

func DecodePolicyCell(value *cell.Cell) (*nativev1.ControllerPolicyV1, error) {
	if value == nil {
		return nil, errors.New("missing Native policy")
	}
	s, err := value.BeginParse()
	if err != nil {
		return nil, errors.New("invalid Native policy cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != policyMagic {
		return nil, errors.New("invalid Native policy magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, errors.New("invalid Native policy schema")
	}
	threshold, err := s.LoadUInt(32)
	if err != nil {
		return nil, err
	}
	recoveryThreshold, err := s.LoadUInt(32)
	if err != nil {
		return nil, err
	}
	timelock, err := s.LoadUInt(64)
	if err != nil {
		return nil, err
	}
	count, err := s.LoadUInt(8)
	if err == nil && count > MaxControllers {
		return nil, nativeError(ErrPolicyTooWide, "Native policy names more controllers than the Registry admits")
	}
	if err != nil || count == 0 {
		return nil, errors.New("invalid Native policy controller count")
	}
	cursor, err := s.LoadRefCell()
	if err != nil {
		return nil, err
	}
	if err := endSlice(s); err != nil {
		return nil, err
	}
	controllers := make([]*nativev1.ControllerV1, 0, count)
	var previous []byte
	for i := uint64(0); i < count; i++ {
		cs, err := cursor.BeginParse()
		if err != nil {
			return nil, err
		}
		key, err := cs.LoadSlice(256)
		if err != nil {
			return nil, err
		}
		publicKey, err := cs.LoadSlice(256)
		if err != nil || !equalBytes(key, publicKey) || previous != nil && compareBytes(key, previous) <= 0 {
			return nil, errors.New("invalid Native policy key ordering")
		}
		weight, err := cs.LoadUInt(32)
		if err != nil {
			return nil, err
		}
		purposes, err := cs.LoadUInt(16)
		if err != nil {
			return nil, err
		}
		recovery, err := cs.LoadBoolBit()
		if err != nil {
			return nil, err
		}
		controllers = append(controllers, &nativev1.ControllerV1{KeyId: "ed25519:" + hex.EncodeToString(key), Ed25519PublicKey: publicKey, Weight: uint32(weight), PurposeMask: uint32(purposes), Recovery: recovery})
		previous = key
		if i+1 < count {
			cursor, err = cs.LoadRefCell()
			if err != nil {
				return nil, err
			}
		}
		if err := endSlice(cs); err != nil {
			return nil, err
		}
	}
	policy := &nativev1.ControllerPolicyV1{Threshold: uint32(threshold), RecoveryThreshold: uint32(recoveryThreshold), RecoveryTimelockSeconds: timelock, Controllers: controllers}
	if _, err := validatePolicy(policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func decodeDelegations(value *cell.Cell) ([]string, error) {
	s, err := value.BeginParse()
	if err != nil {
		return nil, err
	}
	count, err := s.LoadUInt(16)
	if err != nil || count > 128 {
		return nil, errors.New("invalid Native delegation count")
	}
	dict, err := s.LoadDict(256)
	if err != nil {
		return nil, err
	}
	if err := endSlice(s); err != nil {
		return nil, err
	}
	items, err := dict.LoadAll()
	if err != nil || uint64(len(items)) != count {
		return nil, errors.New("Native delegation count mismatch")
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		key, err := item.Key.LoadSlice(256)
		if err != nil || endSlice(item.Key) != nil {
			return nil, errors.New("invalid Native delegation key")
		}
		present, err := item.Value.LoadBoolBit()
		if err != nil || !present || endSlice(item.Value) != nil {
			return nil, errors.New("invalid Native delegation value")
		}
		result = append(result, "sha256:"+hex.EncodeToString(key))
	}
	sort.Strings(result)
	return result, nil
}

func decodeRecovery(value *cell.Cell) (uint64, string, string, *nativev1.ControllerPolicyV1, error) {
	s, err := value.BeginParse()
	if err != nil {
		return 0, "", "", nil, err
	}
	pending, err := s.LoadBoolBit()
	if err != nil {
		return 0, "", "", nil, err
	}
	if !pending {
		return 0, "", "", nil, endSlice(s)
	}
	action, err := s.LoadSlice(256)
	if err != nil || equalBytes(action, make([]byte, 32)) {
		return 0, "", "", nil, errors.New("pending Native recovery has a zero initiation action hash")
	}
	policyHash, err := s.LoadSlice(256)
	if err != nil {
		return 0, "", "", nil, err
	}
	if equalBytes(policyHash, make([]byte, 32)) {
		return 0, "", "", nil, errors.New("pending Native recovery has a zero initiating policy hash")
	}
	executeAt, err := s.LoadUInt(64)
	if err != nil || executeAt == 0 {
		return 0, "", "", nil, errors.New("pending Native recovery has an invalid execution time")
	}
	policyCell, err := s.LoadRefCell()
	if err != nil {
		return 0, "", "", nil, err
	}
	if err := endSlice(s); err != nil {
		return 0, "", "", nil, err
	}
	policy, err := DecodePolicyCell(policyCell)
	return executeAt, "sha256:" + hex.EncodeToString(action), "tvm-cell-sha256:" + hex.EncodeToString(policyHash), policy, err
}

func decodeVersions(value *cell.Cell) ([]*nativev1.CapabilityVersionV1, error) {
	s, err := value.BeginParse()
	if err != nil {
		return nil, err
	}
	count, err := s.LoadUInt(16)
	if err != nil || count == 0 || count > 256 {
		return nil, errors.New("invalid Native version count")
	}
	dict, err := s.LoadDict(256)
	if err != nil {
		return nil, err
	}
	if err := endSlice(s); err != nil {
		return nil, err
	}
	items, err := dict.LoadAll()
	if err != nil || uint64(len(items)) != count {
		return nil, errors.New("Native version count mismatch")
	}
	result := make([]*nativev1.CapabilityVersionV1, 0, len(items))
	for _, item := range items {
		key, err := item.Key.LoadSlice(256)
		if err != nil || endSlice(item.Key) != nil {
			return nil, errors.New("invalid Native version key")
		}
		manifest, err := item.Value.LoadSlice(256)
		if err != nil {
			return nil, err
		}
		revoked, err := item.Value.LoadBoolBit()
		if err != nil {
			return nil, err
		}
		nameCell, err := item.Value.LoadRefCell()
		if err != nil || endSlice(item.Value) != nil {
			return nil, errors.New("invalid Native version value")
		}
		name, err := decodeProtocolText(nameCell, 128)
		if err != nil {
			return nil, errors.New("invalid Native version name")
		}
		if equalBytes(manifest, make([]byte, 32)) {
			return nil, errors.New("invalid Native version manifest")
		}
		h := sha256.Sum256([]byte(name))
		if !equalBytes(h[:], key) {
			return nil, errors.New("Native version key does not match its name")
		}
		result = append(result, &nativev1.CapabilityVersionV1{Version: name, ManifestDigest: "sha256:" + hex.EncodeToString(manifest), Revoked: revoked})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result, nil
}

func decodeProtocolText(value *cell.Cell, limit int) (string, error) {
	if value == nil || limit <= 0 {
		return "", errors.New("missing protocol text")
	}
	var out []byte
	for current := value; current != nil; {
		s, err := current.BeginParse()
		if err != nil {
			return "", err
		}
		bits, refs := s.BitsLeft(), s.RefsNum()
		if bits%8 != 0 || refs > 1 || len(out)+int(bits/8) > limit || refs == 1 && bits != 1016 {
			return "", errors.New("non-canonical protocol text")
		}
		part, err := s.LoadSlice(uint(bits))
		if err != nil {
			return "", err
		}
		for _, character := range part {
			if character < 0x21 || character > 0x7e {
				return "", errors.New("invalid protocol text character")
			}
		}
		out = append(out, part...)
		if refs == 0 {
			current = nil
		} else {
			current, err = s.LoadRefCell()
			if err != nil {
				return "", err
			}
		}
		if err := endSlice(s); err != nil {
			return "", err
		}
	}
	if len(out) == 0 {
		return "", errors.New("empty protocol text")
	}
	return string(out), nil
}

func endSlice(s *cell.Slice) error {
	if s == nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return fmt.Errorf("non-canonical Native Cell has trailing data")
	}
	return nil
}

func equalBytes(a, b []byte) bool { return compareBytes(a, b) == 0 }
func compareBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
