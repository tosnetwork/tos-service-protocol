// Package referencecodec is an independent tos_service_v1 registration
// encoder used only for conformance. It deliberately does not import generated
// protocol messages or pkg/nativecore.
package referencecodec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	actionMagic   = 0x4e564131
	policyMagic   = 0x4e565031
	identityMagic = 0x4e564931
	dataMagic     = 0x4e564431
)

type VectorSet struct {
	Schema                 string                 `json:"schema"`
	Protocol               string                 `json:"protocol"`
	ContractCodeHash       string                 `json:"contract_code_hash"`
	ContractCodeBOCBase64  string                 `json:"contract_code_boc_base64"`
	Network                Network                `json:"network"`
	AgentRegistration      AgentRegistration      `json:"agent_registration"`
	CapabilityRegistration CapabilityRegistration `json:"capability_registration"`
	NegativeMutations      []NegativeMutation     `json:"negative_mutations"`
}

type Network struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

type Controller struct {
	PublicKeyHex string `json:"public_key_hex"`
	Weight       uint32 `json:"weight"`
	PurposeMask  uint32 `json:"purpose_mask"`
	Recovery     bool   `json:"recovery"`
}

type Policy struct {
	Threshold               uint32       `json:"threshold"`
	RecoveryThreshold       uint32       `json:"recovery_threshold"`
	RecoveryTimelockSeconds uint64       `json:"recovery_timelock_seconds"`
	Controllers             []Controller `json:"controllers"`
}

type Expected struct {
	ObjectID        string `json:"object_id"`
	ContractAddress string `json:"contract_address"`
	ActionHash      string `json:"action_hash"`
	ActionBOCBase64 string `json:"action_boc_base64"`
	SignatureHex    string `json:"signature_hex"`
}

type AgentRegistration struct {
	PrivateSeedHex string   `json:"private_seed_hex"`
	ObjectNonceHex string   `json:"object_nonce_hex"`
	ActionNonceHex string   `json:"action_nonce_hex"`
	Policy         Policy   `json:"policy"`
	Expected       Expected `json:"expected"`
}

type CapabilityRegistration struct {
	OwnerAgentID   string   `json:"owner_agent_id"`
	ObjectNonceHex string   `json:"object_nonce_hex"`
	ActionNonceHex string   `json:"action_nonce_hex"`
	Version        string   `json:"version"`
	ManifestDigest string   `json:"manifest_digest"`
	Expected       Expected `json:"expected"`
}

type NegativeMutation struct {
	Registration string `json:"registration"`
	Mutation     string `json:"mutation"`
	ExpectedCode uint16 `json:"expected_code"`
}

type Result struct {
	ObjectID        string
	ContractAddress string
	StateInitBOC    string
	ActionHash      string
	ActionBOCBase64 string
}

type ValidationError struct {
	Code uint16
	err  error
}

func (e *ValidationError) Error() string { return fmt.Sprintf("NATIVE_ERROR_%d: %v", e.Code, e.err) }
func (e *ValidationError) Unwrap() error { return e.err }

func ErrorCodeOf(err error) (uint16, bool) {
	var validation *ValidationError
	if !errors.As(err, &validation) {
		return 0, false
	}
	return validation.Code, true
}

func validationError(code uint16, message string) error {
	return &ValidationError{Code: code, err: errors.New(message)}
}

func Decode(data []byte) (VectorSet, error) {
	var vectors VectorSet
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vectors); err != nil {
		return VectorSet{}, err
	}
	if vectors.Schema != "tos.service.registry.v1.vectors" || vectors.Protocol != "tos_service_v1" {
		return VectorSet{}, errors.New("unsupported Native vector schema")
	}
	return vectors, nil
}

func ComputeAgent(v VectorSet) (Result, error) {
	policy, err := policyCell(v.AgentRegistration.Policy)
	if err != nil {
		return Result{}, err
	}
	objectNonce, err := hex32(v.AgentRegistration.ObjectNonceHex)
	if err != nil {
		return Result{}, err
	}
	domain, err := identityDomain(v.Network)
	if err != nil {
		return Result{}, err
	}
	identity := cell.BeginCell().MustStoreUInt(identityMagic, 32).MustStoreUInt(1, 8).
		MustStoreSlice(objectNonce, 256).MustStoreSlice(policy.Hash(), 256).MustStoreRef(domain).EndCell()
	objectID := "agent_" + hex.EncodeToString(identity.Hash())
	payload := cell.BeginCell().MustStoreSlice(objectNonce, 256).MustStoreRef(policy).EndCell()
	return registrationAction(v, objectID, 1, 1, payload, v.AgentRegistration.ActionNonceHex)
}

func ComputeCapability(v VectorSet) (Result, error) {
	objectNonce, err := hex32(v.CapabilityRegistration.ObjectNonceHex)
	if err != nil {
		return Result{}, err
	}
	owner, err := objectID(v.CapabilityRegistration.OwnerAgentID, "agent_")
	if err != nil {
		return Result{}, err
	}
	if !validText(v.CapabilityRegistration.Version, 128) {
		return Result{}, errors.New("invalid Capability version")
	}
	manifest, err := digest(v.CapabilityRegistration.ManifestDigest, "sha256:")
	if err != nil || zero(manifest) {
		return Result{}, errors.New("invalid Capability manifest")
	}
	versionHash := sha256.Sum256([]byte(v.CapabilityRegistration.Version))
	domain, err := identityDomain(v.Network)
	if err != nil {
		return Result{}, err
	}
	details := cell.BeginCell().MustStoreSlice(versionHash[:], 256).MustStoreSlice(manifest, 256).EndCell()
	identity := cell.BeginCell().MustStoreUInt(identityMagic, 32).MustStoreUInt(2, 8).
		MustStoreSlice(objectNonce, 256).MustStoreSlice(owner, 256).MustStoreRef(domain).MustStoreRef(details).EndCell()
	objectIDValue := "cap_" + hex.EncodeToString(identity.Hash())
	versionDetails := cell.BeginCell().MustStoreSlice(versionHash[:], 256).MustStoreSlice(manifest, 256).
		MustStoreRef(cell.BeginCell().MustStoreBinarySnake([]byte(v.CapabilityRegistration.Version)).EndCell()).EndCell()
	payload := cell.BeginCell().MustStoreSlice(objectNonce, 256).MustStoreSlice(owner, 256).MustStoreRef(versionDetails).EndCell()
	return registrationAction(v, objectIDValue, 2, 7, payload, v.CapabilityRegistration.ActionNonceHex)
}

// CheckNegative applies one frozen mutation to an independent registration
// model and validates it without calling nativecore.
func CheckNegative(v VectorSet, mutation NegativeMutation) error {
	type candidate struct {
		protocol, networkID, genesisRoot, codeHash, actionNonce string
		objectNonce, version                                    string
		target, expectedTarget, owner                           string
		generation, sequence                                    uint64
		revoked, unattainablePolicy                             bool
	}
	registration := v.AgentRegistration.Expected
	actionNonce := v.AgentRegistration.ActionNonceHex
	if mutation.Registration == "capability" {
		registration = v.CapabilityRegistration.Expected
		actionNonce = v.CapabilityRegistration.ActionNonceHex
	}
	c := candidate{protocol: v.Protocol, networkID: v.Network.NetworkID,
		genesisRoot: v.Network.GenesisRootHash, codeHash: v.ContractCodeHash,
		actionNonce: actionNonce, objectNonce: v.AgentRegistration.ObjectNonceHex,
		version: v.CapabilityRegistration.Version, target: registration.ObjectID, expectedTarget: registration.ObjectID,
		owner: v.CapabilityRegistration.OwnerAgentID, generation: 1, sequence: 1}
	if mutation.Registration == "capability" {
		c.objectNonce = v.CapabilityRegistration.ObjectNonceHex
	}
	switch mutation.Mutation {
	case "wrong_protocol":
		c.protocol = "tos_service_v0"
	case "empty_network_id":
		c.networkID = ""
	case "zero_genesis_root":
		c.genesisRoot = "sha256:" + strings.Repeat("00", 32)
	case "wrong_contract_hash":
		c.codeHash = "sha256:" + strings.Repeat("44", 32)
	case "zero_action_nonce":
		c.actionNonce = strings.Repeat("00", 32)
	case "zero_target_id":
		prefix := "agent_"
		if mutation.Registration == "capability" {
			prefix = "cap_"
		}
		c.target = prefix + strings.Repeat("00", 32)
	case "zero_object_nonce":
		c.objectNonce = strings.Repeat("00", 32)
	case "unattainable_policy":
		c.unattainablePolicy = true
	case "caller_selected_id":
		prefix := "agent_"
		if mutation.Registration == "capability" {
			prefix = "cap_"
		}
		c.target = prefix + strings.Repeat("33", 32)
	case "generation_zero":
		c.generation = 0
	case "registration_generation_two":
		c.generation = 2
	case "wrong_owner_kind":
		c.owner = "cap_" + strings.Repeat("44", 32)
	case "revoked_initial_version":
		c.revoked = true
	case "version_too_long":
		c.version = strings.Repeat("v", 129)
	case "version_non_printable":
		c.version = "1.0.0\n"
	case "registration_sequence_two":
		c.sequence = 2
	default:
		return errors.New("unknown frozen mutation")
	}
	if c.protocol != "tos_service_v1" {
		return validationError(2200, "wrong protocol")
	}
	nonce, err := hex32(c.actionNonce)
	if err != nil || zero(nonce) {
		return validationError(2203, "invalid action nonce")
	}
	prefix := "agent_"
	if mutation.Registration == "capability" {
		prefix = "cap_"
	}
	if _, err := objectID(c.target, prefix); err != nil {
		return validationError(2203, "invalid target")
	}
	if code, err := digest(c.codeHash, "tvm-cell-sha256:"); err != nil || zero(code) {
		return validationError(2202, "invalid contract code hash")
	}
	if !validText(c.networkID, 64) {
		return validationError(2201, "invalid network ID")
	}
	if root, err := digest(c.genesisRoot, "sha256:"); err != nil || zero(root) {
		return validationError(2201, "invalid genesis root")
	}
	if c.generation == 0 || c.sequence == 0 {
		return validationError(2205, "zero ordering value")
	}
	if objectNonce, err := hex32(c.objectNonce); err != nil || zero(objectNonce) {
		return validationError(2203, "invalid object nonce")
	}
	if c.unattainablePolicy {
		return validationError(2207, "unattainable controller policy")
	}
	if mutation.Registration == "capability" {
		if _, err := objectID(c.owner, "agent_"); err != nil || c.revoked || !validText(c.version, 128) {
			return validationError(2203, "invalid Capability registration")
		}
	}
	if c.target != c.expectedTarget {
		return validationError(2210, "caller-selected registration identity")
	}
	if c.generation != 1 || c.sequence != 1 {
		return validationError(2205, "registration ordering")
	}
	return errors.New("negative mutation was accepted")
}

func registrationAction(v VectorSet, object string, targetKind, actionKind uint8, payload *cell.Cell, nonceHex string) (Result, error) {
	target, err := objectID(object, map[uint8]string{1: "agent_", 2: "cap_"}[targetKind])
	if err != nil {
		return Result{}, err
	}
	nonce, err := hex32(nonceHex)
	if err != nil || zero(nonce) {
		return Result{}, errors.New("invalid action nonce")
	}
	domain, err := actionDomain(v.Network, v.ContractCodeHash)
	if err != nil {
		return Result{}, err
	}
	root := cell.BeginCell().MustStoreUInt(actionMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(actionKind), 8).MustStoreUInt(uint64(targetKind), 8).
		MustStoreUInt(1, 64).MustStoreUInt(1, 64).MustStoreSlice(target, 256).
		MustStoreSlice(make([]byte, 32), 256).MustStoreSlice(nonce, 256).
		MustStoreRef(domain).MustStoreRef(payload).EndCell()
	address, stateInit, err := locate(v, targetKind, target)
	if err != nil {
		return Result{}, err
	}
	return Result{ObjectID: object, ContractAddress: address, StateInitBOC: stateInit,
		ActionHash:      "sha256:" + hex.EncodeToString(root.Hash()),
		ActionBOCBase64: base64.StdEncoding.EncodeToString(root.ToBOC())}, nil
}

func locate(v VectorSet, kind uint8, objectID []byte) (string, string, error) {
	rawCode, err := base64.StdEncoding.DecodeString(v.ContractCodeBOCBase64)
	if err != nil {
		return "", "", errors.New("invalid contract code BOC")
	}
	code, err := cell.FromBOC(rawCode)
	if err != nil || code == nil || v.ContractCodeHash != "tvm-cell-sha256:"+hex.EncodeToString(code.Hash()) {
		return "", "", errors.New("contract code identity mismatch")
	}
	domain, err := identityDomain(v.Network)
	if err != nil {
		return "", "", err
	}
	s, err := domain.BeginParse()
	if err != nil {
		return "", "", errors.New("invalid identity domain cell")
	}
	root, _ := s.LoadSlice(256)
	file, _ := s.LoadSlice(256)
	networkHash, _ := s.LoadSlice(256)
	networkID := cell.BeginCell().MustStoreBinarySnake([]byte(v.Network.NetworkID)).EndCell()
	runtime := cell.BeginCell().MustStoreInt(0, 32).MustStoreSlice(code.Hash(), 256).
		MustStoreRef(networkID).MustStoreRef(code).EndCell()
	config := cell.BeginCell().MustStoreSlice(root, 256).MustStoreSlice(file, 256).
		MustStoreSlice(networkHash, 256).MustStoreRef(runtime).EndCell()
	data := cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(kind), 8).MustStoreSlice(objectID, 256).MustStoreRef(config).
		MustStoreBoolBit(false).EndCell()
	stateInit := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(code).MustStoreBoolBit(true).MustStoreRef(data).
		MustStoreBoolBit(false).EndCell()
	return "0:" + hex.EncodeToString(stateInit.Hash()), base64.StdEncoding.EncodeToString(stateInit.ToBOC()), nil
}

// maxPolicyControllers is the Native Registry contract's policy width limit.
const maxPolicyControllers = 20

func policyCell(policy Policy) (*cell.Cell, error) {
	if len(policy.Controllers) > maxPolicyControllers {
		return nil, validationError(2215, "policy names more than 20 controllers")
	}
	if policy.Threshold == 0 || policy.RecoveryThreshold == 0 || len(policy.Controllers) == 0 {
		return nil, errors.New("invalid policy header")
	}
	type parsed struct {
		key      []byte
		weight   uint32
		purpose  uint32
		recovery bool
	}
	controllers := make([]parsed, len(policy.Controllers))
	var total, recoveryTotal uint64
	for i, controller := range policy.Controllers {
		key, err := hex32(controller.PublicKeyHex)
		if err != nil || zero(key) || controller.Weight == 0 || controller.Weight > 1_000_000 || controller.PurposeMask == 0 || controller.PurposeMask&^uint32(15) != 0 || controller.Recovery && controller.PurposeMask&4 == 0 {
			return nil, errors.New("invalid controller")
		}
		if weakControllerKey(key) {
			return nil, validationError(2214, "controller key is a small-order or non-canonical Ed25519 point")
		}
		controllers[i] = parsed{key: key, weight: controller.Weight, purpose: controller.PurposeMask, recovery: controller.Recovery}
		total += uint64(controller.Weight)
		if controller.Recovery {
			recoveryTotal += uint64(controller.Weight)
		}
	}
	if uint64(policy.Threshold) > total || uint64(policy.RecoveryThreshold) > recoveryTotal || policy.RecoveryTimelockSeconds > 31536000 {
		return nil, errors.New("unattainable policy")
	}
	sort.Slice(controllers, func(i, j int) bool { return bytes.Compare(controllers[i].key, controllers[j].key) < 0 })
	var next *cell.Cell
	for i := len(controllers) - 1; i >= 0; i-- {
		if i > 0 && bytes.Equal(controllers[i-1].key, controllers[i].key) {
			return nil, errors.New("duplicate controller")
		}
		controller := controllers[i]
		builder := cell.BeginCell().MustStoreSlice(controller.key, 256).MustStoreSlice(controller.key, 256).
			MustStoreUInt(uint64(controller.weight), 32).MustStoreUInt(uint64(controller.purpose), 16).
			MustStoreBoolBit(controller.recovery)
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
	}
	return cell.BeginCell().MustStoreUInt(policyMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(policy.Threshold), 32).MustStoreUInt(uint64(policy.RecoveryThreshold), 32).
		MustStoreUInt(policy.RecoveryTimelockSeconds, 64).MustStoreUInt(uint64(len(controllers)), 8).
		MustStoreRef(next).EndCell(), nil
}

func identityDomain(network Network) (*cell.Cell, error) {
	root, err := digest(network.GenesisRootHash, "sha256:")
	if err != nil || zero(root) {
		return nil, errors.New("invalid genesis root")
	}
	file, err := digest(network.GenesisFileHash, "sha256:")
	if err != nil || zero(file) {
		return nil, errors.New("invalid genesis file")
	}
	if !validText(network.NetworkID, 64) {
		return nil, errors.New("invalid network ID")
	}
	networkHash := sha256.Sum256([]byte(network.NetworkID))
	return cell.BeginCell().MustStoreSlice(root, 256).MustStoreSlice(file, 256).MustStoreSlice(networkHash[:], 256).EndCell(), nil
}

func actionDomain(network Network, codeHash string) (*cell.Cell, error) {
	domain, err := identityDomain(network)
	if err != nil {
		return nil, err
	}
	code, err := digest(codeHash, "tvm-cell-sha256:")
	if err != nil || zero(code) {
		return nil, errors.New("invalid code hash")
	}
	s, err := domain.BeginParse()
	if err != nil {
		return nil, errors.New("invalid identity domain cell")
	}
	root, _ := s.LoadSlice(256)
	file, _ := s.LoadSlice(256)
	networkHash, _ := s.LoadSlice(256)
	return cell.BeginCell().MustStoreSlice(root, 256).MustStoreSlice(file, 256).MustStoreSlice(networkHash, 256).
		MustStoreRef(cell.BeginCell().MustStoreSlice(code, 256).EndCell()).EndCell(), nil
}

func objectID(value, prefix string) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("wrong object kind")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) != 32 || value != prefix+hex.EncodeToString(raw) || zero(raw) {
		return nil, errors.New("invalid object ID")
	}
	return raw, nil
}

func digest(value, prefix string) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("invalid digest prefix")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) != 32 || value != prefix+hex.EncodeToString(raw) {
		return nil, errors.New("invalid digest")
	}
	return raw, nil
}

func hex32(value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || value != hex.EncodeToString(raw) {
		return nil, fmt.Errorf("invalid 32-byte hex")
	}
	return raw, nil
}

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, b := range []byte(value) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func zero(value []byte) bool { return bytes.Equal(value, make([]byte, len(value))) }
