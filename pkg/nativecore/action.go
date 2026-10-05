// Package nativecore implements the single-mode tos_service_v1 execution
// envelope. It is independent of gateway-owned state and per-action contracts.
package nativecore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	Protocol = "tos_service_v1"

	actionMagic = 0x4e564131 // NVA1
	policyMagic = 0x4e565031 // NVP1

	PurposeAgentControl      = 1
	PurposeDelegation        = 2
	PurposeRecovery          = 4
	PurposeCapabilityControl = 8
	knownPurposeMask         = PurposeAgentControl | PurposeDelegation | PurposeRecovery | PurposeCapabilityControl

	// MaxControllers is the Native Registry's policy width limit: a policy
	// naming more controllers is refused with ErrPolicyTooWide before any
	// controller is read, and a signature list may hold at most one
	// signature per controller.
	MaxControllers             = 20
	MaxSignatures              = MaxControllers
	MaxControllerWeight        = 1_000_000
	MaxRecoveryTimelockSeconds = 365 * 24 * 60 * 60
)

type Kind uint8

const (
	KindRegisterAgent Kind = iota + 1
	KindUpdateAgentPolicy
	KindDelegateAgent
	KindInitiateRecovery
	KindCompleteRecovery
	KindRevokeAgent
	KindRegisterCapability
	KindAddCapabilityVersion
	KindTransferCapability
	KindRevokeCapability
)

type BuiltAction struct {
	Cell       *cell.Cell
	Hash       []byte
	HashString string
	Kind       Kind
	TargetKind uint8
}

func BuildAction(action *nativev1.NativeActionV1) (BuiltAction, error) {
	if action == nil || action.Protocol != Protocol || action.Network == nil {
		return BuiltAction{}, nativeError(ErrBadMessage, "invalid Native action header")
	}
	if len(action.Nonce) != 32 || bytes.Equal(action.Nonce, make([]byte, 32)) {
		return BuiltAction{}, nativeError(ErrBadAction, "Native action nonce must be 32 nonzero bytes")
	}
	targetID, targetKind, err := objectID(action.TargetObjectId)
	if err != nil {
		return BuiltAction{}, wrapNativeError(ErrBadAction, "invalid target object ID", err)
	}
	codeHash, err := digestBytes(action.TargetContractCodeHash, "tvm-cell-sha256:", false)
	if err != nil {
		return BuiltAction{}, wrapNativeError(ErrWrongContract, "invalid target code hash", err)
	}
	previous, err := optionalDigest(action.PredecessorTvmStateHash)
	if err != nil {
		return BuiltAction{}, wrapNativeError(ErrBadPredecessor, "invalid predecessor state hash", err)
	}
	genesisRoot, err := digestBytes(action.Network.GenesisRootHash, "sha256:", false)
	if err != nil {
		return BuiltAction{}, wrapNativeError(ErrWrongNetwork, "invalid genesis root", err)
	}
	genesisFile, err := digestBytes(action.Network.GenesisFileHash, "sha256:", false)
	if err != nil {
		return BuiltAction{}, wrapNativeError(ErrWrongNetwork, "invalid genesis file", err)
	}
	if !validProtocolText(action.Network.NetworkId, 64) {
		return BuiltAction{}, nativeError(ErrWrongNetwork, "invalid Native network ID")
	}
	if action.Generation == 0 || action.Sequence == 0 {
		return BuiltAction{}, nativeError(ErrBadSequence, "Native generation and sequence must be positive")
	}
	kind, payload, err := buildPayload(action, targetKind)
	if err != nil {
		return BuiltAction{}, wrapNativeError(ErrBadAction, "invalid Native action payload", err)
	}
	if err := validateRegistrationIdentity(action); err != nil {
		return BuiltAction{}, wrapNativeError(ErrBadTransition, "invalid registration identity", err)
	}
	registration := kind == KindRegisterAgent || kind == KindRegisterCapability
	generationReset := kind == KindCompleteRecovery || kind == KindTransferCapability
	predecessorIsZero := bytes.Equal(previous, make([]byte, 32))
	if registration {
		if action.Generation != 1 || action.Sequence != 1 {
			return BuiltAction{}, nativeError(ErrBadSequence, "Native registration must start at generation 1 sequence 1")
		}
		if !predecessorIsZero {
			return BuiltAction{}, nativeError(ErrBadPredecessor, "Native registration predecessor must be zero")
		}
	} else {
		if predecessorIsZero {
			return BuiltAction{}, nativeError(ErrBadPredecessor, "Native mutation predecessor must be nonzero")
		}
		if generationReset {
			if action.Generation < 2 || action.Sequence != 1 {
				return BuiltAction{}, nativeError(ErrBadSequence, "Native generation reset must advance generation and reset sequence")
			}
		} else if action.Sequence < 2 {
			return BuiltAction{}, nativeError(ErrBadSequence, "ordinary Native mutation must advance sequence")
		}
	}
	domainHash := sha256.Sum256([]byte(action.Network.NetworkId))
	domain := cell.BeginCell().MustStoreSlice(genesisRoot, 256).MustStoreSlice(genesisFile, 256).
		MustStoreSlice(domainHash[:], 256).
		MustStoreRef(cell.BeginCell().MustStoreSlice(codeHash, 256).EndCell()).EndCell()
	root := cell.BeginCell().MustStoreUInt(actionMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(kind), 8).MustStoreUInt(uint64(targetKind), 8).
		MustStoreUInt(action.Generation, 64).MustStoreUInt(action.Sequence, 64).
		MustStoreSlice(targetID, 256).MustStoreSlice(previous, 256).
		MustStoreSlice(action.Nonce, 256).MustStoreRef(domain).MustStoreRef(payload).EndCell()
	hash := append([]byte(nil), root.Hash()...)
	return BuiltAction{Cell: root, Hash: hash, HashString: "sha256:" + hex.EncodeToString(hash), Kind: kind, TargetKind: targetKind}, nil
}

func SignAction(privateKey ed25519.PrivateKey, keyID string, built BuiltAction) (*nativev1.SignatureV1, error) {
	if len(privateKey) != ed25519.PrivateKeySize || built.Cell == nil || !validKeyID(keyID) ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey), keyIDHash(keyID)) {
		return nil, nativeError(ErrBadSignature, "invalid Native signing input")
	}
	return &nativev1.SignatureV1{KeyId: keyID, Ed25519Signature: ed25519.Sign(privateKey, built.Hash)}, nil
}

func VerifySignatures(policy *nativev1.ControllerPolicyV1, signatures []*nativev1.SignatureV1, requiredPurpose uint32, recovery bool, actionHash []byte) error {
	controllers, err := validatePolicy(policy)
	if err != nil {
		return wrapNativeError(ErrBadPolicy, "invalid Native signature policy", err)
	}
	if len(signatures) == 0 || len(signatures) > MaxSignatures || len(actionHash) != 32 {
		return nativeError(ErrBadSignature, "invalid Native signature set")
	}
	threshold := uint64(policy.Threshold)
	if recovery {
		threshold = uint64(policy.RecoveryThreshold)
	}
	var total uint64
	var previous []byte
	for _, signature := range signatures {
		keyHash := keyIDHash(signature.GetKeyId())
		if signature == nil || !validKeyID(signature.KeyId) || len(signature.Ed25519Signature) != ed25519.SignatureSize || previous != nil && bytes.Compare(keyHash, previous) <= 0 {
			return nativeError(ErrDuplicateSignature, "Native signatures must be complete and strictly sorted")
		}
		controller, ok := controllers[signature.KeyId]
		if !ok || controller.PurposeMask&requiredPurpose == 0 || recovery && !controller.Recovery {
			return nativeError(ErrBadSignature, "Native signature is not authorized for the action")
		}
		if !ed25519.Verify(ed25519.PublicKey(controller.Ed25519PublicKey), actionHash, signature.Ed25519Signature) {
			return nativeError(ErrBadSignature, "invalid Native Ed25519 signature")
		}
		total += uint64(controller.Weight)
		previous = keyHash
	}
	if total < threshold {
		return nativeError(ErrThreshold, "Native signature threshold not met")
	}
	return nil
}

func VerifyPolicyPossession(policy *nativev1.ControllerPolicyV1, signatures []*nativev1.SignatureV1, actionHash []byte) error {
	controllers, err := validatePolicy(policy)
	if err != nil {
		return wrapNativeError(ErrBadPolicy, "invalid Native installation policy", err)
	}
	if len(signatures) != len(controllers) || len(actionHash) != 32 {
		return nativeError(ErrBadSignature, "Native policy installation requires every controller signature")
	}
	ordered := append([]*nativev1.SignatureV1(nil), signatures...)
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(keyIDHash(ordered[i].GetKeyId()), keyIDHash(ordered[j].GetKeyId())) < 0
	})
	for i, signature := range ordered {
		if signature == nil || len(signature.Ed25519Signature) != ed25519.SignatureSize {
			return nativeError(ErrBadSignature, "invalid Native policy possession signature")
		}
		controller, ok := controllers[signature.KeyId]
		if !ok || i > 0 && equalBytes(keyIDHash(ordered[i-1].KeyId), keyIDHash(signature.KeyId)) ||
			!ed25519.Verify(controller.Ed25519PublicKey, actionHash, signature.Ed25519Signature) {
			return nativeError(ErrBadSignature, "invalid Native policy possession proof")
		}
	}
	return nil
}

func SignatureCell(signatures []*nativev1.SignatureV1) (*cell.Cell, error) {
	if len(signatures) == 0 || len(signatures) > MaxSignatures {
		return nil, nativeError(ErrThreshold, "invalid Native signature count")
	}
	var next *cell.Cell
	for i := len(signatures) - 1; i >= 0; i-- {
		signature := signatures[i]
		if signature == nil || !validKeyID(signature.KeyId) || len(signature.Ed25519Signature) != ed25519.SignatureSize {
			return nil, nativeError(ErrBadSignature, "invalid Native signature")
		}
		if i > 0 && bytes.Compare(keyIDHash(signatures[i-1].GetKeyId()), keyIDHash(signature.KeyId)) >= 0 {
			return nil, nativeError(ErrDuplicateSignature, "Native signatures are not strictly sorted")
		}
		keyHash := keyIDHash(signature.KeyId)
		builder := cell.BeginCell().MustStoreSlice(keyHash, 256).MustStoreSlice(signature.Ed25519Signature, 512)
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
	}
	return cell.BeginCell().MustStoreUInt(uint64(len(signatures)), 8).MustStoreRef(next).EndCell(), nil
}

func EmptySignatureCell() *cell.Cell { return cell.BeginCell().MustStoreUInt(0, 8).EndCell() }

func MessageBody(action BuiltAction, authority, counterparty []*nativev1.SignatureV1, queryID uint64) (*cell.Cell, error) {
	return messageBody(0x4e560001, action, authority, counterparty, queryID)
}

func AgentAuthorizationBody(action BuiltAction, authority, counterparty []*nativev1.SignatureV1, queryID uint64) (*cell.Cell, error) {
	return messageBody(0x4e560002, action, authority, counterparty, queryID)
}

func messageBody(opcode uint64, action BuiltAction, authority, counterparty []*nativev1.SignatureV1, queryID uint64) (*cell.Cell, error) {
	if action.Cell == nil {
		return nil, errors.New("missing Native action cell")
	}
	authorityCell, err := SignatureCell(authority)
	if err != nil {
		return nil, err
	}
	counterpartyCell := EmptySignatureCell()
	if len(counterparty) != 0 {
		counterpartyCell, err = SignatureCell(counterparty)
		if err != nil {
			return nil, err
		}
	}
	return cell.BeginCell().MustStoreUInt(opcode, 32).MustStoreUInt(queryID, 64).
		MustStoreRef(action.Cell).MustStoreRef(authorityCell).MustStoreRef(counterpartyCell).EndCell(), nil
}

func PolicyCell(policy *nativev1.ControllerPolicyV1) (*cell.Cell, error) {
	controllers, err := validatePolicy(policy)
	if err != nil {
		return nil, wrapNativeError(ErrBadPolicy, "invalid Native controller policy", err)
	}
	ordered := make([]string, 0, len(controllers))
	for keyID := range controllers {
		ordered = append(ordered, keyID)
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(keyIDHash(ordered[i]), keyIDHash(ordered[j])) < 0 })
	var next *cell.Cell
	for i := len(ordered) - 1; i >= 0; i-- {
		controller := controllers[ordered[i]]
		keyHash := keyIDHash(controller.KeyId)
		builder := cell.BeginCell().MustStoreSlice(keyHash, 256).
			MustStoreSlice(controller.Ed25519PublicKey, 256).MustStoreUInt(uint64(controller.Weight), 32).
			MustStoreUInt(uint64(controller.PurposeMask), 16).MustStoreBoolBit(controller.Recovery)
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
	}
	return cell.BeginCell().MustStoreUInt(policyMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(policy.Threshold), 32).MustStoreUInt(uint64(policy.RecoveryThreshold), 32).
		MustStoreUInt(policy.RecoveryTimelockSeconds, 64).MustStoreUInt(uint64(len(ordered)), 8).
		MustStoreRef(next).EndCell(), nil
}

func buildPayload(action *nativev1.NativeActionV1, targetKind uint8) (Kind, *cell.Cell, error) {
	var kind Kind
	b := cell.BeginCell()
	switch payload := action.Payload.(type) {
	case *nativev1.NativeActionV1_RegisterAgent:
		kind = KindRegisterAgent
		if targetKind != 1 || payload.RegisterAgent == nil || len(payload.RegisterAgent.ObjectNonce) != 32 ||
			bytes.Equal(payload.RegisterAgent.ObjectNonce, make([]byte, 32)) {
			return 0, nil, errors.New("invalid register-agent action")
		}
		policy, err := PolicyCell(payload.RegisterAgent.InitialPolicy)
		if err != nil {
			return 0, nil, err
		}
		b.MustStoreSlice(payload.RegisterAgent.ObjectNonce, 256).MustStoreRef(policy)
	case *nativev1.NativeActionV1_UpdateAgentPolicy:
		kind = KindUpdateAgentPolicy
		if targetKind != 1 || payload.UpdateAgentPolicy == nil {
			return 0, nil, errors.New("invalid policy update")
		}
		policy, err := PolicyCell(payload.UpdateAgentPolicy.NewPolicy)
		if err != nil {
			return 0, nil, err
		}
		b.MustStoreRef(policy)
	case *nativev1.NativeActionV1_DelegateAgent:
		kind = KindDelegateAgent
		if targetKind != 1 || payload.DelegateAgent == nil {
			return 0, nil, errors.New("invalid delegation")
		}
		digest, err := digestBytes(payload.DelegateAgent.DelegationDigest, "sha256:", false)
		if err != nil {
			return 0, nil, err
		}
		b.MustStoreSlice(digest, 256)
	case *nativev1.NativeActionV1_InitiateRecovery:
		kind = KindInitiateRecovery
		if targetKind != 1 || payload.InitiateRecovery == nil {
			return 0, nil, errors.New("invalid recovery initiation")
		}
		policy, err := PolicyCell(payload.InitiateRecovery.NewPolicy)
		if err != nil {
			return 0, nil, err
		}
		b.MustStoreUInt(payload.InitiateRecovery.ExecuteAfterUnixSeconds, 64).MustStoreRef(policy)
	case *nativev1.NativeActionV1_CompleteRecovery:
		kind = KindCompleteRecovery
		if targetKind != 1 || payload.CompleteRecovery == nil {
			return 0, nil, errors.New("invalid recovery completion")
		}
		digest, err := digestBytes(payload.CompleteRecovery.InitiationActionHash, "sha256:", false)
		if err != nil {
			return 0, nil, err
		}
		b.MustStoreSlice(digest, 256)
	case *nativev1.NativeActionV1_RevokeAgent:
		kind = KindRevokeAgent
		if targetKind != 1 || payload.RevokeAgent == nil {
			return 0, nil, errors.New("invalid Agent revocation")
		}
	case *nativev1.NativeActionV1_RegisterCapability:
		kind = KindRegisterCapability
		p := payload.RegisterCapability
		if targetKind != 2 || p == nil || len(p.ObjectNonce) != 32 || bytes.Equal(p.ObjectNonce, make([]byte, 32)) || p.InitialVersion == nil {
			return 0, nil, errors.New("invalid Capability registration")
		}
		owner, ownerKind, err := objectID(p.OwnerAgentId)
		if err != nil || ownerKind != 1 {
			return 0, nil, errors.New("invalid Capability owner")
		}
		versionHash, manifest, err := capabilityVersion(p.InitialVersion)
		if err != nil {
			return 0, nil, err
		}
		versionDetails := cell.BeginCell().MustStoreSlice(versionHash, 256).MustStoreSlice(manifest, 256).
			MustStoreRef(stringCell(p.InitialVersion.Version)).EndCell()
		b.MustStoreSlice(p.ObjectNonce, 256).MustStoreSlice(owner, 256).MustStoreRef(versionDetails)
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		kind = KindAddCapabilityVersion
		if targetKind != 2 || payload.AddCapabilityVersion == nil || payload.AddCapabilityVersion.Version == nil {
			return 0, nil, errors.New("invalid Capability version")
		}
		versionHash, manifest, err := capabilityVersion(payload.AddCapabilityVersion.Version)
		if err != nil {
			return 0, nil, err
		}
		owner, ownerKind, err := objectID(payload.AddCapabilityVersion.OwnerAgentId)
		if err != nil || ownerKind != 1 {
			return 0, nil, errors.New("invalid Capability owner")
		}
		b.MustStoreSlice(owner, 256).MustStoreSlice(versionHash, 256).MustStoreSlice(manifest, 256).MustStoreRef(stringCell(payload.AddCapabilityVersion.Version.Version))
	case *nativev1.NativeActionV1_TransferCapability:
		kind = KindTransferCapability
		p := payload.TransferCapability
		if targetKind != 2 || p == nil {
			return 0, nil, errors.New("invalid Capability transfer")
		}
		oldOwner, oldKind, err := objectID(p.CurrentOwnerAgentId)
		if err != nil || oldKind != 1 {
			return 0, nil, errors.New("invalid current owner")
		}
		newOwner, newKind, err := objectID(p.NewOwnerAgentId)
		if err != nil || newKind != 1 || bytes.Equal(oldOwner, newOwner) {
			return 0, nil, errors.New("invalid new owner")
		}
		b.MustStoreSlice(oldOwner, 256).MustStoreSlice(newOwner, 256)
	case *nativev1.NativeActionV1_RevokeCapability:
		kind = KindRevokeCapability
		if targetKind != 2 || payload.RevokeCapability == nil {
			return 0, nil, errors.New("invalid Capability revocation")
		}
		owner, ownerKind, err := objectID(payload.RevokeCapability.OwnerAgentId)
		if err != nil || ownerKind != 1 {
			return 0, nil, errors.New("invalid Capability owner")
		}
		b.MustStoreSlice(owner, 256)
		if payload.RevokeCapability.Version == "" {
			b.MustStoreBoolBit(false)
		} else {
			if !validProtocolText(payload.RevokeCapability.Version, 128) {
				return 0, nil, errors.New("invalid Capability version")
			}
			h := sha256.Sum256([]byte(payload.RevokeCapability.Version))
			b.MustStoreBoolBit(true).MustStoreSlice(h[:], 256).MustStoreRef(stringCell(payload.RevokeCapability.Version))
		}
	default:
		return 0, nil, errors.New("missing Native action payload")
	}
	return kind, b.EndCell(), nil
}

func validatePolicy(policy *nativev1.ControllerPolicyV1) (map[string]*nativev1.ControllerV1, error) {
	if policy != nil && len(policy.Controllers) > MaxControllers {
		return nil, nativeError(ErrPolicyTooWide, "Native controller policy names more controllers than the Registry admits")
	}
	if policy == nil || policy.Threshold == 0 || policy.RecoveryThreshold == 0 || len(policy.Controllers) == 0 {
		return nil, errors.New("invalid Native controller policy")
	}
	controllers := make(map[string]*nativev1.ControllerV1, len(policy.Controllers))
	publicKeys := make(map[string]struct{}, len(policy.Controllers))
	var recoveryTotal uint64
	purposeTotals := map[uint32]uint64{
		PurposeAgentControl:      0,
		PurposeDelegation:        0,
		PurposeCapabilityControl: 0,
	}
	for _, controller := range policy.Controllers {
		if controller == nil || !validKeyID(controller.KeyId) || len(controller.Ed25519PublicKey) != ed25519.PublicKeySize || !bytes.Equal(keyIDHash(controller.KeyId), controller.Ed25519PublicKey) || bytes.Equal(controller.Ed25519PublicKey, make([]byte, 32)) || controller.Weight == 0 || controller.Weight > MaxControllerWeight || controller.PurposeMask == 0 || controller.PurposeMask&^uint32(knownPurposeMask) != 0 {
			return nil, errors.New("Native controllers must be valid")
		}
		if _, duplicate := controllers[controller.KeyId]; duplicate {
			return nil, errors.New("duplicate Native controller key ID")
		}
		publicKey := string(controller.Ed25519PublicKey)
		if _, duplicate := publicKeys[publicKey]; duplicate {
			return nil, errors.New("duplicate Native controller public key")
		}
		if controller.Recovery != (controller.PurposeMask&PurposeRecovery != 0) {
			return nil, errors.New("Native controller must declare recovery purpose consistently")
		}
		controllers[controller.KeyId] = controller
		publicKeys[publicKey] = struct{}{}
		for purpose := range purposeTotals {
			if controller.PurposeMask&purpose != 0 {
				purposeTotals[purpose] += uint64(controller.Weight)
			}
		}
		if controller.Recovery {
			if controller.PurposeMask&PurposeRecovery != 0 {
				recoveryTotal += uint64(controller.Weight)
			}
		}
	}
	for _, total := range purposeTotals {
		if uint64(policy.Threshold) > total {
			return nil, errors.New("Native policy threshold is unreachable for a required purpose")
		}
	}
	if uint64(policy.RecoveryThreshold) > recoveryTotal {
		return nil, errors.New("Native policy threshold is unattainable")
	}
	if policy.RecoveryTimelockSeconds > MaxRecoveryTimelockSeconds {
		return nil, errors.New("Native recovery timelock exceeds bound")
	}
	return controllers, nil
}

func validateRegistrationIdentity(action *nativev1.NativeActionV1) error {
	var expected string
	var err error
	switch payload := action.Payload.(type) {
	case *nativev1.NativeActionV1_RegisterAgent:
		expected, err = DeriveAgentID(action.Network, payload.RegisterAgent.ObjectNonce, payload.RegisterAgent.InitialPolicy)
	case *nativev1.NativeActionV1_RegisterCapability:
		expected, err = DeriveCapabilityID(action.Network, payload.RegisterCapability.ObjectNonce,
			payload.RegisterCapability.OwnerAgentId, payload.RegisterCapability.InitialVersion)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if action.TargetObjectId != expected {
		return errors.New("Native registration target does not match its derived identity")
	}
	return nil
}

func keyIDHash(value string) []byte {
	raw, _ := hex.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	return raw
}

func capabilityVersion(version *nativev1.CapabilityVersionV1) ([]byte, []byte, error) {
	if version == nil || !validProtocolText(version.Version, 128) || version.Revoked {
		return nil, nil, errors.New("invalid new Capability version")
	}
	manifest, err := digestBytes(version.ManifestDigest, "sha256:", false)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256([]byte(version.Version))
	return h[:], manifest, nil
}

func validProtocolText(value string, maximum int) bool {
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

func objectID(value string) ([]byte, uint8, error) {
	for prefix, kind := range map[string]uint8{"agent_": 1, "cap_": 2} {
		if strings.HasPrefix(value, prefix) && len(value) == len(prefix)+64 {
			raw, err := hex.DecodeString(value[len(prefix):])
			if err == nil && value == prefix+hex.EncodeToString(raw) && !bytes.Equal(raw, make([]byte, 32)) {
				return raw, kind, nil
			}
		}
	}
	return nil, 0, errors.New("invalid Native object ID")
}

func digestBytes(value, prefix string, allowZero bool) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("invalid digest prefix")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) != 32 || value != prefix+hex.EncodeToString(raw) {
		return nil, errors.New("invalid digest")
	}
	if !allowZero && bytes.Equal(raw, make([]byte, 32)) {
		return nil, errors.New("zero digest")
	}
	return raw, nil
}

func optionalDigest(value string) ([]byte, error) {
	if value == "" {
		return make([]byte, 32), nil
	}
	return digestBytes(value, "tvm-cell-sha256:", false)
}

func stringCell(value string) *cell.Cell {
	return cell.BeginCell().MustStoreBinarySnake([]byte(value)).EndCell()
}

func validKeyID(value string) bool {
	if !strings.HasPrefix(value, "ed25519:") || len(value) != len("ed25519:")+64 {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "ed25519:"))
	return err == nil && value == "ed25519:"+hex.EncodeToString(raw) && len(raw) == ed25519.PublicKeySize && !bytes.Equal(raw, make([]byte, ed25519.PublicKeySize))
}
