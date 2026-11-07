// Package nativecore implements the single-mode tos_service_v1 execution
// envelope. It is independent of gateway-owned state and per-action contracts.
package nativecore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
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
	// signature per controller (a longer authorizing list is refused with
	// ErrThreshold before any entry is read).
	MaxControllers             = 8
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

// SignAction asks key custody to sign a built action with the named
// controller. The signature covers the action cell (custody derives its hash
// itself) under the registry context; the result is checked for shape and
// for a key ID that matches the key custody signed with.
func SignAction(ctx context.Context, signer mldsa44.Signer, controller string, built BuiltAction) (*nativev1.SignatureV1, error) {
	if ctx == nil || signer == nil || built.Cell == nil || controller == "" {
		return nil, nativeError(ErrBadSignature, "invalid Native signing input")
	}
	signature, err := signer.Sign(ctx, controller, mldsa44.UseRegistry, built.Cell.ToBOC())
	if err != nil {
		return nil, fmt.Errorf("sign Native action with controller %q: %w", controller, err)
	}
	if err := mldsa44.CheckSignature(signature); err != nil {
		return nil, nativeError(ErrBadSignature, "key custody returned a malformed Native signature")
	}
	return &nativev1.SignatureV1{KeyId: mldsa44.KeyIDText(signature.KeyID), Mldsa44Signature: signature.Signature}, nil
}

// verifyOne checks one registry signature against the controller key it is
// attributed to. An unavailable verifier is reported without a protocol
// code: it is never a decision about the signature.
func verifyOne(ctx context.Context, verifier mldsa44.Verifier, actionBOC, publicKey, signature []byte) error {
	err := verifier.Verify(ctx, mldsa44.UseRegistry, actionBOC, publicKey, signature)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mldsa44.ErrInvalidSignature), errors.Is(err, mldsa44.ErrMalformed):
		return wrapNativeError(ErrBadSignature, "invalid Native ML-DSA-44 signature", err)
	default:
		return fmt.Errorf("Native signature verification is unavailable: %w", err)
	}
}

func checkVerificationInput(ctx context.Context, verifier mldsa44.Verifier, built BuiltAction) error {
	if ctx == nil || verifier == nil || built.Cell == nil || len(built.Hash) != 32 {
		return errors.New("Native signature verification is not configured")
	}
	return nil
}

// VerifySignatures mirrors the Registry's threshold authorization against a
// policy: 1 to MaxSignatures entries, each a well-formed signature, strictly
// ascending by key ID, by a controller holding the required purpose (and the
// recovery designation in recovery mode) whose stored key verifies it, with
// their weight reaching the threshold.
func VerifySignatures(ctx context.Context, verifier mldsa44.Verifier, policy *nativev1.ControllerPolicyV1,
	signatures []*nativev1.SignatureV1, requiredPurpose uint32, recovery bool, built BuiltAction) error {
	if err := checkVerificationInput(ctx, verifier, built); err != nil {
		return err
	}
	controllers, err := validatePolicy(policy)
	if err != nil {
		return wrapNativeError(ErrBadPolicy, "invalid Native signature policy", err)
	}
	if len(signatures) == 0 || len(signatures) > MaxSignatures {
		return nativeError(ErrThreshold, "a Native signature set holds 1 to 8 signatures")
	}
	threshold := uint64(policy.Threshold)
	if recovery {
		threshold = uint64(policy.RecoveryThreshold)
	}
	actionBOC := built.Cell.ToBOC()
	var total uint64
	var previous []byte
	for _, signature := range signatures {
		if signature == nil || !validKeyID(signature.KeyId) || len(signature.Mldsa44Signature) != mldsa44.SignatureSize {
			return nativeError(ErrBadSignature, "Native signature entry is malformed")
		}
		keyID := keyIDBytes(signature.KeyId)
		if previous != nil && bytes.Compare(keyID, previous) <= 0 {
			return nativeError(ErrDuplicateSignature, "Native signatures must be strictly ascending by key ID")
		}
		controller, ok := controllers[signature.KeyId]
		if !ok || controller.PurposeMask&requiredPurpose == 0 || recovery && !controller.Recovery {
			return nativeError(ErrBadSignature, "Native signature is not authorized for the action")
		}
		if err := verifyOne(ctx, verifier, actionBOC, controller.Mldsa44PublicKey, signature.Mldsa44Signature); err != nil {
			return err
		}
		total += uint64(controller.Weight)
		previous = keyID
	}
	if total < threshold {
		return nativeError(ErrThreshold, "Native signature threshold not met")
	}
	return nil
}

// VerifyPolicyPossession mirrors the Registry's admission of a policy being
// installed: exactly one signature from every controller, in key-ID order,
// each verified against the key the policy carries. The declared key IDs
// were already checked against the keys by validatePolicy.
func VerifyPolicyPossession(ctx context.Context, verifier mldsa44.Verifier, policy *nativev1.ControllerPolicyV1,
	signatures []*nativev1.SignatureV1, built BuiltAction) error {
	if err := checkVerificationInput(ctx, verifier, built); err != nil {
		return err
	}
	controllers, err := validatePolicy(policy)
	if err != nil {
		return wrapNativeError(ErrBadPolicy, "invalid Native installation policy", err)
	}
	if len(signatures) != len(controllers) {
		return nativeError(ErrBadSignature, "Native policy installation requires one signature from every controller")
	}
	ordered := sortedControllers(controllers)
	actionBOC := built.Cell.ToBOC()
	for i, controller := range ordered {
		signature := signatures[i]
		if signature == nil || signature.KeyId != controller.KeyId || len(signature.Mldsa44Signature) != mldsa44.SignatureSize {
			return nativeError(ErrBadSignature, "Native policy possession signatures must follow the policy's key order")
		}
		if err := verifyOne(ctx, verifier, actionBOC, controller.Mldsa44PublicKey, signature.Mldsa44Signature); err != nil {
			return err
		}
	}
	return nil
}

// VerifyRegistrationConsent is the Registry's consent rule for a registration
// whose possession proofs already passed: every controller signed, so the
// consenting weight is the policy's Agent-control weight, held to the
// threshold. It verifies no signature.
func VerifyRegistrationConsent(policy *nativev1.ControllerPolicyV1) error {
	controllers, err := validatePolicy(policy)
	if err != nil {
		return wrapNativeError(ErrBadPolicy, "invalid Native registration policy", err)
	}
	var total uint64
	for _, controller := range controllers {
		if controller.PurposeMask&PurposeAgentControl != 0 {
			total += uint64(controller.Weight)
		}
	}
	if total < uint64(policy.Threshold) {
		return nativeError(ErrThreshold, "Native registration consent threshold not met")
	}
	return nil
}

// SignatureCell encodes a non-empty signature set:
// count:uint8 ^entry, entry = key_id:uint256 ^stored_signature [^entry].
func SignatureCell(signatures []*nativev1.SignatureV1) (*cell.Cell, error) {
	if len(signatures) == 0 || len(signatures) > MaxSignatures {
		return nil, nativeError(ErrThreshold, "invalid Native signature count")
	}
	var next *cell.Cell
	for i := len(signatures) - 1; i >= 0; i-- {
		signature := signatures[i]
		if signature == nil || !validKeyID(signature.KeyId) || len(signature.Mldsa44Signature) != mldsa44.SignatureSize {
			return nil, nativeError(ErrBadSignature, "invalid Native signature")
		}
		if i > 0 && (signatures[i-1] == nil || bytes.Compare(keyIDBytes(signatures[i-1].KeyId), keyIDBytes(signature.KeyId)) >= 0) {
			return nil, nativeError(ErrDuplicateSignature, "Native signatures are not strictly sorted")
		}
		builder := cell.BeginCell().MustStoreSlice(keyIDBytes(signature.KeyId), 256).
			MustStoreRef(storedBytesCell(signature.Mldsa44Signature))
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
	}
	return cell.BeginCell().MustStoreUInt(uint64(len(signatures)), 8).MustStoreRef(next).EndCell(), nil
}

func EmptySignatureCell() *cell.Cell { return cell.BeginCell().MustStoreUInt(0, 8).EndCell() }

func MessageBody(action BuiltAction, authority, counterparty []*nativev1.SignatureV1, queryID uint64) (*cell.Cell, error) {
	return messageBody(opSubmit, action, authority, counterparty, queryID)
}

func AgentAuthorizationBody(action BuiltAction, authority, counterparty []*nativev1.SignatureV1, queryID uint64) (*cell.Cell, error) {
	return messageBody(opAuthorizeCapability, action, authority, counterparty, queryID)
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
	ordered := sortedControllers(controllers)
	var next *cell.Cell
	for i := len(ordered) - 1; i >= 0; i-- {
		controller := ordered[i]
		builder := cell.BeginCell().MustStoreSlice(keyIDBytes(controller.KeyId), 256).
			MustStoreUInt(uint64(controller.Weight), 32).MustStoreUInt(uint64(controller.PurposeMask), 16).
			MustStoreBoolBit(controller.Recovery).MustStoreRef(storedBytesCell(controller.Mldsa44PublicKey))
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
	var recoveryTotal uint64
	purposeTotals := map[uint32]uint64{
		PurposeAgentControl:      0,
		PurposeDelegation:        0,
		PurposeCapabilityControl: 0,
	}
	for _, controller := range policy.Controllers {
		if controller == nil || !validKeyID(controller.KeyId) || len(controller.Mldsa44PublicKey) != mldsa44.PublicKeySize ||
			controller.Weight == 0 || controller.Weight > MaxControllerWeight || controller.PurposeMask == 0 ||
			controller.PurposeMask&^uint32(knownPurposeMask) != 0 {
			return nil, errors.New("Native controllers must be valid")
		}
		derived, err := mldsa44.KeyID(controller.Mldsa44PublicKey)
		if err != nil || mldsa44.KeyIDText(derived) != controller.KeyId {
			return nil, errors.New("Native controller key ID does not match its ML-DSA-44 public key")
		}
		// A duplicate key yields a duplicate key ID, so one check covers both.
		if _, duplicate := controllers[controller.KeyId]; duplicate {
			return nil, errors.New("duplicate Native controller key ID")
		}
		if controller.Recovery != (controller.PurposeMask&PurposeRecovery != 0) {
			return nil, errors.New("Native controller must declare recovery purpose consistently")
		}
		controllers[controller.KeyId] = controller
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

// keyIDBytes returns the 32 key-ID bytes of a text key ID that validKeyID
// accepted, or nil.
func keyIDBytes(value string) []byte {
	id, err := mldsa44.ParseKeyIDText(value)
	if err != nil {
		return nil
	}
	return id[:]
}

// SortSignatures returns the signatures in ascending key-ID byte order, the
// only order the Registry accepts. It does not remove duplicates or validate
// entries; SignatureCell refuses both.
func SortSignatures(signatures []*nativev1.SignatureV1) []*nativev1.SignatureV1 {
	ordered := append([]*nativev1.SignatureV1(nil), signatures...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return bytes.Compare(keyIDBytes(ordered[i].GetKeyId()), keyIDBytes(ordered[j].GetKeyId())) < 0
	})
	return ordered
}

// sortedControllers orders validated controllers by key ID, the only order
// the Registry stores and checks them in.
func sortedControllers(controllers map[string]*nativev1.ControllerV1) []*nativev1.ControllerV1 {
	ordered := make([]*nativev1.ControllerV1, 0, len(controllers))
	for _, controller := range controllers {
		ordered = append(ordered, controller)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(keyIDBytes(ordered[i].KeyId), keyIDBytes(ordered[j].KeyId)) < 0
	})
	return ordered
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

// validKeyID accepts exactly mldsa44:<64 lowercase hex>, nonzero.
func validKeyID(value string) bool {
	_, err := mldsa44.ParseKeyIDText(value)
	return err == nil
}
