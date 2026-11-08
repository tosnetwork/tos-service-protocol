package agentcommerce

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// ErrEd25519ActionAuthority reports an Ed25519 Action Authority key or
// signature. The Action Authority suite is Pure ML-DSA-44 only; there is no
// other suite to select, so this error is a diagnostic for the refusal the
// canonical text parsers already make.
var ErrEd25519ActionAuthority = errors.New(
	"Ed25519 Action Authority keys and signatures are not accepted; the Action Authority suite is ML-DSA-44")

const removedActionAuthorityPrefix = "ed25519:"

// ParseActionAuthorityKeyID reads the only text form of an Action Authority
// key reference, mldsa44:<64 lowercase hex> of the ML-DSA-44 controller key ID
// (NATIVE_IDENTIFIERS_V1), exactly as AuthorizedAction.AuthorityKeyID and
// WriterFence.KeyID are read.
func ParseActionAuthorityKeyID(value string) ([mldsa44.KeyIDSize]byte, error) {
	if strings.HasPrefix(value, removedActionAuthorityPrefix) {
		return [mldsa44.KeyIDSize]byte{}, ErrEd25519ActionAuthority
	}
	keyID, err := mldsa44.ParseKeyIDText(value)
	if err != nil {
		return [mldsa44.KeyIDSize]byte{}, errors.New("Action Authority key ID is not canonical mldsa44:<64 lowercase hex>")
	}
	return keyID, nil
}

// ParseActionAuthoritySignature reads the only text form of an Action
// Authority signature, mldsa44:<canonical unpadded URL-safe Base64 of 2,420
// bytes>, exactly as AuthorizedAction.AuthorizationProof and
// WriterFence.Proof are read.
func ParseActionAuthoritySignature(value string) ([]byte, error) {
	if strings.HasPrefix(value, removedActionAuthorityPrefix) {
		return nil, ErrEd25519ActionAuthority
	}
	signature, err := mldsa44.ParseSignatureText(value)
	if err != nil {
		return nil, errors.New("Action Authority signature is not canonical mldsa44:<Base64url of 2,420 bytes>")
	}
	return signature, nil
}

// ActionAuthoritySignatureText renders a 2,420-byte ML-DSA-44 signature in the
// only Action Authority signature text form.
func ActionAuthoritySignatureText(signature []byte) (string, error) {
	text, err := mldsa44.SignatureText(signature)
	if err != nil {
		return "", errors.New("Action Authority signature is not 2,420 bytes")
	}
	return text, nil
}

// SignActionAuthorityMessage asks key custody to sign one 32-byte Action
// Authority message with a named controller and returns the key ID and
// signature in their text forms. The returned key and signature are checked
// for shape and for a key ID that matches the key.
func SignActionAuthorityMessage(ctx context.Context, signer mldsa44.Signer, controller string,
	message []byte) (string, string, error) {
	if ctx == nil || signer == nil || mldsa44.CheckMessage(mldsa44.UseActionAuthority, message) != nil {
		return "", "", errors.New("Action Authority signing request is invalid")
	}
	signed, err := signer.Sign(ctx, controller, mldsa44.UseActionAuthority, message)
	if err != nil {
		return "", "", fmt.Errorf("Action Authority signing failed: %w", err)
	}
	if err := mldsa44.CheckSignature(signed); err != nil {
		return "", "", errors.New("Action Authority signer returned a malformed signature")
	}
	signature, err := mldsa44.SignatureText(signed.Signature)
	if err != nil {
		return "", "", errors.New("Action Authority signer returned a malformed signature")
	}
	return mldsa44.KeyIDText(signed.KeyID), signature, nil
}

// VerifyActionAuthoritySignature resolves the key named by keyIDText as
// authorized for authorityID at the authority time, requires the resolved key
// to derive exactly that key ID, and verifies the Pure ML-DSA-44 signature
// over the 32-byte message under the Action Authority context.
func VerifyActionAuthoritySignature(resolver FenceAuthorityResolver, authorityID, keyIDText, signatureText string,
	message []byte, at time.Time) error {
	if resolver == nil {
		return errors.New("Action Authority resolver is unavailable")
	}
	if len(message) != mldsa44.ActionAuthorityMessageSize {
		return errors.New("Action Authority message is not a 32-byte digest")
	}
	keyID, err := ParseActionAuthorityKeyID(keyIDText)
	if err != nil {
		return err
	}
	signature, err := ParseActionAuthoritySignature(signatureText)
	if err != nil {
		return err
	}
	publicKey, err := resolver.ResolveActionAuthorityKey(authorityID, keyID, at.UTC())
	if err != nil {
		return fmt.Errorf("Action Authority key is not authorized: %w", err)
	}
	derived, err := mldsa44.KeyID(publicKey)
	if err != nil || derived != keyID {
		return errors.New("Action Authority resolved key does not derive its key ID")
	}
	if err := resolver.Verify(context.Background(), mldsa44.UseActionAuthority, message, publicKey, signature); err != nil {
		return fmt.Errorf("Action Authority signature does not verify: %w", err)
	}
	return nil
}

type WriterFenceBody struct {
	SchemaVersion    uint16   `json:"schema_version"`
	OwnerID          string   `json:"owner_id"`
	AgentID          string   `json:"agent_id"`
	InstanceID       string   `json:"instance_id"`
	LeaseID          string   `json:"lease_id"`
	WriterGeneration uint64   `json:"writer_generation"`
	IssuedAtUnix     uint64   `json:"issued_at_unix"`
	ExpiresAtUnix    uint64   `json:"expires_at_unix"`
	AuthorityID      string   `json:"authority_id"`
	Scope            []string `json:"scope"`
}

type WriterFence struct {
	Body  WriterFenceBody `json:"body"`
	KeyID string          `json:"key_id"`
	Proof string          `json:"fence_proof"`
}

// FenceAuthorityResolver resolves Action Authority keys and verifies their
// ML-DSA-44 signatures. ResolveActionAuthorityKey returns the 1,312-byte
// public key named by keyID only when that key is authorized for authorityID
// at `at`; any unknown, revoked, ambiguous or unavailable state is an error.
// Verify is the ML-DSA-44 verification boundary (normally the pinned tosctl
// helper). Callers always recompute the key ID of the returned key.
type FenceAuthorityResolver interface {
	mldsa44.Verifier
	ResolveActionAuthorityKey(authorityID string, keyID [mldsa44.KeyIDSize]byte, at time.Time) ([]byte, error)
}

// CurrentWriterFenceResolver adds a live, fail-closed lease check to the
// cryptographic FenceAuthorityResolver contract. Signature/key authorization
// proves that a fence was issued by an authority; it does not prove that the
// same lease and generation are still the authority's current writer after a
// takeover.
//
// Implementations must resolve currentness from the linearizable writer
// authority for the fence's owner/Agent and compare the complete lease
// identity, including InstanceID, LeaseID, WriterGeneration and AuthorityID.
// An unavailable, ambiguous, rolled-back, superseded, or expired authority
// view must return an error. Cached positive results must not outlive the
// authority's stated lease/currentness bound.
//
// This interface is intentionally separate from FenceAuthorityResolver so
// existing read-only and non-relay signature verification callers do not gain
// a new operational dependency.
type CurrentWriterFenceResolver interface {
	FenceAuthorityResolver
	ConfirmCurrentWriterFence(fence WriterFence, at time.Time) error
}

// ConfirmCurrentWriterFence invokes the live writer-authority check and fails
// closed when no currentness resolver is configured.
func ConfirmCurrentWriterFence(fence WriterFence, resolver CurrentWriterFenceResolver, at time.Time) error {
	if resolver == nil {
		return errors.New("current writer fence resolver is unavailable")
	}
	at = at.UTC()
	if !at.Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("current writer fence is expired")
	}
	if err := resolver.ConfirmCurrentWriterFence(fence, at); err != nil {
		return fmt.Errorf("writer fence is not current: %w", err)
	}
	return nil
}

type AuthorizedAction struct {
	SchemaVersion      uint16 `json:"schema_version"`
	OwnerID            string `json:"owner_id"`
	AgentID            string `json:"agent_id"`
	ActionKind         string `json:"action_kind"`
	StableActionID     string `json:"stable_action_id"`
	ExactRequestDigest string `json:"exact_request_digest"`
	WriterGeneration   uint64 `json:"writer_generation"`
	WriterFenceDigest  string `json:"writer_fence_digest"`
	PolicyRevision     uint64 `json:"policy_revision"`
	MandateDigest      string `json:"mandate_digest"`
	ApprovalDigest     string `json:"approval_digest,omitempty"`
	ExpectedPriorState string `json:"expected_prior_state"`
	ExpiresAtUnix      uint64 `json:"expires_at_unix"`
	AuthorityID        string `json:"authority_id"`
	AuthorityKeyID     string `json:"authority_key_id"`
	AuthorizationProof string `json:"authorization_proof"`
}

type ActionResolutionState string

const (
	ActionUnknown   ActionResolutionState = "unknown"
	ActionPrepared  ActionResolutionState = "prepared"
	ActionSubmitted ActionResolutionState = "submitted"
	ActionAccepted  ActionResolutionState = "accepted"
	ActionRejected  ActionResolutionState = "rejected"
	ActionConflict  ActionResolutionState = "conflict"
	ActionTerminal  ActionResolutionState = "terminal"
)

type ActionResolution struct {
	StableActionID     string                `json:"stable_action_id"`
	ExactRequestDigest string                `json:"exact_request_digest"`
	State              ActionResolutionState `json:"state"`
	SinkReference      string                `json:"sink_reference,omitempty"`
	EvidenceRefs       []string              `json:"evidence_refs,omitempty"`
	StateRevision      uint64                `json:"state_revision"`
}

type AuthorityInstanceAllocationRequest struct {
	OwnerID                          string `json:"owner_id"`
	AgentID                          string `json:"agent_id"`
	PurposeKind                      string `json:"purpose_kind"`
	MandateDigest                    string `json:"mandate_digest"`
	ApprovalDigestOrZero             string `json:"approval_digest_or_zero"`
	DownstreamEffectDescriptorDigest string `json:"downstream_effect_descriptor_digest"`
	PredecessorAuthorityInstanceID   string `json:"predecessor_authority_instance_id"`
}

type AuthorityInstanceRecord struct {
	RequestDigest       string `json:"allocation_request_digest"`
	AllocationSequence  uint64 `json:"authority_allocation_sequence"`
	AuthorityInstanceID string `json:"authority_instance_id"`
	PolicyRevision      uint64 `json:"policy_revision"`
	Terminal            bool   `json:"terminal"`
}

// WriterFenceSignatureMessage is the 32-byte message an Action Authority
// signs for a Writer Fence: the framed SHA-256 of its canonical body.
func WriterFenceSignatureMessage(body WriterFenceBody) ([]byte, error) {
	if err := validateWriterFenceBody(body); err != nil {
		return nil, err
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		return nil, err
	}
	return framedSHA256("tos.writer-fence.v1\x00", canonical), nil
}

// SignWriterFence has the Action Authority controller in custody sign a
// Writer Fence body; the fence carries the controller's key ID.
func SignWriterFence(ctx context.Context, body WriterFenceBody, signer mldsa44.Signer, controller string) (WriterFence, error) {
	message, err := WriterFenceSignatureMessage(body)
	if err != nil {
		return WriterFence{}, err
	}
	keyID, proof, err := SignActionAuthorityMessage(ctx, signer, controller, message)
	if err != nil {
		return WriterFence{}, err
	}
	return WriterFence{Body: body, KeyID: keyID, Proof: proof}, nil
}

func VerifyWriterFence(fence WriterFence, resolver FenceAuthorityResolver, now time.Time, actionKind string) error {
	return verifyWriterFenceAtAuthorityTime(fence, resolver, now, now, actionKind)
}

func verifyWriterFenceAtAuthorityTime(fence WriterFence, resolver FenceAuthorityResolver,
	validityAt, authorityAt time.Time, actionKind string) error {
	if err := validateWriterFenceBody(fence.Body); err != nil {
		return err
	}
	issuedAt := time.Unix(int64(fence.Body.IssuedAtUnix), 0).UTC()
	expiresAt := time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()
	validityAt = validityAt.UTC()
	authorityAt = authorityAt.UTC()
	if resolver == nil || !validityAt.Before(expiresAt) || validityAt.Before(issuedAt.Add(-MaxIntentClockSkew)) ||
		authorityAt.Before(issuedAt.Add(-MaxIntentClockSkew)) || !authorityAt.Before(expiresAt) ||
		!containsSorted(fence.Body.Scope, actionKind) {
		return errors.New("writer fence is expired, premature, or out of scope")
	}
	message, err := WriterFenceSignatureMessage(fence.Body)
	if err != nil {
		return err
	}
	if err := VerifyActionAuthoritySignature(resolver, fence.Body.AuthorityID, fence.KeyID, fence.Proof,
		message, authorityAt); err != nil {
		return fmt.Errorf("writer fence proof is invalid: %w", err)
	}
	return nil
}

func WriterFenceDigest(fence WriterFence) (string, error) {
	if err := validateWriterFenceBody(fence.Body); err != nil {
		return "", err
	}
	if _, err := ParseActionAuthorityKeyID(fence.KeyID); err != nil {
		return "", fmt.Errorf("writer fence key ID encoding is invalid: %w", err)
	}
	if _, err := ParseActionAuthoritySignature(fence.Proof); err != nil {
		return "", fmt.Errorf("writer fence proof encoding is invalid: %w", err)
	}
	return codec.Digest("tos.writer-fence-envelope.v1", fence)
}

// AuthorizedActionDigest commits the complete signed authorization envelope.
// It is used by downstream admission receipts so replacing a policy, mandate,
// approval, writer generation, authority key, or proof cannot preserve an
// already-issued side-effect admission.
func AuthorizedActionDigest(action AuthorizedAction) (string, error) {
	if err := validateAuthorizedActionShape(action); err != nil || action.AuthorityKeyID == "" {
		return "", errors.New("authorized action envelope is invalid")
	}
	return codec.Digest("tos.authorized-action-envelope.v1", action)
}

func BuildAuthorizedAction(ownerID, agentID, actionKind string, semanticFields map[string]SemanticValue,
	canonicalRequest []byte, fence WriterFence, policyRevision uint64, mandateDigest, approvalDigest,
	expectedPriorState string, expiresAt uint64) (AuthorizedAction, error) {
	if err := validateSemanticActionPrincipals(ownerID, agentID, semanticFields); err != nil {
		return AuthorizedAction{}, err
	}
	stableID, _, err := DeriveStableActionID(actionKind, semanticFields)
	if err != nil {
		return AuthorizedAction{}, err
	}
	requestDigest, err := ExactRequestDigest(canonicalRequest)
	if err != nil {
		return AuthorizedAction{}, err
	}
	fenceDigest, err := WriterFenceDigest(fence)
	if err != nil {
		return AuthorizedAction{}, err
	}
	action := AuthorizedAction{SchemaVersion: 1, OwnerID: ownerID, AgentID: agentID, ActionKind: actionKind,
		StableActionID: stableID, ExactRequestDigest: requestDigest, WriterGeneration: fence.Body.WriterGeneration,
		WriterFenceDigest: fenceDigest, PolicyRevision: policyRevision, MandateDigest: mandateDigest,
		ApprovalDigest: approvalDigest, ExpectedPriorState: expectedPriorState, ExpiresAtUnix: expiresAt,
		AuthorityID: fence.Body.AuthorityID}
	if err := validateAuthorizedActionShape(action); err != nil {
		return AuthorizedAction{}, err
	}
	return action, nil
}

// SignAuthorizedAction has the Action Authority controller in custody sign
// an unsigned AuthorizedAction. The key ID is part of the signed canonical
// object, so the caller names it first; custody must sign with exactly that
// key.
func SignAuthorizedAction(ctx context.Context, action AuthorizedAction, keyID string, signer mldsa44.Signer,
	controller string) (AuthorizedAction, error) {
	if action.AuthorityKeyID != "" || action.AuthorizationProof != "" {
		return AuthorizedAction{}, errors.New("authorized action signing request is invalid")
	}
	if _, err := ParseActionAuthorityKeyID(keyID); err != nil {
		return AuthorizedAction{}, err
	}
	if err := validateAuthorizedActionShape(action); err != nil {
		return AuthorizedAction{}, err
	}
	action.AuthorityKeyID = keyID
	message, err := AuthorizedActionSignatureMessage(action)
	if err != nil {
		return AuthorizedAction{}, err
	}
	signedKeyID, proof, err := SignActionAuthorityMessage(ctx, signer, controller, message)
	if err != nil {
		return AuthorizedAction{}, err
	}
	if signedKeyID != keyID {
		return AuthorizedAction{}, errors.New("authorized action was signed by a key other than the named key")
	}
	action.AuthorizationProof = proof
	return action, nil
}

func VerifyAuthorizedAction(action AuthorizedAction, semanticFields map[string]SemanticValue, canonicalRequest []byte,
	fence WriterFence, resolver FenceAuthorityResolver, now time.Time) error {
	return VerifyAuthorizedActionAtAuthorityTime(action, semanticFields, canonicalRequest, fence, resolver, now, now)
}

// VerifyAuthorizedActionAtAuthorityTime keeps all signed validity windows live
// at validityAt while resolving the authority key at authorityAt. A downstream
// sink uses the authenticated side-effect admission receipt's issuance instant
// as authorityAt, so an already-issued action can drain after a legitimate key
// rotation without reviving an expired action or writer lease.
func VerifyAuthorizedActionAtAuthorityTime(action AuthorizedAction, semanticFields map[string]SemanticValue,
	canonicalRequest []byte, fence WriterFence, resolver FenceAuthorityResolver,
	validityAt, authorityAt time.Time) error {
	if err := validateAuthorizedActionShape(action); err != nil {
		return err
	}
	if err := validateSemanticActionPrincipals(action.OwnerID, action.AgentID, semanticFields); err != nil {
		return err
	}
	if action.OwnerID != fence.Body.OwnerID || action.AgentID != fence.Body.AgentID || action.WriterGeneration != fence.Body.WriterGeneration ||
		action.ExpiresAtUnix > fence.Body.ExpiresAtUnix || !validityAt.UTC().Before(time.Unix(int64(action.ExpiresAtUnix), 0).UTC()) {
		return errors.New("authorized action does not match the current writer fence")
	}
	if err := verifyWriterFenceAtAuthorityTime(fence, resolver, validityAt, authorityAt, action.ActionKind); err != nil {
		return err
	}
	if action.AuthorityID != fence.Body.AuthorityID || action.AuthorityKeyID != fence.KeyID {
		return errors.New("authorized action authority differs from the writer fence")
	}
	message, err := AuthorizedActionSignatureMessage(action)
	if err != nil {
		return errors.New("authorized action proof is invalid")
	}
	if err := VerifyActionAuthoritySignature(resolver, action.AuthorityID, action.AuthorityKeyID,
		action.AuthorizationProof, message, authorityAt); err != nil {
		return fmt.Errorf("authorized action proof is invalid: %w", err)
	}
	fenceDigest, err := WriterFenceDigest(fence)
	if err != nil || fenceDigest != action.WriterFenceDigest {
		return errors.New("authorized action fence digest mismatch")
	}
	stableID, _, err := DeriveStableActionID(action.ActionKind, semanticFields)
	if err != nil || stableID != action.StableActionID {
		return errors.New("authorized action semantic identity mismatch")
	}
	requestDigest, err := ExactRequestDigest(canonicalRequest)
	if err != nil || requestDigest != action.ExactRequestDigest {
		return errors.New("authorized action request digest mismatch")
	}
	return nil
}

func validateSemanticActionPrincipals(ownerID, agentID string, fields map[string]SemanticValue) error {
	owner, ownerFound := fields["owner_id"]
	agent, agentFound := fields["agent_id"]
	if !ownerFound || !agentFound || owner.typeOf != SemanticID || agent.typeOf != SemanticID ||
		string(owner.bytes) != ownerID || string(agent.bytes) != agentID {
		return errors.New("semantic action principals differ from the authorized action")
	}
	return nil
}

func ValidateActionResolution(resolution ActionResolution) error {
	if !canonicalDigestPattern.MatchString(resolution.StableActionID) || !canonicalDigestPattern.MatchString(resolution.ExactRequestDigest) ||
		resolution.StateRevision == 0 || validateSortedDigests(resolution.EvidenceRefs, 256) != nil || len(resolution.SinkReference) > 1024 {
		return errors.New("action resolution is invalid")
	}
	switch resolution.State {
	case ActionUnknown:
		if resolution.StateRevision != 1 || resolution.SinkReference != "" || len(resolution.EvidenceRefs) != 0 {
			return errors.New("unknown action carries sink state")
		}
	case ActionPrepared, ActionSubmitted, ActionAccepted, ActionRejected, ActionConflict, ActionTerminal:
	default:
		return errors.New("action resolution state is unknown")
	}
	return nil
}

func DownstreamEffectDescriptorDigest(canonicalEffectBody []byte) (string, error) {
	if len(canonicalEffectBody) == 0 || len(canonicalEffectBody) > MaxActionRequestBytes {
		return "", errors.New("canonical effect body has invalid size")
	}
	return "sha256:" + hex.EncodeToString(framedSHA256("tos.authority-instance-effect.v1\x00", canonicalEffectBody)), nil
}

func AuthorityInstanceAllocationRequestDigest(request AuthorityInstanceAllocationRequest) (string, error) {
	if !boundedIdentifier(request.OwnerID, 256) || !boundedIdentifier(request.AgentID, 256) || !canonicalLowerToken(request.PurposeKind) ||
		!canonicalDigestPattern.MatchString(request.MandateDigest) || !canonicalDigestOrZero(request.ApprovalDigestOrZero) ||
		!canonicalDigestPattern.MatchString(request.DownstreamEffectDescriptorDigest) || !canonicalDigestOrZero(request.PredecessorAuthorityInstanceID) {
		return "", errors.New("authority instance allocation request is invalid")
	}
	canonical, err := codec.Marshal(request)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(framedSHA256("tos.authority-instance-allocation.v1\x00", canonical)), nil
}

func DeriveAuthorityInstanceID(request AuthorityInstanceAllocationRequest, sequence uint64) (string, error) {
	requestDigest, err := AuthorityInstanceAllocationRequestDigest(request)
	if err != nil || sequence == 0 {
		return "", errors.New("authority instance allocation sequence is invalid")
	}
	identifier, _, err := DeriveStableActionID("authority.instance", map[string]SemanticValue{
		"owner_id": ID(request.OwnerID), "agent_id": ID(request.AgentID), "purpose_kind": Kind(request.PurposeKind),
		"mandate_digest": Digest32(request.MandateDigest), "allocation_request_digest": Digest32(requestDigest),
		"authority_allocation_sequence": U64(sequence),
	})
	return identifier, err
}

func validateWriterFenceBody(body WriterFenceBody) error {
	if body.SchemaVersion != 1 || !boundedIdentifier(body.OwnerID, 256) || !boundedIdentifier(body.AgentID, 256) ||
		!boundedIdentifier(body.InstanceID, 256) || !boundedIdentifier(body.LeaseID, 256) || body.WriterGeneration == 0 ||
		body.IssuedAtUnix == 0 || body.ExpiresAtUnix <= body.IssuedAtUnix || body.ExpiresAtUnix-body.IssuedAtUnix > 24*60*60 ||
		!boundedIdentifier(body.AuthorityID, 256) || len(body.Scope) == 0 || validateSortedStrings(body.Scope, 64, 128) != nil {
		return errors.New("writer fence body is invalid")
	}
	for _, kind := range body.Scope {
		if _, known := semanticActionRegistry[kind]; !known {
			return fmt.Errorf("writer fence contains unknown action scope %q", kind)
		}
	}
	return nil
}

func validateAuthorizedActionShape(action AuthorizedAction) error {
	if action.SchemaVersion != 1 || !boundedIdentifier(action.OwnerID, 256) || !boundedIdentifier(action.AgentID, 256) ||
		semanticActionRegistry[action.ActionKind].ActionKind == "" || !canonicalDigestPattern.MatchString(action.StableActionID) ||
		!canonicalDigestPattern.MatchString(action.ExactRequestDigest) || action.WriterGeneration == 0 ||
		!canonicalDigestPattern.MatchString(action.WriterFenceDigest) || action.PolicyRevision == 0 ||
		!canonicalDigestPattern.MatchString(action.MandateDigest) || action.ApprovalDigest != "" && !canonicalDigestPattern.MatchString(action.ApprovalDigest) ||
		!boundedIdentifier(action.ExpectedPriorState, 128) || action.ExpiresAtUnix == 0 || !boundedIdentifier(action.AuthorityID, 256) ||
		(action.AuthorityKeyID == "") != (action.AuthorizationProof == "") {
		return errors.New("authorized action is invalid")
	}
	if action.AuthorityKeyID != "" {
		if _, err := ParseActionAuthorityKeyID(action.AuthorityKeyID); err != nil {
			return fmt.Errorf("authorized action authority key ID is invalid: %w", err)
		}
		if _, err := ParseActionAuthoritySignature(action.AuthorizationProof); err != nil {
			return fmt.Errorf("authorized action proof encoding is invalid: %w", err)
		}
	}
	return nil
}

// AuthorizedActionSignatureMessage is the 32-byte message an Action Authority
// signs for an AuthorizedAction: the framed SHA-256 of its canonical object
// with an empty authorization_proof (authority_key_id included).
func AuthorizedActionSignatureMessage(action AuthorizedAction) ([]byte, error) {
	if !strings.HasPrefix(action.AuthorityKeyID, mldsa44.KeyIDPrefix) {
		return nil, errors.New("authorized action names no Action Authority key")
	}
	return authorizedActionSignatureMessage(action)
}

func authorizedActionSignatureMessage(action AuthorizedAction) ([]byte, error) {
	action.AuthorizationProof = ""
	canonical, err := codec.Marshal(action)
	if err != nil {
		return nil, err
	}
	return framedSHA256("tos.authorized-action-proof.v1\x00", canonical), nil
}

func canonicalDigestOrZero(value string) bool {
	return value == "sha256:"+stringsOfZero(64) || canonicalDigestPattern.MatchString(value)
}

func stringsOfZero(length int) string {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = '0'
	}
	return string(buffer)
}
