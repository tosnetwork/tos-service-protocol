package agentcommerce

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

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
	Body      WriterFenceBody `json:"body"`
	PublicKey string          `json:"public_key"`
	Proof     string          `json:"fence_proof"`
}

type FenceAuthorityResolver interface {
	AuthorizeFenceKey(authorityID string, publicKey ed25519.PublicKey, at time.Time) error
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
	AuthorityPublicKey string `json:"authority_public_key"`
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

func SignWriterFence(body WriterFenceBody, privateKey ed25519.PrivateKey) (WriterFence, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return WriterFence{}, errors.New("writer fence signing key is invalid")
	}
	if err := validateWriterFenceBody(body); err != nil {
		return WriterFence{}, err
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		return WriterFence{}, err
	}
	message := framedSHA256("tos.writer-fence.v1\x00", canonical)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return WriterFence{Body: body, PublicKey: "ed25519:" + hex.EncodeToString(publicKey),
		Proof: "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
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
	publicKey, err := parseEd25519PublicKey(fence.PublicKey)
	if err != nil {
		return err
	}
	if err := resolver.AuthorizeFenceKey(fence.Body.AuthorityID, publicKey, authorityAt); err != nil {
		return err
	}
	proof, err := parseEd25519Signature(fence.Proof)
	if err != nil {
		return err
	}
	canonical, err := codec.Marshal(fence.Body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, framedSHA256("tos.writer-fence.v1\x00", canonical), proof) {
		return errors.New("writer fence proof is invalid")
	}
	return nil
}

func WriterFenceDigest(fence WriterFence) (string, error) {
	if err := validateWriterFenceBody(fence.Body); err != nil {
		return "", err
	}
	if _, err := parseEd25519PublicKey(fence.PublicKey); err != nil {
		return "", errors.New("writer fence public key encoding is invalid")
	}
	if _, err := parseEd25519Signature(fence.Proof); err != nil {
		return "", errors.New("writer fence proof encoding is invalid")
	}
	return codec.Digest("tos.writer-fence-envelope.v1", fence)
}

// AuthorizedActionDigest commits the complete signed authorization envelope.
// It is used by downstream admission receipts so replacing a policy, mandate,
// approval, writer generation, authority key, or proof cannot preserve an
// already-issued side-effect admission.
func AuthorizedActionDigest(action AuthorizedAction) (string, error) {
	if err := validateAuthorizedActionShape(action); err != nil || action.AuthorityPublicKey == "" {
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

func SignAuthorizedAction(action AuthorizedAction, privateKey ed25519.PrivateKey) (AuthorizedAction, error) {
	if len(privateKey) != ed25519.PrivateKeySize || action.AuthorityPublicKey != "" || action.AuthorizationProof != "" {
		return AuthorizedAction{}, errors.New("authorized action signing request is invalid")
	}
	if err := validateAuthorizedActionShape(action); err != nil {
		return AuthorizedAction{}, err
	}
	public := privateKey.Public().(ed25519.PublicKey)
	action.AuthorityPublicKey = "ed25519:" + hex.EncodeToString(public)
	message, err := authorizedActionSignatureMessage(action)
	if err != nil {
		return AuthorizedAction{}, err
	}
	action.AuthorizationProof = "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	return action, nil
}

// ParseAuthorizedActionPublicKey reads the only text form of an Action
// Authority key, `ed25519:` and 64 lowercase hex characters, exactly as
// AuthorizedAction.AuthorityPublicKey is read.
func ParseAuthorizedActionPublicKey(value string) (ed25519.PublicKey, error) {
	return parseEd25519PublicKey(value)
}

// ParseAuthorizedActionProof reads the only text form of an Action Authority
// signature, `ed25519:` and the canonical unpadded URL-safe Base64 of 64
// bytes, exactly as AuthorizedAction.AuthorizationProof is read.
func ParseAuthorizedActionProof(value string) ([]byte, error) {
	return parseEd25519Signature(value)
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
	if action.AuthorityID != fence.Body.AuthorityID || action.AuthorityPublicKey != fence.PublicKey {
		return errors.New("authorized action authority differs from the writer fence")
	}
	authorityKey, err := parseEd25519PublicKey(action.AuthorityPublicKey)
	if err != nil || resolver.AuthorizeFenceKey(action.AuthorityID, authorityKey, authorityAt.UTC()) != nil {
		return errors.New("authorized action authority key is not authorized")
	}
	authorizationProof, err := parseEd25519Signature(action.AuthorizationProof)
	message, messageErr := authorizedActionSignatureMessage(action)
	if err != nil || messageErr != nil || !ed25519.Verify(authorityKey, message, authorizationProof) {
		return errors.New("authorized action proof is invalid")
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
		(action.AuthorityPublicKey == "") != (action.AuthorizationProof == "") {
		return errors.New("authorized action is invalid")
	}
	if action.AuthorityPublicKey != "" {
		if _, err := parseEd25519PublicKey(action.AuthorityPublicKey); err != nil {
			return errors.New("authorized action authority key is invalid")
		}
		if _, err := parseEd25519Signature(action.AuthorizationProof); err != nil {
			return errors.New("authorized action proof encoding is invalid")
		}
	}
	return nil
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
