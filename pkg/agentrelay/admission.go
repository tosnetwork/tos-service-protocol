package agentrelay

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

const (
	AdmissionRequestContentType = "application/vnd.tos.agent-relay-side-effect-admission-request.v1+cbor"
	AdmissionReceiptContentType = "application/vnd.tos.agent-relay-side-effect-admission-receipt.v1+cbor"
	MaxRelayRouteAttempts       = uint32(32)
)

// RelaySideEffectAdmissionDescriptor is the trusted coordinator's internal
// verification context. It is deliberately not the cross-host wire schema;
// transports must encode RelaySideEffectAdmissionRequest instead.
type RelaySideEffectAdmissionDescriptor struct {
	SchemaVersion             uint16                             `json:"schema_version"`
	OwnerID                   string                             `json:"owner_id"`
	AgentID                   string                             `json:"agent_id"`
	AuthenticatedPrincipal    string                             `json:"authenticated_principal_id"`
	ProviderAgentID           string                             `json:"provider_agent_id"`
	ServiceProfileDigest      string                             `json:"service_profile_digest"`
	ProviderQuoteDigest       string                             `json:"provider_quote_digest"`
	NetworkDigest             string                             `json:"network_digest"`
	TransactionIdentityDigest string                             `json:"transaction_identity_digest"`
	Mode                      Mode                               `json:"mode"`
	AssuranceLevel            AssuranceLevel                     `json:"assurance_level"`
	StageMask                 []SideEffectStage                  `json:"stage_mask"`
	RouteAttempt              uint32                             `json:"route_attempt"`
	PredecessorReceiptDigest  string                             `json:"predecessor_receipt_digest,omitempty"`
	StableActionID            string                             `json:"stable_action_id"`
	ExactRequestDigest        string                             `json:"exact_request_digest"`
	RelayExecutionDigest      string                             `json:"relay_execution_request_digest"`
	AuthorizedActionDigest    string                             `json:"authorized_action_digest"`
	WriterFenceDigest         string                             `json:"writer_fence_digest"`
	StartNotAfterCapUnix      uint64                             `json:"start_not_after_cap_unix"`
	AuthorizedAction          agentcommerce.AuthorizedAction     `json:"authorized_action"`
	WriterFence               agentcommerce.WriterFence          `json:"writer_fence"`
	UnderlyingActionRequest   []byte                             `json:"underlying_action_request"`
	SemanticFields            []agentcommerce.SemanticFieldValue `json:"semantic_fields"`
}

// RelaySideEffectAdmissionRequest is the exact cross-host
// RelaySideEffectAdmissionRequestV1 wire object. The bearer signed transaction,
// full Provider execution, computed action/fence digests, and deadline cap in
// Descriptor remain in the trusted coordinator context and are never serialized
// as this type.
type RelaySideEffectAdmissionRequest struct {
	SchemaVersion              uint16                             `json:"schema_version"`
	OwnerID                    string                             `json:"owner_id"`
	AgentID                    string                             `json:"agent_id"`
	AuthenticatedPrincipal     string                             `json:"authenticated_principal_id"`
	ProviderAgentID            string                             `json:"provider_agent_id"`
	ServiceProfileDigest       string                             `json:"service_profile_digest"`
	ProviderQuoteDigest        string                             `json:"provider_quote_digest"`
	NetworkDigest              string                             `json:"network_digest"`
	TransactionIdentityDigest  string                             `json:"transaction_identity_digest"`
	Mode                       Mode                               `json:"mode"`
	AssuranceLevel             AssuranceLevel                     `json:"assurance_level"`
	StageMask                  []SideEffectStage                  `json:"stage_mask"`
	RouteAttempt               uint32                             `json:"route_attempt"`
	PredecessorReceiptDigest   string                             `json:"predecessor_receipt_digest,omitempty"`
	StableActionID             string                             `json:"stable_action_id"`
	ExactRequestDigest         string                             `json:"exact_request_digest"`
	RelayExecutionDigest       string                             `json:"relay_execution_request_digest"`
	AuthorizedAction           agentcommerce.AuthorizedAction     `json:"authorized_action"`
	WriterFence                agentcommerce.WriterFence          `json:"writer_fence"`
	UnderlyingActionRequest    []byte                             `json:"underlying_action_request"`
	SemanticFields             []agentcommerce.SemanticFieldValue `json:"semantic_fields"`
	RequestedStartNotAfterUnix uint64                             `json:"requested_start_not_after_unix"`
}

type RelaySideEffectAdmissionReceiptBody struct {
	SchemaVersion             uint16            `json:"schema_version"`
	OwnerID                   string            `json:"owner_id"`
	AgentID                   string            `json:"agent_id"`
	AuthenticatedPrincipal    string            `json:"authenticated_principal_id"`
	AuthorityID               string            `json:"authority_id"`
	ProviderAgentID           string            `json:"provider_agent_id"`
	ServiceProfileDigest      string            `json:"service_profile_digest"`
	ProviderQuoteDigest       string            `json:"provider_quote_digest"`
	NetworkDigest             string            `json:"network_digest"`
	TransactionIdentityDigest string            `json:"transaction_identity_digest"`
	Mode                      Mode              `json:"mode"`
	AssuranceLevel            AssuranceLevel    `json:"assurance_level"`
	StageMask                 []SideEffectStage `json:"stage_mask"`
	RouteAttempt              uint32            `json:"route_attempt"`
	PredecessorReceiptDigest  string            `json:"predecessor_receipt_digest,omitempty"`
	StableActionID            string            `json:"stable_action_id"`
	ExactRequestDigest        string            `json:"exact_request_digest"`
	RelayExecutionDigest      string            `json:"relay_execution_request_digest"`
	AuthorizedActionDigest    string            `json:"authorized_action_digest"`
	WriterFenceDigest         string            `json:"writer_fence_digest"`
	WriterLeaseID             string            `json:"writer_lease_id"`
	WriterGeneration          uint64            `json:"writer_generation"`
	PolicyRevision            uint64            `json:"policy_revision"`
	MandateDigest             string            `json:"mandate_digest"`
	ApprovalDigest            string            `json:"approval_digest,omitempty"`
	AdmissionSequence         uint64            `json:"admission_sequence"`
	IssuedAtUnix              uint64            `json:"issued_at_unix"`
	StartNotAfterUnix         uint64            `json:"start_not_after_unix"`
}

// SignedRelaySideEffectAdmissionReceipt is signed by the owner Action
// Authority with Pure ML-DSA-44 under TOS-ACTION-AUTHORITY-V1. KeyID is the
// mldsa44:<64 hex> key ID of the same key that issued the Writer Fence and the
// AuthorizedAction; the key itself is resolved, never carried.
type SignedRelaySideEffectAdmissionReceipt struct {
	Body      RelaySideEffectAdmissionReceiptBody `json:"body"`
	KeyID     string                              `json:"key_id"`
	Signature string                              `json:"signature"`
}

// VerifiedRelayAdmissionReceipt records that one exact signed receipt passed
// its Action Authority check: its key resolved for the receipt's authority at
// the receipt's issuance time and its ML-DSA-44 signature verified. Only
// VerifyRelaySideEffectAdmissionReceiptAuthority constructs it, so a journal
// that receives one never repeats the resolver or helper work.
type VerifiedRelayAdmissionReceipt struct {
	bodyDigest string
	keyID      string
	signature  string
}

func (verified VerifiedRelayAdmissionReceipt) matches(receipt SignedRelaySideEffectAdmissionReceipt) bool {
	if verified.bodyDigest == "" {
		return false
	}
	bodyDigest, err := RelaySideEffectAdmissionReceiptBodyDigest(receipt.Body)
	return err == nil && bodyDigest == verified.bodyDigest && receipt.KeyID == verified.keyID &&
		receipt.Signature == verified.signature
}

// RelaySideEffectAdmissionLookup is the immutable authority key used after an
// ambiguous Admit response. Resolve must return the originally persisted
// receipt; it may not allocate another sequence or extend its start window.
type RelaySideEffectAdmissionLookup struct {
	SchemaVersion             uint16            `json:"schema_version"`
	OwnerID                   string            `json:"owner_id"`
	AgentID                   string            `json:"agent_id"`
	AuthenticatedPrincipal    string            `json:"authenticated_principal_id"`
	AuthorityID               string            `json:"authority_id"`
	ProviderAgentID           string            `json:"provider_agent_id"`
	ServiceProfileDigest      string            `json:"service_profile_digest"`
	ProviderQuoteDigest       string            `json:"provider_quote_digest"`
	NetworkDigest             string            `json:"network_digest"`
	TransactionIdentityDigest string            `json:"transaction_identity_digest"`
	Mode                      Mode              `json:"mode"`
	AssuranceLevel            AssuranceLevel    `json:"assurance_level"`
	StageMask                 []SideEffectStage `json:"stage_mask"`
	RouteAttempt              uint32            `json:"route_attempt"`
	PredecessorReceiptDigest  string            `json:"predecessor_receipt_digest,omitempty"`
	StableActionID            string            `json:"stable_action_id"`
	ExactRequestDigest        string            `json:"exact_request_digest"`
	RelayExecutionDigest      string            `json:"relay_execution_request_digest"`
}

// RelayTransactionIdentity is the route-independent signed-transaction
// projection. A Provider failover may change quote and endpoint, but never the
// exact network, source authority, transaction bytes, intent, sequence, or
// validity represented by this digest.
type RelayTransactionIdentity struct {
	SchemaVersion                uint16        `json:"schema_version"`
	Network                      NetworkDomain `json:"network"`
	SourceAccount                string        `json:"source_account"`
	SourceAccountAuthorityDigest string        `json:"source_account_authority_digest"`
	TransactionProfileURI        string        `json:"transaction_profile_uri"`
	TransactionProfileDigest     string        `json:"transaction_profile_digest"`
	UnderlyingActionKind         string        `json:"underlying_action_kind"`
	StableActionID               string        `json:"stable_action_id"`
	ExactRequestDigest           string        `json:"exact_request_digest"`
	SignedTransactionDigest      string        `json:"signed_transaction_digest"`
	SignedTransactionCellHash    string        `json:"signed_transaction_cell_hash"`
	SignedTransactionSize        uint32        `json:"signed_transaction_size"`
	TransactionIntentDigest      string        `json:"transaction_intent_digest"`
	SourceSequence               uint64        `json:"source_sequence"`
	TransactionValidUntilUnix    uint64        `json:"transaction_valid_until_unix"`
}

// RelaySideEffectAdmissionBindingKey is the Authority's owner-wide secondary
// index. The route-specific lookup is insufficient by itself: without this
// key two Providers could each receive attempt 1 for one economic action.
type RelaySideEffectAdmissionBindingKey struct {
	OwnerID        string
	AgentID        string
	StableActionID string
}

func (descriptor RelaySideEffectAdmissionDescriptor) BindingKey() RelaySideEffectAdmissionBindingKey {
	return RelaySideEffectAdmissionBindingKey{OwnerID: descriptor.OwnerID,
		AgentID: descriptor.AgentID, StableActionID: descriptor.StableActionID}
}

// RelaySideEffectAdmissionAuthority is the linearization boundary between a
// current writer check and every later Provider economic side effect. Admit
// implementations must atomically maintain both the exact Lookup and the
// owner/Agent/stable-action BindingKey. A second route is allowed only through
// ValidateRelaySideEffectAdmissionRouteTransition; sponsorship modes have no
// successor route in V1.
type RelaySideEffectAdmissionAuthority interface {
	AdmitRelaySideEffects(context.Context, RelaySideEffectAdmissionDescriptor) (SignedRelaySideEffectAdmissionReceipt, error)
	ResolveRelaySideEffectAdmission(context.Context, RelaySideEffectAdmissionLookup) (SignedRelaySideEffectAdmissionReceipt, error)
}

func RelaySideEffectStages(mode Mode) ([]SideEffectStage, error) {
	switch mode {
	case ModeRelayExact:
		return []SideEffectStage{SideEffectBroadcast}, nil
	case ModeSponsorOnly:
		return []SideEffectStage{SideEffectSponsorship}, nil
	case ModeSponsorAndRelay:
		return []SideEffectStage{SideEffectBroadcast, SideEffectSponsorship}, nil
	default:
		return nil, errors.New("relay admission mode is invalid")
	}
}

func RelayTransactionIdentityDigest(body RelayQuoteRequestBody) (string, error) {
	if err := validateRelayQuoteRequestShape(body); err != nil {
		return "", err
	}
	identity := RelayTransactionIdentity{SchemaVersion: 1, Network: body.Network,
		SourceAccount: body.SourceAccount, SourceAccountAuthorityDigest: body.SourceAccountAuthorityDigest,
		TransactionProfileURI: body.TransactionProfileURI, TransactionProfileDigest: body.TransactionProfileDigest,
		UnderlyingActionKind: body.UnderlyingActionKind, StableActionID: body.StableActionID,
		ExactRequestDigest: body.ExactRequestDigest, SignedTransactionDigest: body.SignedTransactionDigest,
		SignedTransactionCellHash: body.SignedTransactionCellHash, SignedTransactionSize: body.SignedTransactionSize,
		TransactionIntentDigest: body.TransactionIntentDigest, SourceSequence: body.SourceSequence,
		TransactionValidUntilUnix: body.TransactionValidUntilUnix}
	return RelayTransactionIdentityProjectionDigest(identity)
}

// RelayTransactionIdentityProjectionDigest is exposed for independent codecs
// and conformance vectors that operate on the released projection directly.
func RelayTransactionIdentityProjectionDigest(identity RelayTransactionIdentity) (string, error) {
	if identity.SchemaVersion != 1 || validateNetworkDomain(identity.Network) != nil ||
		!identifier(identity.SourceAccount, 256) || !digestPattern.MatchString(identity.SourceAccountAuthorityDigest) ||
		!identifier(identity.TransactionProfileURI, 256) || !digestPattern.MatchString(identity.TransactionProfileDigest) ||
		agentcommerce.SemanticActionRegistry()[identity.UnderlyingActionKind].ActionKind == "" ||
		!digestPattern.MatchString(identity.StableActionID) || !digestPattern.MatchString(identity.ExactRequestDigest) ||
		!digestPattern.MatchString(identity.SignedTransactionDigest) ||
		!cellHashPattern.MatchString(identity.SignedTransactionCellHash) || identity.SignedTransactionSize == 0 ||
		identity.SignedTransactionSize > MaxSignedTransactionBytes ||
		!digestPattern.MatchString(identity.TransactionIntentDigest) || identity.TransactionValidUntilUnix == 0 {
		return "", errors.New("relay transaction identity is invalid")
	}
	return codec.Digest("tos.agent-relay-transaction-identity.v1", identity)
}

func BuildRelaySideEffectAdmissionDescriptor(request RelayExecutionRequest) (RelaySideEffectAdmissionDescriptor, error) {
	return BuildRelaySideEffectAdmissionDescriptorForPrincipal(request, request.QuoteRequest.Body.RequesterAgentID)
}

// BuildRelaySideEffectAdmissionDescriptorForPrincipal binds the transport-
// authenticated principal that is asking the owner Action Authority to admit
// the exact side effects. The principal is deliberately independent of AgentID:
// carrying an Agent identifier in an application object is not transport
// authentication, and owner policy may authorize a distinct local principal.
func BuildRelaySideEffectAdmissionDescriptorForPrincipal(request RelayExecutionRequest,
	authenticatedPrincipal string) (RelaySideEffectAdmissionDescriptor, error) {
	return buildRelaySideEffectAdmissionDescriptorForRoute(request, authenticatedPrincipal, 1, "")
}

func buildRelaySideEffectAdmissionDescriptorForRoute(request RelayExecutionRequest,
	authenticatedPrincipal string, routeAttempt uint32,
	predecessorReceiptDigest string) (RelaySideEffectAdmissionDescriptor, error) {
	if err := validateRelayExecutionRequestCoreShape(request); err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	if !identifier(authenticatedPrincipal, 256) {
		return RelaySideEffectAdmissionDescriptor{}, errors.New("relay admission authenticated principal is invalid")
	}
	if err := validateRelayAdmissionRoute(routeAttempt, predecessorReceiptDigest); err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	executionDigest, err := relayExecutionRequestProjectionDigest(request)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	quoteDigest, err := ProviderRelayQuoteDigest(request.ProviderQuote.Body)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	networkDigest, err := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	transactionIdentityDigest, err := RelayTransactionIdentityDigest(request.QuoteRequest.Body)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	actionDigest, err := agentcommerce.AuthorizedActionDigest(request.AuthorizedAction)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	fenceDigest, err := agentcommerce.WriterFenceDigest(request.WriterFence)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	stages, err := RelaySideEffectStages(request.QuoteRequest.Body.Mode)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	action := request.AuthorizedAction
	startCap := request.ExpiresAtUnix
	for _, candidate := range []uint64{request.AgreementExpiresAtUnix, request.ProviderQuote.Body.ExpiresAtUnix,
		request.QuoteRequest.Body.TransactionValidUntilUnix, action.ExpiresAtUnix, request.WriterFence.Body.ExpiresAtUnix} {
		if candidate < startCap {
			startCap = candidate
		}
	}
	return RelaySideEffectAdmissionDescriptor{SchemaVersion: 1, OwnerID: action.OwnerID, AgentID: action.AgentID,
		AuthenticatedPrincipal: authenticatedPrincipal,
		ProviderAgentID:        request.ProviderQuote.Body.ProviderAgentID,
		ServiceProfileDigest:   request.ProviderQuote.Body.ServiceProfileDigest, ProviderQuoteDigest: quoteDigest,
		NetworkDigest: networkDigest, TransactionIdentityDigest: transactionIdentityDigest,
		Mode: request.QuoteRequest.Body.Mode, AssuranceLevel: request.QuoteRequest.Body.AssuranceLevel,
		StageMask:    stages,
		RouteAttempt: routeAttempt, PredecessorReceiptDigest: predecessorReceiptDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		RelayExecutionDigest: executionDigest, AuthorizedActionDigest: actionDigest, WriterFenceDigest: fenceDigest,
		StartNotAfterCapUnix: startCap,
		AuthorizedAction:     action, WriterFence: request.WriterFence,
		UnderlyingActionRequest: append([]byte(nil), request.UnderlyingActionRequest...),
		SemanticFields:          append([]agentcommerce.SemanticFieldValue(nil), request.SemanticFields...)}, nil
}

// BuildRelaySideEffectAdmissionSuccessorDescriptor creates a relay-only route
// successor. The predecessor receipt remains valid for its already-admitted
// exact BOC; the successor may change Provider route but cannot change the
// owner, Agent, Authority high-water domain, policy, mandate, approval, stable
// action, exact underlying request, or network.
func BuildRelaySideEffectAdmissionSuccessorDescriptor(request RelayExecutionRequest,
	authenticatedPrincipal string, predecessor SignedRelaySideEffectAdmissionReceipt,
	resolver agentcommerce.FenceAuthorityResolver) (RelaySideEffectAdmissionDescriptor, error) {
	if _, err := VerifyRelaySideEffectAdmissionReceiptAuthority(predecessor, resolver); err != nil ||
		predecessor.Body.Mode != ModeRelayExact ||
		predecessor.Body.AssuranceLevel != AssuranceAutonomousDecentralized ||
		predecessor.Body.RouteAttempt >= MaxRelayRouteAttempts {
		return RelaySideEffectAdmissionDescriptor{}, errors.New("relay admission predecessor is not successor-eligible")
	}
	predecessorDigest, err := RelaySideEffectAdmissionReceiptBodyDigest(predecessor.Body)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	descriptor, err := buildRelaySideEffectAdmissionDescriptorForRoute(request, authenticatedPrincipal,
		predecessor.Body.RouteAttempt+1, predecessorDigest)
	if err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	if err := validateRelaySideEffectAdmissionRouteTransitionShape(predecessor, descriptor); err != nil {
		return RelaySideEffectAdmissionDescriptor{}, err
	}
	return descriptor, nil
}

func (descriptor RelaySideEffectAdmissionDescriptor) Lookup() RelaySideEffectAdmissionLookup {
	return RelaySideEffectAdmissionLookup{SchemaVersion: 1, OwnerID: descriptor.OwnerID, AgentID: descriptor.AgentID,
		AuthenticatedPrincipal: descriptor.AuthenticatedPrincipal, AuthorityID: descriptor.WriterFence.Body.AuthorityID,
		ProviderAgentID: descriptor.ProviderAgentID, ServiceProfileDigest: descriptor.ServiceProfileDigest,
		ProviderQuoteDigest: descriptor.ProviderQuoteDigest, NetworkDigest: descriptor.NetworkDigest,
		TransactionIdentityDigest: descriptor.TransactionIdentityDigest, Mode: descriptor.Mode,
		AssuranceLevel: descriptor.AssuranceLevel,
		RouteAttempt:   descriptor.RouteAttempt, PredecessorReceiptDigest: descriptor.PredecessorReceiptDigest,
		StableActionID:     descriptor.StableActionID,
		ExactRequestDigest: descriptor.ExactRequestDigest, RelayExecutionDigest: descriptor.RelayExecutionDigest,
		StageMask: append([]SideEffectStage(nil), descriptor.StageMask...)}
}

func RelaySideEffectAdmissionLookupDigest(lookup RelaySideEffectAdmissionLookup) (string, error) {
	if lookup.SchemaVersion != 1 || !identifier(lookup.OwnerID, 256) || !identifier(lookup.AgentID, 256) ||
		!identifier(lookup.AuthenticatedPrincipal, 256) || !identifier(lookup.AuthorityID, 256) ||
		!identifier(lookup.ProviderAgentID, 256) || !digestPattern.MatchString(lookup.ServiceProfileDigest) ||
		!digestPattern.MatchString(lookup.ProviderQuoteDigest) || !digestPattern.MatchString(lookup.NetworkDigest) ||
		!digestPattern.MatchString(lookup.TransactionIdentityDigest) ||
		!validMode(lookup.Mode) || !validAssuranceLevel(lookup.AssuranceLevel) ||
		validateRelayAdmissionRoute(lookup.RouteAttempt, lookup.PredecessorReceiptDigest) != nil ||
		lookup.RouteAttempt > 1 && (lookup.Mode != ModeRelayExact ||
			lookup.AssuranceLevel != AssuranceAutonomousDecentralized) ||
		!digestPattern.MatchString(lookup.StableActionID) ||
		!digestPattern.MatchString(lookup.ExactRequestDigest) || !digestPattern.MatchString(lookup.RelayExecutionDigest) ||
		len(lookup.StageMask) == 0 || len(lookup.StageMask) > 2 {
		return "", errors.New("relay side-effect admission lookup is invalid")
	}
	stages, err := RelaySideEffectStages(lookup.Mode)
	if err != nil || !equalStages(lookup.StageMask, stages) {
		return "", errors.New("relay side-effect admission lookup stage mask is invalid")
	}
	return codec.Digest("tos.agent-relay-side-effect-admission-lookup.v1", lookup)
}

func validateRelayAdmissionRoute(routeAttempt uint32, predecessorReceiptDigest string) error {
	if routeAttempt == 0 || routeAttempt > MaxRelayRouteAttempts || routeAttempt == 1 && predecessorReceiptDigest != "" ||
		routeAttempt > 1 && !digestPattern.MatchString(predecessorReceiptDigest) {
		return errors.New("relay admission route lineage is invalid")
	}
	return nil
}

// ValidateRelaySideEffectAdmissionRouteTransition proves that descriptor is
// the one allowed relay-only Provider failover from predecessor. Sponsorship
// stages never receive successor receipts in V1 because a second Provider
// route could duplicate a top-up payment.
func ValidateRelaySideEffectAdmissionRouteTransition(predecessor SignedRelaySideEffectAdmissionReceipt,
	descriptor RelaySideEffectAdmissionDescriptor, resolver agentcommerce.FenceAuthorityResolver) error {
	if _, err := VerifyRelaySideEffectAdmissionReceiptAuthority(predecessor, resolver); err != nil {
		return errors.New("relay admission route predecessor does not verify: " + err.Error())
	}
	return validateRelaySideEffectAdmissionRouteTransitionShape(predecessor, descriptor)
}

func validateRelaySideEffectAdmissionRouteTransitionShape(predecessor SignedRelaySideEffectAdmissionReceipt,
	descriptor RelaySideEffectAdmissionDescriptor) error {
	if err := validateRelaySideEffectAdmissionReceiptShape(predecessor); err != nil ||
		predecessor.Body.Mode != ModeRelayExact || descriptor.Mode != ModeRelayExact ||
		predecessor.Body.AssuranceLevel != AssuranceAutonomousDecentralized ||
		descriptor.AssuranceLevel != AssuranceAutonomousDecentralized ||
		predecessor.Body.RouteAttempt >= MaxRelayRouteAttempts || descriptor.RouteAttempt != predecessor.Body.RouteAttempt+1 {
		return errors.New("relay admission route transition is not relay-only or consecutive")
	}
	predecessorDigest, err := RelaySideEffectAdmissionReceiptBodyDigest(predecessor.Body)
	if err != nil || descriptor.PredecessorReceiptDigest != predecessorDigest ||
		descriptor.OwnerID != predecessor.Body.OwnerID || descriptor.AgentID != predecessor.Body.AgentID ||
		descriptor.AuthenticatedPrincipal != predecessor.Body.AuthenticatedPrincipal ||
		descriptor.WriterFence.Body.AuthorityID != predecessor.Body.AuthorityID ||
		descriptor.AuthorizedAction.PolicyRevision != predecessor.Body.PolicyRevision ||
		descriptor.AuthorizedAction.MandateDigest != predecessor.Body.MandateDigest ||
		descriptor.AuthorizedAction.ApprovalDigest != predecessor.Body.ApprovalDigest ||
		descriptor.NetworkDigest != predecessor.Body.NetworkDigest ||
		descriptor.TransactionIdentityDigest != predecessor.Body.TransactionIdentityDigest ||
		descriptor.AssuranceLevel != predecessor.Body.AssuranceLevel ||
		descriptor.StableActionID != predecessor.Body.StableActionID ||
		descriptor.ExactRequestDigest != predecessor.Body.ExactRequestDigest {
		return errors.New("relay admission successor differs from its immutable predecessor action")
	}
	if descriptor.ProviderAgentID == predecessor.Body.ProviderAgentID {
		return errors.New("relay admission successor does not select a different Provider")
	}
	return nil
}

// ValidateRelaySideEffectAdmissionRouteChain validates a complete persisted
// route-head chain before a durable Authority or auditor trusts its last
// receipt. Writer lease IDs, generations, fence digests, and action-envelope
// digests may change after a legitimate takeover. The Authority high-water
// domain and the economic policy/mandate/approval context may not.
func ValidateRelaySideEffectAdmissionRouteChain(chain []SignedRelaySideEffectAdmissionReceipt,
	resolver agentcommerce.FenceAuthorityResolver) error {
	if len(chain) == 0 || len(chain) > int(MaxRelayRouteAttempts) {
		return errors.New("relay admission route chain length is invalid")
	}
	for index := range chain {
		if _, err := VerifyRelaySideEffectAdmissionReceiptAuthority(chain[index], resolver); err != nil {
			return errors.New("relay admission route chain contains an invalid receipt")
		}
		if index == 0 {
			if chain[index].Body.RouteAttempt != 1 || chain[index].Body.PredecessorReceiptDigest != "" {
				return errors.New("relay admission route chain does not start at attempt one")
			}
			continue
		}
		if err := validateRelaySideEffectAdmissionReceiptRouteTransition(chain[index-1], chain[index]); err != nil {
			return err
		}
	}
	return nil
}

func validateRelaySideEffectAdmissionReceiptRouteTransition(predecessor,
	successor SignedRelaySideEffectAdmissionReceipt) error {
	if predecessor.Body.Mode != ModeRelayExact || successor.Body.Mode != ModeRelayExact ||
		predecessor.Body.AssuranceLevel != AssuranceAutonomousDecentralized ||
		successor.Body.AssuranceLevel != AssuranceAutonomousDecentralized ||
		predecessor.Body.RouteAttempt >= MaxRelayRouteAttempts ||
		successor.Body.RouteAttempt != predecessor.Body.RouteAttempt+1 {
		return errors.New("persisted relay admission route transition is not relay-only or consecutive")
	}
	predecessorDigest, err := RelaySideEffectAdmissionReceiptBodyDigest(predecessor.Body)
	if err != nil || successor.Body.PredecessorReceiptDigest != predecessorDigest ||
		successor.Body.OwnerID != predecessor.Body.OwnerID || successor.Body.AgentID != predecessor.Body.AgentID ||
		successor.Body.AuthenticatedPrincipal != predecessor.Body.AuthenticatedPrincipal ||
		successor.Body.AuthorityID != predecessor.Body.AuthorityID ||
		successor.Body.PolicyRevision != predecessor.Body.PolicyRevision ||
		successor.Body.MandateDigest != predecessor.Body.MandateDigest ||
		successor.Body.ApprovalDigest != predecessor.Body.ApprovalDigest ||
		successor.Body.NetworkDigest != predecessor.Body.NetworkDigest ||
		successor.Body.TransactionIdentityDigest != predecessor.Body.TransactionIdentityDigest ||
		successor.Body.AssuranceLevel != predecessor.Body.AssuranceLevel ||
		successor.Body.StableActionID != predecessor.Body.StableActionID ||
		successor.Body.ExactRequestDigest != predecessor.Body.ExactRequestDigest {
		return errors.New("persisted relay admission successor differs from its immutable route head")
	}
	if successor.Body.ProviderAgentID == predecessor.Body.ProviderAgentID ||
		successor.Body.AdmissionSequence <= predecessor.Body.AdmissionSequence {
		return errors.New("persisted relay admission successor Provider or sequence is invalid")
	}
	return nil
}

func BuildRelaySideEffectAdmissionRequest(descriptor RelaySideEffectAdmissionDescriptor,
	requestedStartNotAfterUnix uint64) (RelaySideEffectAdmissionRequest, error) {
	request := RelaySideEffectAdmissionRequest{SchemaVersion: 1, OwnerID: descriptor.OwnerID,
		AgentID: descriptor.AgentID, AuthenticatedPrincipal: descriptor.AuthenticatedPrincipal,
		ProviderAgentID: descriptor.ProviderAgentID, ServiceProfileDigest: descriptor.ServiceProfileDigest,
		ProviderQuoteDigest: descriptor.ProviderQuoteDigest, NetworkDigest: descriptor.NetworkDigest,
		TransactionIdentityDigest: descriptor.TransactionIdentityDigest,
		Mode:                      descriptor.Mode, AssuranceLevel: descriptor.AssuranceLevel,
		StageMask:    append([]SideEffectStage(nil), descriptor.StageMask...),
		RouteAttempt: descriptor.RouteAttempt, PredecessorReceiptDigest: descriptor.PredecessorReceiptDigest,
		StableActionID: descriptor.StableActionID, ExactRequestDigest: descriptor.ExactRequestDigest,
		RelayExecutionDigest: descriptor.RelayExecutionDigest, AuthorizedAction: descriptor.AuthorizedAction,
		WriterFence:                descriptor.WriterFence,
		UnderlyingActionRequest:    append([]byte(nil), descriptor.UnderlyingActionRequest...),
		SemanticFields:             append([]agentcommerce.SemanticFieldValue(nil), descriptor.SemanticFields...),
		RequestedStartNotAfterUnix: requestedStartNotAfterUnix}
	if requestedStartNotAfterUnix > descriptor.StartNotAfterCapUnix ||
		validateRelaySideEffectAdmissionRequestShape(request) != nil {
		return RelaySideEffectAdmissionRequest{}, errors.New("relay side-effect admission wire request is invalid")
	}
	return request, nil
}

func RelaySideEffectAdmissionRequestBytes(request RelaySideEffectAdmissionRequest) ([]byte, error) {
	if err := validateRelaySideEffectAdmissionRequestShape(request); err != nil {
		return nil, err
	}
	return codec.Marshal(request)
}

// ValidateRelaySideEffectAdmissionRequest is the standalone cross-host
// Authority verifier. The signed BOC and full Provider execution remain out of
// this non-bearer request, while the canonical action request and semantic
// fields let the Authority independently verify stable/exact action identity.
func ValidateRelaySideEffectAdmissionRequest(request RelaySideEffectAdmissionRequest,
	resolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if err := validateRelaySideEffectAdmissionRequestShape(request); err != nil {
		return err
	}
	fields, err := agentcommerce.ImportSemanticFields(request.AuthorizedAction.ActionKind, request.SemanticFields)
	if err != nil {
		return err
	}
	if err := agentcommerce.VerifyAuthorizedAction(request.AuthorizedAction, fields,
		request.UnderlyingActionRequest, request.WriterFence, resolver, now); err != nil {
		return errors.New("relay side-effect admission wire action is invalid: " + err.Error())
	}
	return nil
}

// ValidateRelaySideEffectAdmissionRequestAgainstDescriptor validates the exact
// public wire object against the trusted full execution context. This is the
// cross-host Authority boundary; directly serializing Descriptor would create
// a different, incompatible schema.
func ValidateRelaySideEffectAdmissionRequestAgainstDescriptor(request RelaySideEffectAdmissionRequest,
	descriptor RelaySideEffectAdmissionDescriptor, resolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if err := ValidateRelaySideEffectAdmissionRequest(request, resolver, now); err != nil {
		return err
	}
	if err := ValidateRelaySideEffectAdmissionDescriptor(descriptor, resolver, now); err != nil {
		return err
	}
	expected, err := BuildRelaySideEffectAdmissionRequest(descriptor, request.RequestedStartNotAfterUnix)
	if err != nil {
		return err
	}
	want, err := RelaySideEffectAdmissionRequestBytes(expected)
	if err != nil {
		return err
	}
	got, err := RelaySideEffectAdmissionRequestBytes(request)
	if err != nil || !bytes.Equal(got, want) {
		return errors.New("relay side-effect admission wire request conflicts with trusted execution context")
	}
	return nil
}

func validateRelaySideEffectAdmissionRequestShape(request RelaySideEffectAdmissionRequest) error {
	if request.SchemaVersion != 1 || !identifier(request.OwnerID, 256) || !identifier(request.AgentID, 256) ||
		!identifier(request.AuthenticatedPrincipal, 256) || !identifier(request.ProviderAgentID, 256) ||
		!digestPattern.MatchString(request.ServiceProfileDigest) || !digestPattern.MatchString(request.ProviderQuoteDigest) ||
		!digestPattern.MatchString(request.NetworkDigest) || !digestPattern.MatchString(request.TransactionIdentityDigest) ||
		!validAssuranceLevel(request.AssuranceLevel) ||
		validateRelayAdmissionRoute(request.RouteAttempt, request.PredecessorReceiptDigest) != nil ||
		request.RouteAttempt > 1 && (request.Mode != ModeRelayExact ||
			request.AssuranceLevel != AssuranceAutonomousDecentralized) ||
		!digestPattern.MatchString(request.StableActionID) || !digestPattern.MatchString(request.ExactRequestDigest) ||
		!digestPattern.MatchString(request.RelayExecutionDigest) || len(request.UnderlyingActionRequest) == 0 ||
		len(request.UnderlyingActionRequest) > MaxRelayActionRequestBytes || len(request.SemanticFields) == 0 ||
		request.RequestedStartNotAfterUnix == 0 {
		return errors.New("relay side-effect admission wire request is invalid")
	}
	stages, err := RelaySideEffectStages(request.Mode)
	if err != nil || !equalStages(request.StageMask, stages) {
		return errors.New("relay side-effect admission wire stage mask is invalid")
	}
	action, fence := request.AuthorizedAction, request.WriterFence
	fenceDigest, fenceErr := agentcommerce.WriterFenceDigest(fence)
	if fenceErr != nil || action.OwnerID != request.OwnerID || action.AgentID != request.AgentID ||
		action.StableActionID != request.StableActionID || action.ExactRequestDigest != request.ExactRequestDigest ||
		action.WriterFenceDigest != fenceDigest || action.AuthorityID != fence.Body.AuthorityID ||
		action.AuthorityKeyID != fence.KeyID || action.WriterGeneration != fence.Body.WriterGeneration ||
		request.RequestedStartNotAfterUnix > action.ExpiresAtUnix ||
		request.RequestedStartNotAfterUnix > fence.Body.ExpiresAtUnix {
		return errors.New("relay side-effect admission wire credentials conflict")
	}
	return nil
}

// VerifyRelaySubmitPrincipal binds a receipt to the authenticated Submit
// channel. The string in the signed receipt is not authentication by itself;
// HTTP/RPC adapters call this helper with the mTLS or equivalent transport
// principal before ProviderService.Submit.
func VerifyRelaySubmitPrincipal(request RelayExecutionRequest, authenticatedPrincipal string) error {
	if !identifier(authenticatedPrincipal, 256) ||
		request.AdmissionReceipt.Body.AuthenticatedPrincipal != authenticatedPrincipal {
		return errors.New("relay Submit principal does not match the side-effect admission receipt")
	}
	return nil
}

// ValidateRelaySideEffectAdmissionDescriptor verifies the owner-authorized
// action and every field the Action Authority is expected to atomically
// register. The authority must additionally compare WriterFence with its
// current high-water record in the same transaction that persists the receipt.
func ValidateRelaySideEffectAdmissionDescriptor(descriptor RelaySideEffectAdmissionDescriptor,
	resolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if descriptor.SchemaVersion != 1 || !identifier(descriptor.OwnerID, 256) || !identifier(descriptor.AgentID, 256) ||
		!identifier(descriptor.AuthenticatedPrincipal, 256) ||
		!identifier(descriptor.ProviderAgentID, 256) || !digestPattern.MatchString(descriptor.ServiceProfileDigest) ||
		!digestPattern.MatchString(descriptor.ProviderQuoteDigest) || !digestPattern.MatchString(descriptor.NetworkDigest) ||
		!digestPattern.MatchString(descriptor.TransactionIdentityDigest) ||
		!validAssuranceLevel(descriptor.AssuranceLevel) ||
		validateRelayAdmissionRoute(descriptor.RouteAttempt, descriptor.PredecessorReceiptDigest) != nil ||
		descriptor.RouteAttempt > 1 && (descriptor.Mode != ModeRelayExact ||
			descriptor.AssuranceLevel != AssuranceAutonomousDecentralized) ||
		!digestPattern.MatchString(descriptor.StableActionID) || !digestPattern.MatchString(descriptor.ExactRequestDigest) ||
		!digestPattern.MatchString(descriptor.RelayExecutionDigest) || !digestPattern.MatchString(descriptor.AuthorizedActionDigest) ||
		!digestPattern.MatchString(descriptor.WriterFenceDigest) || descriptor.StartNotAfterCapUnix == 0 {
		return errors.New("relay side-effect admission descriptor is invalid")
	}
	stages, err := RelaySideEffectStages(descriptor.Mode)
	if err != nil || !equalStages(descriptor.StageMask, stages) {
		return errors.New("relay side-effect admission stage mask is invalid")
	}
	action, fence := descriptor.AuthorizedAction, descriptor.WriterFence
	actionDigest, actionDigestErr := agentcommerce.AuthorizedActionDigest(action)
	fenceDigest, fenceDigestErr := agentcommerce.WriterFenceDigest(fence)
	if actionDigestErr != nil || fenceDigestErr != nil || actionDigest != descriptor.AuthorizedActionDigest ||
		fenceDigest != descriptor.WriterFenceDigest || action.OwnerID != descriptor.OwnerID || action.AgentID != descriptor.AgentID ||
		action.StableActionID != descriptor.StableActionID || action.ExactRequestDigest != descriptor.ExactRequestDigest ||
		action.WriterGeneration != fence.Body.WriterGeneration || action.WriterFenceDigest != fenceDigest ||
		action.AuthorityID != fence.Body.AuthorityID || action.AuthorityKeyID != fence.KeyID ||
		descriptor.StartNotAfterCapUnix > action.ExpiresAtUnix || descriptor.StartNotAfterCapUnix > fence.Body.ExpiresAtUnix {
		return errors.New("relay side-effect admission credentials conflict")
	}
	fields, err := agentcommerce.ImportSemanticFields(action.ActionKind, descriptor.SemanticFields)
	if err != nil {
		return err
	}
	if err := agentcommerce.VerifyAuthorizedAction(action, fields, descriptor.UnderlyingActionRequest,
		fence, resolver, now); err != nil {
		return errors.New("relay side-effect admission action is invalid: " + err.Error())
	}
	return nil
}

func BuildRelaySideEffectAdmissionReceiptBody(descriptor RelaySideEffectAdmissionDescriptor,
	admissionSequence, issuedAtUnix, startNotAfterUnix uint64) (RelaySideEffectAdmissionReceiptBody, error) {
	action, fence := descriptor.AuthorizedAction, descriptor.WriterFence
	if startNotAfterUnix > descriptor.StartNotAfterCapUnix {
		return RelaySideEffectAdmissionReceiptBody{}, errors.New("relay side-effect admission receipt exceeds its descriptor cap")
	}
	body := RelaySideEffectAdmissionReceiptBody{SchemaVersion: 1, OwnerID: descriptor.OwnerID,
		AgentID: descriptor.AgentID, AuthenticatedPrincipal: descriptor.AuthenticatedPrincipal,
		AuthorityID: fence.Body.AuthorityID, ProviderAgentID: descriptor.ProviderAgentID,
		ServiceProfileDigest: descriptor.ServiceProfileDigest, ProviderQuoteDigest: descriptor.ProviderQuoteDigest,
		NetworkDigest: descriptor.NetworkDigest, TransactionIdentityDigest: descriptor.TransactionIdentityDigest,
		Mode: descriptor.Mode, AssuranceLevel: descriptor.AssuranceLevel,
		StageMask: append([]SideEffectStage(nil), descriptor.StageMask...), StableActionID: descriptor.StableActionID,
		RouteAttempt: descriptor.RouteAttempt, PredecessorReceiptDigest: descriptor.PredecessorReceiptDigest,
		ExactRequestDigest: descriptor.ExactRequestDigest, RelayExecutionDigest: descriptor.RelayExecutionDigest,
		AuthorizedActionDigest: descriptor.AuthorizedActionDigest, WriterFenceDigest: descriptor.WriterFenceDigest,
		WriterLeaseID: fence.Body.LeaseID, WriterGeneration: fence.Body.WriterGeneration,
		PolicyRevision: action.PolicyRevision, MandateDigest: action.MandateDigest, ApprovalDigest: action.ApprovalDigest,
		AdmissionSequence: admissionSequence, IssuedAtUnix: issuedAtUnix, StartNotAfterUnix: startNotAfterUnix}
	if err := validateRelaySideEffectAdmissionReceiptBody(body); err != nil {
		return RelaySideEffectAdmissionReceiptBody{}, err
	}
	return body, nil
}

func RelaySideEffectAdmissionReceiptDigest(receipt SignedRelaySideEffectAdmissionReceipt) (string, error) {
	if err := validateRelaySideEffectAdmissionReceiptShape(receipt); err != nil {
		return "", err
	}
	return RelaySideEffectAdmissionReceiptBodyDigest(receipt.Body)
}

func equalCanonicalRelayAdmissionReceipts(left, right SignedRelaySideEffectAdmissionReceipt) (bool, error) {
	if err := validateRelaySideEffectAdmissionReceiptShape(left); err != nil {
		return false, err
	}
	if err := validateRelaySideEffectAdmissionReceiptShape(right); err != nil {
		return false, err
	}
	leftCanonical, err := codec.Marshal(left)
	if err != nil {
		return false, err
	}
	rightCanonical, err := codec.Marshal(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftCanonical, rightCanonical), nil
}

// RelaySideEffectAdmissionReceiptBodyDigest is the released receipt identity.
// The Provider stores the complete signed receipt alongside this body digest;
// signatures and public-key wrappers are evidence over, not alternate
// identities for, the same admission decision.
func RelaySideEffectAdmissionReceiptBodyDigest(body RelaySideEffectAdmissionReceiptBody) (string, error) {
	if err := validateRelaySideEffectAdmissionReceiptBody(body); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-side-effect-admission-receipt.v1", body)
}

// RelaySideEffectAdmissionReceiptSignatureMessage is the 32-byte message the
// Action Authority signs for a receipt: the framed SHA-256 of its canonical
// body.
func RelaySideEffectAdmissionReceiptSignatureMessage(body RelaySideEffectAdmissionReceiptBody) ([]byte, error) {
	if err := validateRelaySideEffectAdmissionReceiptBody(body); err != nil {
		return nil, errors.New("relay side-effect admission receipt is invalid")
	}
	return signatureMessage("tos.agent-relay-side-effect-admission-receipt-signature.v1\x00", body)
}

// SignRelaySideEffectAdmissionReceipt has the owner Action Authority
// controller in custody sign a receipt body.
func SignRelaySideEffectAdmissionReceipt(ctx context.Context, body RelaySideEffectAdmissionReceiptBody,
	signer mldsa44.Signer, controller string) (SignedRelaySideEffectAdmissionReceipt, error) {
	message, err := RelaySideEffectAdmissionReceiptSignatureMessage(body)
	if err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	keyID, signature, err := agentcommerce.SignActionAuthorityMessage(ctx, signer, controller, message)
	if err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	return SignedRelaySideEffectAdmissionReceipt{Body: body, KeyID: keyID, Signature: signature}, nil
}

// VerifyRelaySideEffectAdmissionReceiptAuthority is the only expensive
// receipt check: it resolves the receipt key for the receipt's authority at
// its issuance instant and verifies the ML-DSA-44 signature. It reads no
// clock, so it can run before any journal lock and its result stays valid
// for the exact receipt bytes.
func VerifyRelaySideEffectAdmissionReceiptAuthority(receipt SignedRelaySideEffectAdmissionReceipt,
	resolver agentcommerce.FenceAuthorityResolver) (VerifiedRelayAdmissionReceipt, error) {
	if err := validateRelaySideEffectAdmissionReceiptShape(receipt); err != nil {
		return VerifiedRelayAdmissionReceipt{}, err
	}
	if receipt.Body.IssuedAtUnix > uint64(1<<63-1) {
		return VerifiedRelayAdmissionReceipt{}, errors.New("relay side-effect admission receipt issuance time is invalid")
	}
	message, err := RelaySideEffectAdmissionReceiptSignatureMessage(receipt.Body)
	if err != nil {
		return VerifiedRelayAdmissionReceipt{}, err
	}
	issuedAt := time.Unix(int64(receipt.Body.IssuedAtUnix), 0).UTC()
	if err := agentcommerce.VerifyActionAuthoritySignature(resolver, receipt.Body.AuthorityID, receipt.KeyID,
		receipt.Signature, message, issuedAt); err != nil {
		return VerifiedRelayAdmissionReceipt{}, errors.New("relay side-effect admission receipt signature is invalid: " + err.Error())
	}
	bodyDigest, err := RelaySideEffectAdmissionReceiptBodyDigest(receipt.Body)
	if err != nil {
		return VerifiedRelayAdmissionReceipt{}, err
	}
	return VerifiedRelayAdmissionReceipt{bodyDigest: bodyDigest, keyID: receipt.KeyID, signature: receipt.Signature}, nil
}

// CheckRelaySideEffectAdmissionReceipt is the cheap admission check for a
// receipt whose authority was already verified: it requires verified to be
// for exactly this signed receipt, then checks every execution binding and the
// exclusive start boundary at now. It calls no resolver or helper.
func CheckRelaySideEffectAdmissionReceipt(receipt SignedRelaySideEffectAdmissionReceipt,
	verified VerifiedRelayAdmissionReceipt, request RelayExecutionRequest, now time.Time) error {
	if !verified.matches(receipt) {
		return errors.New("relay side-effect admission receipt was not verified by its Action Authority")
	}
	descriptor, err := buildRelaySideEffectAdmissionDescriptorForRoute(request, receipt.Body.AuthenticatedPrincipal,
		receipt.Body.RouteAttempt, receipt.Body.PredecessorReceiptDigest)
	if err != nil {
		return err
	}
	return checkRelaySideEffectAdmissionReceiptForDescriptor(receipt, descriptor, request, now)
}

// VerifyRelaySideEffectAdmissionReceipt verifies a receipt's authority and
// then its bindings and start window at now.
func VerifyRelaySideEffectAdmissionReceipt(receipt SignedRelaySideEffectAdmissionReceipt,
	request RelayExecutionRequest, resolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	verified, err := VerifyRelaySideEffectAdmissionReceiptAuthority(receipt, resolver)
	if err != nil {
		return err
	}
	return CheckRelaySideEffectAdmissionReceipt(receipt, verified, request, now)
}

// VerifyRelaySideEffectAdmissionSuccessorReceipt additionally verifies the
// predecessor chain required for route_attempt > 1. Ordinary verification can
// reconstruct all current-route bindings from the signed receipt, but a caller
// that is admitting or auditing a successor supplies the stored predecessor so
// the n+1 transition and route-independent transaction identity are proven.
func VerifyRelaySideEffectAdmissionSuccessorReceipt(receipt SignedRelaySideEffectAdmissionReceipt,
	request RelayExecutionRequest, predecessor SignedRelaySideEffectAdmissionReceipt,
	resolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	descriptor, err := BuildRelaySideEffectAdmissionSuccessorDescriptor(request,
		receipt.Body.AuthenticatedPrincipal, predecessor, resolver)
	if err != nil {
		return err
	}
	if descriptor.RouteAttempt != receipt.Body.RouteAttempt ||
		descriptor.PredecessorReceiptDigest != receipt.Body.PredecessorReceiptDigest {
		return errors.New("relay side-effect admission successor receipt has the wrong lineage")
	}
	return VerifyRelaySideEffectAdmissionReceiptForDescriptor(receipt, descriptor, request, resolver, now)
}

// VerifyRelaySideEffectAdmissionReceiptForDescriptor verifies a receipt's
// authority and its bindings to descriptor and request at now.
func VerifyRelaySideEffectAdmissionReceiptForDescriptor(receipt SignedRelaySideEffectAdmissionReceipt,
	descriptor RelaySideEffectAdmissionDescriptor, request RelayExecutionRequest,
	resolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if _, err := VerifyRelaySideEffectAdmissionReceiptAuthority(receipt, resolver); err != nil {
		return err
	}
	return checkRelaySideEffectAdmissionReceiptForDescriptor(receipt, descriptor, request, now)
}

func checkRelaySideEffectAdmissionReceiptForDescriptor(receipt SignedRelaySideEffectAdmissionReceipt,
	descriptor RelaySideEffectAdmissionDescriptor, request RelayExecutionRequest, now time.Time) error {
	if err := validateRelaySideEffectAdmissionReceiptShape(receipt); err != nil {
		return err
	}
	body := receipt.Body
	action, fence := descriptor.AuthorizedAction, descriptor.WriterFence
	if body.OwnerID != descriptor.OwnerID || body.AgentID != descriptor.AgentID ||
		body.AuthenticatedPrincipal != descriptor.AuthenticatedPrincipal || body.ProviderAgentID != descriptor.ProviderAgentID ||
		body.ServiceProfileDigest != descriptor.ServiceProfileDigest || body.ProviderQuoteDigest != descriptor.ProviderQuoteDigest ||
		body.NetworkDigest != descriptor.NetworkDigest || body.TransactionIdentityDigest != descriptor.TransactionIdentityDigest ||
		body.Mode != descriptor.Mode || body.AssuranceLevel != descriptor.AssuranceLevel ||
		!equalStages(body.StageMask, descriptor.StageMask) ||
		body.RouteAttempt != descriptor.RouteAttempt || body.PredecessorReceiptDigest != descriptor.PredecessorReceiptDigest ||
		body.StableActionID != descriptor.StableActionID || body.ExactRequestDigest != descriptor.ExactRequestDigest ||
		body.RelayExecutionDigest != descriptor.RelayExecutionDigest || body.AuthorizedActionDigest != descriptor.AuthorizedActionDigest ||
		body.WriterFenceDigest != descriptor.WriterFenceDigest || body.WriterLeaseID != fence.Body.LeaseID ||
		body.WriterGeneration != fence.Body.WriterGeneration || body.PolicyRevision != action.PolicyRevision ||
		body.MandateDigest != action.MandateDigest || body.ApprovalDigest != action.ApprovalDigest ||
		body.AuthorityID != fence.Body.AuthorityID || receipt.KeyID != fence.KeyID || receipt.KeyID != action.AuthorityKeyID {
		return errors.New("relay side-effect admission receipt conflicts with the exact execution")
	}
	nowUnix := now.UTC().Unix()
	if nowUnix < 0 || body.IssuedAtUnix > uint64(nowUnix) || uint64(nowUnix) >= body.StartNotAfterUnix {
		return errors.New("relay side-effect admission receipt is premature or expired")
	}
	if body.IssuedAtUnix < fence.Body.IssuedAtUnix || body.StartNotAfterUnix > fence.Body.ExpiresAtUnix ||
		body.StartNotAfterUnix > action.ExpiresAtUnix || body.StartNotAfterUnix > descriptor.StartNotAfterCapUnix ||
		request.SchemaVersion != 0 &&
			(body.IssuedAtUnix < request.CreatedAtUnix || body.StartNotAfterUnix > request.ExpiresAtUnix ||
				body.StartNotAfterUnix > request.AgreementExpiresAtUnix ||
				body.StartNotAfterUnix > request.ProviderQuote.Body.ExpiresAtUnix ||
				body.StartNotAfterUnix > request.QuoteRequest.Body.TransactionValidUntilUnix) {
		return errors.New("relay side-effect admission receipt exceeds a frozen authorization window")
	}
	return nil
}

// VerifyRelaySideEffectAdmissionReceiptIntegrity is for an already-admitted
// downstream sink. It checks the immutable receipt shape and its bindings to
// the exact execution at the signed issuance instant, and grants no authority
// to create a new journal admission after StartNotAfterUnix. It does not
// resolve the Action Authority key: the Provider's durable receipt digest is
// the evidence that the verified live admission already happened.
func VerifyRelaySideEffectAdmissionReceiptIntegrity(receipt SignedRelaySideEffectAdmissionReceipt,
	request RelayExecutionRequest) error {
	if receipt.Body.IssuedAtUnix == 0 || receipt.Body.IssuedAtUnix > uint64(1<<63-1) {
		return errors.New("relay side-effect admission receipt issuance time is invalid")
	}
	descriptor, err := buildRelaySideEffectAdmissionDescriptorForRoute(request, receipt.Body.AuthenticatedPrincipal,
		receipt.Body.RouteAttempt, receipt.Body.PredecessorReceiptDigest)
	if err != nil {
		return err
	}
	return checkRelaySideEffectAdmissionReceiptForDescriptor(receipt, descriptor, request,
		time.Unix(int64(receipt.Body.IssuedAtUnix), 0).UTC())
}

func validateRelaySideEffectAdmissionReceiptShape(receipt SignedRelaySideEffectAdmissionReceipt) error {
	if validateRelaySideEffectAdmissionReceiptBody(receipt.Body) != nil {
		return errors.New("relay side-effect admission receipt body is invalid")
	}
	if _, err := agentcommerce.ParseActionAuthorityKeyID(receipt.KeyID); err != nil {
		return errors.New("relay side-effect admission receipt key ID is invalid: " + err.Error())
	}
	if _, err := agentcommerce.ParseActionAuthoritySignature(receipt.Signature); err != nil {
		return errors.New("relay side-effect admission receipt signature is invalid: " + err.Error())
	}
	return nil
}

func validateRelaySideEffectAdmissionReceiptBody(body RelaySideEffectAdmissionReceiptBody) error {
	stages, err := RelaySideEffectStages(body.Mode)
	if err != nil || body.SchemaVersion != 1 || !identifier(body.OwnerID, 256) || !identifier(body.AgentID, 256) ||
		!identifier(body.AuthenticatedPrincipal, 256) || !identifier(body.AuthorityID, 256) ||
		!identifier(body.ProviderAgentID, 256) || !identifier(body.WriterLeaseID, 256) ||
		!digestPattern.MatchString(body.ServiceProfileDigest) || !digestPattern.MatchString(body.ProviderQuoteDigest) ||
		!digestPattern.MatchString(body.NetworkDigest) || !digestPattern.MatchString(body.TransactionIdentityDigest) ||
		!validAssuranceLevel(body.AssuranceLevel) ||
		validateRelayAdmissionRoute(body.RouteAttempt, body.PredecessorReceiptDigest) != nil ||
		body.RouteAttempt > 1 && (body.Mode != ModeRelayExact ||
			body.AssuranceLevel != AssuranceAutonomousDecentralized) || !digestPattern.MatchString(body.StableActionID) ||
		!digestPattern.MatchString(body.ExactRequestDigest) || !digestPattern.MatchString(body.RelayExecutionDigest) ||
		!digestPattern.MatchString(body.AuthorizedActionDigest) || !digestPattern.MatchString(body.WriterFenceDigest) ||
		!digestPattern.MatchString(body.MandateDigest) || body.ApprovalDigest != "" && !digestPattern.MatchString(body.ApprovalDigest) ||
		!equalStages(body.StageMask, stages) || body.WriterGeneration == 0 || body.PolicyRevision == 0 ||
		body.AdmissionSequence == 0 || body.IssuedAtUnix == 0 || body.StartNotAfterUnix <= body.IssuedAtUnix ||
		body.StartNotAfterUnix-body.IssuedAtUnix > MaxRelayAdmissionStartDelay {
		return errors.New("relay side-effect admission receipt body is invalid")
	}
	return nil
}

func equalStages(left, right []SideEffectStage) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
