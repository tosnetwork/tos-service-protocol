package agentrelay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type conformanceAdmissionAuthority struct {
	mu       sync.Mutex
	key      relayAuthorityKey
	resolver agentcommerce.CurrentWriterFenceResolver
	now      time.Time
	next     uint64
	receipts map[string]SignedRelaySideEffectAdmissionReceipt
	bindings map[RelaySideEffectAdmissionBindingKey]SignedRelaySideEffectAdmissionReceipt
}

func newConformanceAdmissionAuthority(key relayAuthorityKey,
	resolver agentcommerce.CurrentWriterFenceResolver, now time.Time) *conformanceAdmissionAuthority {
	return &conformanceAdmissionAuthority{key: key, resolver: resolver, now: now.UTC(), next: 1,
		receipts: make(map[string]SignedRelaySideEffectAdmissionReceipt),
		bindings: make(map[RelaySideEffectAdmissionBindingKey]SignedRelaySideEffectAdmissionReceipt)}
}

func (authority *conformanceAdmissionAuthority) AdmitRelaySideEffects(_ context.Context,
	descriptor RelaySideEffectAdmissionDescriptor) (SignedRelaySideEffectAdmissionReceipt, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := ValidateRelaySideEffectAdmissionDescriptor(descriptor, authority.resolver, authority.now); err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	lookupDigest, err := RelaySideEffectAdmissionLookupDigest(descriptor.Lookup())
	if err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	if existing, found := authority.receipts[lookupDigest]; found {
		body := existing.Body
		if body.AuthorizedActionDigest != descriptor.AuthorizedActionDigest ||
			body.WriterFenceDigest != descriptor.WriterFenceDigest || body.PolicyRevision != descriptor.AuthorizedAction.PolicyRevision ||
			body.MandateDigest != descriptor.AuthorizedAction.MandateDigest ||
			body.ApprovalDigest != descriptor.AuthorizedAction.ApprovalDigest {
			return SignedRelaySideEffectAdmissionReceipt{}, ErrRelayConflict
		}
		return existing, nil
	}
	bindingKey := descriptor.BindingKey()
	if predecessor, found := authority.bindings[bindingKey]; found {
		if err := ValidateRelaySideEffectAdmissionRouteTransition(predecessor, descriptor, authority.resolver); err != nil {
			return SignedRelaySideEffectAdmissionReceipt{}, ErrRelayConflict
		}
	} else if descriptor.RouteAttempt != 1 {
		return SignedRelaySideEffectAdmissionReceipt{}, ErrRelayConflict
	}
	if err := agentcommerce.ConfirmCurrentWriterFence(descriptor.WriterFence, authority.resolver, authority.now); err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	startNotAfter := uint64(authority.now.Add(30 * time.Second).Unix())
	if startNotAfter > descriptor.StartNotAfterCapUnix {
		startNotAfter = descriptor.StartNotAfterCapUnix
	}
	body, err := BuildRelaySideEffectAdmissionReceiptBody(descriptor, authority.next,
		uint64(authority.now.Unix()), startNotAfter)
	if err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	receipt, err := signTestReceipt(body, authority.key)
	if err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	authority.next++
	authority.receipts[lookupDigest] = receipt
	authority.bindings[bindingKey] = receipt
	return receipt, nil
}

func (authority *conformanceAdmissionAuthority) ResolveRelaySideEffectAdmission(_ context.Context,
	lookup RelaySideEffectAdmissionLookup) (SignedRelaySideEffectAdmissionReceipt, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	digest, err := RelaySideEffectAdmissionLookupDigest(lookup)
	if err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, err
	}
	receipt, found := authority.receipts[digest]
	if !found {
		return SignedRelaySideEffectAdmissionReceipt{}, ErrRelayUnknown
	}
	return receipt, nil
}

func TestRelaySideEffectAdmissionExactRetryResolveAndTakeover(t *testing.T) {
	fixture := newRelayFixture(t)
	descriptor, err := BuildRelaySideEffectAdmissionDescriptorForPrincipal(
		fixture.execution, "principal:openfox-client")
	if err != nil {
		t.Fatal(err)
	}
	authority := newConformanceAdmissionAuthority(fixture.authorityKey, fixture.resolver, fixture.now)
	first, err := authority.AdmitRelaySideEffects(t.Context(), descriptor)
	if err != nil {
		t.Fatal(err)
	}

	// Exact retry and ResolveAdmission return the originally persisted envelope,
	// even if a takeover has happened since its linearization.
	fixture.resolver.current.fence = fixture.takeoverFence(t)
	retry, err := authority.AdmitRelaySideEffects(t.Context(), descriptor)
	if err != nil || !reflect.DeepEqual(retry, first) {
		t.Fatalf("exact admission retry changed its receipt: err=%v", err)
	}
	resolved, err := authority.ResolveRelaySideEffectAdmission(t.Context(), descriptor.Lookup())
	if err != nil || !reflect.DeepEqual(resolved, first) {
		t.Fatalf("ResolveAdmission did not return the byte-identical receipt: err=%v", err)
	}

	// A new generation cannot replace the action/fence behind the same immutable
	// lookup tuple and execution projection.
	takeover := fixture.takeover(t, 2)
	takeoverDescriptor, err := BuildRelaySideEffectAdmissionDescriptorForPrincipal(
		takeover, "principal:openfox-client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AdmitRelaySideEffects(t.Context(), takeoverDescriptor); !errors.Is(err, ErrRelayConflict) {
		t.Fatalf("takeover replaced an already-issued admission: %v", err)
	}

	// An old unconsumed writer cannot obtain its first receipt after takeover.
	fresh := newConformanceAdmissionAuthority(fixture.authorityKey, fixture.resolver, fixture.now)
	if _, err := fresh.AdmitRelaySideEffects(t.Context(), descriptor); err == nil {
		t.Fatal("stale writer obtained a new side-effect admission receipt")
	}
}

func TestRelayExecutionDigestExcludesCredentialsButBindsEconomicRoute(t *testing.T) {
	fixture := newRelayFixture(t)
	want, err := RelayExecutionRequestDigest(fixture.execution)
	if err != nil {
		t.Fatal(err)
	}
	credentialFree := fixture.execution
	credentialFree.AuthorizedAction = agentcommerce.AuthorizedAction{}
	credentialFree.WriterFence = agentcommerce.WriterFence{}
	credentialFree.AdmissionReceipt = SignedRelaySideEffectAdmissionReceipt{}
	got, err := RelayExecutionRequestDigest(credentialFree)
	if err != nil || got != want {
		t.Fatalf("credential-free pre-admission digest mismatch: got=%s want=%s err=%v", got, want, err)
	}

	for name, mutate := range map[string]func(*RelayExecutionRequest){
		"agreement": func(request *RelayExecutionRequest) { request.AgreementBodyDigest = digest("8") },
		"bytes":     func(request *RelayExecutionRequest) { request.SignedTransactionBytes[0] ^= 1 },
		"quote": func(request *RelayExecutionRequest) {
			request.ProviderQuote.Body.QuoteID = "relay-quote:changed"
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := credentialFree
			mutated.SignedTransactionBytes = append([]byte(nil), credentialFree.SignedTransactionBytes...)
			mutate(&mutated)
			changed, digestErr := RelayExecutionRequestDigest(mutated)
			if digestErr == nil && changed == want {
				t.Fatal("economic execution mutation preserved its digest")
			}
		})
	}
}

func TestRelayAdmissionReceiptRejectsFieldAndPrincipalSubstitution(t *testing.T) {
	fixture := newRelayFixture(t)
	request := fixture.execution
	if err := VerifyRelaySubmitPrincipal(request, "principal:openfox-client"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelaySubmitPrincipal(request, "principal:attacker"); err == nil {
		t.Fatal("receipt was accepted on another authenticated Submit channel")
	}

	for name, mutate := range map[string]func(*RelaySideEffectAdmissionReceiptBody){
		"provider": func(body *RelaySideEffectAdmissionReceiptBody) { body.ProviderAgentID = "agent:attacker" },
		"network":  func(body *RelaySideEffectAdmissionReceiptBody) { body.NetworkDigest = digest("9") },
		"transaction": func(body *RelaySideEffectAdmissionReceiptBody) {
			body.TransactionIdentityDigest = digest("9")
		},
		"policy": func(body *RelaySideEffectAdmissionReceiptBody) { body.PolicyRevision++ },
		"fence":  func(body *RelaySideEffectAdmissionReceiptBody) { body.WriterGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			body := request.AdmissionReceipt.Body
			mutate(&body)
			mutated, err := signTestReceipt(body, fixture.authorityKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyRelaySideEffectAdmissionReceipt(mutated, request, fixture.resolver, fixture.now); err == nil {
				t.Fatal("re-signed receipt field substitution was accepted")
			}
		})
	}
	invalidRoute := request.AdmissionReceipt.Body
	invalidRoute.RouteAttempt++
	if _, err := signTestReceipt(invalidRoute, fixture.authorityKey); err == nil {
		t.Fatal("successor route without a predecessor receipt digest was signed")
	}

	if err := VerifyRelaySideEffectAdmissionReceipt(request.AdmissionReceipt, request, fixture.resolver,
		time.Unix(int64(request.AdmissionReceipt.Body.StartNotAfterUnix), 0)); err == nil {
		t.Fatal("receipt was consumed at its exclusive start boundary")
	}
	if err := VerifyRelaySideEffectAdmissionReceiptIntegrity(request.AdmissionReceipt, request); err != nil {
		t.Fatalf("durably consumed receipt lost immutable recovery validity: %v", err)
	}
}

func TestRelayAdmissionWireRequestIsExactNormativeShape(t *testing.T) {
	fixture := newRelayFixture(t)
	descriptor, err := BuildRelaySideEffectAdmissionDescriptorForPrincipal(
		fixture.execution, "principal:openfox-client")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := BuildRelaySideEffectAdmissionRequest(descriptor,
		uint64(fixture.now.Add(20*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRelaySideEffectAdmissionRequestAgainstDescriptor(wire, descriptor,
		fixture.resolver, fixture.now); err != nil {
		t.Fatal(err)
	}
	first, err := RelaySideEffectAdmissionRequestBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RelaySideEffectAdmissionRequestBytes(wire)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("admission request canonical bytes are not deterministic")
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	expected := []string{"schema_version", "owner_id", "agent_id", "authenticated_principal_id",
		"provider_agent_id", "service_profile_digest", "provider_quote_digest", "network_digest",
		"transaction_identity_digest", "mode", "assurance_level", "stage_mask", "route_attempt", "stable_action_id",
		"exact_request_digest", "relay_execution_request_digest", "authorized_action", "writer_fence",
		"underlying_action_request", "semantic_fields", "requested_start_not_after_unix"}
	if len(fields) != len(expected) {
		t.Fatalf("wire request has %d fields, want %d: %s", len(fields), len(expected), raw)
	}
	for _, name := range expected {
		if _, found := fields[name]; !found {
			t.Fatalf("wire request is missing %s", name)
		}
	}
	for _, forbidden := range []string{"authorized_action_digest", "writer_fence_digest", "start_not_after_cap_unix"} {
		if _, found := fields[forbidden]; found {
			t.Fatalf("internal descriptor field %s leaked onto the wire", forbidden)
		}
	}
	changedAction := wire
	changedAction.UnderlyingActionRequest = append([]byte(nil), wire.UnderlyingActionRequest...)
	changedAction.UnderlyingActionRequest[0] ^= 1
	if err := ValidateRelaySideEffectAdmissionRequest(changedAction, fixture.resolver, fixture.now); err == nil {
		t.Fatal("wire request changed the exact underlying action bytes")
	}
	changedFields := wire
	changedFields.SemanticFields = append([]agentcommerce.SemanticFieldValue(nil), wire.SemanticFields...)
	changedFields.SemanticFields[0].Text += ":changed"
	if err := ValidateRelaySideEffectAdmissionRequest(changedFields, fixture.resolver, fixture.now); err == nil {
		t.Fatal("wire request changed a stable-action semantic field")
	}
	wire.RequestedStartNotAfterUnix = descriptor.StartNotAfterCapUnix + 1
	if err := ValidateRelaySideEffectAdmissionRequestAgainstDescriptor(wire, descriptor,
		fixture.resolver, fixture.now); err == nil {
		t.Fatal("wire request extended the trusted coordinator deadline cap")
	}
}

func TestRelayAdmissionRouteSuccessorBindsPriorReceiptAndExactTransaction(t *testing.T) {
	fixture := newRelayFixture(t)
	authority := newConformanceAdmissionAuthority(fixture.authorityKey, fixture.resolver, fixture.now)
	firstDescriptor, err := BuildRelaySideEffectAdmissionDescriptorForPrincipal(
		fixture.execution, "principal:openfox-client")
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.AdmitRelaySideEffects(t.Context(), firstDescriptor)
	if err != nil {
		t.Fatal(err)
	}

	next := fixture.execution
	next.QuoteRequest.Body.ProviderAgentID = "agent:provider-two"
	next.ProviderQuote.Body.ProviderAgentID = "agent:provider-two"
	next.ProviderQuote.Body.QuoteID = "relay-quote:provider-two"
	next.ProviderQuote.Body.ServiceProfileDigest = digest("8")
	next.ProviderQuote.Body.QuoteRequestDigest, err = RelayQuoteRequestDigest(next.QuoteRequest.Body)
	if err != nil {
		t.Fatal(err)
	}
	successorDescriptor, err := BuildRelaySideEffectAdmissionSuccessorDescriptor(next,
		"principal:openfox-client", first, fixture.resolver)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.AdmitRelaySideEffects(t.Context(), successorDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	if second.Body.RouteAttempt != 2 || second.Body.PredecessorReceiptDigest == "" ||
		second.Body.TransactionIdentityDigest != first.Body.TransactionIdentityDigest {
		t.Fatalf("successor receipt lost its route lineage: %+v", second.Body)
	}
	if err := VerifyRelaySideEffectAdmissionSuccessorReceipt(second, next, first, fixture.resolver, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRelaySideEffectAdmissionRouteChain(
		[]SignedRelaySideEffectAdmissionReceipt{first, second}, fixture.resolver); err != nil {
		t.Fatalf("persisted route-head chain failed validation: %v", err)
	}
	takeoverBody := second.Body
	takeoverBody.WriterLeaseID = "lease:takeover"
	takeoverBody.WriterGeneration++
	takeoverBody.WriterFenceDigest = digest("b")
	takeoverBody.AuthorizedActionDigest = digest("d")
	takeoverSecond, err := signTestReceipt(takeoverBody, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRelaySideEffectAdmissionRouteChain(
		[]SignedRelaySideEffectAdmissionReceipt{first, takeoverSecond}, fixture.resolver); err != nil {
		t.Fatalf("persisted route-head chain rejected a same-Authority writer takeover: %v", err)
	}
	for name, mutate := range map[string]func(*RelaySideEffectAdmissionDescriptor){
		"policy-revision": func(value *RelaySideEffectAdmissionDescriptor) {
			value.AuthorizedAction.PolicyRevision++
		},
		"mandate": func(value *RelaySideEffectAdmissionDescriptor) {
			value.AuthorizedAction.MandateDigest = digest("9")
		},
		"approval": func(value *RelaySideEffectAdmissionDescriptor) {
			value.AuthorizedAction.ApprovalDigest = digest("a")
		},
		"authority-domain": func(value *RelaySideEffectAdmissionDescriptor) {
			value.WriterFence.Body.AuthorityID = "authority:other"
		},
	} {
		t.Run("descriptor-"+name, func(t *testing.T) {
			mutated := successorDescriptor
			mutate(&mutated)
			if err := ValidateRelaySideEffectAdmissionRouteTransition(first, mutated, fixture.resolver); err == nil {
				t.Fatal("route successor changed immutable owner authority context")
			}
		})
	}
	for name, mutate := range map[string]func(*RelaySideEffectAdmissionReceiptBody){
		"policy-revision": func(value *RelaySideEffectAdmissionReceiptBody) { value.PolicyRevision++ },
		"mandate":         func(value *RelaySideEffectAdmissionReceiptBody) { value.MandateDigest = digest("9") },
		"approval":        func(value *RelaySideEffectAdmissionReceiptBody) { value.ApprovalDigest = digest("a") },
		"authority-domain": func(value *RelaySideEffectAdmissionReceiptBody) {
			value.AuthorityID = "authority:other"
		},
	} {
		t.Run("persisted-"+name, func(t *testing.T) {
			mutatedBody := second.Body
			mutate(&mutatedBody)
			mutated, signErr := signTestReceipt(mutatedBody, fixture.authorityKey)
			if signErr != nil {
				t.Fatal(signErr)
			}
			if err := ValidateRelaySideEffectAdmissionRouteChain(
				[]SignedRelaySideEffectAdmissionReceipt{first, mutated}, fixture.resolver); err == nil {
				t.Fatal("persisted route chain accepted an immutable owner authority mutation")
			}
		})
	}
	retry, err := authority.AdmitRelaySideEffects(t.Context(), successorDescriptor)
	if err != nil || !reflect.DeepEqual(retry, second) {
		t.Fatalf("successor exact retry changed its receipt: err=%v", err)
	}

	alternateFirst, err := BuildRelaySideEffectAdmissionDescriptorForPrincipal(next, "principal:openfox-client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AdmitRelaySideEffects(t.Context(), alternateFirst); !errors.Is(err, ErrRelayConflict) {
		t.Fatalf("second route attempt 1 escaped the stable-action binding: %v", err)
	}
	sameProviderRequote := next
	sameProviderRequote.QuoteRequest.Body.ProviderAgentID = first.Body.ProviderAgentID
	sameProviderRequote.ProviderQuote.Body.ProviderAgentID = first.Body.ProviderAgentID
	if _, err := BuildRelaySideEffectAdmissionSuccessorDescriptor(sameProviderRequote,
		"principal:openfox-client", first, fixture.resolver); err == nil {
		t.Fatal("same Provider obtained a successor route through a requote")
	}

	changedTransaction := next
	changedTransaction.QuoteRequest.Body.SourceSequence++
	if _, err := BuildRelaySideEffectAdmissionSuccessorDescriptor(changedTransaction,
		"principal:openfox-client", second, fixture.resolver); err == nil {
		t.Fatal("successor route changed the exact transaction identity")
	}
	sponsorSuccessor := successorDescriptor
	sponsorSuccessor.Mode = ModeSponsorOnly
	sponsorSuccessor.StageMask = []SideEffectStage{SideEffectSponsorship}
	if err := ValidateRelaySideEffectAdmissionRouteTransition(second, sponsorSuccessor, fixture.resolver); err == nil {
		t.Fatal("sponsorship received a successor Provider route")
	}
}

func TestRelayAdmissionRouteAttemptCapAndSponsorshipFirstRouteOnly(t *testing.T) {
	fixture := newRelayFixture(t)
	descriptor, err := BuildRelaySideEffectAdmissionDescriptorForPrincipal(
		fixture.execution, "principal:openfox-client")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDigest := digest("f")

	tooMany := descriptor
	tooMany.Mode = ModeRelayExact
	tooMany.StageMask = []SideEffectStage{SideEffectBroadcast}
	tooMany.RouteAttempt = MaxRelayRouteAttempts + 1
	tooMany.PredecessorReceiptDigest = predecessorDigest
	if err := ValidateRelaySideEffectAdmissionDescriptor(tooMany, fixture.resolver, fixture.now); err == nil {
		t.Fatal("descriptor exceeded the V1 route-attempt cap")
	}
	if _, err := RelaySideEffectAdmissionLookupDigest(tooMany.Lookup()); err == nil {
		t.Fatal("lookup exceeded the V1 route-attempt cap")
	}
	wire, err := BuildRelaySideEffectAdmissionRequest(descriptor,
		uint64(fixture.now.Add(20*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	wire.Mode = ModeRelayExact
	wire.StageMask = []SideEffectStage{SideEffectBroadcast}
	wire.RouteAttempt = MaxRelayRouteAttempts + 1
	wire.PredecessorReceiptDigest = predecessorDigest
	if _, err := RelaySideEffectAdmissionRequestBytes(wire); err == nil {
		t.Fatal("wire request exceeded the V1 route-attempt cap")
	}
	body := fixture.execution.AdmissionReceipt.Body
	body.Mode = ModeRelayExact
	body.StageMask = []SideEffectStage{SideEffectBroadcast}
	body.RouteAttempt = MaxRelayRouteAttempts + 1
	body.PredecessorReceiptDigest = predecessorDigest
	if _, err := signTestReceipt(body, fixture.authorityKey); err == nil {
		t.Fatal("receipt exceeded the V1 route-attempt cap")
	}

	sponsorship := descriptor
	sponsorship.Mode = ModeSponsorAndRelay
	sponsorship.StageMask = []SideEffectStage{SideEffectBroadcast, SideEffectSponsorship}
	sponsorship.RouteAttempt = 2
	sponsorship.PredecessorReceiptDigest = predecessorDigest
	if err := ValidateRelaySideEffectAdmissionDescriptor(sponsorship, fixture.resolver, fixture.now); err == nil {
		t.Fatal("sponsorship descriptor obtained a successor route")
	}
	sponsorshipWire, err := BuildRelaySideEffectAdmissionRequest(descriptor,
		uint64(fixture.now.Add(20*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	sponsorshipWire.RouteAttempt = 2
	sponsorshipWire.PredecessorReceiptDigest = predecessorDigest
	sponsorshipWire.Mode = ModeSponsorAndRelay
	sponsorshipWire.StageMask = []SideEffectStage{SideEffectBroadcast, SideEffectSponsorship}
	if _, err := RelaySideEffectAdmissionRequestBytes(sponsorshipWire); err == nil {
		t.Fatal("sponsorship wire request obtained a successor route")
	}
	sponsorshipLookup := descriptor.Lookup()
	sponsorshipLookup.Mode = ModeSponsorAndRelay
	sponsorshipLookup.StageMask = []SideEffectStage{SideEffectBroadcast, SideEffectSponsorship}
	sponsorshipLookup.RouteAttempt = 2
	sponsorshipLookup.PredecessorReceiptDigest = predecessorDigest
	if _, err := RelaySideEffectAdmissionLookupDigest(sponsorshipLookup); err == nil {
		t.Fatal("sponsorship lookup obtained a successor route")
	}

	last := fixture.execution.AdmissionReceipt.Body
	last.Mode = ModeRelayExact
	last.StageMask = []SideEffectStage{SideEffectBroadcast}
	last.RouteAttempt = MaxRelayRouteAttempts
	last.PredecessorReceiptDigest = predecessorDigest
	signedLast, err := signTestReceipt(last, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRelaySideEffectAdmissionSuccessorDescriptor(fixture.execution,
		"principal:openfox-client", signedLast, fixture.resolver); err == nil {
		t.Fatal("route-attempt 32 produced an unbounded successor")
	}
}

func TestRelayTransactionIdentityIgnoresRouteButBindsSignedTransaction(t *testing.T) {
	fixture := newRelayFixture(t)
	want, err := RelayTransactionIdentityDigest(fixture.execution.QuoteRequest.Body)
	if err != nil {
		t.Fatal(err)
	}
	routeOnly := fixture.execution.QuoteRequest.Body
	routeOnly.ProviderAgentID = "agent:provider-two"
	routeOnly.RequestID = "relay-request:provider-two"
	if got, err := RelayTransactionIdentityDigest(routeOnly); err != nil || got != want {
		t.Fatalf("Provider route changed transaction identity: got=%s want=%s err=%v", got, want, err)
	}
	changed := fixture.execution.QuoteRequest.Body
	changed.SourceSequence++
	if got, err := RelayTransactionIdentityDigest(changed); err != nil || got == want {
		t.Fatal("source-sequence mutation preserved transaction identity")
	}
	vector := RelayTransactionIdentity{SchemaVersion: 1,
		Network: NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42,
			ZeroStateRootHash: digest("1"), ZeroStateFileHash: digest("2"), WorkchainID: 0},
		SourceAccount: "0:" + strings.Repeat("1", 64), SourceAccountAuthorityDigest: digest("0"),
		TransactionProfileURI: "tos.signed-external-boc.v1", TransactionProfileDigest: digest("3"),
		UnderlyingActionKind:      "payment.direct",
		StableActionID:            "sha256:f951d5db1f4a955b156164b9985a9be3e965e2959ca6dce6db2436147662e0ae",
		ExactRequestDigest:        "sha256:f218789c7750655634f28dc6607798d0004537aa63528e63b921fb9ea96c1039",
		SignedTransactionDigest:   "sha256:5371a2e4ff0a623c8fbe653b7c89307262f5b16074cbbae1dd2326a0ef2f1817",
		SignedTransactionCellHash: "tvm-cell-sha256:" + strings.Repeat("d", 64), SignedTransactionSize: 28,
		TransactionIntentDigest: digest("e"), SourceSequence: 7, TransactionValidUntilUnix: 1_800_000_600}
	if got, err := RelayTransactionIdentityProjectionDigest(vector); err != nil ||
		got != "sha256:2e66a85268292338d0915286f941631938cdcb3b1e0c55841a337a2a236c42e6" {
		t.Fatalf("cross-language transaction identity vector changed: got=%s err=%v", got, err)
	}
}

func TestRelayPreparedAdmissionRejectsExpiredStartReceipt(t *testing.T) {
	fixture := newRelayFixture(t)
	atBoundary := time.Unix(int64(fixture.execution.AdmissionReceipt.Body.StartNotAfterUnix), 0).UTC()
	verified := verifiedTestReceipt(t, fixture.execution, fixture.resolver)
	if _, err := NewPreparedRecord(fixture.execution, verified, atBoundary); err == nil {
		t.Fatal("NewPreparedRecord consumed a receipt at its exclusive start boundary")
	}
	if _, err := NewPreparedRecord(fixture.execution, verified, atBoundary.Add(-time.Second)); err != nil {
		t.Fatalf("NewPreparedRecord refused a receipt one second before its start boundary: %v", err)
	}
	if _, err := NewPreparedRecord(fixture.execution, VerifiedRelayAdmissionReceipt{}, fixture.now); err == nil {
		t.Fatal("NewPreparedRecord accepted a receipt whose Action Authority was never verified")
	}
}

func TestRelayAdmissionCrossLanguageRequestAndReceiptVectors(t *testing.T) {
	fixture := newRelayFixture(t)
	networkDigest := "sha256:2bb4cdc2e2e1001bc54e519087598582717217b82cbfd005c0acfe03269f6a69"
	payment := agentcommerce.AgreementPaymentRequest{SchemaVersion: 3, OwnerID: "owner:client",
		AgentID: "agent:client", AgreementBodyDigest: digest("5"),
		AgreementObligationID: "obligation:underlying-payment", ObligationInstanceID: digest("6"),
		PayerAgentID: "agent:client", PayeeAgentID: "agent:merchant", NetworkID: "tos:testnet",
		NetworkDomainDigest: networkDigest,
		Amount: agentcommerce.AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "tos:testnet",
			AmountAtomic: "25", Unit: "nanotos"},
		Destination: []byte("0:" + strings.Repeat("2", 64)), SettlementAdapterURI: "tos.payment.direct.v1",
		StableActionID: "sha256:81ee1e20e2dc9135975343ca3433116e73477f3edd9c876d49941c54451ad0fa",
		ExpiresAtUnix:  1_800_000_480}
	underlying, semanticMap, err := agentcommerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		t.Fatal(err)
	}
	semanticFields, err := agentcommerce.ExportSemanticFields("payment.domain-bound", semanticMap)
	if err != nil {
		t.Fatal(err)
	}
	// The Action Authority signatures here come from the deterministic test
	// Fake, so these pins cover the canonical request and receipt encoding
	// only; real ML-DSA-44 bytes are pinned by the shared Action Authority
	// vector (pkg/agentcommerce/testdata).
	fence, err := signTestFence(agentcommerce.WriterFenceBody{SchemaVersion: 1,
		OwnerID: "owner:client", AgentID: "agent:client", InstanceID: "instance:client", LeaseID: "lease:client",
		WriterGeneration: 1, IssuedAtUnix: 1_799_999_940, ExpiresAtUnix: 1_800_000_600,
		AuthorityID: "authority:client", Scope: []string{"payment.domain-bound"}}, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	fenceDigest, err := agentcommerce.WriterFenceDigest(fence)
	if err != nil || fenceDigest != "sha256:973cf592d478afe576378e5bc800d69cb2175a96e752534d9842f9b82c3e998f" {
		t.Fatalf("cross-language writer fence digest changed: got=%s err=%v", fenceDigest, err)
	}
	action, err := signTestAction(agentcommerce.AuthorizedAction{SchemaVersion: 1, OwnerID: "owner:client", AgentID: "agent:client",
		ActionKind: "payment.domain-bound", StableActionID: payment.StableActionID,
		ExactRequestDigest: "sha256:c16ad477c999b08ea3fefece7ec62fd4f8bee1805a1fc76f45a45623c3a6a294",
		WriterGeneration:   1, WriterFenceDigest: fenceDigest,
		PolicyRevision: 1, MandateDigest: digest("c"), ExpectedPriorState: "unknown", ExpiresAtUnix: 1_800_000_480,
		AuthorityID: "authority:client"}, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil || actionDigest != "sha256:854a90cdc387b2500265eda4cff1edbc4bb704ba030446e8c7cab1565180cd3c" {
		t.Fatalf("cross-language authorized action digest changed: got=%s err=%v", actionDigest, err)
	}
	wire := RelaySideEffectAdmissionRequest{SchemaVersion: 1, OwnerID: "owner:client", AgentID: "agent:client",
		AuthenticatedPrincipal: "principal:openfox-client", ProviderAgentID: "agent:provider",
		ServiceProfileDigest:      "sha256:434777cea11e97002fac9923772e10bb314dd2a17ea2804d682b7719222f51b9",
		ProviderQuoteDigest:       "sha256:c2745562ea90aa23d2613338e4c94f08f8afc9e1e154b229e927b9a9e79f36b4",
		NetworkDigest:             networkDigest,
		TransactionIdentityDigest: "sha256:2e66a85268292338d0915286f941631938cdcb3b1e0c55841a337a2a236c42e6",
		Mode:                      ModeSponsorAndRelay, AssuranceLevel: AssuranceAuthorizedSingleProvider,
		StageMask:    []SideEffectStage{SideEffectBroadcast, SideEffectSponsorship},
		RouteAttempt: 1, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		RelayExecutionDigest: "sha256:223b192b7a9e8b072d4b6491fcf19d989d12cb662559ca3bea8d6b0cf711dca1",
		AuthorizedAction:     action, WriterFence: fence, UnderlyingActionRequest: underlying,
		SemanticFields: semanticFields, RequestedStartNotAfterUnix: 1_800_000_030}
	if err := ValidateRelaySideEffectAdmissionRequest(wire, fixture.resolver, fixture.now); err != nil {
		t.Fatal(err)
	}
	canonical, err := RelaySideEffectAdmissionRequestBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	canonicalHash := sha256.Sum256(canonical)
	if got, want := hex.EncodeToString(canonicalHash[:]), "c70b908e9496073c0790c72b177e02f6c5d5ac37ffd167d466c13adb89d0c649"; got != want {
		t.Fatalf("cross-language admission request bytes changed: got=%s want=%s", got, want)
	}

	body := RelaySideEffectAdmissionReceiptBody{SchemaVersion: 1, OwnerID: wire.OwnerID, AgentID: wire.AgentID,
		AuthenticatedPrincipal: wire.AuthenticatedPrincipal, AuthorityID: "authority:client",
		ProviderAgentID: wire.ProviderAgentID, ServiceProfileDigest: wire.ServiceProfileDigest,
		ProviderQuoteDigest: wire.ProviderQuoteDigest, NetworkDigest: wire.NetworkDigest,
		TransactionIdentityDigest: wire.TransactionIdentityDigest, Mode: wire.Mode,
		AssuranceLevel: wire.AssuranceLevel,
		StageMask:      append([]SideEffectStage(nil), wire.StageMask...), RouteAttempt: 1,
		StableActionID: wire.StableActionID, ExactRequestDigest: wire.ExactRequestDigest,
		RelayExecutionDigest:   wire.RelayExecutionDigest,
		AuthorizedActionDigest: actionDigest,
		WriterFenceDigest:      action.WriterFenceDigest, WriterLeaseID: "lease:client", WriterGeneration: 1,
		PolicyRevision: 1, MandateDigest: digest("c"), AdmissionSequence: 1,
		IssuedAtUnix: 1_800_000_000, StartNotAfterUnix: 1_800_000_030}
	if got, err := RelaySideEffectAdmissionReceiptBodyDigest(body); err != nil ||
		got != "sha256:ba9bdb7a05297e8c7bd14c1a764e24f89423618e37b964fc1d567a8b57be58d7" {
		t.Fatalf("cross-language admission receipt digest changed: got=%s err=%v", got, err)
	}
	signed, err := signTestReceipt(body, fixture.authorityKey)
	if err != nil || signed.KeyID != fence.KeyID {
		t.Fatalf("receipt was not signed by the fence key: %v", err)
	}
	if _, err := VerifyRelaySideEffectAdmissionReceiptAuthority(signed, fixture.resolver); err != nil {
		t.Fatal(err)
	}
}

func TestRelayAdmissionLookupRequiresModeExactStageMask(t *testing.T) {
	fixture := newRelayFixture(t)
	descriptor, err := BuildRelaySideEffectAdmissionDescriptor(fixture.execution)
	if err != nil {
		t.Fatal(err)
	}
	lookup := descriptor.Lookup()
	lookup.StageMask = []SideEffectStage{SideEffectSponsorship}
	if _, err := RelaySideEffectAdmissionLookupDigest(lookup); err == nil {
		t.Fatal("mode-incompatible ResolveAdmission stage mask was accepted")
	}
}
