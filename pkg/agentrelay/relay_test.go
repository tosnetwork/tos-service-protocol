package agentrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// relayAuthorityFake signs and verifies every Action Authority signature of
// the pure-logic relay tests. It is not ML-DSA-44; tests of real bytes use the
// shared vector and the tosctl helper.
var relayAuthorityFake = &mldsa44test.Fake{}

// relayAuthorityKey names an Action Authority controller of relayAuthorityFake.
type relayAuthorityKey string

func (key relayAuthorityKey) publicKey() []byte { return relayAuthorityFake.PublicKey(string(key)) }

func (key relayAuthorityKey) keyID() string { return relayAuthorityFake.KeyID(string(key)) }

func signTestFence(body agentcommerce.WriterFenceBody, key relayAuthorityKey) (agentcommerce.WriterFence, error) {
	return agentcommerce.SignWriterFence(context.Background(), body, relayAuthorityFake, string(key))
}

func signTestAction(action agentcommerce.AuthorizedAction, key relayAuthorityKey) (agentcommerce.AuthorizedAction, error) {
	return agentcommerce.SignAuthorizedAction(context.Background(), action, key.keyID(), relayAuthorityFake, string(key))
}

func signTestReceipt(body RelaySideEffectAdmissionReceiptBody, key relayAuthorityKey) (SignedRelaySideEffectAdmissionReceipt, error) {
	return SignRelaySideEffectAdmissionReceipt(context.Background(), body, relayAuthorityFake, string(key))
}

// testVerified is the Action Authority check of a request's receipt, or the
// zero value (which every journal refuses) when it does not verify.
func testVerified(request RelayExecutionRequest, resolver agentcommerce.FenceAuthorityResolver) VerifiedRelayAdmissionReceipt {
	verified, err := VerifyRelaySideEffectAdmissionReceiptAuthority(request.AdmissionReceipt, resolver)
	if err != nil {
		return VerifiedRelayAdmissionReceipt{}
	}
	return verified
}

// verifiedTestReceipt is the Action Authority check a Service performs before
// a journal admission.
func verifiedTestReceipt(t *testing.T, request RelayExecutionRequest, resolver agentcommerce.FenceAuthorityResolver) VerifiedRelayAdmissionReceipt {
	t.Helper()
	verified, err := VerifyRelaySideEffectAdmissionReceiptAuthority(request.AdmissionReceipt, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

type relayResolver struct {
	agents    map[string]ed25519.PublicKey
	authority []byte
	current   *relayCurrentFenceState
}

// Verify implements mldsa44.Verifier for the Action Authority signatures.
func (resolver relayResolver) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	return relayAuthorityFake.Verify(ctx, use, payload, publicKey, signature)
}

type relayDomainResolver struct {
	relayResolver
	networkDigest string
}

func (resolver relayDomainResolver) AuthorizeRelayKey(network NetworkDomain, agentID string,
	key ed25519.PublicKey, at time.Time) error {
	digest, err := NetworkDomainDigest(network)
	if err != nil || digest != resolver.networkDigest {
		return errors.New("Agent key is not authorized in this relay network domain")
	}
	return resolver.relayResolver.AuthorizeRelayKey(network, agentID, key, at)
}

type relayObservationTimeResolver struct {
	key     ed25519.PublicKey
	network NetworkDomain
	at      time.Time
}

func (resolver *relayObservationTimeResolver) AuthorizeRelayKey(network NetworkDomain, _ string, key ed25519.PublicKey,
	at time.Time) error {
	resolver.network = network
	resolver.at = at.UTC()
	if resolver.key == nil || !resolver.key.Equal(key) {
		return errors.New("unknown Agent key")
	}
	return nil
}

type relayCurrentFenceState struct {
	mu                      sync.Mutex
	fence                   agentcommerce.WriterFence
	successor               agentcommerce.WriterFence
	confirmations           int
	supersedeOnConfirmation int
}

type rotatingFenceResolver struct {
	base      relayResolver
	oldKey    []byte
	newKey    []byte
	rotatesAt time.Time
	mu        sync.Mutex
	observed  []time.Time
}

func (resolver *rotatingFenceResolver) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	return relayAuthorityFake.Verify(ctx, use, payload, publicKey, signature)
}

func (resolver *rotatingFenceResolver) ResolveActionAuthorityKey(authorityID string,
	keyID [mldsa44.KeyIDSize]byte, at time.Time) ([]byte, error) {
	resolver.mu.Lock()
	resolver.observed = append(resolver.observed, at.UTC())
	resolver.mu.Unlock()
	wanted := resolver.oldKey
	if !at.UTC().Before(resolver.rotatesAt) {
		wanted = resolver.newKey
	}
	id, err := mldsa44.KeyID(wanted)
	if authorityID != "authority:client" || err != nil || id != keyID {
		return nil, errors.New("authority key is not valid at the requested historical instant")
	}
	return append([]byte(nil), wanted...), nil
}

func (resolver *rotatingFenceResolver) ConfirmCurrentWriterFence(fence agentcommerce.WriterFence,
	at time.Time) error {
	return resolver.base.ConfirmCurrentWriterFence(fence, at)
}

func (resolver *rotatingFenceResolver) observedTimes() []time.Time {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return append([]time.Time(nil), resolver.observed...)
}

func (resolver relayResolver) AuthorizeRelayKey(_ NetworkDomain, agentID string, key ed25519.PublicKey, _ time.Time) error {
	wanted := resolver.agents[agentID]
	if wanted == nil || !wanted.Equal(key) {
		return errors.New("unknown Agent key")
	}
	return nil
}

func (resolver relayResolver) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, at time.Time) error {
	return resolver.AuthorizeRelayKey(NetworkDomain{}, agentID, key, at)
}

func (resolver relayResolver) ResolveActionAuthorityKey(authorityID string, keyID [mldsa44.KeyIDSize]byte,
	_ time.Time) ([]byte, error) {
	id, err := mldsa44.KeyID(resolver.authority)
	if authorityID != "authority:client" || err != nil || id != keyID {
		return nil, errors.New("unknown authority key")
	}
	return append([]byte(nil), resolver.authority...), nil
}

func (resolver relayResolver) ConfirmCurrentWriterFence(fence agentcommerce.WriterFence, now time.Time) error {
	if resolver.current == nil {
		return errors.New("writer authority currentness is unavailable")
	}
	resolver.current.mu.Lock()
	defer resolver.current.mu.Unlock()
	resolver.current.confirmations++
	if resolver.current.supersedeOnConfirmation != 0 &&
		resolver.current.confirmations == resolver.current.supersedeOnConfirmation {
		resolver.current.fence = resolver.current.successor
	}
	wanted, wantedErr := agentcommerce.WriterFenceDigest(resolver.current.fence)
	got, gotErr := agentcommerce.WriterFenceDigest(fence)
	if wantedErr != nil || gotErr != nil || wanted != got ||
		!now.UTC().Before(time.Unix(int64(fence.Body.ExpiresAtUnix), 0).UTC()) {
		return errors.New("writer lease was superseded")
	}
	return nil
}

func (resolver relayResolver) supersedeAt(confirmation int, successor agentcommerce.WriterFence) {
	resolver.current.mu.Lock()
	defer resolver.current.mu.Unlock()
	resolver.current.successor = successor
	resolver.current.supersedeOnConfirmation = confirmation
}

func (resolver relayResolver) confirmationCount() int {
	resolver.current.mu.Lock()
	defer resolver.current.mu.Unlock()
	return resolver.current.confirmations
}

type fixedInspector struct{ inspected InspectedTransaction }

func (inspector fixedInspector) InspectTransaction(context.Context, RelayQuoteRequestBody, TransactionProfile, []byte,
	TransactionInspectionPhase) (InspectedTransaction, error) {
	return inspector.inspected, nil
}

type fixedActionBinder struct{}

func (fixedActionBinder) VerifyActionTransaction(request RelayExecutionRequest, inspected InspectedTransaction) error {
	if request.AuthorizedAction.ActionKind != "payment.direct" || inspected.ValueAtomic != "25" {
		return errors.New("underlying action does not match transaction")
	}
	return nil
}

type fixedQuotePolicy struct{ body ProviderRelayQuoteBody }

func (policy fixedQuotePolicy) Quote(context.Context, RelayServiceProfile, SignedRelayQuoteRequest, time.Time) (ProviderRelayQuoteBody, error) {
	return policy.body, nil
}

type recordingBroadcaster struct {
	submits    int
	payloads   [][]byte
	result     BroadcastResult
	submitErr  error
	resolution ChainResolution
}

type recordingSponsorship struct {
	calls                          int
	prepareCalls                   int
	resolveCalls                   int
	dualCalls                      int
	after                          func()
	resolveFinalized               bool
	resolveCorroborated            bool
	resolveAbsent                  bool
	resolveComponentAbsent         bool
	observed                       bool
	dualSubstituteSponsor          bool
	dualRecovery                   SponsorshipRecoveryHandle
	dualSponsorshipRefs            []RelayAbsenceObservationReference
	dualPriorBundleDigest          string
	dualPriorBundle                []byte
	transactionComponentCalls      int
	transactionComponentSubstitute bool
	transactionComponentRecovery   SponsorshipRecoveryHandle
}

func (processor *recordingSponsorship) PrepareRecovery(_ context.Context, request RelayExecutionRequest,
	_ agentcommerce.AgentAgreement, _ agentcommerce.AgreementObligation) (SponsorshipRecoveryHandle, error) {
	processor.prepareCalls++
	return sponsorshipRecoveryHandle(request, "opaque-sponsorship-recovery-token"), nil
}

func (processor *recordingSponsorship) EnsureFinalized(_ context.Context, request RelayExecutionRequest,
	_ agentcommerce.AgentAgreement, _ agentcommerce.AgreementObligation,
	recovery SponsorshipRecoveryHandle) (SponsorshipResolution, error) {
	processor.calls++
	if processor.after != nil {
		processor.after()
	}
	if processor.resolveComponentAbsent {
		resolution := finalizedAbsentSponsorshipResolution(request, recovery)
		resolution.TransactionAbsenceObservations = nil
		resolution.AbsenceProofBundleDigest, resolution.AbsenceProofBundle =
			testAbsenceProofBundle(resolution.SponsorshipAbsenceObservations, nil)
		return resolution, nil
	}
	if processor.resolveAbsent {
		return finalizedAbsentSponsorshipResolution(request, recovery), nil
	}
	if processor.observed && !processor.resolveFinalized {
		observation := sponsorshipCreditObservation(request, recovery, time.Unix(1_800_000_030, 0).UTC())
		return SponsorshipResolution{Status: SponsorshipResolutionObservedUnproven,
			CreditObservation: &observation}, nil
	}
	evidence := sponsorshipTransactionEvidence(request, recovery, time.Unix(1_800_000_030, 0).UTC())
	status := SponsorshipResolutionFinalized
	if processor.resolveCorroborated {
		evidence.TerminalEvidenceClass = SponsorshipTerminalClientCorroborated
		evidence.ValidatorAuthenticatedPortableProof = false
		evidence.PortableProofLocator = ""
		status = SponsorshipResolutionCorroboratedTerminal
	}
	return SponsorshipResolution{Status: status,
		TransferReference: evidence.SubmittedTransactionHash, EvidenceRefs: evidence.ObservationDigests,
		TransactionEvidence: &evidence}, nil
}

func (processor *recordingSponsorship) ResolveRelayDualAbsence(_ context.Context,
	request RelayExecutionRequest, recovery SponsorshipRecoveryHandle,
	sponsorship []RelayAbsenceObservationReference, priorBundleDigest string,
	priorBundle []byte) (SponsorshipResolution, error) {
	processor.dualCalls++
	processor.dualRecovery = recovery
	processor.dualRecovery.OpaqueToken = append([]byte(nil), recovery.OpaqueToken...)
	processor.dualSponsorshipRefs = append([]RelayAbsenceObservationReference(nil), sponsorship...)
	processor.dualPriorBundleDigest = priorBundleDigest
	processor.dualPriorBundle = append([]byte(nil), priorBundle...)
	outcome := OutcomeFinalizedAbsent
	status := SponsorshipResolutionFinalizedAbsent
	if request.ProviderQuote.Body.SponsorshipTerminalProfile != nil &&
		request.ProviderQuote.Body.SponsorshipTerminalProfile.TerminalEvidenceClass ==
			SponsorshipTerminalClientCorroborated {
		outcome = OutcomeCorroboratedAbsent
		status = SponsorshipResolutionCorroboratedAbsent
	}
	preserved := append([]RelayAbsenceObservationReference(nil), sponsorship...)
	if processor.dualSubstituteSponsor && len(preserved) != 0 {
		preserved[0].ObservationDigest = digest("f")
	}
	_, transaction := absenceObservationReferences(request, recovery, outcome)
	bundleDigest, bundle := testAbsenceProofBundle(preserved, transaction)
	return SponsorshipResolution{Status: status, AbsenceOutcome: outcome,
		SponsorshipAbsenceObservations: preserved, TransactionAbsenceObservations: transaction,
		AbsenceProofBundleDigest: bundleDigest, AbsenceProofBundle: bundle}, nil
}

func (processor *recordingSponsorship) ResolveRelayTransactionAbsence(_ context.Context,
	request RelayExecutionRequest, recovery SponsorshipRecoveryHandle,
	outcome TerminalOutcome) (ChainResolution, error) {
	processor.transactionComponentCalls++
	processor.transactionComponentRecovery = recovery
	processor.transactionComponentRecovery.OpaqueToken = append([]byte(nil), recovery.OpaqueToken...)
	componentOutcome := outcome
	if processor.transactionComponentSubstitute {
		componentOutcome = OutcomeCorroboratedInvalidated
		if transactionConclusion(componentOutcome) == transactionConclusion(outcome) {
			componentOutcome = OutcomeCorroboratedAbsent
		}
	}
	_, transaction := absenceObservationReferences(request, recovery, componentOutcome)
	bundleDigest, bundle := testAbsenceProofBundle(nil, transaction)
	return ChainResolution{State: agentcommerce.ActionTerminal, TerminalOutcome: componentOutcome,
		TransactionAbsenceObservations: transaction, AbsenceProofBundleDigest: bundleDigest,
		AbsenceProofBundle: bundle}, nil
}

func (processor *recordingSponsorship) ResolveFinalized(_ context.Context, request RelayExecutionRequest,
	recovery SponsorshipRecoveryHandle) (SponsorshipResolution, error) {
	processor.resolveCalls++
	if processor.resolveComponentAbsent {
		resolution := finalizedAbsentSponsorshipResolution(request, recovery)
		resolution.TransactionAbsenceObservations = nil
		resolution.AbsenceProofBundleDigest, resolution.AbsenceProofBundle =
			testAbsenceProofBundle(resolution.SponsorshipAbsenceObservations, nil)
		return resolution, nil
	}
	if processor.resolveAbsent {
		return finalizedAbsentSponsorshipResolution(request, recovery), nil
	}
	if processor.observed && !processor.resolveFinalized {
		observation := sponsorshipCreditObservation(request, recovery, time.Unix(1_800_000_181, 0).UTC())
		return SponsorshipResolution{Status: SponsorshipResolutionObservedUnproven,
			CreditObservation: &observation}, nil
	}
	if !processor.resolveFinalized {
		return SponsorshipResolution{Status: SponsorshipResolutionUnknown}, nil
	}
	evidence := sponsorshipTransactionEvidence(request, recovery, time.Unix(1_800_000_181, 0).UTC())
	status := SponsorshipResolutionFinalized
	if processor.resolveCorroborated {
		evidence.TerminalEvidenceClass = SponsorshipTerminalClientCorroborated
		evidence.ValidatorAuthenticatedPortableProof = false
		evidence.PortableProofLocator = ""
		status = SponsorshipResolutionCorroboratedTerminal
	}
	return SponsorshipResolution{Status: status,
		TransferReference: evidence.SubmittedTransactionHash, EvidenceRefs: evidence.ObservationDigests,
		TransactionEvidence: &evidence}, nil
}

type phaseInspector struct {
	admission InspectedTransaction
	ready     InspectedTransaction
}

type fixedEvidenceSource struct{ body RelayFinalityEvidenceBody }

func (source fixedEvidenceSource) Evidence(context.Context, Record) (RelayFinalityEvidenceBody, error) {
	return source.body, nil
}

func (fixedEvidenceSource) SupportsRelayEvidenceCapability(RelayEvidenceCapability) bool { return true }
func (fixedEvidenceSource) SupportsRelayDualAbsenceEvidence(RelayEvidenceCapability) bool {
	return true
}
func (fixedEvidenceSource) SupportsRelaySponsorshipComponentAbsenceEvidence(RelayEvidenceCapability) bool {
	return true
}
func (fixedEvidenceSource) SupportsRelayTransactionComponentAbsenceEvidence(RelayEvidenceCapability) bool {
	return true
}
func (fixedEvidenceSource) HasRetrievableIndependentProofs() bool        { return true }
func (fixedEvidenceSource) HasRollbackResistantCheckpoint() bool         { return true }
func (fixedEvidenceSource) HasRollbackResistantTerminalCommitment() bool { return true }

type acceptingPortableSponsorshipVerifier struct{}

func (acceptingPortableSponsorshipVerifier) VerifySponsorshipTransactionEvidence(context.Context,
	RelaySponsorshipTransactionEvidence, RelaySponsorshipEvidenceContext, FinalityProfile) error {
	return nil
}

func (acceptingPortableSponsorshipVerifier) HasIndependentPortableSponsorshipProofs() bool {
	return true
}

type acceptingPortableRelayFinalityVerifier struct{}

func (acceptingPortableRelayFinalityVerifier) VerifyRelayFinality(context.Context,
	RelayExecutionRequest, SignedRelayFinalityEvidence) error {
	return nil
}

func (acceptingPortableRelayFinalityVerifier) SupportsRelayEvidenceCapability(RelayEvidenceCapability) bool {
	return true
}

func (acceptingPortableRelayFinalityVerifier) SupportsRelayDualAbsenceEvidence(RelayEvidenceCapability) bool {
	return true
}
func (acceptingPortableRelayFinalityVerifier) SupportsRelaySponsorshipComponentAbsenceEvidence(RelayEvidenceCapability) bool {
	return true
}
func (acceptingPortableRelayFinalityVerifier) SupportsRelayTransactionComponentAbsenceEvidence(RelayEvidenceCapability) bool {
	return true
}

func (acceptingPortableRelayFinalityVerifier) HasIndependentPortableRelayFinalityProofs() bool {
	return true
}

type acceptingSponsorshipObservationVerifier struct{}

func (acceptingSponsorshipObservationVerifier) VerifySponsorshipCreditObservation(context.Context,
	RelaySponsorshipCreditObservation, SponsorshipReleaseProfile) error {
	return nil
}

func (inspector phaseInspector) InspectTransaction(_ context.Context, _ RelayQuoteRequestBody, _ TransactionProfile,
	_ []byte, phase TransactionInspectionPhase) (InspectedTransaction, error) {
	if phase == InspectionReadyToBroadcast {
		return inspector.ready, nil
	}
	return inspector.admission, nil
}

func (broadcaster *recordingBroadcaster) SubmitExact(_ context.Context, request RelayExecutionRequest) (BroadcastResult, error) {
	broadcaster.submits++
	broadcaster.payloads = append(broadcaster.payloads, append([]byte(nil), request.SignedTransactionBytes...))
	return broadcaster.result, broadcaster.submitErr
}

func (broadcaster *recordingBroadcaster) Resolve(context.Context, Record) (ChainResolution, error) {
	return broadcaster.resolution, nil
}

func TestRelayQuoteAgreementAndExecutionBindExactBytes(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	networkVector, _ := NetworkDomainDigest(fixture.profile.NetworkDomains[0])
	profileVector, _ := RelayServiceProfileDigest(fixture.profile)
	requestVector, _ := RelayQuoteRequestDigest(fixture.request.Body)
	transactionIdentityVector, _ := RelayTransactionIdentityDigest(fixture.request.Body)
	quoteVector, _ := ProviderRelayQuoteDigest(quote.Body)
	vectors := []struct{ got, want string }{
		{networkVector, "sha256:2bb4cdc2e2e1001bc54e519087598582717217b82cbfd005c0acfe03269f6a69"},
		{profileVector, "sha256:96bc9e18795563afbf31cf3b76814315991268e52a0070682236239f9fed4af2"},
		{requestVector, "sha256:f4cd388f94c3ef2b7acd1e155468e49f42844712eac4d9979984c6a6a06c011b"},
		{transactionIdentityVector, "sha256:fef25d1f929db50d9d399a58f9fd77ed7cdca9f97d8f6b186abb2ce2f51386d9"},
		{quoteVector, "sha256:4bca62f015d2efe25059d975a2d1564ceebc86fb9d8389c66b735656184fd02d"},
		{fixture.request.PublicKey, "ed25519:48075a597e721a156e2e0799de5cc0c5324dc6e7eaf1cdd46250868ec53215dd"},
		{fixture.request.Signature, "ed25519:L-4GloB1NZ3m3cUlsT-GUYia5-6NDyKGSVgBgQ7PDyT6N9uKuvru4h7-qw-yUNSkL02NiEsJztdvBxhOBvj7DQ"},
		{quote.PublicKey, "ed25519:5e212c0980e4b39fc09721134aa02109374edfd260c0d3d03cb501c8d65457a9"},
		{quote.Signature, "ed25519:RowIcF2oxsuY9o-ealz3aC5YvI4Hrn-sAe0vh_NfFiFtUv1cBUo9NOpuZfPtD4jGhIMPs6cTDTsEJFH_Ic4CCA"},
	}
	for _, vector := range vectors {
		if vector.got != vector.want {
			t.Fatalf("relay conformance vector changed: got %s want %s", vector.got, vector.want)
		}
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	digest, _ := agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementBodyDigest = digest
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	if err := VerifyRelayExecutionRequest(t.Context(), fixture.execution, fixture.profile, fixture.resolver,
		fixture.resolver, fixture.inspector, fixture.now); err != nil {
		t.Fatalf("exact relay execution rejected: %v", err)
	}
	if err := VerifyRelayExecutionAgreement(fixture.execution, agreement,
		agentcommerce.AgentSignatureEvidenceVerifier{Resolver: fixture.resolver}, fixture.now); err != nil {
		t.Fatalf("exact relay Agreement rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentcommerce.AgentAgreementBody){
		"content-type": func(body *agentcommerce.AgentAgreementBody) { body.TermsContentType = "application/octet-stream" },
		"terms": func(body *agentcommerce.AgentAgreementBody) {
			body.Terms = append(append([]byte(nil), body.Terms...), 0xff)
		},
	} {
		t.Run("reject-top-level-"+name+"-mutation", func(t *testing.T) {
			mutatedBody := cloneRelayAgreementBody(agreement.Body)
			mutate(&mutatedBody)
			mutatedAgreement := authorizeRelayAgreementBody(t, fixture, mutatedBody)
			mutatedExecution := fixture.execution
			mutatedExecution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(mutatedAgreement.Body)
			if err := VerifyRelayExecutionAgreement(mutatedExecution, mutatedAgreement,
				agentcommerce.AgentSignatureEvidenceVerifier{Resolver: fixture.resolver}, fixture.now); err == nil {
				t.Fatal("Agreement with mutated top-level binding terms was accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*agentcommerce.AgentAgreementBody){
		"duplicate-reserved-fee-kind": func(body *agentcommerce.AgentAgreementBody) {
			extra := body.Obligations[1]
			extra.ObligationID = "obligation:relay-fee-extra"
			body.Obligations = append(body.Obligations, extra)
			body.AuthorizationPredicates[0].ObligationIDs = append(
				body.AuthorizationPredicates[0].ObligationIDs, extra.ObligationID)
		},
		"extra-obligation-reusing-binding": func(body *agentcommerce.AgentAgreementBody) {
			extra := body.Obligations[1]
			extra.ObligationID = "obligation:relay-z-bound"
			extra.Kind = "unrelated_service_liability"
			body.Obligations = append(body.Obligations, extra)
			body.AuthorizationPredicates[0].ObligationIDs = append(
				body.AuthorizationPredicates[0].ObligationIDs, extra.ObligationID)
		},
	} {
		t.Run("reject-"+name, func(t *testing.T) {
			mutatedBody := cloneRelayAgreementBody(agreement.Body)
			mutate(&mutatedBody)
			mutatedAgreement := authorizeRelayAgreementBody(t, fixture, mutatedBody)
			mutatedExecution := fixture.execution
			mutatedExecution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(mutatedAgreement.Body)
			if err := VerifyRelayExecutionAgreement(mutatedExecution, mutatedAgreement,
				agentcommerce.AgentSignatureEvidenceVerifier{Resolver: fixture.resolver}, fixture.now); err == nil {
				t.Fatal("Agreement with an extra relay service obligation was accepted")
			}
		})
	}
	mutated := fixture.execution
	mutated.SignedTransactionBytes = append([]byte(nil), mutated.SignedTransactionBytes...)
	mutated.SignedTransactionBytes[0] ^= 0xff
	if err := VerifyRelayExecutionRequest(t.Context(), mutated, fixture.profile, fixture.resolver,
		fixture.resolver, fixture.inspector, fixture.now); err == nil {
		t.Fatal("mutated signed transaction bytes were accepted")
	}
}

func TestRelayAssuranceLevelIsSignedAndCannotChangeAcrossLifecycle(t *testing.T) {
	fixture := newRelayFixture(t)

	unsupported := fixture.request.Body
	unsupported.AssuranceLevel = AssuranceTrustedLocal
	unsupportedSigned, err := SignRelayQuoteRequest(unsupported, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayQuoteRequest(unsupportedSigned, fixture.profile, fixture.resolver, fixture.now); err == nil {
		t.Fatal("request selected an assurance level absent from the signed service profile")
	}

	profile := fixture.profile
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceTrustedLocal}
	profileDigest, err := RelayServiceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	request := unsupportedSigned
	if err := VerifyRelayQuoteRequest(request, profile, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("trusted-local request did not preserve the ordinary signed safety envelope: %v", err)
	}
	requestDigest, err := RelayQuoteRequestDigest(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	quoteBody := fixture.execution.ProviderQuote.Body
	quoteBody.QuoteRequestDigest = requestDigest
	quoteBody.ServiceProfileDigest = profileDigest
	quoteBody.AssuranceLevel = AssuranceTrustedLocal
	quote, err := SignProviderRelayQuote(quoteBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProviderRelayQuote(quote, request, profile, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("matching trusted-local quote was rejected: %v", err)
	}

	downgradedQuote := quoteBody
	downgradedQuote.AssuranceLevel = AssuranceAuthorizedSingleProvider
	downgraded, err := SignProviderRelayQuote(downgradedQuote, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProviderRelayQuote(downgraded, request, profile, fixture.resolver, fixture.now); err == nil {
		t.Fatal("Provider changed the requester-selected assurance level")
	}

	binding, err := CompileRelayAgreementBinding(request, quote)
	if err != nil {
		t.Fatal(err)
	}
	if binding.AssuranceLevel != AssuranceTrustedLocal {
		t.Fatal("Agreement binding omitted the selected assurance level")
	}

	execution := fixture.execution
	execution.QuoteRequest = request
	execution.ProviderQuote = quote
	execution = fixture.withAdmission(t, execution)
	if err := VerifyRelaySideEffectAdmissionReceipt(execution.AdmissionReceipt, execution, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("matching assurance admission receipt was rejected: %v", err)
	}
	mutatedReceiptBody := execution.AdmissionReceipt.Body
	mutatedReceiptBody.AssuranceLevel = AssuranceAuthorizedSingleProvider
	mutatedReceipt, err := signTestReceipt(mutatedReceiptBody, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelaySideEffectAdmissionReceipt(mutatedReceipt, execution, fixture.resolver, fixture.now); err == nil {
		t.Fatal("admission receipt changed the signed request assurance level")
	}
	if _, err := BuildRelaySideEffectAdmissionSuccessorDescriptor(execution,
		"principal:openfox-client", execution.AdmissionReceipt, fixture.resolver); err == nil {
		t.Fatal("trusted-local assurance unexpectedly allowed decentralized Provider failover")
	}

	executionDigest, err := RelayExecutionRequestDigest(execution)
	if err != nil {
		t.Fatal(err)
	}
	resolutionBody := RelayResolutionBody{SchemaVersion: 1, ProviderAgentID: quote.Body.ProviderAgentID,
		Network: request.Body.Network, AssuranceLevel: AssuranceTrustedLocal,
		StableActionID: request.Body.StableActionID, ExactRequestDigest: request.Body.ExactRequestDigest,
		RelayExecutionDigest: executionDigest, State: agentcommerce.ActionPrepared, StateRevision: 1,
		ObservedAtUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(fixture.now.Add(time.Minute).Unix())}
	resolution, err := SignRelayResolution(resolutionBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolutionForExecution(resolution, execution, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("matching assurance resolution was rejected: %v", err)
	}
	resolutionBody.AssuranceLevel = AssuranceAuthorizedSingleProvider
	mutatedResolution, err := SignRelayResolution(resolutionBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolutionForExecution(mutatedResolution, execution, fixture.resolver, fixture.now); err == nil {
		t.Fatal("resolution relabelled the exact execution under another assurance level")
	}
}

func TestRelayServiceProfileAssuranceLevelsAreCanonical(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := fixture.profile
	profile.SupportedAssuranceLevels = []AssuranceLevel{
		AssuranceAuthorizedSingleProvider,
		AssuranceAutonomousDecentralized,
		AssuranceTrustedLocal,
	}
	if err := ValidateRelayServiceProfile(profile, fixture.now); err != nil {
		t.Fatalf("canonical assurance-level set was rejected: %v", err)
	}
	profile.SupportedAssuranceLevels[0], profile.SupportedAssuranceLevels[1] =
		profile.SupportedAssuranceLevels[1], profile.SupportedAssuranceLevels[0]
	if err := ValidateRelayServiceProfile(profile, fixture.now); err == nil {
		t.Fatal("unsorted assurance-level set was accepted")
	}
	profile.SupportedAssuranceLevels = []AssuranceLevel{"production-certified"}
	if err := ValidateRelayServiceProfile(profile, fixture.now); err == nil {
		t.Fatal("unknown deployment-certification label was accepted as a wire assurance level")
	}
}

func TestLowerAssuranceFinalityClassesHaveExactProfileURIs(t *testing.T) {
	fixture := newRelayFixture(t)
	for _, test := range []struct {
		name  string
		class TerminalEvidenceClass
		uri   string
	}{
		{name: "relay provider corroborated", class: RelayTerminalProviderCorroborated,
			uri: ProviderCorroboratedTerminalProfileURI},
		{name: "sponsorship client corroborated", class: SponsorshipTerminalClientCorroborated,
			uri: ClientCorroboratedTerminalProfileURI},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := fixture.profile.FinalityProfiles[0]
			profile.TerminalEvidenceClass = test.class
			profile.ProfileURI = test.uri
			if err := validateFinalityProfile(profile); err != nil {
				t.Fatalf("released lower-assurance URI was rejected: %v", err)
			}
			profile.ProfileURI = "tos.attacker.chosen-lower-assurance.v1"
			if err := validateFinalityProfile(profile); err == nil {
				t.Fatal("lower-assurance class accepted an implementation-defined URI")
			}
		})
	}
}

func TestSponsorshipReleaseProfileIsSignedAndCannotBeDowngraded(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "50", "100")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, quote := sponsorshipQuotePair(t, fixture, profile, "request:release-profile", "quote:release-profile", "50",
		fixture.now.Add(4*time.Minute))
	if request.Body.SponsorshipReleaseEvidenceClass != SponsorshipReleaseObservedUnproven ||
		request.Body.SponsorshipReleaseProfileURI != RPCCorroborationEvidenceProfileURI ||
		request.Body.SponsorshipTerminalProfileURI != ClientCorroboratedTerminalProfileURI ||
		request.Body.SelectedSponsorshipReleaseProfile() != quote.Body.SelectedSponsorshipReleaseProfile() {
		t.Fatal("signed quote pair did not freeze one exact lower-assurance release profile")
	}
	if err := VerifyRelayQuoteRequest(request, profile, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("owner-pinned observed release request was rejected: %v", err)
	}
	if err := VerifyProviderRelayQuote(quote, request, profile, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("matching observed release quote was rejected: %v", err)
	}
	legacyObserved := request.Body
	legacyObserved.SponsorshipTerminalProfileURI = fixture.profile.FinalityProfiles[0].ProfileURI
	legacyObserved.SponsorshipTerminalProfileDigest = fixture.profile.FinalityProfiles[0].ProfileDigest
	if _, err := SignRelayQuoteRequest(legacyObserved, fixture.clientKey); err == nil {
		t.Fatal("an observed-only Agreement without an explicit client terminal predicate was accepted")
	}

	mutatedBody := quote.Body
	mutatedBody.SponsorshipReleaseEvidenceClass = SponsorshipReleaseValidatorFinality
	mutatedBody.SponsorshipReleaseProfileURI = fixture.profile.FinalityProfiles[0].ProfileURI
	mutatedBody.SponsorshipReleaseProfileDigest = fixture.profile.FinalityProfiles[0].ProfileDigest
	mutatedBody.SponsorshipTerminalEvidenceClass = SponsorshipTerminalValidatorFinality
	validatorProfile := fixture.profile.FinalityProfiles[0]
	mutatedBody.SponsorshipTerminalProfile = &validatorProfile
	mutated, err := SignProviderRelayQuote(mutatedBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProviderRelayQuote(mutated, request, profile, fixture.resolver, fixture.now); err == nil {
		t.Fatal("Provider changed observed-unproven to validator-finality after request authorization")
	}
	mutatedBody = quote.Body
	mutatedBody.SponsorshipReleaseProfileDigest = digest("d")
	mutated, err = SignProviderRelayQuote(mutatedBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProviderRelayQuote(mutated, request, profile, fixture.resolver, fixture.now); err == nil {
		t.Fatal("Provider changed the owner-pinned corroboration profile digest")
	}

	binding, err := CompileRelayAgreementBinding(request, quote)
	if err != nil {
		t.Fatal(err)
	}
	if binding.SponsorshipReleaseEvidenceClass != request.Body.SponsorshipReleaseEvidenceClass ||
		binding.SponsorshipReleaseProfileURI != request.Body.SponsorshipReleaseProfileURI ||
		binding.SponsorshipReleaseProfileDigest != request.Body.SponsorshipReleaseProfileDigest {
		t.Fatal("Agreement binding omitted the signed sponsorship release profile")
	}

	autonomous := request.Body
	autonomous.AssuranceLevel = AssuranceAutonomousDecentralized
	if _, err := SignRelayQuoteRequest(autonomous, fixture.clientKey); err == nil {
		t.Fatal("autonomous request selected observed-unproven sponsorship release")
	}
	relayOnly := fixture.request.Body
	relayOnly.SponsorshipReleaseEvidenceClass = SponsorshipReleaseValidatorFinality
	relayOnly.SponsorshipReleaseProfileURI = relayOnly.RelayFinalityProfileURI
	relayOnly.SponsorshipReleaseProfileDigest = relayOnly.RelayFinalityProfileDigest
	if _, err := SignRelayQuoteRequest(relayOnly, fixture.clientKey); err == nil {
		t.Fatal("relay_exact request carried a sponsorship release profile")
	}

	autoProfile := sponsorshipProfile(fixture.profile, "50", "100")
	autoRequest, autoQuote := sponsorshipQuotePair(t, fixture, autoProfile, "request:validator-release",
		"quote:validator-release", "50", fixture.now.Add(4*time.Minute))
	autoExecution := sponsorshipExecution(fixture.execution, autoRequest, autoQuote)
	autoExecution = fixture.withAdmission(t, autoExecution)
	autoExecutionDigest, err := RelayExecutionRequestDigest(autoExecution)
	if err != nil {
		t.Fatal(err)
	}
	resolutionBody := RelayResolutionBody{SchemaVersion: 1, ProviderAgentID: autoRequest.Body.ProviderAgentID,
		Network: autoRequest.Body.Network, AssuranceLevel: autoRequest.Body.AssuranceLevel,
		StableActionID: autoRequest.Body.StableActionID, ExactRequestDigest: autoRequest.Body.ExactRequestDigest,
		RelayExecutionDigest: autoExecutionDigest, State: agentcommerce.ActionPrepared, StateRevision: 1,
		SponsorshipStableActionID: digest("1"), SponsorshipExactRequestDigest: digest("2"),
		SponsorshipValidUntilUnix: uint64(fixture.now.Add(4 * time.Minute).Unix()),
		SponsorshipStatus:         SponsorshipResolutionObservedUnproven, SponsorshipObservationDigest: digest("3"),
		ObservedAtUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(fixture.now.Add(time.Minute).Unix())}
	resolution, err := SignRelayResolution(resolutionBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolutionForExecution(resolution, autoExecution, fixture.resolver, fixture.now); err == nil {
		t.Fatal("observed-unproven resolution weakened validator-finality sponsorship release")
	}
}

func TestNetworkDomainOrderingUsesSignedNumericCoordinates(t *testing.T) {
	base := NetworkDomain{NetworkID: "tos:testnet", GlobalID: -2,
		ZeroStateRootHash: digest("1"), ZeroStateFileHash: digest("2"), WorkchainID: -2}
	globalMinusOne := base
	globalMinusOne.GlobalID = -1
	workchainMinusOne := base
	workchainMinusOne.WorkchainID = -1
	for name, values := range map[string][]NetworkDomain{
		"negative global IDs": {base, globalMinusOne},
		"negative workchains": {base, workchainMinusOne},
	} {
		t.Run(name, func(t *testing.T) {
			if !sortedNetworkDomains(values) {
				t.Fatal("numeric ascending NetworkDomain order was rejected")
			}
			reversed := []NetworkDomain{values[1], values[0]}
			if sortedNetworkDomains(reversed) {
				t.Fatal("lexically misleading descending NetworkDomain order was accepted")
			}
		})
	}
}

func TestRelayActionRequestLimitFitsCanonicalCodecBoundary(t *testing.T) {
	if MaxRelayActionRequestBytes > 3*codec.MaxStringBytes/4 {
		t.Fatal("relay raw-byte limit exceeds the canonical base64 string limit")
	}
	type envelope struct {
		UnderlyingActionRequest []byte `json:"underlying_action_request"`
	}
	if _, err := codec.Marshal(envelope{UnderlyingActionRequest: bytes.Repeat([]byte{'x'},
		MaxRelayActionRequestBytes)}); err != nil {
		t.Fatalf("exact relay action boundary is not canonically encodable: %v", err)
	}
	// The relay profile deliberately retains its smaller released request
	// ceiling even when the generic codec can encode a larger byte string. The
	// profile validator, rather than the shared codec, is the authority for
	// rejecting MaxRelayActionRequestBytes+1.
	if MaxRelayActionRequestBytes >= codec.MaxCanonicalBytes {
		t.Fatal("relay action boundary must leave room for its signed envelope")
	}
}

func TestRelayFinalityEvidenceUsesHistoricalObservationAuthority(t *testing.T) {
	fixture := newRelayFixture(t)
	observedAt := fixture.now
	body := RelayFinalityEvidenceBody{SchemaVersion: 1, ProviderAgentID: fixture.profile.ProviderAgentID,
		Network: fixture.request.Body.Network, AssuranceLevel: fixture.request.Body.AssuranceLevel,
		StableActionID:     fixture.request.Body.StableActionID,
		ExactRequestDigest: fixture.request.Body.ExactRequestDigest, RelayExecutionDigest: digest("8"),
		SignedTransactionDigest:   fixture.request.Body.SignedTransactionDigest,
		SignedTransactionCellHash: fixture.request.Body.SignedTransactionCellHash,
		TransactionValidUntilUnix: fixture.request.Body.TransactionValidUntilUnix,
		SourceAccount:             fixture.request.Body.SourceAccount, SourceSequence: fixture.request.Body.SourceSequence,
		RelayTerminalEvidenceClass:               RelayTerminalValidatorFinality,
		RelayValidatorAuthenticatedPortableProof: relayBoolPointer(true),
		RelayFinalizedCheckpointID:               "checkpoint:historical", RelayFinalizedCheckpointSequence: 100,
		RelayFinalizedCheckpointUnix: uint64(observedAt.Unix()),
		RelayConfirmationDepth:       fixture.profile.FinalityProfiles[0].MinimumConfirmationDepth,
		RelayFinalityProfile:         finalityPointer(fixture.profile.FinalityProfiles[0]),
		RelayObservationDigests:      []string{digest("1"), digest("2"), digest("3")},
		Outcome:                      OutcomeFinalizedExpired, ObservedAtUnix: uint64(observedAt.Unix()),
		SigningAuthorityAtUnix: uint64(observedAt.Add(7 * 24 * time.Hour).Unix())}
	signed, err := SignRelayFinalityEvidence(body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &relayObservationTimeResolver{key: fixture.providerKey.Public().(ed25519.PublicKey)}
	if err := VerifyRelayFinalityEvidence(signed, resolver, observedAt.Add(30*24*time.Hour)); err != nil {
		t.Fatalf("durable evidence failed after a later key-authorization epoch: %v", err)
	}
	wantAuthorityTime := observedAt.Add(7 * 24 * time.Hour)
	if !resolver.at.Equal(wantAuthorityTime) {
		t.Fatalf("evidence key was authorized at %s, want signing time %s", resolver.at, wantAuthorityTime)
	}
	if resolver.network != body.Network {
		t.Fatalf("evidence key was authorized in network %+v, want %+v", resolver.network, body.Network)
	}
	body.ObservedAtUnix = uint64(observedAt.Add(6 * time.Minute).Unix())
	body.RelayFinalizedCheckpointUnix = body.ObservedAtUnix
	future, err := SignRelayFinalityEvidence(body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver.at = time.Time{}
	if err := VerifyRelayFinalityEvidence(future, resolver, observedAt); err == nil || !resolver.at.IsZero() {
		t.Fatalf("future-dated evidence reached key authorization: at=%s err=%v", resolver.at, err)
	}
}

func TestRelayFinalityPortableProofBooleanHasExplicitPresence(t *testing.T) {
	fixture := newRelayFixture(t)
	observedAt := fixture.now
	profile := fixture.profile.FinalityProfiles[0]
	profile.ProfileURI = ProviderCorroboratedTerminalProfileURI
	profile.ProfileDigest = digest("7")
	profile.TerminalEvidenceClass = RelayTerminalProviderCorroborated
	body := RelayFinalityEvidenceBody{SchemaVersion: 1, ProviderAgentID: fixture.profile.ProviderAgentID,
		Network: fixture.request.Body.Network, AssuranceLevel: AssuranceAuthorizedSingleProvider,
		StableActionID: fixture.request.Body.StableActionID, ExactRequestDigest: fixture.request.Body.ExactRequestDigest,
		RelayExecutionDigest: digest("8"), SignedTransactionDigest: fixture.request.Body.SignedTransactionDigest,
		SignedTransactionCellHash: fixture.request.Body.SignedTransactionCellHash,
		TransactionValidUntilUnix: fixture.request.Body.TransactionValidUntilUnix,
		SourceAccount:             fixture.request.Body.SourceAccount, SourceSequence: fixture.request.Body.SourceSequence,
		RelayTerminalEvidenceClass:               RelayTerminalProviderCorroborated,
		RelayValidatorAuthenticatedPortableProof: relayBoolPointer(false),
		RelayFinalizedCheckpointID:               "checkpoint:corroborated", RelayFinalizedCheckpointSequence: 100,
		RelayFinalizedCheckpointUnix: uint64(observedAt.Unix()), RelayConfirmationDepth: profile.MinimumConfirmationDepth,
		RelayFinalityProfile: &profile, RelayObservationDigests: []string{digest("1"), digest("2"), digest("3")},
		Outcome: OutcomeCorroboratedExpired, ObservedAtUnix: uint64(observedAt.Unix()),
		SigningAuthorityAtUnix: uint64(observedAt.Unix())}
	if _, err := SignRelayFinalityEvidence(body, fixture.providerKey); err != nil {
		t.Fatalf("explicit false lower-assurance predicate was rejected: %v", err)
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := codec.Unmarshal(canonical, &fields); err != nil {
		t.Fatal(err)
	}
	value, present := fields["relay_validator_authenticated_portable_proof"]
	if !present || value != false {
		t.Fatalf("explicit false proof predicate was omitted or changed: present=%v value=%v", present, value)
	}
	body.RelayValidatorAuthenticatedPortableProof = nil
	if _, err := SignRelayFinalityEvidence(body, fixture.providerKey); err == nil {
		t.Fatal("applicable relay finality omitted its proof-authentication predicate")
	}
}

func TestRelayResolutionRejectsExpiredAndFutureWrappers(t *testing.T) {
	fixture := newRelayFixture(t)
	body := RelayResolutionBody{SchemaVersion: 1, ProviderAgentID: fixture.profile.ProviderAgentID,
		Network: fixture.request.Body.Network, AssuranceLevel: fixture.request.Body.AssuranceLevel,
		StableActionID:     fixture.request.Body.StableActionID,
		ExactRequestDigest: fixture.request.Body.ExactRequestDigest, RelayExecutionDigest: digest("8"),
		State: agentcommerce.ActionPrepared, StateRevision: 1, ObservedAtUnix: uint64(fixture.now.Unix()),
		ExpiresAtUnix: uint64(fixture.now.Add(5 * time.Minute).Unix())}
	signed, err := SignRelayResolution(body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolution(signed, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("fresh relay resolution was rejected: %v", err)
	}
	if err := VerifyRelayResolution(signed, fixture.resolver, fixture.now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired relay resolution was accepted")
	}
	body.ObservedAtUnix = uint64(fixture.now.Add(6 * time.Minute).Unix())
	body.ExpiresAtUnix = uint64(fixture.now.Add(10 * time.Minute).Unix())
	future, err := SignRelayResolution(body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolution(future, fixture.resolver, fixture.now); err == nil {
		t.Fatal("future-dated relay resolution was accepted")
	}
}

func TestRelayAgentAuthorityIsScopedToExactNetworkDomain(t *testing.T) {
	fixture := newRelayFixture(t)
	originalDigest, _ := NetworkDomainDigest(fixture.request.Body.Network)
	resolver := relayDomainResolver{relayResolver: fixture.resolver, networkDigest: originalDigest}

	other := fixture.request.Body.Network
	other.ZeroStateRootHash = digest("9")
	profile := fixture.profile
	profile.NetworkDomains = []NetworkDomain{other}
	body := fixture.request.Body
	body.Network = other
	signed, err := SignRelayQuoteRequest(body, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayQuoteRequest(signed, profile, resolver, fixture.now); err == nil {
		t.Fatal("same Agent key was accepted on an unauthorized genesis domain")
	}
}

func TestRelayProfileRejectsUnsafeOrPathlessEndpoints(t *testing.T) {
	fixture := newRelayFixture(t)
	for name, endpoint := range map[string]string{
		"loopback":              "https://127.0.0.1/quote",
		"private":               "https://10.0.0.1/quote",
		"localhost":             "https://relay.localhost/quote",
		"documentation":         "https://192.0.2.1/quote",
		"this-network":          "https://0.0.0.1/quote",
		"future-use":            "https://240.0.0.1/quote",
		"ipv6-discard":          "https://[100::1]/quote",
		"ipv6-special-protocol": "https://[2001::1]/quote",
		"ipv6-local-nat64":      "https://[64:ff9b:1::1]/quote",
		"pathless":              "https://relay.example",
	} {
		t.Run(name, func(t *testing.T) {
			profile := fixture.profile
			profile.Endpoints.QuoteURL = endpoint
			if err := ValidateRelayServiceProfile(profile, fixture.now); err == nil {
				t.Fatal("unsafe or pathless relay endpoint was accepted")
			}
		})
	}
}

func TestRelayJournalRejectsMutationAndCredentialReplacement(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	journal := NewMemoryJournal()
	if _, created, err := journal.ReserveQuote(fixture.profile, fixture.request, quote, fixture.now); err != nil || !created {
		t.Fatalf("quote reservation failed: created=%v err=%v", created, err)
	}
	first, created, err := journal.Admit(fixture.execution, testVerified(fixture.execution, fixture.resolver), fixture.now)
	if err != nil || !created || first.State != agentcommerce.ActionPrepared {
		t.Fatalf("first admission failed: created=%v state=%s err=%v", created, first.State, err)
	}
	retry, created, err := journal.Admit(fixture.execution, testVerified(fixture.execution, fixture.resolver), fixture.now)
	if err != nil || created || retry.RelayExecutionDigest != first.RelayExecutionDigest {
		t.Fatalf("exact retry changed admission: created=%v err=%v", created, err)
	}
	restored, err := RestoreRecord(first.Snapshot(), fixture.execution)
	if err != nil || string(restored.ExecutionRequest().SignedTransactionBytes) !=
		string(fixture.execution.SignedTransactionBytes) {
		t.Fatalf("durable relay record did not restore exact bytes: %v", err)
	}
	takeover := fixture.takeover(t, 2)
	takeover = attachRelayTestAdmission(t, takeover, fixture.authorityKey, fixture.now, 2)
	beforeDigest, _ := RelayExecutionRequestDigest(fixture.execution)
	afterDigest, _ := RelayExecutionRequestDigest(takeover)
	if beforeDigest != afterDigest {
		t.Fatal("credential-only writer takeover changed the semantic relay execution digest")
	}
	if _, created, err := journal.Admit(takeover, testVerified(takeover, fixture.resolver), fixture.now); !errors.Is(err, ErrRelayConflict) || created {
		t.Fatalf("takeover replaced an already-consumed admission receipt: created=%v err=%v", created, err)
	}
	if exact, created, err := journal.Admit(fixture.execution, testVerified(fixture.execution, fixture.resolver), fixture.now); err != nil || created ||
		exact.AdmissionReceiptDigest != first.AdmissionReceiptDigest {
		t.Fatalf("exact receipt retry did not return the frozen record: created=%v err=%v", created, err)
	}
	mutated := takeover
	mutated.AgreementBodyDigest = digest("9")
	if _, _, err := journal.Admit(mutated, testVerified(mutated, fixture.resolver), fixture.now); !errors.Is(err, ErrRelayConflict) {
		t.Fatalf("same action with a changed execution envelope was not conflict: %v", err)
	}
}

func TestRelayJournalConcurrentAdmissionHasOneWinner(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	journal := NewMemoryJournal()
	if _, created, err := journal.ReserveQuote(fixture.profile, fixture.request, quote, fixture.now); err != nil || !created {
		t.Fatalf("quote reservation failed: created=%v err=%v", created, err)
	}
	const callers = 16
	var wait sync.WaitGroup
	wait.Add(callers)
	results := make(chan bool, callers)
	errorsSeen := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			_, created, admitErr := journal.Admit(fixture.execution, testVerified(fixture.execution, fixture.resolver), fixture.now)
			results <- created
			errorsSeen <- admitErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	winners := 0
	for created := range results {
		if created {
			winners++
		}
	}
	for admitErr := range errorsSeen {
		if admitErr != nil {
			t.Fatalf("concurrent exact retry failed: %v", admitErr)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent admission produced %d winners", winners)
	}
}

func TestRelayQuoteReservationIsDeterministicAndReleasesExpiredUnconsumedExposure(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "100", "100")
	request, first := sponsorshipQuotePair(t, fixture, profile, "request:deterministic", "quote:first", "100",
		fixture.now.Add(10*time.Second))
	journal := NewMemoryJournal()
	reserved, created, err := journal.ReserveQuote(profile, request, first, fixture.now)
	if err != nil || !created || reserved.Signature != first.Signature {
		t.Fatalf("first quote was not reserved exactly: created=%v err=%v", created, err)
	}
	second := resignRelayQuote(t, first, fixture.providerKey, "quote:replacement", fixture.now.Add(20*time.Second))
	requoted, created, err := journal.ReserveQuote(profile, request, second, fixture.now.Add(time.Second))
	if err != nil || created || requoted.Signature != first.Signature {
		t.Fatalf("exact re-quote did not return the first signed quote: created=%v err=%v", created, err)
	}
	replaced, created, err := journal.ReserveQuote(profile, request, second, fixture.now.Add(11*time.Second))
	if err != nil || !created || replaced.Signature != second.Signature {
		t.Fatalf("expired unconsumed quote did not release exposure: created=%v err=%v", created, err)
	}
}

func TestRelayQuoteReservationEnforcesProviderWideExposureAtomically(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:exposure:a", "quote:exposure:a", "60",
		fixture.now.Add(4*time.Minute))
	requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:exposure:b", "quote:exposure:b", "60",
		fixture.now.Add(4*time.Minute))
	journal := NewMemoryJournal()
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for _, candidate := range []struct {
		request SignedRelayQuoteRequest
		quote   SignedProviderRelayQuote
	}{{requestA, quoteA}, {requestB, quoteB}} {
		candidate := candidate
		go func() {
			defer wait.Done()
			<-start
			_, _, reserveErr := journal.ReserveQuote(profile, candidate.request, candidate.quote, fixture.now)
			results <- reserveErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, exhausted := 0, 0
	for reserveErr := range results {
		switch {
		case reserveErr == nil:
			successes++
		case errors.Is(reserveErr, ErrRelayExposure):
			exhausted++
		default:
			t.Fatalf("unexpected concurrent reservation error: %v", reserveErr)
		}
	}
	if successes != 1 || exhausted != 1 {
		t.Fatalf("provider-wide exposure was not linearized: successes=%d exhausted=%d", successes, exhausted)
	}
}

func TestRelayQuoteAndExecutionAdmissionLimitsAreAtomic(t *testing.T) {
	fixture := newRelayFixture(t)

	t.Run("quote reservation and expiry", func(t *testing.T) {
		profile := sponsorshipProfile(fixture.profile, "10", "100")
		profile.AdmissionLimits.MaximumQuoteReservations = 1
		profile.AdmissionLimits.MaximumQuoteRequestsPerRequesterWindow = 10
		requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:slot:a", "quote:slot:a", "1",
			fixture.now.Add(10*time.Second))
		requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:slot:b", "quote:slot:b", "1",
			fixture.now.Add(4*time.Minute))
		journal := NewMemoryJournal()
		if _, created, err := journal.ReserveQuote(profile, requestA, quoteA, fixture.now); err != nil || !created {
			t.Fatalf("first quote slot was not reserved: created=%v err=%v", created, err)
		}
		if _, _, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); !errors.Is(err, ErrRelayAdmissionLimit) {
			t.Fatalf("quote reservation limit was not enforced: %v", err)
		}
		if _, created, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now.Add(11*time.Second)); err != nil || !created {
			t.Fatalf("expired quote slot was not released: created=%v err=%v", created, err)
		}
	})

	t.Run("requester quote rate", func(t *testing.T) {
		profile := sponsorshipProfile(fixture.profile, "10", "100")
		profile.AdmissionLimits.MaximumQuoteReservations = 10
		profile.AdmissionLimits.MaximumQuoteRequestsPerRequesterWindow = 1
		profile.AdmissionLimits.QuoteRequestWindowSeconds = 60
		requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:rate:a", "quote:rate:a", "1",
			fixture.now.Add(4*time.Minute))
		requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:rate:b", "quote:rate:b", "1",
			fixture.now.Add(4*time.Minute))
		journal := NewMemoryJournal()
		if _, _, err := journal.ReserveQuote(profile, requestA, quoteA, fixture.now); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now.Add(30*time.Second)); !errors.Is(err, ErrRelayAdmissionLimit) {
			t.Fatalf("requester quote rate was not enforced: %v", err)
		}
		if _, created, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now.Add(61*time.Second)); err != nil || !created {
			t.Fatalf("quote rate window did not reopen: created=%v err=%v", created, err)
		}
	})

	t.Run("provider global quote rate", func(t *testing.T) {
		profile := sponsorshipProfile(fixture.profile, "10", "100")
		profile.AdmissionLimits.MaximumQuoteRequestsPerWindow = 1
		profile.AdmissionLimits.MaximumQuoteRequestsPerRequesterWindow = 1
		requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:global-rate:a", "quote:global-rate:a", "1",
			fixture.now.Add(4*time.Minute))
		requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:global-rate:b", "quote:global-rate:b", "1",
			fixture.now.Add(4*time.Minute))
		requestB.Body.RequesterAgentID = "agent:other"
		var err error
		requestB, err = SignRelayQuoteRequest(requestB.Body, fixture.clientKey)
		if err != nil {
			t.Fatal(err)
		}
		quoteB.Body.QuoteRequestDigest, err = RelayQuoteRequestDigest(requestB.Body)
		if err != nil {
			t.Fatal(err)
		}
		quoteB, err = SignProviderRelayQuote(quoteB.Body, fixture.providerKey)
		if err != nil {
			t.Fatal(err)
		}
		journal := NewMemoryJournal()
		if _, _, err := journal.ReserveQuote(profile, requestA, quoteA, fixture.now); err != nil {
			t.Fatal(err)
		}
		if _, _, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); !errors.Is(err, ErrRelayAdmissionLimit) {
			t.Fatalf("provider-global quote rate was not enforced across requesters: %v", err)
		}
	})

	t.Run("active execution", func(t *testing.T) {
		profile := sponsorshipProfile(fixture.profile, "10", "100")
		profile.AdmissionLimits.MaximumActiveExecutions = 1
		profile.AdmissionLimits.MaximumActivePerRequester = 1
		request, quote := sponsorshipQuotePair(t, fixture, profile, "request:work-limit", "quote:work-limit", "1",
			fixture.now.Add(4*time.Minute))
		execution := sponsorshipExecution(fixture.execution, request, quote)
		execution = fixture.withAdmission(t, execution)
		journal := NewMemoryJournal()
		if _, _, err := journal.ReserveQuote(profile, request, quote, fixture.now); err != nil {
			t.Fatal(err)
		}
		journal.records["existing"] = Record{State: agentcommerce.ActionPrepared,
			request: RelayExecutionRequest{QuoteRequest: SignedRelayQuoteRequest{Body: RelayQuoteRequestBody{
				RequesterAgentID: request.Body.RequesterAgentID}}}}
		if _, _, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now); !errors.Is(err, ErrRelayAdmissionLimit) {
			t.Fatalf("active execution limit was not enforced: %v", err)
		}
		existing := journal.records["existing"]
		existing.State = agentcommerce.ActionTerminal
		journal.records["existing"] = existing
		if _, created, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now); err != nil || !created {
			t.Fatalf("terminal work slot was not released: created=%v err=%v", created, err)
		}
	})
}

func TestRelayAdmissionRetainsFinalizedSponsorshipUntilExplicitAccountingRelease(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:lifecycle:a", "quote:lifecycle:a", "60",
		fixture.now.Add(4*time.Minute))
	requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:lifecycle:b", "quote:lifecycle:b", "60",
		fixture.now.Add(4*time.Minute))
	execution := sponsorshipExecution(fixture.execution, requestA, quoteA)
	execution = fixture.withAdmission(t, execution)
	unreserved := NewMemoryJournal()
	if _, _, err := unreserved.Admit(execution, testVerified(execution, fixture.resolver), fixture.now); !errors.Is(err, ErrRelayQuoteUnreserved) {
		t.Fatalf("execution without a quote reservation was admitted: %v", err)
	}
	journal := NewMemoryJournal()
	if _, created, err := journal.ReserveQuote(profile, requestA, quoteA, fixture.now); err != nil || !created {
		t.Fatalf("first sponsorship quote reservation failed: created=%v err=%v", created, err)
	}
	record, created, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now)
	if err != nil || !created || record.State != agentcommerce.ActionPrepared {
		t.Fatalf("reserved sponsorship quote was not consumed: created=%v state=%s err=%v", created, record.State, err)
	}
	if _, _, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); !errors.Is(err, ErrRelayExposure) {
		t.Fatalf("PREPARED exposure was released early: %v", err)
	}
	record, err = journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		sponsorshipRecoveryHandle(execution, "lifecycle-recovery-token"), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	evidence := sponsorshipTransactionEvidence(execution, record.SponsorshipRecoveryHandle(), fixture.now)
	record, err = journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		evidence, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision-1,
		evidence, fixture.now); err != nil {
		t.Fatalf("exact sponsorship checkpoint retry was not idempotent: %v", err)
	}
	mutatedEvidence := evidence
	mutatedEvidence.SubmittedTransactionHash = "sponsorship:substitution"
	if _, err := journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		mutatedEvidence, fixture.now); !errors.Is(err, ErrRelayConflict) {
		t.Fatalf("sponsorship reference substitution was accepted: %v", err)
	}
	if _, _, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); !errors.Is(err, ErrRelayExposure) {
		t.Fatalf("finalized sponsorship exposure was released before terminal accounting: %v", err)
	}
	record, err = journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionTerminal, "sponsorship:final", record.EvidenceRefs, OutcomeFinalizedSponsorshipOnly, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); !errors.Is(err, ErrRelayExposure) {
		t.Fatalf("relay terminality incorrectly released actual sponsored value: %v", err)
	}
	releaseEvidence := []string{digest("d")}
	record, err = journal.ReleaseSponsorshipExposure(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, releaseEvidence, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ReleaseSponsorshipExposure(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision-1, releaseEvidence, fixture.now); err != nil {
		t.Fatalf("exact accounting release retry was not idempotent: %v", err)
	}
	if _, err := journal.ReleaseSponsorshipExposure(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, []string{digest("e")}, fixture.now); !errors.Is(err, ErrRelayConflict) {
		t.Fatalf("conflicting accounting release evidence was accepted: %v", err)
	}
	if _, created, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); err != nil || !created {
		t.Fatalf("verified accounting release did not replenish exposure: created=%v err=%v", created, err)
	}
}

func TestSponsorshipAttemptCheckpointRequiresExactProtectedTokenAndCannotTransition(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "50", "50")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, quote := sponsorshipQuotePair(t, fixture, profile, "request:attempt-token", "quote:attempt-token", "50",
		fixture.now.Add(4*time.Minute))
	execution := sponsorshipExecution(fixture.execution, request, quote)
	execution = fixture.withAdmission(t, execution)
	journal := NewMemoryJournal()
	if _, _, err := journal.ReserveQuote(profile, request, quote, fixture.now); err != nil {
		t.Fatal(err)
	}
	record, _, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	recovery := sponsorshipRecoveryHandle(execution, "protected-ambiguous-payment-token")
	token := recovery.OpaqueToken
	record, err = journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		recovery, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision-1,
		recovery, fixture.now); err != nil {
		t.Fatalf("exact BeginSponsorship retry was not idempotent: %v", err)
	}
	if _, err := journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		sponsorshipRecoveryHandle(execution, "different-token"), fixture.now); !errors.Is(err, ErrRelayConflict) {
		t.Fatalf("recovery token substitution was accepted: %v", err)
	}
	if _, err := journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionRejected, "", nil, "", fixture.now); !errors.Is(err, ErrRelayInvalidState) {
		t.Fatalf("ambiguous sponsorship attempt transitioned to a releasable state: %v", err)
	}
	if _, err := RestoreRecord(record.Snapshot(), execution); err == nil {
		t.Fatal("attempted sponsorship restored without its protected recovery token")
	}
	if _, err := RestoreRecord(record.Snapshot(), execution, []byte("different-token")); err == nil {
		t.Fatal("attempted sponsorship restored with a substituted recovery token")
	}
	restored, err := RestoreRecord(record.Snapshot(), execution, token)
	if err != nil || !restored.SponsorshipAttempted || string(restored.SponsorshipRecoveryToken()) != string(token) {
		t.Fatalf("attempted sponsorship did not restore exactly: %v", err)
	}
}

func TestRelayRejectedAndConflictRecordsReleaseExposure(t *testing.T) {
	for _, target := range []agentcommerce.ActionResolutionState{agentcommerce.ActionRejected, agentcommerce.ActionConflict} {
		t.Run(string(target), func(t *testing.T) {
			fixture := newRelayFixture(t)
			profile := sponsorshipProfile(fixture.profile, "50", "50")
			requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:release:a", "quote:release:a", "50",
				fixture.now.Add(4*time.Minute))
			requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:release:b", "quote:release:b", "50",
				fixture.now.Add(4*time.Minute))
			journal := NewMemoryJournal()
			if _, _, err := journal.ReserveQuote(profile, requestA, quoteA, fixture.now); err != nil {
				t.Fatal(err)
			}
			execution := fixture.withAdmission(t, sponsorshipExecution(fixture.execution, requestA, quoteA))
			record, _, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
				target, "", nil, "", fixture.now); err != nil {
				t.Fatal(err)
			}
			if _, created, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); err != nil || !created {
				t.Fatalf("%s did not release sponsorship exposure: created=%v err=%v", target, created, err)
			}
		})
	}
}

func TestProviderQuoteCannotRewriteFinalityDescriptor(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	quote.Body.RelayFinalityProfile.MinimumObservers++
	quote.PublicKey, quote.Signature = "", ""
	quote, err = SignProviderRelayQuote(quote.Body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProviderRelayQuote(quote, fixture.request, fixture.profile, fixture.resolver, fixture.now); err == nil {
		t.Fatal("provider changed the selected finality descriptor while retaining its URI and digest")
	}
}

func TestRelayRemainingValidityUsesCurrentTimeAndFailsClosedAtBoundaries(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	if err := VerifyRelayRemainingValidity(fixture.execution, fixture.now.Add(119*time.Second), SideEffectBroadcast); err != nil {
		t.Fatalf("request with more than the required window was rejected: %v", err)
	}
	if err := VerifyRelayRemainingValidity(fixture.execution, fixture.now.Add(120*time.Second), SideEffectBroadcast); err == nil {
		t.Fatal("request at the exact finality-plus-inclusion boundary was accepted")
	}
	if hasStrictRemainingWindow(^uint64(0)-10, ^uint64(0), 30) {
		t.Fatal("remaining-validity arithmetic wrapped near uint64 maximum")
	}
	if !hasStrictRemainingWindow(^uint64(0)-31, ^uint64(0), 30) {
		t.Fatal("checked remaining-validity arithmetic rejected a valid near-maximum window")
	}
}

func TestProviderServiceDoesNotBroadcastWithoutFullRemainingWindow(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted}}
	fixture.service.Broadcaster = broadcaster
	fixture.service.Now = func() time.Time { return fixture.now.Add(120 * time.Second) }
	if _, err := fixture.service.Submit(context.Background(), fixture.execution, agreement); err == nil {
		t.Fatal("near-expiry relay execution reached the broadcaster")
	}
	if broadcaster.submits != 0 {
		t.Fatalf("near-expiry relay execution made %d network writes", broadcaster.submits)
	}
}

func TestProviderServiceDoesNotSponsorWithoutFullRemainingWindow(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	request, proposed := sponsorshipQuotePair(t, fixture, profile, "request:sponsor-window", "quote:sponsor-window", "60",
		fixture.now.Add(4*time.Minute))
	processor := &recordingSponsorship{}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := sponsorshipExecution(fixture.execution, request, quote)
	execution = fixture.withAdmission(t, execution)
	agreement := sponsorshipAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	fixture.service.Now = func() time.Time { return fixture.now.Add(120 * time.Second) }
	if _, err := fixture.service.Submit(context.Background(), execution, agreement); err == nil {
		t.Fatal("near-expiry sponsorship reached the payment processor")
	}
	if processor.calls != 0 {
		t.Fatalf("near-expiry sponsorship made %d payment attempts", processor.calls)
	}
}

func TestProviderServiceDoesNotRebroadcastWithoutFullRemainingWindow(t *testing.T) {
	fixture := newRelayFixture(t)
	clock := fixture.now
	fixture.service.Now = func() time.Time { return clock }
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastUnknown}, submitErr: errors.New("response lost")}
	fixture.service.Broadcaster = broadcaster
	record, err := fixture.service.Submit(context.Background(), fixture.execution, agreement)
	if err == nil || record.State != agentcommerce.ActionSubmitted || broadcaster.submits != 1 {
		t.Fatalf("ambiguous initial submission was not frozen: state=%s submits=%d err=%v", record.State, broadcaster.submits, err)
	}
	clock = fixture.now.Add(120 * time.Second)
	broadcaster.submitErr = nil
	broadcaster.result = BroadcastResult{Status: BroadcastAccepted, TransactionReference: "tx:late"}
	broadcaster.resolution = ChainResolution{SafeToRebroadcastExact: true}
	if _, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest); err == nil {
		t.Fatal("near-expiry action was safely rebroadcast")
	}
	if broadcaster.submits != 1 {
		t.Fatalf("near-expiry recovery made %d total writes", broadcaster.submits)
	}
}

func TestRelayAdmissionPreflightRejectsUnexpiredSupersededWriter(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	fixture.execution.AdmissionReceipt = SignedRelaySideEffectAdmissionReceipt{}
	fixture.resolver.supersedeAt(1, fixture.takeoverFence(t))
	if err := VerifyRelayExecutionRequestForAdmission(t.Context(), fixture.execution, fixture.profile,
		fixture.resolver, fixture.resolver, fixture.inspector, fixture.now); err == nil {
		t.Fatal("an unexpired but superseded writer passed receipt preflight")
	}
}

func TestProviderFirstAdmissionRequiresCurrentAuthoritativeReceiptAndStoredRetryDoesNot(t *testing.T) {
	prepare := func(t *testing.T) (*relayFixture, agentcommerce.AgentAgreement, *recordingBroadcaster) {
		t.Helper()
		fixture := newRelayFixture(t)
		quote, err := fixture.service.Quote(t.Context(), fixture.request)
		if err != nil {
			t.Fatal(err)
		}
		fixture.execution.ProviderQuote = quote
		agreement := fixture.agreement(t, quote)
		fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
		fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
		fixture.execution = fixture.withAdmission(t, fixture.execution)
		broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
			TransactionReference: "tx:authoritative"}}
		fixture.service.Broadcaster = broadcaster
		return fixture, agreement, broadcaster
	}

	t.Run("revoked or unavailable", func(t *testing.T) {
		fixture, agreement, broadcaster := prepare(t)
		fixture.admissionAuthority.err = ErrRelayUnknown
		if _, err := fixture.service.Submit(t.Context(), fixture.execution, agreement); err == nil {
			t.Fatal("locally valid but no-longer-authoritative receipt was admitted")
		}
		if broadcaster.submits != 0 {
			t.Fatal("receipt revocation was discovered after the side effect")
		}
		if _, err := fixture.service.Journal.Resolve(fixture.execution.AuthorizedAction.StableActionID,
			fixture.execution.AuthorizedAction.ExactRequestDigest); !errors.Is(err, ErrRelayUnknown) {
			t.Fatalf("revoked receipt created a local admission: %v", err)
		}
	})

	t.Run("rollback or backdated answer", func(t *testing.T) {
		fixture, agreement, broadcaster := prepare(t)
		descriptor, err := buildRelaySideEffectAdmissionDescriptorForRoute(fixture.execution,
			fixture.execution.AdmissionReceipt.Body.AuthenticatedPrincipal,
			fixture.execution.AdmissionReceipt.Body.RouteAttempt,
			fixture.execution.AdmissionReceipt.Body.PredecessorReceiptDigest)
		if err != nil {
			t.Fatal(err)
		}
		lookupDigest, _ := RelaySideEffectAdmissionLookupDigest(descriptor.Lookup())
		olderBody := fixture.execution.AdmissionReceipt.Body
		olderBody.IssuedAtUnix--
		older, err := signTestReceipt(olderBody, fixture.authorityKey)
		if err != nil {
			t.Fatal(err)
		}
		fixture.admissionAuthority.mu.Lock()
		fixture.admissionAuthority.receipts[lookupDigest] = older
		fixture.admissionAuthority.mu.Unlock()
		if _, err := fixture.service.Submit(t.Context(), fixture.execution, agreement); err == nil {
			t.Fatal("rollback-conflicting authoritative receipt was admitted")
		}
		if broadcaster.submits != 0 {
			t.Fatal("rollback conflict was discovered after the side effect")
		}
	})

	t.Run("byte-identical stored retry", func(t *testing.T) {
		fixture, agreement, broadcaster := prepare(t)
		broadcaster.result = BroadcastResult{Status: BroadcastUnknown}
		broadcaster.submitErr = errors.New("ambiguous transport close")
		first, err := fixture.service.Submit(t.Context(), fixture.execution, agreement)
		if err == nil || first.State != agentcommerce.ActionSubmitted || broadcaster.submits != 1 {
			t.Fatalf("first ambiguous admission was not persisted: state=%s submits=%d err=%v",
				first.State, broadcaster.submits, err)
		}
		fixture.admissionAuthority.err = errors.New("authority temporarily unavailable")
		retried, err := fixture.service.Submit(t.Context(), fixture.execution, agreement)
		if err != nil || retried.State != agentcommerce.ActionSubmitted || broadcaster.submits != 1 {
			t.Fatalf("stored byte-identical retry depended on remote lookup or rewrote bytes: state=%s submits=%d err=%v",
				retried.State, broadcaster.submits, err)
		}
		mutated := fixture.execution
		mutated.AdmissionReceipt.Signature = fixture.request.Signature
		if _, err := fixture.service.Submit(t.Context(), mutated, agreement); !errors.Is(err, ErrRelayConflict) {
			t.Fatalf("stored retry accepted a different signed receipt wrapper: %v", err)
		}
	})
}

func TestProviderDrainsAdmittedBroadcastAfterWriterTakeover(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:must-not-submit"}}
	fixture.service.Broadcaster = broadcaster

	// Receipt issuance happened while generation 1 was current. A later takeover
	// cannot cancel the exact broadcast stage already frozen in that receipt.
	fixture.resolver.current.fence = fixture.takeoverFence(t)
	record, err := fixture.service.Submit(context.Background(), fixture.execution, agreement)
	if err != nil || record.State != agentcommerce.ActionAccepted || broadcaster.submits != 1 {
		t.Fatalf("takeover cancelled an already-admitted broadcast: state=%s submits=%d err=%v",
			record.State, broadcaster.submits, err)
	}
}

func TestProviderResolvesActionAuthorityAtReceiptIssuanceAfterKeyRotationAndTakeover(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	newAuthorityKey := relayAuthorityKey("rotated-authority")
	rotating := &rotatingFenceResolver{base: fixture.resolver,
		oldKey: fixture.authorityKey.publicKey(),
		newKey: newAuthorityKey.publicKey(), rotatesAt: fixture.now.Add(time.Second)}
	fixture.service.FenceResolver = rotating
	fixture.service.Now = func() time.Time { return fixture.now.Add(2 * time.Second) }
	fixture.service.Broadcaster = &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:historically-authorized"}}
	fixture.resolver.current.fence = fixture.takeoverFence(t)
	record, err := fixture.service.Submit(context.Background(), fixture.execution, agreement)
	if err != nil || record.State != agentcommerce.ActionAccepted {
		t.Fatalf("historically authorized admitted action did not drain: state=%s err=%v", record.State, err)
	}
	times := rotating.observedTimes()
	if len(times) < 2 {
		t.Fatalf("action and fence keys were not both resolved: %d calls", len(times))
	}
	issuedAt := time.Unix(int64(fixture.execution.AdmissionReceipt.Body.IssuedAtUnix), 0).UTC()
	for _, observed := range times {
		if !observed.Equal(issuedAt) {
			t.Fatalf("authority key was resolved at %s instead of receipt issuance %s", observed, issuedAt)
		}
	}
}

func TestProviderRechecksReceiptStartWindowImmediatelyBeforeFirstAdmit(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	boundary := time.Unix(int64(fixture.execution.AdmissionReceipt.Body.StartNotAfterUnix), 0).UTC()
	calls := 0
	fixture.service.Now = func() time.Time {
		calls++
		if calls == 1 {
			return fixture.now
		}
		return boundary
	}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:must-not-send"}}
	fixture.service.Broadcaster = broadcaster
	if _, err := fixture.service.Submit(context.Background(), fixture.execution, agreement); err == nil {
		t.Fatal("receipt that expired during validation reached durable admission")
	}
	if broadcaster.submits != 0 {
		t.Fatal("receipt that expired before admission reached the network sink")
	}
	if _, err := fixture.service.Journal.Resolve(fixture.execution.AuthorizedAction.StableActionID,
		fixture.execution.AuthorizedAction.ExactRequestDigest); !errors.Is(err, ErrRelayUnknown) {
		t.Fatalf("late receipt created a durable Provider record: %v", err)
	}
}

func TestProviderDrainsAdmittedSponsorshipAfterWriterTakeover(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	request, proposed := sponsorshipQuotePair(t, fixture, profile, "request:stale-sponsor",
		"quote:stale-sponsor", "60", fixture.now.Add(4*time.Minute))
	processor := &recordingSponsorship{}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := sponsorshipExecution(fixture.execution, request, quote)
	agreement := sponsorshipAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)

	fixture.resolver.current.fence = fixture.takeoverFence(t)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionTerminal || record.SponsorshipAttempted ||
		processor.prepareCalls != 1 || processor.calls != 1 {
		t.Fatalf("takeover cancelled an admitted sponsorship: state=%s attempted=%v prepares=%d payments=%d err=%v",
			record.State, record.SponsorshipAttempted, processor.prepareCalls, processor.calls, err)
	}
}

func TestProviderDrainsAdmittedSafeExactRebroadcastAfterWriterTakeover(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastUnknown},
		submitErr: errors.New("response lost")}
	fixture.service.Broadcaster = broadcaster
	record, err := fixture.service.Submit(context.Background(), fixture.execution, agreement)
	if err == nil || record.State != agentcommerce.ActionSubmitted || broadcaster.submits != 1 {
		t.Fatalf("initial ambiguous write was not frozen: state=%s submits=%d err=%v",
			record.State, broadcaster.submits, err)
	}

	broadcaster.submitErr = nil
	broadcaster.result = BroadcastResult{Status: BroadcastAccepted, TransactionReference: "tx:must-not-rebroadcast"}
	broadcaster.resolution = ChainResolution{SafeToRebroadcastExact: true}
	fixture.resolver.current.fence = fixture.takeoverFence(t)
	accepted, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || accepted.State != agentcommerce.ActionAccepted || broadcaster.submits != 2 {
		t.Fatalf("takeover cancelled an admitted exact rebroadcast: state=%s submits=%d err=%v",
			accepted.State, broadcaster.submits, err)
	}
}

func TestFinalizedSponsorshipThenInsufficientRelayWindowBecomesDurablePartialTerminal(t *testing.T) {
	fixture := newRelayFixture(t)
	clock := fixture.now
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	request, proposed := combinedQuotePair(t, fixture, profile, "request:combined-window", "quote:combined-window", "60")
	processor := &recordingSponsorship{after: func() { clock = fixture.now.Add(130 * time.Second) }}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted}}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	fixture.service.Now = func() time.Time { return clock }
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err == nil || record.State != agentcommerce.ActionTerminal ||
		record.TerminalOutcome != OutcomeFinalizedSponsorshipOnly || record.SponsorshipTransferReference != "sponsorship:final" {
		t.Fatalf("partial sponsorship outcome was not terminalized: state=%s outcome=%s reference=%q err=%v",
			record.State, record.TerminalOutcome, record.SponsorshipTransferReference, err)
	}
	if processor.calls != 1 || broadcaster.submits != 0 || record.SponsorshipAttempted {
		t.Fatalf("partial terminal side effects are wrong: sponsor_calls=%d broadcasts=%d attempted=%v",
			processor.calls, broadcaster.submits, record.SponsorshipAttempted)
	}
	resolved, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || resolved.SponsorshipTransferReference != record.SponsorshipTransferReference {
		t.Fatalf("failover could not recover partial sponsorship: %v", err)
	}
	retried, submitErr := fixture.service.Submit(context.Background(), execution, agreement)
	if submitErr != nil || retried.State != agentcommerce.ActionTerminal ||
		retried.TerminalOutcome != OutcomeFinalizedSponsorshipOnly {
		t.Fatalf("expired exact Submit retry did not return its durable terminal record: state=%s outcome=%s err=%v",
			retried.State, retried.TerminalOutcome, submitErr)
	}
	if processor.calls != 1 {
		t.Fatalf("partial terminal exact retry duplicated sponsorship: calls=%d", processor.calls)
	}
	requestB, quoteB := combinedQuotePair(t, fixture, profile, "request:combined-window:b", "quote:combined-window:b", "60")
	if _, _, err := fixture.service.Journal.ReserveQuote(profile, requestB, quoteB, clock); !errors.Is(err, ErrRelayExposure) {
		t.Fatalf("partial terminal incorrectly released provider exposure: %v", err)
	}
}

func TestFinalizedSponsorshipThenSourceInvalidationNeverBroadcastsOrRepeatsPayment(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	request, proposed := combinedQuotePair(t, fixture, profile, "request:combined-invalidated", "quote:combined-invalidated", "60")
	invalidated := fixture.inspector.inspected
	invalidated.SourceSequence++
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Inspector = phaseInspector{admission: fixture.inspector.inspected, ready: invalidated}
	processor := &recordingSponsorship{}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted}}
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err == nil || record.State != agentcommerce.ActionTerminal || record.TerminalOutcome != OutcomeFinalizedSponsorshipOnly {
		t.Fatalf("invalidated source did not become a partial terminal: state=%s outcome=%s err=%v",
			record.State, record.TerminalOutcome, err)
	}
	if processor.calls != 1 || broadcaster.submits != 0 {
		t.Fatalf("invalidated source side effects are wrong: sponsor_calls=%d broadcasts=%d", processor.calls, broadcaster.submits)
	}
	retry, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || retry.State != agentcommerce.ActionTerminal || processor.calls != 1 || broadcaster.submits != 0 {
		t.Fatalf("partial terminal retry was not idempotent: state=%s sponsor_calls=%d broadcasts=%d err=%v",
			retry.State, processor.calls, broadcaster.submits, err)
	}
}

func TestCombinedUnauthenticatedBroadcastRejectionRemainsAmbiguous(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	request, proposed := combinedQuotePair(t, fixture, profile, "request:combined-rejected", "quote:combined-rejected", "60")
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	processor := &recordingSponsorship{}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastStatus("rejected"),
		TransactionReference: "rpc:rejected"}}
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err == nil || record.State != agentcommerce.ActionSubmitted || record.TerminalOutcome != "" ||
		record.TransactionReference != "" || record.SponsorshipTransferReference != "sponsorship:final" {
		t.Fatalf("unauthenticated rejection resolved an ambiguous write: state=%s outcome=%s txref=%q sponsorref=%q err=%v",
			record.State, record.TerminalOutcome, record.TransactionReference, record.SponsorshipTransferReference, err)
	}
	if processor.calls != 1 || broadcaster.submits != 1 {
		t.Fatalf("combined rejection side effects are wrong: sponsor_calls=%d broadcasts=%d", processor.calls, broadcaster.submits)
	}
	for _, unsafeState := range []agentcommerce.ActionResolutionState{
		agentcommerce.ActionRejected, agentcommerce.ActionConflict,
	} {
		broadcaster.resolution = ChainResolution{State: unsafeState}
		if _, err := fixture.service.Resolve(t.Context(), record.StableActionID, record.ExactRequestDigest); err == nil {
			t.Fatalf("post-submit %s terminalized an ambiguous combined relay", unsafeState)
		}
		stored, resolveErr := fixture.service.Journal.Resolve(record.StableActionID, record.ExactRequestDigest)
		if resolveErr != nil || stored.State != agentcommerce.ActionSubmitted || stored.TerminalOutcome != "" ||
			stored.SponsorshipTransferReference != "sponsorship:final" {
			t.Fatalf("post-submit %s released or rewrote the combined action: %+v err=%v",
				unsafeState, stored, resolveErr)
		}
	}
}

func TestCombinedFinalizedAbsenceNeverBroadcasts(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	request, proposed := combinedQuotePair(t, fixture, profile, "request:combined-absence", "quote:combined-absence", "60")
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	processor := &recordingSponsorship{resolveAbsent: true}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted}}
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err == nil || record.State != agentcommerce.ActionPrepared || record.TerminalOutcome != "" ||
		record.SponsorshipTransferReference != "" {
		t.Fatalf("premature no-credit proof was accepted: state=%s outcome=%s err=%v",
			record.State, record.TerminalOutcome, err)
	}
	fixture.service.Now = func() time.Time { return fixture.now.Add(11 * time.Minute) }
	record, err = fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || record.State != agentcommerce.ActionTerminal ||
		record.TerminalOutcome != OutcomeFinalizedAbsent || record.SponsorshipTransferReference != "" {
		t.Fatalf("combined no-credit outcome was not terminalized exactly: state=%s outcome=%s err=%v",
			record.State, record.TerminalOutcome, err)
	}
	if processor.calls != 1 || broadcaster.submits != 0 {
		t.Fatalf("combined no-credit outcome made wrong side effects: sponsorship=%d broadcasts=%d",
			processor.calls, broadcaster.submits)
	}
}

func TestObservedUnprovenCombinedRelaySurvivesCrashAndWaitsForTopUpFinality(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, proposed := combinedQuotePair(t, fixture, profile, "request:combined-observed", "quote:combined-observed", "60")
	processor := &recordingSponsorship{observed: true}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:client"}}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionAccepted || !record.SponsorshipAttempted ||
		record.SponsorshipCreditObservation == nil || record.SponsorshipTransferReference != "" || broadcaster.submits != 1 {
		t.Fatalf("observed sponsorship did not gate one exact relay: state=%s attempted=%v sponsorref=%q submits=%d err=%v",
			record.State, record.SponsorshipAttempted, record.SponsorshipTransferReference, broadcaster.submits, err)
	}
	signed, err := fixture.service.SignedResolution(record)
	if err != nil || signed.Body.SponsorshipStatus != SponsorshipResolutionObservedUnproven ||
		!digestPattern.MatchString(signed.Body.SponsorshipObservationDigest) {
		t.Fatalf("signed resolution hid nonterminal sponsorship observation: %+v err=%v", signed.Body, err)
	}
	if err := VerifyRelayResolutionForExecution(signed, execution, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("signed observed-unproven resolution was unverifiable: %v", err)
	}
	preparedBody := signed.Body
	preparedBody.State = agentcommerce.ActionPrepared
	prepared, err := SignRelayResolution(preparedBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolutionForExecution(prepared, execution, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("safe prepared observed-unproven resolution was unverifiable: %v", err)
	}
	restored, err := RestoreRecord(record.Snapshot(), execution, record.SponsorshipRecoveryToken())
	if err != nil || restored.SponsorshipCreditObservation == nil || !restored.SponsorshipAttempted {
		t.Fatalf("observed sponsorship did not survive protected journal restore: attempted=%v err=%v",
			restored.SponsorshipAttempted, err)
	}
	journal := NewMemoryJournal()
	journal.records[relayRecordKey(restored.StableActionID)] = restored
	fixture.service.Journal = journal
	broadcaster.resolution = ChainResolution{State: agentcommerce.ActionTerminal,
		TransactionReference: "tx:client", EvidenceRefs: []string{digest("4"), digest("5"), digest("6")},
		TerminalOutcome: OutcomeFinalizedSuccess}
	stillOpen, err := fixture.service.Resolve(context.Background(), restored.StableActionID, restored.ExactRequestDigest)
	if err != nil || stillOpen.State != agentcommerce.ActionAccepted || !stillOpen.SponsorshipAttempted ||
		stillOpen.TerminalOutcome != "" {
		t.Fatalf("client finality prematurely terminalized unproven sponsorship: state=%s outcome=%s attempted=%v err=%v",
			stillOpen.State, stillOpen.TerminalOutcome, stillOpen.SponsorshipAttempted, err)
	}
	processor.resolveFinalized = true
	processor.resolveCorroborated = true
	terminal, err := fixture.service.Resolve(context.Background(), restored.StableActionID, restored.ExactRequestDigest)
	if err != nil || terminal.State != agentcommerce.ActionTerminal || terminal.SponsorshipAttempted ||
		terminal.SponsorshipTransactionEvidence == nil ||
		terminal.TerminalOutcome != OutcomeCorroboratedSuccess {
		t.Fatalf("dual finality did not close combined action: state=%s outcome=%s attempted=%v err=%v",
			terminal.State, terminal.TerminalOutcome, terminal.SponsorshipAttempted, err)
	}
}

func TestObservedUnprovenCreditCanBeSupersededByExactDualAbsence(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, proposed := combinedQuotePair(t, fixture, profile, "request:observed-reorg",
		"quote:observed-reorg", "60")
	processor := &recordingSponsorship{observed: true}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:client-before-reorg"}}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionAccepted || record.SponsorshipCreditObservation == nil {
		t.Fatalf("expected nonterminal observed top-up before reorg: state=%s err=%v", record.State, err)
	}
	observationDigest, err := RelaySponsorshipCreditObservationDigest(*record.SponsorshipCreditObservation)
	if err != nil {
		t.Fatal(err)
	}

	processor.resolveAbsent = true
	fixture.service.Now = func() time.Time { return fixture.now.Add(11 * time.Minute) }
	terminal, err := fixture.service.Resolve(context.Background(), record.StableActionID,
		record.ExactRequestDigest)
	if err != nil || terminal.State != agentcommerce.ActionTerminal ||
		terminal.TerminalOutcome != OutcomeCorroboratedAbsent || terminal.SponsorshipAttempted ||
		terminal.SponsorshipCreditObservation != nil ||
		terminal.SupersededSponsorshipCreditObservationDigest != observationDigest ||
		len(terminal.SponsorshipAbsenceObservations) == 0 || len(terminal.TransactionAbsenceObservations) == 0 {
		t.Fatalf("dual absence did not supersede reorged observation: state=%s outcome=%s archive=%q err=%v",
			terminal.State, terminal.TerminalOutcome,
			terminal.SupersededSponsorshipCreditObservationDigest, err)
	}
	restored, err := RestoreRecord(terminal.Snapshot(), execution)
	if err != nil || restored.SupersededSponsorshipCreditObservationDigest != observationDigest ||
		restored.SponsorshipCreditObservation != nil || !validSponsorshipAbsenceRecord(restored) {
		t.Fatalf("superseded observation or terminal absence was lost on restart: %+v err=%v", restored, err)
	}
}

func TestPendingSponsorshipAbsencePromotesAfterRestartWithoutSecondTopUp(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, proposed := combinedQuotePair(t, fixture, profile, "request:component-promotion",
		"quote:component-promotion", "60")
	processor := &recordingSponsorship{observed: true}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:client-before-sponsor-reorg"}}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionAccepted || processor.prepareCalls != 1 ||
		processor.calls != 1 || broadcaster.submits != 1 || record.SponsorshipCreditObservation == nil {
		t.Fatalf("initial observed top-up/relay attempt is wrong: state=%s prepare=%d ensure=%d submit=%d err=%v",
			record.State, processor.prepareCalls, processor.calls, broadcaster.submits, err)
	}

	// The lower-assurance credit later disappears. The sponsorship processor
	// commits one immutable component tombstone, while the relay journal keeps
	// the protected recovery material solely for later dual aggregation.
	processor.resolveComponentAbsent = true
	fixture.service.Now = func() time.Time { return fixture.now.Add(11 * time.Minute) }
	pending, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || pending.State != agentcommerce.ActionAccepted || pending.TerminalOutcome != "" ||
		len(pending.SponsorshipAbsenceObservations) == 0 || len(pending.TransactionAbsenceObservations) != 0 ||
		!pending.SponsorshipAttempted || len(pending.SponsorshipRecoveryToken()) == 0 {
		t.Fatalf("sponsorship component was not durably checkpointed: state=%s outcome=%s attempted=%v err=%v",
			pending.State, pending.TerminalOutcome, pending.SponsorshipAttempted, err)
	}
	priorRefs := append([]RelayAbsenceObservationReference(nil), pending.SponsorshipAbsenceObservations...)
	priorDigest := pending.AbsenceProofBundleDigest
	priorBundle := append([]byte(nil), pending.AbsenceProofBundle...)
	recoveryToken := pending.SponsorshipRecoveryToken()

	// Simulate a process/config restart. Restore must require the exact protected
	// token even though that token can never authorize another top-up.
	if _, err := RestoreRecord(pending.Snapshot(), execution); err == nil {
		t.Fatal("pending sponsorship component restored without its protected snapshot handle")
	}
	restored, err := RestoreRecord(pending.Snapshot(), execution, recoveryToken)
	if err != nil || !restored.SponsorshipAttempted ||
		!bytes.Equal(restored.SponsorshipRecoveryToken(), recoveryToken) {
		t.Fatalf("pending sponsorship component did not survive protected restart: %+v err=%v", restored, err)
	}
	restartedJournal := NewMemoryJournal()
	restartedJournal.records[relayRecordKey(restored.StableActionID)] = restored
	fixture.service.Journal = restartedJournal
	broadcaster.resolution = ChainResolution{State: agentcommerce.ActionTerminal,
		TerminalOutcome: OutcomeCorroboratedAbsent}

	// A substituted sponsorship component must fail before journal mutation.
	processor.dualSubstituteSponsor = true
	if _, err := fixture.service.Resolve(context.Background(), restored.StableActionID,
		restored.ExactRequestDigest); err == nil {
		t.Fatal("dual aggregation accepted substituted sponsorship observations")
	}
	stillPending, err := restartedJournal.Resolve(restored.StableActionID, restored.ExactRequestDigest)
	if err != nil || stillPending.TerminalOutcome != "" ||
		stillPending.AbsenceProofBundleDigest != priorDigest {
		t.Fatalf("failed promotion changed the pending component: %+v err=%v", stillPending, err)
	}

	processor.dualSubstituteSponsor = false
	terminal, err := fixture.service.Resolve(context.Background(), restored.StableActionID,
		restored.ExactRequestDigest)
	if err != nil || terminal.State != agentcommerce.ActionTerminal ||
		terminal.TerminalOutcome != OutcomeCorroboratedAbsent || terminal.SponsorshipAttempted ||
		len(terminal.SponsorshipRecoveryToken()) != 0 ||
		terminal.SupersededAbsenceProofBundleDigest != priorDigest ||
		!equalStrings(relayAbsenceObservationReferenceDigests(priorRefs),
			relayAbsenceObservationReferenceDigests(terminal.SponsorshipAbsenceObservations)) ||
		len(terminal.TransactionAbsenceObservations) == 0 {
		t.Fatalf("pending component did not promote monotonically: %+v err=%v", terminal, err)
	}
	if processor.dualCalls != 2 || processor.prepareCalls != 1 || processor.calls != 1 ||
		processor.resolveCalls != 1 || broadcaster.submits != 1 ||
		processor.dualRecovery.StableActionID != restored.SponsorshipStableActionID ||
		processor.dualPriorBundleDigest != priorDigest ||
		!bytes.Equal(processor.dualPriorBundle, priorBundle) {
		t.Fatalf("promotion did not reuse exact recovery/component inputs: dual=%d prepare=%d ensure=%d resolve=%d submit=%d",
			processor.dualCalls, processor.prepareCalls, processor.calls, processor.resolveCalls, broadcaster.submits)
	}
	if retried, retryErr := fixture.service.Submit(context.Background(), execution, agreement); retryErr != nil ||
		retried.State != agentcommerce.ActionTerminal || processor.prepareCalls != 1 || processor.calls != 1 ||
		broadcaster.submits != 1 {
		t.Fatalf("terminal retry created a successor: state=%s prepare=%d ensure=%d submit=%d err=%v",
			retried.State, processor.prepareCalls, processor.calls, broadcaster.submits, retryErr)
	}
	if _, err := restartedJournal.RecordSponsorship(terminal.StableActionID, terminal.ExactRequestDigest,
		terminal.StateRevision, sponsorshipTransactionEvidence(execution, processor.dualRecovery,
			fixture.now.Add(12*time.Minute)), fixture.now.Add(12*time.Minute)); !errors.Is(err, ErrRelayInvalidState) {
		t.Fatalf("terminal dual absence admitted a sponsorship successor: %v", err)
	}
}

func TestSuccessfulSponsorshipRetainsFrozenHandleForTransactionAbsenceAfterRestart(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, proposed := combinedQuotePair(t, fixture, profile, "request:transaction-component",
		"quote:transaction-component", "60")
	processor := &recordingSponsorship{resolveCorroborated: true}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:client-pending"}}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	fixture.service.Broadcaster = broadcaster
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionAccepted || record.SponsorshipTransferReference == "" ||
		!record.SponsorshipAttempted || len(record.SponsorshipRecoveryToken()) == 0 ||
		processor.prepareCalls != 1 || processor.calls != 1 || broadcaster.submits != 1 {
		t.Fatalf("combined sponsorship success did not retain one query-only recovery handle: %+v err=%v",
			record, err)
	}
	token := record.SponsorshipRecoveryToken()
	if _, err := RestoreRecord(record.Snapshot(), execution); err == nil {
		t.Fatal("combined S+ restart accepted a missing protected snapshot handle")
	}
	missingFence := record.Snapshot()
	missingFence.SponsorshipAttempted = false
	missingFence.SponsorshipRecoveryTokenDigest = ""
	if _, err := RestoreRecord(missingFence, execution); err == nil {
		t.Fatal("combined S+ restart accepted a cleared no-successor/recovery fence")
	}
	restored, err := RestoreRecord(record.Snapshot(), execution, token)
	if err != nil || !restored.SponsorshipAttempted || !bytes.Equal(restored.SponsorshipRecoveryToken(), token) {
		t.Fatalf("combined S+ recovery handle did not survive restart/config rotation: %+v err=%v", restored, err)
	}
	restartedJournal := NewMemoryJournal()
	restartedJournal.records[relayRecordKey(restored.StableActionID)] = restored
	fixture.service.Journal = restartedJournal
	fixture.service.Now = func() time.Time { return fixture.now.Add(11 * time.Minute) }
	broadcaster.resolution = ChainResolution{State: agentcommerce.ActionTerminal,
		TerminalOutcome: OutcomeCorroboratedAbsent}

	processor.transactionComponentSubstitute = true
	if _, err := fixture.service.Resolve(context.Background(), restored.StableActionID,
		restored.ExactRequestDigest); err == nil {
		t.Fatal("transaction-component producer substituted the relay conclusion")
	}
	unchanged, err := restartedJournal.Resolve(restored.StableActionID, restored.ExactRequestDigest)
	if err != nil || unchanged.State != agentcommerce.ActionAccepted || !unchanged.SponsorshipAttempted ||
		len(unchanged.TransactionAbsenceObservations) != 0 {
		t.Fatalf("malformed transaction component changed durable state: %+v err=%v", unchanged, err)
	}

	processor.transactionComponentSubstitute = false
	terminal, err := fixture.service.Resolve(context.Background(), restored.StableActionID,
		restored.ExactRequestDigest)
	if err != nil || terminal.State != agentcommerce.ActionTerminal ||
		terminal.TerminalOutcome != OutcomeCorroboratedSponsorshipOnly || terminal.SponsorshipAttempted ||
		len(terminal.SponsorshipRecoveryToken()) != 0 || terminal.SponsorshipTransferReference == "" ||
		len(terminal.TransactionAbsenceObservations) == 0 || len(terminal.SponsorshipAbsenceObservations) != 0 ||
		terminal.AbsenceProofBundleDigest == "" {
		t.Fatalf("S+/R- did not become exact sponsorship-only terminal state: %+v err=%v", terminal, err)
	}
	if processor.transactionComponentCalls != 2 || processor.prepareCalls != 1 || processor.calls != 1 ||
		broadcaster.submits != 1 ||
		!bytes.Equal(processor.transactionComponentRecovery.OpaqueToken, token) {
		t.Fatalf("S+/R- recovery duplicated a side effect or lost its frozen handle: component=%d prepare=%d ensure=%d submit=%d",
			processor.transactionComponentCalls, processor.prepareCalls, processor.calls, broadcaster.submits)
	}
	replayed, err := RestoreRecord(terminal.Snapshot(), execution)
	if err != nil || replayed.TerminalOutcome != OutcomeCorroboratedSponsorshipOnly ||
		len(replayed.TransactionAbsenceObservations) == 0 || replayed.SponsorshipAttempted {
		t.Fatalf("S+/R- terminal proof did not survive restart: %+v err=%v", replayed, err)
	}
	if retry, retryErr := fixture.service.Submit(context.Background(), execution, agreement); retryErr != nil ||
		retry.State != agentcommerce.ActionTerminal || processor.prepareCalls != 1 || processor.calls != 1 ||
		broadcaster.submits != 1 {
		t.Fatalf("S+/R- retry created a second side effect: %+v err=%v", retry, retryErr)
	}
}

func TestCombinedJournalRestoresAllFourTerminalQuadrants(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "100", "1000")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, quote := combinedQuotePair(t, fixture, profile, "request:four-quadrants",
		"quote:four-quadrants", "10")
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	terminalAt := fixture.now.Add(11 * time.Minute)

	newAttempt := func(t *testing.T, suffix string) (*MemoryJournal, Record, SponsorshipRecoveryHandle) {
		t.Helper()
		journal := NewMemoryJournal()
		executionCopy := execution
		if _, _, err := journal.ReserveQuote(profile, request, quote, fixture.now); err != nil {
			t.Fatal(err)
		}
		record, _, err := journal.Admit(executionCopy, testVerified(executionCopy, fixture.resolver), fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		recovery := sponsorshipRecoveryHandle(executionCopy, "four-quadrants:"+suffix)
		record, err = journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, recovery, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		return journal, record, recovery
	}

	t.Run("both-success", func(t *testing.T) {
		journal, record, recovery := newAttempt(t, "both-success")
		evidence := sponsorshipTransactionEvidence(record.ExecutionRequest(), recovery, fixture.now.Add(time.Minute))
		record, _ = journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, evidence, fixture.now.Add(time.Minute))
		relayRefs := []string{digest("7"), digest("8"), digest("9")}
		record, err := journal.Transition(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, agentcommerce.ActionTerminal, "relay:success", mergeEvidenceRefs(record.EvidenceRefs, relayRefs),
			OutcomeCorroboratedSuccess, terminalAt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreRecord(record.Snapshot(), record.ExecutionRequest()); err != nil {
			t.Fatalf("both-success quadrant did not survive restart: %v", err)
		}
	})

	t.Run("relay-only", func(t *testing.T) {
		journal, record, recovery := newAttempt(t, "relay-only")
		observation := sponsorshipCreditObservation(record.ExecutionRequest(), recovery, fixture.now.Add(time.Minute))
		record, _ = journal.RecordSponsorshipObservation(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, observation, fixture.now.Add(time.Minute))
		var err error
		record, err = journal.Transition(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, agentcommerce.ActionSubmitted, "relay:accepted", nil, "", fixture.now.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		record, err = journal.Transition(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, agentcommerce.ActionAccepted, "relay:accepted", nil, "", fixture.now.Add(3*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		sponsorshipRefs, _ := absenceObservationReferences(record.ExecutionRequest(), recovery,
			OutcomeCorroboratedAbsent)
		bundleDigest, bundle := testAbsenceProofBundle(sponsorshipRefs, nil)
		record, err = journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, "", sponsorshipRefs, nil, bundleDigest, bundle, terminalAt)
		if err != nil || record.State != agentcommerce.ActionAccepted || record.TerminalOutcome != "" {
			t.Fatalf("sponsorship component did not remain pending for relay resolution: %+v err=%v", record, err)
		}
		record, err = journal.Transition(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, agentcommerce.ActionTerminal, "relay:success",
			mergeEvidenceRefs(record.EvidenceRefs, []string{digest("7"), digest("8"), digest("9")}),
			OutcomeCorroboratedRelayOnly, terminalAt.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreRecord(record.Snapshot(), record.ExecutionRequest()); err != nil {
			t.Fatalf("relay-only quadrant did not survive restart: %v", err)
		}
	})

	t.Run("sponsorship-only-after-relay-submit", func(t *testing.T) {
		journal, record, recovery := newAttempt(t, "sponsorship-only")
		evidence := sponsorshipTransactionEvidence(record.ExecutionRequest(), recovery, fixture.now.Add(time.Minute))
		record, _ = journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, evidence, fixture.now.Add(time.Minute))
		record, _ = journal.Transition(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, agentcommerce.ActionAccepted, "relay:accepted", record.EvidenceRefs, "",
			fixture.now.Add(2*time.Minute))
		_, transactionRefs := absenceObservationReferences(record.ExecutionRequest(), recovery,
			OutcomeCorroboratedAbsent)
		bundleDigest, bundle := testAbsenceProofBundle(nil, transactionRefs)
		record, err := journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, OutcomeCorroboratedSponsorshipOnly, nil, transactionRefs,
			bundleDigest, bundle, terminalAt)
		if err != nil || record.SponsorshipTransferReference == "" {
			t.Fatalf("transaction absence lost the proven sponsorship transfer: %+v err=%v", record, err)
		}
		if _, err := RestoreRecord(record.Snapshot(), record.ExecutionRequest()); err != nil {
			t.Fatalf("sponsorship-only quadrant did not survive restart: %v", err)
		}
	})

	t.Run("whole-negative", func(t *testing.T) {
		journal, record, recovery := newAttempt(t, "whole-negative")
		sponsorshipRefs, transactionRefs := absenceObservationReferences(record.ExecutionRequest(), recovery,
			OutcomeCorroboratedAbsent)
		bundleDigest, bundle := testAbsenceProofBundle(sponsorshipRefs, transactionRefs)
		record, err := journal.RecordSponsorshipAbsence(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, OutcomeCorroboratedAbsent, sponsorshipRefs, transactionRefs,
			bundleDigest, bundle, terminalAt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreRecord(record.Snapshot(), record.ExecutionRequest()); err != nil {
			t.Fatalf("whole-negative quadrant did not survive restart: %v", err)
		}
		if _, err := journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest,
			record.StateRevision, sponsorshipTransactionEvidence(record.ExecutionRequest(), recovery, terminalAt),
			terminalAt); !errors.Is(err, ErrRelayInvalidState) {
			t.Fatalf("terminal absence admitted a sponsorship successor: %v", err)
		}
	})
}

func TestObservedUnprovenCrashBeforeRelayBroadcastDoesNotReresolveTopUp(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "60", "60")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, quote := combinedQuotePair(t, fixture, profile, "request:observed-crash", "quote:observed-crash", "60")
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	journal := NewMemoryJournal()
	if _, _, err := journal.ReserveQuote(profile, request, quote, fixture.now); err != nil {
		t.Fatal(err)
	}
	record, _, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	recovery := sponsorshipRecoveryHandle(execution, "crash-before-client-broadcast")
	record, err = journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, recovery, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	observation := sponsorshipCreditObservation(execution, recovery, fixture.now.Add(30*time.Second))
	observation.ObservationDigests = observation.ObservationDigests[:2]
	if execution.ProviderQuote.Body.RelayFinalityProfile.MinimumObservers != 3 {
		t.Fatal("test fixture no longer distinguishes RPC release threshold from validator finality")
	}
	if err := validateSponsorshipCreditObservationForRequest(observation, execution, recovery,
		fixture.now.Add(30*time.Second)); err != nil {
		t.Fatalf("exact two-of-three RPC release was coupled to validator minimum observers: %v", err)
	}
	record, err = journal.RecordSponsorshipObservation(record.StableActionID, record.ExactRequestDigest,
		record.StateRevision, observation, fixture.now.Add(30*time.Second))
	if err != nil || record.State != agentcommerce.ActionPrepared {
		t.Fatalf("crash checkpoint was not prepared with one observation: state=%s err=%v", record.State, err)
	}
	processor := &recordingSponsorship{observed: true}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:after-crash"}}
	service := fixture.service
	service.Profile, service.Journal, service.Sponsorship, service.Broadcaster = profile, journal, processor, broadcaster
	resumed, err := service.Submit(context.Background(), execution, agreement)
	if err != nil || resumed.State != agentcommerce.ActionAccepted || broadcaster.submits != 1 {
		t.Fatalf("crash recovery did not continue the exact client transaction: state=%s submits=%d err=%v",
			resumed.State, broadcaster.submits, err)
	}
	if processor.prepareCalls != 0 || processor.calls != 0 || processor.resolveCalls != 0 {
		t.Fatalf("crash recovery re-resolved or repeated the exact top-up: prepare=%d ensure=%d resolve=%d",
			processor.prepareCalls, processor.calls, processor.resolveCalls)
	}
}

func TestObservedUnprovenSponsorOnlyExpiryRemainsNonterminalAndCannotTopUpAgain(t *testing.T) {
	fixture := newRelayFixture(t)
	clock := fixture.now
	profile := sponsorshipProfile(fixture.profile, "50", "50")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceTrustedLocal}
	request, proposed := sponsorshipQuotePair(t, fixture, profile, "request:sponsor-observed", "quote:sponsor-observed", "50",
		fixture.now.Add(4*time.Minute))
	processor := &recordingSponsorship{observed: true}
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = processor
	fixture.service.Now = func() time.Time { return clock }
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := sponsorshipExecution(fixture.execution, request, quote)
	agreement := sponsorshipAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionSubmitted || !record.SponsorshipAttempted ||
		record.SponsorshipCreditObservation == nil || processor.calls != 1 {
		t.Fatalf("sponsor-only observation was not durably nonterminal: state=%s attempted=%v calls=%d err=%v",
			record.State, record.SponsorshipAttempted, processor.calls, err)
	}
	clock = fixture.now.Add(181 * time.Second)
	resolved, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || resolved.State != agentcommerce.ActionSubmitted || !resolved.SponsorshipAttempted ||
		resolved.TerminalOutcome != "" || processor.resolveCalls != 1 {
		t.Fatalf("expired unproven sponsorship became terminal: state=%s outcome=%s attempted=%v resolves=%d err=%v",
			resolved.State, resolved.TerminalOutcome, resolved.SponsorshipAttempted, processor.resolveCalls, err)
	}
	retried, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || retried.State != agentcommerce.ActionSubmitted || processor.calls != 1 || processor.prepareCalls != 1 {
		t.Fatalf("expired exact retry attempted a second top-up: state=%s prepare=%d ensure=%d err=%v",
			retried.State, processor.prepareCalls, processor.calls, err)
	}
	processor.resolveFinalized = true
	processor.resolveCorroborated = true
	terminal, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || terminal.State != agentcommerce.ActionTerminal || terminal.SponsorshipAttempted ||
		terminal.SponsorshipTransactionEvidence == nil ||
		terminal.TerminalOutcome != OutcomeCorroboratedSponsorshipOnly {
		t.Fatalf("mature sponsor-only evidence did not close the exact observed action: state=%s outcome=%s attempted=%v err=%v",
			terminal.State, terminal.TerminalOutcome, terminal.SponsorshipAttempted, err)
	}
}

func TestSponsorshipFinalityBindsAssuranceAndExactAgreementPaymentRequest(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "50", "100")
	request, quote := combinedQuotePair(t, fixture, profile, "request:finality-binding", "quote:finality-binding", "50")
	execution := combinedExecution(fixture.execution, request, quote)
	agreement := combinedAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	journal := NewMemoryJournal()
	if _, _, err := journal.ReserveQuote(profile, request, quote, fixture.now); err != nil {
		t.Fatal(err)
	}
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:client"}, resolution: ChainResolution{State: agentcommerce.ActionTerminal,
		TransactionReference: "tx:client", EvidenceRefs: []string{digest("4"), digest("5"), digest("6")},
		TerminalOutcome: OutcomeFinalizedSuccess}}
	service := fixture.service
	service.Profile, service.Journal, service.Sponsorship, service.Broadcaster = profile, journal, &recordingSponsorship{}, broadcaster
	record, err := service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionAccepted {
		t.Fatalf("combined action was not accepted: state=%s err=%v", record.State, err)
	}
	record, err = service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || record.State != agentcommerce.ActionTerminal || record.SponsorshipTransactionEvidence == nil {
		t.Fatalf("combined action did not retain exact sponsorship finality: state=%s err=%v", record.State, err)
	}
	body := relaySuccessEvidence(record, fixture.now.Add(time.Minute))
	service.EvidenceSource = fixedEvidenceSource{body: body}
	signed, err := service.Evidence(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil {
		t.Fatalf("exact combined finality evidence was rejected: %v", err)
	}
	if err := VerifyRelayFinalityEvidenceForExecution(context.Background(), signed, execution, fixture.resolver,
		acceptingPortableRelayFinalityVerifier{}, acceptingPortableSponsorshipVerifier{},
		fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("exact combined finality evidence was unverifiable: %v", err)
	}
	strippedBody := signed.Body
	strippedBody.SponsorshipStableActionID = ""
	strippedBody.SponsorshipExactRequestDigest = ""
	strippedBody.SponsorshipValidUntilUnix = 0
	strippedBody.SponsorshipTransferReference = ""
	strippedBody.SponsorshipTransactionEvidence = nil
	strippedBody.Outcome = OutcomeFinalizedSuccess
	stripped, err := SignRelayFinalityEvidence(strippedBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayFinalityEvidenceForExecution(context.Background(), stripped, execution, fixture.resolver,
		acceptingPortableRelayFinalityVerifier{}, acceptingPortableSponsorshipVerifier{},
		fixture.now.Add(time.Minute)); err == nil {
		t.Fatal("Provider stripped the paid sponsorship obligation from combined finality evidence")
	}
	tamperedBundle := *record.SponsorshipTransactionEvidence
	tamperedBundle.ProofBundle = append([]byte(nil), tamperedBundle.ProofBundle...)
	tamperedBundle.ProofBundle[len(tamperedBundle.ProofBundle)-1] ^= 1
	if _, err := RelaySponsorshipTransactionEvidenceDigest(tamperedBundle); err == nil {
		t.Fatal("mutated in-band sponsorship proof retained its committed digest")
	}

	mutatedBody := signed.Body
	mutatedBody.AssuranceLevel = AssuranceAuthorizedSingleProvider
	mutated, err := SignRelayFinalityEvidence(mutatedBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayFinalityEvidenceForExecution(context.Background(), mutated, execution, fixture.resolver,
		acceptingPortableRelayFinalityVerifier{}, acceptingPortableSponsorshipVerifier{},
		fixture.now.Add(time.Minute)); err == nil {
		t.Fatal("finality evidence relabelled the exact action under a lower assurance")
	}

	otherExecution := execution
	otherExecution.AgreementBodyDigest = digest("9")
	otherPayment := sponsorshipPaymentRequest(otherExecution)
	otherRecovery := sponsorshipRecoveryHandle(otherExecution, "unrelated-payment-recovery")
	otherEvidence := sponsorshipTransactionEvidence(otherExecution, otherRecovery, fixture.now.Add(time.Minute))
	expectedEvidence := *record.SponsorshipTransactionEvidence
	expected := RelaySponsorshipEvidenceContext{AgreementBodyDigest: execution.AgreementBodyDigest,
		AgreementObligationID: execution.SponsorshipObligationID, PayerAgentID: request.Body.ProviderAgentID,
		PayeeAgentID: request.Body.RequesterAgentID, NetworkID: request.Body.Network.NetworkID,
		NetworkDomainDigest: expectedEvidence.NetworkDigest, DestinationSourceAccount: request.Body.SourceAccount,
		Amount: *quote.Body.ReservedSponsorship, MaximumExpiresAtUnix: execution.ExpiresAtUnix,
		SponsorshipStableActionID:     otherEvidence.SponsorshipStableActionID,
		SponsorshipExactRequestDigest: otherEvidence.SponsorshipExactRequestDigest}
	if err := VerifySponsorshipPaymentRequestForEvidence(otherPayment, otherEvidence, expected); err == nil {
		t.Fatal("valid same-route payment evidence from another Agreement was replayed")
	}

	originalPayment := expectedEvidence.AgreementPaymentRequest
	attackerObligation := agentcommerce.SettlementObligation{AgreementBodyDigest: originalPayment.AgreementBodyDigest,
		AgreementObligationID: originalPayment.AgreementObligationID,
		ObligationInstanceID:  originalPayment.ObligationInstanceID, Sequence: 1,
		PayerAgentID: originalPayment.PayerAgentID, PayeeAgentID: originalPayment.PayeeAgentID,
		Amount: originalPayment.Amount, MaximumAggregateAmount: originalPayment.Amount,
		ExpiresAtUnix: originalPayment.ExpiresAtUnix, SettlementAdapterURI: originalPayment.SettlementAdapterURI,
		SettlementParametersDigest: digest("5"), StableActionID: digest("4")}
	attackerPayment, err := agentcommerce.BuildDomainBoundAgreementPaymentRequest(originalPayment.OwnerID,
		"agent:attacker", originalPayment.NetworkID, originalPayment.NetworkDomainDigest,
		originalPayment.Destination, attackerObligation)
	if err != nil {
		t.Fatal(err)
	}
	attackerEvidence := expectedEvidence
	attackerEvidence.AgreementPaymentRequest = attackerPayment
	attackerEvidence.AgreementPaymentRequestDigest, _ = agentcommerce.AgreementPaymentRequestDigest(attackerPayment)
	attackerCanonical, _, _ := agentcommerce.PaymentAuthorizationMaterial(attackerPayment)
	attackerEvidence.SponsorshipStableActionID = attackerPayment.StableActionID
	attackerEvidence.SponsorshipExactRequestDigest, _ = agentcommerce.ExactRequestDigest(attackerCanonical)
	attackerExpected := expected
	attackerExpected.SponsorshipStableActionID = attackerEvidence.SponsorshipStableActionID
	attackerExpected.SponsorshipExactRequestDigest = attackerEvidence.SponsorshipExactRequestDigest
	if err := VerifySponsorshipPaymentRequestForEvidence(attackerPayment, attackerEvidence, attackerExpected); err == nil {
		t.Fatal("payment action owned by a different Agent was accepted for Provider sponsorship")
	}
}

func TestSponsorOnlyTerminalEvidenceCannotBeRelabelledAsCombinedSuccess(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "50", "50")
	profile.SupportedAssuranceLevels = []AssuranceLevel{AssuranceAuthorizedSingleProvider}
	request, proposed := sponsorshipQuotePair(t, fixture, profile, "request:mode-binding",
		"quote:mode-binding", "50", fixture.now.Add(4*time.Minute))
	fixture.service.Profile = profile
	fixture.service.QuotePolicy = fixedQuotePolicy{body: proposed.Body}
	fixture.service.Journal = NewMemoryJournal()
	fixture.service.Sponsorship = &recordingSponsorship{resolveCorroborated: true}
	quote, err := fixture.service.Quote(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	execution := sponsorshipExecution(fixture.execution, request, quote)
	agreement := sponsorshipAgreement(t, fixture, request, quote)
	execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	execution = fixture.withAdmission(t, execution)
	testRecovery := sponsorshipRecoveryHandle(execution, "mode-binding-preflight")
	testEvidence := sponsorshipTransactionEvidence(execution, testRecovery, fixture.now.Add(30*time.Second))
	testEvidence.TerminalEvidenceClass = SponsorshipTerminalClientCorroborated
	testEvidence.ValidatorAuthenticatedPortableProof = false
	testEvidence.PortableProofLocator = ""
	if err := validateRelaySponsorshipTransactionEvidenceShape(testEvidence); err != nil {
		t.Fatalf("client-corroborated evidence shape: %v", err)
	}
	if err := validateSponsorshipTransactionEvidenceForRequest(testEvidence, execution, testRecovery,
		fixture.now.Add(30*time.Second)); err != nil {
		t.Fatalf("client-corroborated evidence request binding: %v", err)
	}
	record, err := fixture.service.Submit(context.Background(), execution, agreement)
	if err != nil || record.State != agentcommerce.ActionTerminal ||
		record.TerminalOutcome != OutcomeCorroboratedSponsorshipOnly {
		t.Fatalf("sponsor-only action did not terminalize: state=%s outcome=%s err=%v",
			record.State, record.TerminalOutcome, err)
	}

	resolution, err := fixture.service.SignedResolution(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolutionForExecution(resolution, execution, fixture.resolver, fixture.now); err != nil {
		t.Fatalf("valid sponsor-only resolution was rejected: %v", err)
	}
	mutatedResolutionBody := resolution.Body
	mutatedResolutionBody.TerminalOutcome = OutcomeCorroboratedSuccess
	mutatedResolutionBody.TransactionReference = "tx:invented-relay"
	mutatedResolution, err := SignRelayResolution(mutatedResolutionBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayResolutionForExecution(mutatedResolution, execution, fixture.resolver, fixture.now); err == nil {
		t.Fatal("sponsor-only resolution was relabelled as combined success")
	}

	body := relaySuccessEvidence(record, fixture.now.Add(time.Minute))
	body.SubmittedTransactionHash = ""
	body.SourceExecutionReference = ""
	body.DestinationCreditReferences = nil
	body.SigningAuthorityAtUnix = uint64(fixture.now.Add(time.Minute).Unix())
	signed, err := SignRelayFinalityEvidence(body, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayFinalityEvidenceForExecution(context.Background(), signed, execution,
		fixture.resolver, acceptingPortableRelayFinalityVerifier{}, acceptingPortableSponsorshipVerifier{},
		fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("valid sponsor-only terminal evidence was rejected: %v", err)
	}
	mutatedBody := body
	mutatedBody.Outcome = OutcomeCorroboratedSuccess
	mutatedBody.SubmittedTransactionHash = "tx:invented-relay"
	mutatedBody.SourceExecutionReference = "chain:invented-relay"
	mutatedBody.RelayTerminalEvidenceClass = RelayTerminalProviderCorroborated
	mutatedBody.RelayValidatorAuthenticatedPortableProof = relayBoolPointer(false)
	mutatedBody.RelayFinalizedCheckpointID = "checkpoint:invented-relay"
	mutatedBody.RelayFinalizedCheckpointSequence = 1
	mutatedBody.RelayFinalizedCheckpointUnix = uint64(fixture.now.Add(time.Minute).Unix())
	mutatedBody.RelayConfirmationDepth = fixture.profile.FinalityProfiles[0].MinimumConfirmationDepth
	mutatedBody.RelayObservationDigests = []string{digest("1"), digest("2"), digest("3")}
	providerProfile := fixture.profile.FinalityProfiles[0]
	providerProfile.TerminalEvidenceClass = RelayTerminalProviderCorroborated
	providerProfile.ProfileURI = "tos.relay.provider-corroborated-terminal.v1"
	providerProfile.ProfileDigest = digest("e")
	mutatedBody.RelayFinalityProfile = &providerProfile
	mutated, err := SignRelayFinalityEvidence(mutatedBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayFinalityEvidenceForExecution(context.Background(), mutated, execution,
		fixture.resolver, acceptingPortableRelayFinalityVerifier{}, acceptingPortableSponsorshipVerifier{},
		fixture.now.Add(time.Minute)); err == nil {
		t.Fatal("sponsor-only terminal evidence was relabelled as combined success")
	}
}

func TestRelayEvidenceCannotSubstituteSubmittedTransactionReference(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	journal := fixture.service.Journal
	record, _, err := journal.Admit(fixture.execution, testVerified(fixture.execution, fixture.resolver), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionSubmitted, "", nil, "", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionAccepted, "tx:durable", nil, "", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	observations := []string{digest("1"), digest("2"), digest("3")}
	record, err = journal.Transition(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		agentcommerce.ActionTerminal, "tx:durable", observations, OutcomeFinalizedSuccess, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	body := relaySuccessEvidence(record, fixture.now)
	body.SubmittedTransactionHash = "tx:substituted"
	fixture.service.EvidenceSource = fixedEvidenceSource{body: body}
	if _, err := fixture.service.Evidence(context.Background(), record.StableActionID, record.ExactRequestDigest); err == nil {
		t.Fatal("finality evidence substituted the durable submitted transaction reference")
	}
	body.SubmittedTransactionHash = record.TransactionReference
	fixture.service.EvidenceSource = fixedEvidenceSource{body: body}
	if _, err := fixture.service.Evidence(context.Background(), record.StableActionID, record.ExactRequestDigest); err != nil {
		t.Fatalf("exact submitted transaction evidence was rejected: %v", err)
	}
}

func TestExpiredAmbiguousSponsorshipUsesReadOnlyRecoveryToken(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "50", "50")
	request, quote := sponsorshipQuotePair(t, fixture, profile, "request:query-recovery", "quote:query-recovery", "50",
		fixture.now.Add(4*time.Minute))
	execution := sponsorshipExecution(fixture.execution, request, quote)
	execution = fixture.withAdmission(t, execution)
	journal := NewMemoryJournal()
	if _, _, err := journal.ReserveQuote(profile, request, quote, fixture.now); err != nil {
		t.Fatal(err)
	}
	record, _, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		sponsorshipRecoveryHandle(execution, "query-only-recovery-token"), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	processor := &recordingSponsorship{resolveFinalized: true}
	service := ProviderService{Profile: profile, Journal: journal, Sponsorship: processor,
		Now: func() time.Time { return fixture.now.Add(181 * time.Second) }}
	resolved, err := service.Submit(context.Background(), execution, agentcommerce.AgentAgreement{})
	if err != nil || resolved.State != agentcommerce.ActionTerminal ||
		resolved.TerminalOutcome != OutcomeFinalizedSponsorshipOnly || resolved.SponsorshipTransferReference != "sponsorship:final" {
		t.Fatalf("query-only recovery did not terminalize finalized top-up: state=%s outcome=%s err=%v",
			resolved.State, resolved.TerminalOutcome, err)
	}
	if processor.resolveCalls != 1 || processor.prepareCalls != 0 || processor.calls != 0 {
		t.Fatalf("expired recovery used a write-capable path: prepare=%d ensure=%d resolve=%d",
			processor.prepareCalls, processor.calls, processor.resolveCalls)
	}
}

func TestSponsorOnlyAbsenceProvesOnlyTheSponsorshipActionAndReleasesExposure(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "50", "50")
	requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:absence:a", "quote:absence:a", "50",
		fixture.now.Add(4*time.Minute))
	requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:absence:b", "quote:absence:b", "50",
		fixture.now.Add(4*time.Minute))
	execution := sponsorshipExecution(fixture.execution, requestA, quoteA)
	execution = fixture.withAdmission(t, execution)
	journal := NewMemoryJournal()
	if _, _, err := journal.ReserveQuote(profile, requestA, quoteA, fixture.now); err != nil {
		t.Fatal(err)
	}
	record, _, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	recovery := sponsorshipRecoveryHandle(execution, "absence-recovery-token")
	record, err = journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
		recovery, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	processor := &recordingSponsorship{resolveAbsent: true}
	resolvedAt := fixture.now.Add(11 * time.Minute)
	service := ProviderService{Profile: profile, SigningKey: fixture.providerKey, Journal: journal,
		Sponsorship: processor, Now: func() time.Time { return resolvedAt }}
	resolved, err := service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || resolved.State != agentcommerce.ActionTerminal ||
		resolved.TerminalOutcome != OutcomeFinalizedAbsent || resolved.SponsorshipTransferReference != "" ||
		resolved.SponsorshipAttempted {
		t.Fatalf("profile-qualified no-credit resolution failed: state=%s outcome=%s attempted=%v err=%v",
			resolved.State, resolved.TerminalOutcome, resolved.SponsorshipAttempted, err)
	}
	if processor.resolveCalls != 1 || processor.calls != 0 || processor.prepareCalls != 0 {
		t.Fatalf("absence recovery used a write-capable path: prepare=%d ensure=%d resolve=%d",
			processor.prepareCalls, processor.calls, processor.resolveCalls)
	}
	if _, err := RestoreRecord(resolved.Snapshot(), execution); err != nil {
		t.Fatalf("terminal sponsorship absence was not durably restorable: %v", err)
	}
	sponsorshipObservations, _ := absenceObservationReferences(execution, recovery, OutcomeFinalizedAbsent)
	pointInTime := append([]RelayAbsenceObservationReference(nil), sponsorshipObservations...)
	for index := range pointInTime {
		pointInTime[index].Conclusion = AbsenceConclusionAbsent
	}
	sortRelayAbsenceObservationReferences(pointInTime)
	if err := validateSponsorshipResolution(SponsorshipResolution{Status: SponsorshipResolutionFinalizedAbsent,
		AbsenceOutcome: OutcomeFinalizedAbsent, SponsorshipAbsenceObservations: pointInTime,
		TransactionAbsenceObservations: nil}, execution, recovery, resolvedAt); err == nil {
		t.Fatal("point-in-time sponsorship absence authorized a second sponsorship")
	}
	prematureSponsorship := append([]RelayAbsenceObservationReference(nil), sponsorshipObservations...)
	for index := range prematureSponsorship {
		prematureSponsorship[index].FinalizedCheckpointUnix = recovery.ValidUntilUnix - 1
	}
	sortRelayAbsenceObservationReferences(prematureSponsorship)
	if err := validateSponsorshipResolution(SponsorshipResolution{Status: SponsorshipResolutionFinalizedAbsent,
		AbsenceOutcome: OutcomeFinalizedAbsent, SponsorshipAbsenceObservations: prematureSponsorship,
		TransactionAbsenceObservations: nil}, execution, recovery, resolvedAt); err == nil {
		t.Fatal("pre-expiry checkpoint authorized a second sponsorship")
	}
	_, unexpectedTransaction := absenceObservationReferences(execution, recovery, OutcomeFinalizedAbsent)
	if err := validateSponsorshipResolution(SponsorshipResolution{Status: SponsorshipResolutionFinalizedAbsent,
		AbsenceOutcome: OutcomeFinalizedAbsent, SponsorshipAbsenceObservations: sponsorshipObservations,
		TransactionAbsenceObservations: unexpectedTransaction}, execution, recovery, resolvedAt); err == nil {
		t.Fatal("sponsor-only action accepted a nonexistent client-transaction absence domain")
	}
	if _, err := journal.RecordSponsorshipAbsence(resolved.StableActionID, resolved.ExactRequestDigest,
		resolved.StateRevision-1, resolved.TerminalOutcome, sponsorshipObservations,
		nil, resolved.AbsenceProofBundleDigest, resolved.AbsenceProofBundle, resolvedAt); err != nil {
		t.Fatalf("exact sponsorship absence retry was not idempotent: %v", err)
	}
	conflictingSponsorshipProof := append([]RelayAbsenceObservationReference(nil), sponsorshipObservations...)
	conflictingSponsorshipProof[0].ObservationDigest = digest("7")
	sortRelayAbsenceObservationReferences(conflictingSponsorshipProof)
	if _, err := journal.RecordSponsorshipAbsence(resolved.StableActionID, resolved.ExactRequestDigest,
		resolved.StateRevision, resolved.TerminalOutcome, conflictingSponsorshipProof,
		nil, resolved.AbsenceProofBundleDigest,
		resolved.AbsenceProofBundle, resolvedAt); !errors.Is(err, ErrRelayConflict) {
		t.Fatalf("conflicting sponsorship absence retry was accepted: %v", err)
	}
	if _, err := journal.ReleaseSponsorshipExposure(resolved.StableActionID, resolved.ExactRequestDigest,
		resolved.StateRevision, []string{digest("b")}, resolvedAt); !errors.Is(err, ErrRelayInvalidState) {
		t.Fatalf("no-credit outcome was treated as reimbursed sponsored value: %v", err)
	}
	if _, created, err := journal.ReserveQuote(profile, requestB, quoteB, fixture.now); err != nil || !created {
		t.Fatalf("proved no-credit outcome did not release sponsorship exposure: created=%v err=%v", created, err)
	}
	body := sponsorshipAbsenceEvidence(resolved, resolvedAt, sponsorshipObservations, nil)
	service.EvidenceSource = fixedEvidenceSource{body: body}
	if _, err := service.Evidence(context.Background(), resolved.StableActionID, resolved.ExactRequestDigest); err != nil {
		t.Fatalf("exact typed sponsorship absence evidence was rejected: %v", err)
	}
	mutations := map[string]func(*RelayFinalityEvidenceBody){
		"payment identity": func(body *RelayFinalityEvidenceBody) { body.SponsorshipExactRequestDigest = digest("a") },
		"invented transaction absence": func(body *RelayFinalityEvidenceBody) {
			body.TransactionAbsenceObservations = unexpectedTransaction
		},
		"conflated absence sets": func(body *RelayFinalityEvidenceBody) {
			body.SponsorshipAbsenceObservations = nil
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := body
			mutate(&mutated)
			service.EvidenceSource = fixedEvidenceSource{body: mutated}
			if _, err := service.Evidence(context.Background(), resolved.StableActionID,
				resolved.ExactRequestDigest); err == nil {
				t.Fatal("substituted sponsorship absence evidence was accepted")
			}
		})
	}
}

func TestExpiredPreparedRelayReleasesOnlyProvablyUnspentExposure(t *testing.T) {
	for _, test := range []struct {
		name      string
		attempt   bool
		finalized bool
		wantState agentcommerce.ActionResolutionState
		wantFree  bool
	}{
		{name: "no sponsorship attempt", wantState: agentcommerce.ActionRejected, wantFree: true},
		{name: "ambiguous sponsorship attempt", attempt: true, wantState: agentcommerce.ActionPrepared},
		{name: "finalized sponsorship", attempt: true, finalized: true, wantState: agentcommerce.ActionTerminal},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayFixture(t)
			profile := sponsorshipProfile(fixture.profile, "50", "50")
			requestA, quoteA := sponsorshipQuotePair(t, fixture, profile, "request:expiry:a", "quote:expiry:a", "50",
				fixture.now.Add(4*time.Minute))
			requestB, quoteB := sponsorshipQuotePair(t, fixture, profile, "request:expiry:b", "quote:expiry:b", "50",
				fixture.now.Add(4*time.Minute))
			journal := NewMemoryJournal()
			if _, _, err := journal.ReserveQuote(profile, requestA, quoteA, fixture.now); err != nil {
				t.Fatal(err)
			}
			execution := fixture.withAdmission(t, sponsorshipExecution(fixture.execution, requestA, quoteA))
			record, _, err := journal.Admit(execution, testVerified(execution, fixture.resolver), fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			if test.attempt {
				record, err = journal.BeginSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
					sponsorshipRecoveryHandle(execution, "expiry-recovery-token"), fixture.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			if test.finalized {
				evidence := sponsorshipTransactionEvidence(execution, record.SponsorshipRecoveryHandle(), fixture.now)
				record, err = journal.RecordSponsorship(record.StableActionID, record.ExactRequestDigest, record.StateRevision,
					evidence, fixture.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			service := ProviderService{Profile: profile, Journal: journal, Now: func() time.Time {
				return fixture.now.Add(181 * time.Second)
			}}
			var recovery *recordingSponsorship
			if test.attempt && !test.finalized {
				recovery = &recordingSponsorship{}
				service.Sponsorship = recovery
			}
			resolved, err := service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
			if err != nil || resolved.State != test.wantState {
				t.Fatalf("expired PREPARED resolution mismatch: state=%s err=%v", resolved.State, err)
			}
			if recovery != nil && recovery.resolveCalls != 1 {
				t.Fatalf("ordinary Resolve did not use the query-only sponsorship path: calls=%d", recovery.resolveCalls)
			}
			_, created, reserveErr := journal.ReserveQuote(profile, requestB, quoteB, fixture.now.Add(181*time.Second))
			if test.wantFree && (reserveErr != nil || !created) {
				t.Fatalf("provably unspent exposure was not released: created=%v err=%v", created, reserveErr)
			}
			if !test.wantFree && !errors.Is(reserveErr, ErrRelayExposure) {
				t.Fatalf("ambiguous or spent exposure was released: %v", reserveErr)
			}
		})
	}
}

func TestRelayExecutionCannotOutliveActionAuthorization(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	fields, err := agentcommerce.ImportSemanticFields("payment.direct", fixture.execution.SemanticFields)
	if err != nil {
		t.Fatal(err)
	}
	action, err := agentcommerce.BuildAuthorizedAction("owner:client", "agent:client", "payment.direct", fields,
		fixture.execution.UnderlyingActionRequest, fixture.execution.WriterFence, 1, digest("c"), "", "unknown",
		uint64(fixture.now.Add(2*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.AuthorizedAction, err = signTestAction(action, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	if err := VerifyRelayExecutionRequest(t.Context(), fixture.execution, fixture.profile, fixture.resolver,
		fixture.resolver, fixture.inspector, fixture.now); err == nil {
		t.Fatal("relay execution outlived its owner authorization")
	}
}

func TestProviderServiceQueriesBeforeExactRebroadcast(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastUnknown}, submitErr: errors.New("response lost")}
	fixture.service.Broadcaster = broadcaster
	record, err := fixture.service.Submit(context.Background(), fixture.execution, agreement)
	if err == nil || record.State != agentcommerce.ActionSubmitted || broadcaster.submits != 1 {
		t.Fatalf("ambiguous submit was not frozen: state=%s submits=%d err=%v", record.State, broadcaster.submits, err)
	}
	// An exact Submit retry returns the journal record; it cannot write again.
	retry, err := fixture.service.Submit(context.Background(), fixture.execution, agreement)
	if err != nil || retry.State != agentcommerce.ActionSubmitted || broadcaster.submits != 1 {
		t.Fatalf("exact retry rebroadcast before resolution: state=%s submits=%d err=%v", retry.State, broadcaster.submits, err)
	}
	broadcaster.submitErr = nil
	broadcaster.resolution = ChainResolution{State: agentcommerce.ActionSubmitted}
	if _, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest); err != nil || broadcaster.submits != 1 {
		t.Fatalf("unresolved action was rebroadcast without safe evidence: submits=%d err=%v", broadcaster.submits, err)
	}
	broadcaster.resolution = ChainResolution{SafeToRebroadcastExact: true}
	broadcaster.result = BroadcastResult{Status: BroadcastAccepted, TransactionReference: "tx:exact"}
	accepted, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest)
	if err != nil || accepted.State != agentcommerce.ActionAccepted || broadcaster.submits != 2 {
		t.Fatalf("safe exact rebroadcast failed: state=%s submits=%d err=%v", accepted.State, broadcaster.submits, err)
	}
	if string(broadcaster.payloads[0]) != string(broadcaster.payloads[1]) {
		t.Fatal("relay recovery changed the exact signed transaction bytes")
	}
}

func TestRebroadcastRejectionCannotEraseAnAmbiguousPriorWrite(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	broadcaster := &recordingBroadcaster{result: BroadcastResult{Status: BroadcastUnknown}, submitErr: errors.New("response lost")}
	fixture.service.Broadcaster = broadcaster
	record, err := fixture.service.Submit(context.Background(), fixture.execution, agreement)
	if err == nil || record.State != agentcommerce.ActionSubmitted {
		t.Fatalf("initial ambiguous write was not journaled: state=%s err=%v", record.State, err)
	}
	broadcaster.submitErr = nil
	broadcaster.result = BroadcastResult{Status: BroadcastStatus("rejected"), TransactionReference: "rpc:rejected"}
	broadcaster.resolution = ChainResolution{SafeToRebroadcastExact: true}
	if _, err := fixture.service.Resolve(context.Background(), record.StableActionID, record.ExactRequestDigest); err == nil {
		t.Fatal("a later endpoint rejection resolved an earlier ambiguous write")
	}
	stillUnknown, err := fixture.service.Journal.Resolve(record.StableActionID, record.ExactRequestDigest)
	if err != nil || stillUnknown.State != agentcommerce.ActionSubmitted {
		t.Fatalf("ambiguous prior write was erased: state=%s err=%v", stillUnknown.State, err)
	}
}

type relayFixture struct {
	now                time.Time
	clientKey          ed25519.PrivateKey
	providerKey        ed25519.PrivateKey
	authorityKey       relayAuthorityKey
	resolver           relayResolver
	admissionAuthority *testRelayAdmissionAuthority
	profile            RelayServiceProfile
	request            SignedRelayQuoteRequest
	inspector          fixedInspector
	execution          RelayExecutionRequest
	service            ProviderService
}

type testRelayAdmissionAuthority struct {
	mu       sync.Mutex
	receipts map[string]SignedRelaySideEffectAdmissionReceipt
	err      error
}

func newTestRelayAdmissionAuthority() *testRelayAdmissionAuthority {
	return &testRelayAdmissionAuthority{receipts: make(map[string]SignedRelaySideEffectAdmissionReceipt)}
}

func (authority *testRelayAdmissionAuthority) AdmitRelaySideEffects(context.Context,
	RelaySideEffectAdmissionDescriptor) (SignedRelaySideEffectAdmissionReceipt, error) {
	return SignedRelaySideEffectAdmissionReceipt{}, errors.New("test authority does not issue receipts")
}

func (authority *testRelayAdmissionAuthority) ResolveRelaySideEffectAdmission(_ context.Context,
	lookup RelaySideEffectAdmissionLookup) (SignedRelaySideEffectAdmissionReceipt, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.err != nil {
		return SignedRelaySideEffectAdmissionReceipt{}, authority.err
	}
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

func (authority *testRelayAdmissionAuthority) remember(t *testing.T, request RelayExecutionRequest) {
	t.Helper()
	descriptor, err := buildRelaySideEffectAdmissionDescriptorForRoute(request,
		request.AdmissionReceipt.Body.AuthenticatedPrincipal, request.AdmissionReceipt.Body.RouteAttempt,
		request.AdmissionReceipt.Body.PredecessorReceiptDigest)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := RelaySideEffectAdmissionLookupDigest(descriptor.Lookup())
	if err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	authority.receipts[digest] = request.AdmissionReceipt
	authority.mu.Unlock()
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	clientKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("1", ed25519.SeedSize)))
	providerKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("2", ed25519.SeedSize)))
	authorityKey := relayAuthorityKey("authority")
	resolver := relayResolver{agents: map[string]ed25519.PublicKey{
		"agent:client": clientKey.Public().(ed25519.PublicKey), "agent:provider": providerKey.Public().(ed25519.PublicKey)},
		authority: authorityKey.publicKey(), current: &relayCurrentFenceState{}}
	admissionAuthority := newTestRelayAdmissionAuthority()
	network := NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42, ZeroStateRootHash: digest("1"),
		ZeroStateFileHash: digest("2"), WorkchainID: 0}
	transactionProfile := TransactionProfile{ProfileURI: "tos.signed-external-boc.v1", ProfileDigest: digest("3"),
		MaximumSignedBytes: MaxSignedTransactionBytes, InspectableSourceSequence: true, InspectableTransactionExpiry: true}
	finality := FinalityProfile{ProfileURI: "tos.depth-quorum.v1", ProfileDigest: digest("4"),
		TerminalEvidenceClass: RelayTerminalValidatorFinality, MinimumConfirmationDepth: 2,
		MinimumObservers: 3, MinimumOperatorDomains: 2, ReorgWindowSeconds: 10, MaximumResolutionSeconds: 30}
	asset := AssetIdentity{AssetNamespace: "tos.native", AssetIdentifier: "tos:testnet", Unit: "nanotos"}
	profile := RelayServiceProfile{SchemaVersion: 1, ProfileID: "relay:provider", Revision: 1,
		ProviderAgentID: "agent:provider", NetworkDomains: []NetworkDomain{network}, SupportedModes: []Mode{ModeRelayExact},
		SupportedAssuranceLevels: []AssuranceLevel{AssuranceAutonomousDecentralized},
		TransactionProfiles:      []TransactionProfile{transactionProfile}, FinalityProfiles: []FinalityProfile{finality},
		FeeAssets: []AssetIdentity{asset}, ExposureLimits: []ExposureLimit{{Asset: asset, MaximumPerRequestAtomic: "1000", MaximumOutstandingAtomic: "10000"}},
		AdmissionLimits: AdmissionLimits{MaximumQuoteReservations: 64, MaximumActiveExecutions: 32,
			MaximumActivePerRequester: 8, MaximumQuoteRequestsPerWindow: 256,
			MaximumQuoteRequestsPerRequesterWindow: 32, QuoteRequestWindowSeconds: 60},
		MaximumRequestBytes: MaxSignedTransactionBytes, Endpoints: ServiceEndpoints{QuoteURL: "https://relay.example/quote",
			SubmitURL: "https://relay.example/submit", ResolveURL: "https://relay.example/resolve", EvidenceURL: "https://relay.example/evidence"},
		PolicyRevision: 1, CreatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	payload := []byte("exact signed TOS BOC fixture")
	payloadDigest, _ := SignedTransactionDigest(payload)
	networkDigest, _ := NetworkDomainDigest(network)
	underlyingRequest := []byte{0xa1, 0x01, 0x02}
	underlyingRequestDigest, _ := agentcommerce.ExactRequestDigest(underlyingRequest)
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID("owner:client"), "agent_id": agentcommerce.ID("agent:client"),
		"agreement_body_digest": agentcommerce.Digest32(digest("5")), "obligation_instance_id": agentcommerce.Digest32(digest("6")),
		"payer_id": agentcommerce.ID("agent:client"), "payee_id": agentcommerce.ID("agent:merchant"), "network_id": agentcommerce.ID("tos:testnet"),
		"asset_digest": agentcommerce.Digest32(digest("a")), "amount_atomic": agentcommerce.ID("25"), "destination_digest": agentcommerce.Digest32(digest("b"))}
	stableID, _, _ := agentcommerce.DeriveStableActionID("payment.direct", fields)
	wireFields, _ := agentcommerce.ExportSemanticFields("payment.direct", fields)
	fence, err := signTestFence(agentcommerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:client", AgentID: "agent:client",
		InstanceID: "instance:client", LeaseID: "lease:client", WriterGeneration: 1, IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(10 * time.Minute).Unix()), AuthorityID: "authority:client", Scope: []string{"payment.direct"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver.current.fence = fence
	action, err := agentcommerce.BuildAuthorizedAction("owner:client", "agent:client", "payment.direct", fields, underlyingRequest, fence, 1,
		digest("c"), "", "unknown", uint64(now.Add(8*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = signTestAction(action, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	requestBody := RelayQuoteRequestBody{SchemaVersion: 1, RequestID: "relay-request:one", RequesterAgentID: "agent:client",
		ProviderAgentID: "agent:provider", Network: network, Mode: ModeRelayExact,
		AssuranceLevel: AssuranceAutonomousDecentralized, SourceAccount: "0:" + strings.Repeat("1", 64),
		SourceAccountAuthorityDigest: digest("0"),
		TransactionProfileURI:        transactionProfile.ProfileURI, TransactionProfileDigest: transactionProfile.ProfileDigest,
		UnderlyingActionKind: "payment.direct", StableActionID: stableID, ExactRequestDigest: underlyingRequestDigest,
		SignedTransactionDigest: payloadDigest, SignedTransactionCellHash: "tvm-cell-sha256:" + strings.Repeat("d", 64), SignedTransactionSize: uint32(len(payload)),
		TransactionIntentDigest: digest("e"), SourceSequence: 7, TransactionValidUntilUnix: uint64(now.Add(10 * time.Minute).Unix()),
		MaximumServiceFee: AssetAmount{Asset: asset, AmountAtomic: "10"}, MaximumNetworkFeeAtomic: "100",
		MaximumTransactionValueAtomic: "25", RelayFinalityProfileURI: finality.ProfileURI, RelayFinalityProfileDigest: finality.ProfileDigest,
		RelayTerminalEvidenceClass: finality.TerminalEvidenceClass,
		CreatedAtUnix:              uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(5 * time.Minute).Unix())}
	signedRequest, err := SignRelayQuoteRequest(requestBody, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, _ := RelayQuoteRequestDigest(requestBody)
	profileDigest, _ := RelayServiceProfileDigest(profile)
	quoteBody := ProviderRelayQuoteBody{SchemaVersion: 1, QuoteID: "relay-quote:one", QuoteRequestDigest: requestDigest,
		ServiceProfileDigest: profileDigest, ProviderAgentID: "agent:provider", Mode: ModeRelayExact,
		AssuranceLevel:          AssuranceAutonomousDecentralized,
		FeeLines:                []FeeLine{{Kind: ObligationRelayFee, Amount: AssetAmount{Asset: asset, AmountAtomic: "3"}}},
		MaximumNetworkFeeAtomic: "100", MaximumTransactionValueAtomic: "25", MaximumRequestBytes: MaxSignedTransactionBytes,
		RelayTerminalEvidenceClass: finality.TerminalEvidenceClass,
		RelayFinalityProfile:       finalityPointer(finality), StatusEndpoint: profile.Endpoints.ResolveURL, ProviderPolicyRevision: 1,
		ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(4 * time.Minute).Unix())}
	inspector := fixedInspector{InspectedTransaction{NetworkDigest: networkDigest, SourceAccount: requestBody.SourceAccount,
		SourceAccountAuthorityDigest: requestBody.SourceAccountAuthorityDigest, AuthorizedAgentID: "agent:client",
		ControllerEpoch: 1, SourceSequence: requestBody.SourceSequence, ValidUntilUnix: requestBody.TransactionValidUntilUnix,
		Destination: "0:" + strings.Repeat("2", 64), ValueAtomic: "25",
		TransactionIntentDigest: requestBody.TransactionIntentDigest, SignedTransactionCellHash: requestBody.SignedTransactionCellHash,
		MaximumNetworkFeeAtomic: "90", MaximumTransactionValueAtomic: "25"}}
	service := ProviderService{Profile: profile, SigningKey: providerKey, AgentResolver: resolver, FenceResolver: resolver,
		Inspector: inspector, ActionBinder: fixedActionBinder{}, AgreementVerifier: agentcommerce.AgentSignatureEvidenceVerifier{Resolver: resolver},
		AdmissionAuthority: admissionAuthority, QuotePolicy: fixedQuotePolicy{body: quoteBody}, Journal: NewMemoryJournal(),
		EvidenceSource:                 fixedEvidenceSource{},
		SponsorshipObservationVerifier: acceptingSponsorshipObservationVerifier{}, Now: func() time.Time { return now }}
	signedQuote, err := SignProviderRelayQuote(quoteBody, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	execution := RelayExecutionRequest{SchemaVersion: 1, QuoteRequest: signedRequest, SignedTransactionBytes: payload,
		ProviderQuote:          signedQuote,
		AgreementBodyDigest:    digest("f"),
		AgreementExpiresAtUnix: uint64(now.Add(7 * time.Minute).Unix()), RelayObligationID: "obligation:relay",
		FeeObligationIDs: []string{"obligation:relay-fee"}, UnderlyingActionRequest: underlyingRequest,
		SemanticFields: wireFields, AuthorizedAction: action, WriterFence: fence, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(3 * time.Minute).Unix())}
	execution = attachRelayTestAdmission(t, execution, authorityKey, now, 1)
	admissionAuthority.remember(t, execution)
	return &relayFixture{now: now, clientKey: clientKey, providerKey: providerKey, authorityKey: authorityKey,
		resolver: resolver, admissionAuthority: admissionAuthority, profile: profile, request: signedRequest,
		inspector: inspector, execution: execution, service: service}
}

func finalityPointer(profile FinalityProfile) *FinalityProfile { return &profile }

func relayBoolPointer(value bool) *bool { return &value }

func attachRelayTestAdmission(t *testing.T, request RelayExecutionRequest, authorityKey relayAuthorityKey,
	issuedAt time.Time, sequence uint64) RelayExecutionRequest {
	t.Helper()
	descriptor, err := BuildRelaySideEffectAdmissionDescriptorForPrincipal(request, "principal:openfox-client")
	if err != nil {
		t.Fatal(err)
	}
	startNotAfter := uint64(issuedAt.Add(30 * time.Second).Unix())
	if startNotAfter > descriptor.StartNotAfterCapUnix {
		startNotAfter = descriptor.StartNotAfterCapUnix
	}
	body, err := BuildRelaySideEffectAdmissionReceiptBody(descriptor, sequence,
		uint64(issuedAt.Unix()), startNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signTestReceipt(body, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	request.AdmissionReceipt = receipt
	return request
}

func (fixture *relayFixture) withAdmission(t *testing.T, request RelayExecutionRequest) RelayExecutionRequest {
	t.Helper()
	request = attachRelayTestAdmission(t, request, fixture.authorityKey, fixture.now, 1)
	fixture.admissionAuthority.remember(t, request)
	return request
}

func cloneRelayAgreementBody(body agentcommerce.AgentAgreementBody) agentcommerce.AgentAgreementBody {
	cloned := body
	cloned.Participants = append([]agentcommerce.AgreementParticipant(nil), body.Participants...)
	for index := range cloned.Participants {
		cloned.Participants[index].Roles = append([]string(nil), body.Participants[index].Roles...)
	}
	cloned.Terms = append([]byte(nil), body.Terms...)
	cloned.Obligations = append([]agentcommerce.AgreementObligation(nil), body.Obligations...)
	for index := range cloned.Obligations {
		cloned.Obligations[index].Subject = append([]byte(nil), body.Obligations[index].Subject...)
		cloned.Obligations[index].SettlementParameters = append([]byte(nil), body.Obligations[index].SettlementParameters...)
		cloned.Obligations[index].AuthorizationPredicateIDs = append([]string(nil),
			body.Obligations[index].AuthorizationPredicateIDs...)
	}
	cloned.AuthorizationPredicates = append([]agentcommerce.AgreementAuthorizationPredicate(nil),
		body.AuthorizationPredicates...)
	for index := range cloned.AuthorizationPredicates {
		cloned.AuthorizationPredicates[index].RoleScope = append([]string(nil), body.AuthorizationPredicates[index].RoleScope...)
		cloned.AuthorizationPredicates[index].ObligationIDs = append([]string(nil), body.AuthorizationPredicates[index].ObligationIDs...)
	}
	return cloned
}

func (fixture *relayFixture) agreement(t *testing.T, quote SignedProviderRelayQuote) agentcommerce.AgentAgreement {
	t.Helper()
	binding, err := CompileRelayAgreementBinding(fixture.request, quote)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := RelayAgreementBindingBytes(binding)
	amount := quote.Body.FeeLines[0].Amount
	body := agentcommerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:relay-service", Version: 1,
		NetworkContext: "tos:testnet", Participants: []agentcommerce.AgreementParticipant{
			{AgentID: "agent:client", Roles: []string{"client"}}, {AgentID: "agent:provider", Roles: []string{"provider"}}},
		TermsContentType: AgreementBindingContentType, Terms: subject,
		Obligations: []agentcommerce.AgreementObligation{
			{ObligationID: "obligation:relay", Kind: ObligationRelayDelivery, ObligorAgentID: "agent:provider", BeneficiaryAgentID: "agent:client",
				SubjectContentType: AgreementBindingContentType, Subject: subject, ConfidentialityPolicy: "participants",
				CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1", AuthorizationPredicateIDs: []string{"predicate:provider"}},
			{ObligationID: "obligation:relay-fee", Kind: ObligationRelayFee, ObligorAgentID: "agent:client", BeneficiaryAgentID: "agent:provider",
				SubjectContentType: AgreementBindingContentType, Subject: subject,
				Amount: &agentcommerce.AgreementAmount{AssetNamespace: amount.Asset.AssetNamespace, AssetIdentifier: amount.Asset.AssetIdentifier,
					AmountAtomic: amount.AmountAtomic, Unit: amount.Asset.Unit}, ConfidentialityPolicy: "participants",
				CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1", SettlementAdapterURI: DirectPaymentAdapterURI,
				SettlementParameters: []byte("destination=provider"), AuthorizationPredicateIDs: []string{"predicate:client"}}},
		AuthorizationPredicates: []agentcommerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:client", AuthoritySubject: agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:client"},
				RoleScope: []string{"client"}, ObligationIDs: []string{"obligation:relay-fee"}, EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:provider"},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"obligation:relay"}, EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())}},
		ValidFromUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(fixture.now.Add(7 * time.Minute).Unix())}
	body, err = agentcommerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest, _ := agentcommerce.AgreementBodyDigest(body)
	var evidence []agentcommerce.AgreementAuthorizationEvidence
	for index, key := range []ed25519.PrivateKey{fixture.clientKey, fixture.providerKey} {
		predicate := body.AuthorizationPredicates[index]
		acceptance, signErr := agentcommerce.SignAgreementAcceptance(agentcommerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
			AgreementVersion: body.Version, AgreementBodyDigest: bodyDigest, AcceptingSubject: predicate.AuthoritySubject,
			AcceptedRoles: predicate.RoleScope, PredicateIDs: []string{predicate.PredicateID},
			EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest}, ExpiresAtUnix: predicate.ExpiresAtUnix}, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		converted, evidenceErr := agentcommerce.AgentSignatureEvidence(body, acceptance)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		evidence = append(evidence, converted)
	}
	return agentcommerce.AgentAgreement{Body: body, AuthorizationEvidence: evidence}
}

func (fixture *relayFixture) takeoverFence(t *testing.T) agentcommerce.WriterFence {
	t.Helper()
	body := fixture.execution.WriterFence.Body
	body.InstanceID = "instance:takeover"
	body.LeaseID = "lease:takeover"
	body.WriterGeneration++
	body.IssuedAtUnix = uint64(fixture.now.Unix())
	fence, err := signTestFence(body, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return fence
}

func (fixture *relayFixture) takeover(t *testing.T, generation uint64) RelayExecutionRequest {
	t.Helper()
	fence, err := signTestFence(agentcommerce.WriterFenceBody{SchemaVersion: 1,
		OwnerID: "owner:client", AgentID: "agent:client", InstanceID: "instance:takeover", LeaseID: "lease:takeover",
		WriterGeneration: generation, IssuedAtUnix: uint64(fixture.now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(fixture.now.Add(10 * time.Minute).Unix()), AuthorityID: "authority:client",
		Scope: []string{"payment.direct"}}, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := agentcommerce.ImportSemanticFields("payment.direct", fixture.execution.SemanticFields)
	if err != nil {
		t.Fatal(err)
	}
	action, err := agentcommerce.BuildAuthorizedAction("owner:client", "agent:client", "payment.direct", fields,
		fixture.execution.UnderlyingActionRequest, fence, 1, digest("c"), "", "unknown",
		uint64(fixture.now.Add(8*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = signTestAction(action, fixture.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.execution
	result.WriterFence, result.AuthorizedAction = fence, action
	return result
}

func sponsorshipProfile(base RelayServiceProfile, perRequest, outstanding string) RelayServiceProfile {
	profile := base
	profile.SupportedModes = []Mode{ModeRelayExact, ModeSponsorAndRelay, ModeSponsorOnly}
	clientCorroborated := base.FinalityProfiles[0]
	clientCorroborated.ProfileURI = ClientCorroboratedTerminalProfileURI
	clientCorroborated.ProfileDigest = digest("9")
	clientCorroborated.TerminalEvidenceClass = SponsorshipTerminalClientCorroborated
	profile.FinalityProfiles = append(append([]FinalityProfile(nil), base.FinalityProfiles...), clientCorroborated)
	profile.ExposureLimits = []ExposureLimit{{Asset: base.ExposureLimits[0].Asset,
		MaximumPerRequestAtomic: perRequest, MaximumOutstandingAtomic: outstanding}}
	return profile
}

func testSponsorshipFinality(profile RelayServiceProfile, assurance AssuranceLevel) FinalityProfile {
	if assurance != AssuranceAutonomousDecentralized {
		for _, candidate := range profile.FinalityProfiles {
			if candidate.ProfileURI == ClientCorroboratedTerminalProfileURI {
				return candidate
			}
		}
	}
	return profile.FinalityProfiles[0]
}

func sponsorshipQuotePair(t *testing.T, fixture *relayFixture, profile RelayServiceProfile, requestID, quoteID,
	amountAtomic string, quoteExpiry time.Time) (SignedRelayQuoteRequest, SignedProviderRelayQuote) {
	t.Helper()
	amount := AssetAmount{Asset: profile.ExposureLimits[0].Asset, AmountAtomic: amountAtomic}
	requestBody := fixture.request.Body
	requestBody.RequestID = requestID
	requestBody.Mode = ModeSponsorOnly
	requestBody.AssuranceLevel = profile.SupportedAssuranceLevels[0]
	finality := testSponsorshipFinality(profile, requestBody.AssuranceLevel)
	requestBody.RelayFinalityProfileURI = ""
	requestBody.RelayFinalityProfileDigest = ""
	requestBody.RelayTerminalEvidenceClass = ""
	requestBody.SponsorshipTerminalProfileURI = finality.ProfileURI
	requestBody.SponsorshipTerminalProfileDigest = finality.ProfileDigest
	requestBody.SponsorshipTerminalEvidenceClass = finality.TerminalEvidenceClass
	requestBody.RequestedSponsorship = &amount
	setTestSponsorshipRelease(&requestBody)
	request, err := SignRelayQuoteRequest(requestBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := RelayQuoteRequestDigest(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := RelayServiceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	quoteBody := ProviderRelayQuoteBody{SchemaVersion: 1, QuoteID: quoteID, QuoteRequestDigest: requestDigest,
		ServiceProfileDigest: profileDigest, ProviderAgentID: profile.ProviderAgentID, Mode: ModeSponsorOnly,
		AssuranceLevel:                   requestBody.AssuranceLevel,
		SponsorshipReleaseEvidenceClass:  requestBody.SponsorshipReleaseEvidenceClass,
		SponsorshipReleaseProfileURI:     requestBody.SponsorshipReleaseProfileURI,
		SponsorshipReleaseProfileDigest:  requestBody.SponsorshipReleaseProfileDigest,
		SponsorshipTerminalEvidenceClass: requestBody.SponsorshipTerminalEvidenceClass,
		FeeLines:                         []FeeLine{{Kind: ObligationSponsorshipFee, Amount: AssetAmount{Asset: amount.Asset, AmountAtomic: "1"}}},
		ReservedSponsorship:              &amount,
		MaximumNetworkFeeAtomic:          requestBody.MaximumNetworkFeeAtomic, MaximumTransactionValueAtomic: requestBody.MaximumTransactionValueAtomic,
		MaximumRequestBytes: profile.MaximumRequestBytes, SponsorshipTerminalProfile: finalityPointer(finality),
		StatusEndpoint: profile.Endpoints.ResolveURL, ProviderPolicyRevision: profile.PolicyRevision,
		ValidFromUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(quoteExpiry.Unix())}
	quote, err := SignProviderRelayQuote(quoteBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	return request, quote
}

func resignRelayQuote(t *testing.T, quote SignedProviderRelayQuote, key ed25519.PrivateKey, quoteID string,
	expires time.Time) SignedProviderRelayQuote {
	t.Helper()
	body := quote.Body
	body.QuoteID = quoteID
	body.ExpiresAtUnix = uint64(expires.Unix())
	result, err := SignProviderRelayQuote(body, key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func sponsorshipExecution(base RelayExecutionRequest, request SignedRelayQuoteRequest,
	quote SignedProviderRelayQuote) RelayExecutionRequest {
	execution := base
	execution.QuoteRequest = request
	execution.ProviderQuote = quote
	execution.RelayObligationID = ""
	execution.SponsorshipObligationID = "obligation:sponsorship"
	execution.FeeObligationIDs = []string{"obligation:sponsorship-fee"}
	return execution
}

func combinedQuotePair(t *testing.T, fixture *relayFixture, profile RelayServiceProfile, requestID, quoteID,
	amountAtomic string) (SignedRelayQuoteRequest, SignedProviderRelayQuote) {
	t.Helper()
	amount := AssetAmount{Asset: profile.ExposureLimits[0].Asset, AmountAtomic: amountAtomic}
	requestBody := fixture.request.Body
	requestBody.RequestID = requestID
	requestBody.Mode = ModeSponsorAndRelay
	requestBody.AssuranceLevel = profile.SupportedAssuranceLevels[0]
	sponsorshipFinality := testSponsorshipFinality(profile, requestBody.AssuranceLevel)
	requestBody.RelayTerminalEvidenceClass = profile.FinalityProfiles[0].TerminalEvidenceClass
	requestBody.SponsorshipTerminalProfileURI = sponsorshipFinality.ProfileURI
	requestBody.SponsorshipTerminalProfileDigest = sponsorshipFinality.ProfileDigest
	requestBody.SponsorshipTerminalEvidenceClass = sponsorshipFinality.TerminalEvidenceClass
	requestBody.RequestedSponsorship = &amount
	setTestSponsorshipRelease(&requestBody)
	request, err := SignRelayQuoteRequest(requestBody, fixture.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := RelayQuoteRequestDigest(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := RelayServiceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	quoteBody := ProviderRelayQuoteBody{SchemaVersion: 1, QuoteID: quoteID, QuoteRequestDigest: requestDigest,
		ServiceProfileDigest: profileDigest, ProviderAgentID: profile.ProviderAgentID, Mode: ModeSponsorAndRelay,
		AssuranceLevel:                   requestBody.AssuranceLevel,
		SponsorshipReleaseEvidenceClass:  requestBody.SponsorshipReleaseEvidenceClass,
		SponsorshipReleaseProfileURI:     requestBody.SponsorshipReleaseProfileURI,
		SponsorshipReleaseProfileDigest:  requestBody.SponsorshipReleaseProfileDigest,
		RelayTerminalEvidenceClass:       requestBody.RelayTerminalEvidenceClass,
		SponsorshipTerminalEvidenceClass: requestBody.SponsorshipTerminalEvidenceClass,
		FeeLines: []FeeLine{
			{Kind: ObligationSponsorshipFee, Amount: AssetAmount{Asset: amount.Asset, AmountAtomic: "1"}},
			{Kind: ObligationRelayFee, Amount: AssetAmount{Asset: amount.Asset, AmountAtomic: "1"}},
		}, ReservedSponsorship: &amount,
		MaximumNetworkFeeAtomic: requestBody.MaximumNetworkFeeAtomic, MaximumTransactionValueAtomic: requestBody.MaximumTransactionValueAtomic,
		MaximumRequestBytes:        profile.MaximumRequestBytes,
		RelayFinalityProfile:       finalityPointer(profile.FinalityProfiles[0]),
		SponsorshipTerminalProfile: finalityPointer(sponsorshipFinality),
		StatusEndpoint:             profile.Endpoints.ResolveURL, ProviderPolicyRevision: profile.PolicyRevision,
		ValidFromUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(fixture.now.Add(4 * time.Minute).Unix())}
	quote, err := SignProviderRelayQuote(quoteBody, fixture.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	return request, quote
}

func setTestSponsorshipRelease(body *RelayQuoteRequestBody) {
	if body.AssuranceLevel == AssuranceAutonomousDecentralized {
		body.SponsorshipReleaseEvidenceClass = SponsorshipReleaseValidatorFinality
		body.SponsorshipReleaseProfileURI = body.SponsorshipTerminalProfileURI
		body.SponsorshipReleaseProfileDigest = body.SponsorshipTerminalProfileDigest
		return
	}
	body.SponsorshipReleaseEvidenceClass = SponsorshipReleaseObservedUnproven
	body.SponsorshipReleaseProfileURI = RPCCorroborationEvidenceProfileURI
	body.SponsorshipReleaseProfileDigest = digest("c")
}

func combinedExecution(base RelayExecutionRequest, request SignedRelayQuoteRequest,
	quote SignedProviderRelayQuote) RelayExecutionRequest {
	execution := base
	execution.QuoteRequest = request
	execution.ProviderQuote = quote
	execution.RelayObligationID = "obligation:relay"
	execution.SponsorshipObligationID = "obligation:sponsorship"
	execution.FeeObligationIDs = []string{"obligation:relay-fee", "obligation:sponsorship-fee"}
	return execution
}

func sponsorshipAgreement(t *testing.T, fixture *relayFixture, request SignedRelayQuoteRequest,
	quote SignedProviderRelayQuote) agentcommerce.AgentAgreement {
	t.Helper()
	binding, err := CompileRelayAgreementBinding(request, quote)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := RelayAgreementBindingBytes(binding)
	if err != nil {
		t.Fatal(err)
	}
	sponsorship := quote.Body.ReservedSponsorship
	fee := quote.Body.FeeLines[0].Amount
	body := agentcommerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:sponsorship-service", Version: 1,
		NetworkContext: "tos:testnet", Participants: []agentcommerce.AgreementParticipant{
			{AgentID: "agent:client", Roles: []string{"client"}}, {AgentID: "agent:provider", Roles: []string{"provider"}}},
		TermsContentType: AgreementBindingContentType, Terms: subject,
		Obligations: []agentcommerce.AgreementObligation{
			{ObligationID: "obligation:sponsorship", Kind: ObligationSponsorDelivery, ObligorAgentID: "agent:provider", BeneficiaryAgentID: "agent:client",
				SubjectContentType: AgreementBindingContentType, Subject: subject,
				Amount: &agentcommerce.AgreementAmount{AssetNamespace: sponsorship.Asset.AssetNamespace, AssetIdentifier: sponsorship.Asset.AssetIdentifier,
					AmountAtomic: sponsorship.AmountAtomic, Unit: sponsorship.Asset.Unit}, ConfidentialityPolicy: "participants",
				CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1", SettlementAdapterURI: DirectPaymentAdapterURI,
				SettlementParameters: []byte("destination=client"), AuthorizationPredicateIDs: []string{"predicate:provider"}},
			{ObligationID: "obligation:sponsorship-fee", Kind: ObligationSponsorshipFee, ObligorAgentID: "agent:client", BeneficiaryAgentID: "agent:provider",
				SubjectContentType: AgreementBindingContentType, Subject: subject,
				Amount: &agentcommerce.AgreementAmount{AssetNamespace: fee.Asset.AssetNamespace, AssetIdentifier: fee.Asset.AssetIdentifier,
					AmountAtomic: fee.AmountAtomic, Unit: fee.Asset.Unit}, ConfidentialityPolicy: "participants",
				CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1", SettlementAdapterURI: DirectPaymentAdapterURI,
				SettlementParameters: []byte("destination=provider"), AuthorizationPredicateIDs: []string{"predicate:client"}},
		},
		AuthorizationPredicates: []agentcommerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:client", AuthoritySubject: agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:client"},
				RoleScope: []string{"client"}, ObligationIDs: []string{"obligation:sponsorship-fee"}, EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:provider"},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"obligation:sponsorship"}, EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())}},
		ValidFromUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(fixture.now.Add(7 * time.Minute).Unix())}
	body, err = agentcommerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest, err := agentcommerce.AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	evidence := make([]agentcommerce.AgreementAuthorizationEvidence, 0, len(body.AuthorizationPredicates))
	keys := []ed25519.PrivateKey{fixture.clientKey, fixture.providerKey}
	for index, predicate := range body.AuthorizationPredicates {
		acceptance, signErr := agentcommerce.SignAgreementAcceptance(agentcommerce.AgreementAcceptanceBody{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: bodyDigest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: predicate.ExpiresAtUnix}, keys[index])
		if signErr != nil {
			t.Fatal(signErr)
		}
		converted, evidenceErr := agentcommerce.AgentSignatureEvidence(body, acceptance)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		evidence = append(evidence, converted)
	}
	return agentcommerce.AgentAgreement{Body: body, AuthorizationEvidence: evidence}
}

func combinedAgreement(t *testing.T, fixture *relayFixture, request SignedRelayQuoteRequest,
	quote SignedProviderRelayQuote) agentcommerce.AgentAgreement {
	t.Helper()
	binding, err := CompileRelayAgreementBinding(request, quote)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := RelayAgreementBindingBytes(binding)
	if err != nil {
		t.Fatal(err)
	}
	sponsorship := quote.Body.ReservedSponsorship
	fees := make(map[string]AssetAmount, len(quote.Body.FeeLines))
	for _, line := range quote.Body.FeeLines {
		fees[line.Kind] = line.Amount
	}
	agreementAmount := func(amount AssetAmount) *agentcommerce.AgreementAmount {
		return &agentcommerce.AgreementAmount{AssetNamespace: amount.Asset.AssetNamespace,
			AssetIdentifier: amount.Asset.AssetIdentifier, AmountAtomic: amount.AmountAtomic, Unit: amount.Asset.Unit}
	}
	body := agentcommerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:combined-relay-service", Version: 1,
		NetworkContext: "tos:testnet", Participants: []agentcommerce.AgreementParticipant{
			{AgentID: "agent:client", Roles: []string{"client"}}, {AgentID: "agent:provider", Roles: []string{"provider"}}},
		TermsContentType: AgreementBindingContentType, Terms: subject,
		Obligations: []agentcommerce.AgreementObligation{
			{ObligationID: "obligation:relay", Kind: ObligationRelayDelivery, ObligorAgentID: "agent:provider", BeneficiaryAgentID: "agent:client",
				SubjectContentType: AgreementBindingContentType, Subject: subject, ConfidentialityPolicy: "participants",
				CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1", AuthorizationPredicateIDs: []string{"predicate:provider"}},
			{ObligationID: "obligation:relay-fee", Kind: ObligationRelayFee, ObligorAgentID: "agent:client", BeneficiaryAgentID: "agent:provider",
				SubjectContentType: AgreementBindingContentType, Subject: subject, Amount: agreementAmount(fees[ObligationRelayFee]),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1",
				SettlementAdapterURI: DirectPaymentAdapterURI, SettlementParameters: []byte("destination=provider"),
				AuthorizationPredicateIDs: []string{"predicate:client"}},
			{ObligationID: "obligation:sponsorship", Kind: ObligationSponsorDelivery, ObligorAgentID: "agent:provider", BeneficiaryAgentID: "agent:client",
				SubjectContentType: AgreementBindingContentType, Subject: subject, Amount: agreementAmount(*sponsorship),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1",
				SettlementAdapterURI: DirectPaymentAdapterURI, SettlementParameters: []byte("destination=client"),
				AuthorizationPredicateIDs: []string{"predicate:provider"}},
			{ObligationID: "obligation:sponsorship-fee", Kind: ObligationSponsorshipFee, ObligorAgentID: "agent:client", BeneficiaryAgentID: "agent:provider",
				SubjectContentType: AgreementBindingContentType, Subject: subject, Amount: agreementAmount(fees[ObligationSponsorshipFee]),
				ConfidentialityPolicy: "participants", CancellationPolicy: "before-submit", DisputePolicy: "evidence-v1",
				SettlementAdapterURI: DirectPaymentAdapterURI, SettlementParameters: []byte("destination=provider"),
				AuthorizationPredicateIDs: []string{"predicate:client"}},
		},
		AuthorizationPredicates: []agentcommerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:client", AuthoritySubject: agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:client"},
				RoleScope: []string{"client"}, ObligationIDs: []string{"obligation:relay-fee", "obligation:sponsorship-fee"},
				EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
				EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:provider"},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"obligation:relay", "obligation:sponsorship"},
				EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
				EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: uint64(fixture.now.Add(6 * time.Minute).Unix())}},
		ValidFromUnix: uint64(fixture.now.Unix()), ExpiresAtUnix: uint64(fixture.now.Add(7 * time.Minute).Unix())}
	return authorizeRelayAgreement(t, fixture, body)
}

func authorizeRelayAgreement(t *testing.T, fixture *relayFixture,
	body agentcommerce.AgentAgreementBody) agentcommerce.AgentAgreement {
	t.Helper()
	prepared, err := agentcommerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest, err := agentcommerce.AgreementBodyDigest(prepared)
	if err != nil {
		t.Fatal(err)
	}
	evidence := make([]agentcommerce.AgreementAuthorizationEvidence, 0, len(prepared.AuthorizationPredicates))
	keys := []ed25519.PrivateKey{fixture.clientKey, fixture.providerKey}
	for index, predicate := range prepared.AuthorizationPredicates {
		acceptance, signErr := agentcommerce.SignAgreementAcceptance(agentcommerce.AgreementAcceptanceBody{
			AgreementID: prepared.AgreementID, AgreementVersion: prepared.Version, AgreementBodyDigest: bodyDigest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: predicate.ExpiresAtUnix}, keys[index])
		if signErr != nil {
			t.Fatal(signErr)
		}
		converted, evidenceErr := agentcommerce.AgentSignatureEvidence(prepared, acceptance)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		evidence = append(evidence, converted)
	}
	return agentcommerce.AgentAgreement{Body: prepared, AuthorizationEvidence: evidence}
}

func partialSponsorshipEvidence(record Record, observedAt time.Time) RelayFinalityEvidenceBody {
	request := record.ExecutionRequest()
	return RelayFinalityEvidenceBody{SchemaVersion: 1, ProviderAgentID: record.ProviderAgentID,
		Network: request.QuoteRequest.Body.Network, AssuranceLevel: request.QuoteRequest.Body.AssuranceLevel,
		StableActionID:     record.StableActionID,
		ExactRequestDigest: record.ExactRequestDigest, RelayExecutionDigest: record.RelayExecutionDigest,
		SignedTransactionDigest:   request.QuoteRequest.Body.SignedTransactionDigest,
		SignedTransactionCellHash: request.QuoteRequest.Body.SignedTransactionCellHash,
		TransactionValidUntilUnix: request.QuoteRequest.Body.TransactionValidUntilUnix,
		SourceAccount:             request.QuoteRequest.Body.SourceAccount, SourceSequence: request.QuoteRequest.Body.SourceSequence,
		SponsorshipStableActionID:      record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest:  record.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:      record.SponsorshipValidUntilUnix,
		SponsorshipTransferReference:   record.SponsorshipTransferReference,
		SponsorshipTransactionEvidence: cloneSponsorshipTransactionEvidence(record.SponsorshipTransactionEvidence),
		SponsorshipTerminalProfile:     request.ProviderQuote.Body.SponsorshipTerminalProfile,
		Outcome:                        OutcomeFinalizedSponsorshipOnly, ObservedAtUnix: uint64(observedAt.Unix())}
}

func sponsorshipAbsenceEvidence(record Record, observedAt time.Time, sponsorshipObservations,
	transactionObservations []RelayAbsenceObservationReference) RelayFinalityEvidenceBody {
	request := record.ExecutionRequest()
	body := RelayFinalityEvidenceBody{SchemaVersion: 1, ProviderAgentID: record.ProviderAgentID,
		Network: request.QuoteRequest.Body.Network, AssuranceLevel: request.QuoteRequest.Body.AssuranceLevel,
		StableActionID:     record.StableActionID,
		ExactRequestDigest: record.ExactRequestDigest, RelayExecutionDigest: record.RelayExecutionDigest,
		SignedTransactionDigest:        request.QuoteRequest.Body.SignedTransactionDigest,
		SignedTransactionCellHash:      request.QuoteRequest.Body.SignedTransactionCellHash,
		TransactionValidUntilUnix:      request.QuoteRequest.Body.TransactionValidUntilUnix,
		SourceAccount:                  request.QuoteRequest.Body.SourceAccount,
		SourceSequence:                 request.QuoteRequest.Body.SourceSequence,
		SponsorshipStableActionID:      record.SponsorshipStableActionID,
		SponsorshipExactRequestDigest:  record.SponsorshipExactRequestDigest,
		SponsorshipValidUntilUnix:      record.SponsorshipValidUntilUnix,
		SponsorshipAbsenceObservations: sponsorshipObservations,
		TransactionAbsenceObservations: transactionObservations,
		SponsorshipTerminalProfile:     request.ProviderQuote.Body.SponsorshipTerminalProfile,
		RelayFinalityProfile:           request.ProviderQuote.Body.RelayFinalityProfile,
		Outcome:                        record.TerminalOutcome,
		ObservedAtUnix:                 uint64(observedAt.Unix())}
	attachTestAbsenceProofBundle(&body)
	return body
}

func attachTestAbsenceProofBundle(body *RelayFinalityEvidenceBody) {
	body.AbsenceProofBundleDigest, body.AbsenceProofBundle = testAbsenceProofBundle(
		body.SponsorshipAbsenceObservations, body.TransactionAbsenceObservations)
}

func testAbsenceProofBundle(sponsorship,
	transaction []RelayAbsenceObservationReference) (string, []byte) {
	payload, _ := codec.Marshal(map[string]interface{}{"schema": "tos.test.relay-absence-proof-payload.v1"})
	payloadDigest, _ := codec.DigestCanonical(RelayAbsenceProofPayloadDomainV1, payload)
	profileDigest, _ := RelayAbsenceTOSRPCProofProfileDigest()
	scope := RelayAbsenceProofDual
	if len(sponsorship) != 0 && len(transaction) == 0 {
		scope = RelayAbsenceProofSponsorshipOnly
	} else if len(sponsorship) == 0 && len(transaction) != 0 {
		scope = RelayAbsenceProofTransactionOnly
	}
	bundle, _ := codec.Marshal(RelayAbsenceProofBundleV1{SchemaVersion: 1, ProofScope: scope,
		ProofProfileURI: RelayAbsenceTOSRPCProofProfileURI, ProofProfileDigest: profileDigest,
		ProofPayloadDigest: payloadDigest, ProofPayload: payload,
		SponsorshipAbsenceObservations: append([]RelayAbsenceObservationReference(nil), sponsorship...),
		TransactionAbsenceObservations: append([]RelayAbsenceObservationReference(nil), transaction...)})
	digest, _ := RelayAbsenceProofBundleDigest(bundle)
	return digest, bundle
}

func relaySuccessEvidence(record Record, observedAt time.Time) RelayFinalityEvidenceBody {
	request := record.ExecutionRequest()
	body := RelayFinalityEvidenceBody{SchemaVersion: 1, ProviderAgentID: record.ProviderAgentID,
		Network: request.QuoteRequest.Body.Network, AssuranceLevel: request.QuoteRequest.Body.AssuranceLevel,
		StableActionID:     record.StableActionID,
		ExactRequestDigest: record.ExactRequestDigest, RelayExecutionDigest: record.RelayExecutionDigest,
		SignedTransactionDigest:    request.QuoteRequest.Body.SignedTransactionDigest,
		SignedTransactionCellHash:  request.QuoteRequest.Body.SignedTransactionCellHash,
		TransactionValidUntilUnix:  request.QuoteRequest.Body.TransactionValidUntilUnix,
		SourceAccount:              request.QuoteRequest.Body.SourceAccount,
		SourceSequence:             request.QuoteRequest.Body.SourceSequence,
		SubmittedTransactionHash:   record.TransactionReference,
		SourceExecutionReference:   "chain:execution:durable",
		RelayTerminalEvidenceClass: request.QuoteRequest.Body.RelayTerminalEvidenceClass,
		RelayValidatorAuthenticatedPortableProof: relayBoolPointer(request.QuoteRequest.Body.RelayTerminalEvidenceClass ==
			RelayTerminalValidatorFinality),
		RelayFinalizedCheckpointID:       "checkpoint:relay-success",
		RelayFinalizedCheckpointSequence: 1,
		RelayFinalizedCheckpointUnix:     uint64(observedAt.Unix()),
		RelayFinalityProfile:             request.ProviderQuote.Body.RelayFinalityProfile,
		RelayObservationDigests:          append([]string(nil), record.EvidenceRefs...),
		Outcome:                          record.TerminalOutcome,
		ObservedAtUnix:                   uint64(observedAt.Unix())}
	if request.ProviderQuote.Body.RelayFinalityProfile != nil {
		body.RelayConfirmationDepth = request.ProviderQuote.Body.RelayFinalityProfile.MinimumConfirmationDepth
	} else {
		body.RelayTerminalEvidenceClass = ""
		body.RelayValidatorAuthenticatedPortableProof = nil
		body.RelayFinalizedCheckpointID = ""
		body.RelayFinalizedCheckpointSequence = 0
		body.RelayFinalizedCheckpointUnix = 0
		body.RelayObservationDigests = nil
	}
	if record.SponsorshipTransactionEvidence != nil {
		evidence := *record.SponsorshipTransactionEvidence
		body.SponsorshipStableActionID = record.SponsorshipStableActionID
		body.SponsorshipExactRequestDigest = record.SponsorshipExactRequestDigest
		body.SponsorshipValidUntilUnix = record.SponsorshipValidUntilUnix
		body.SponsorshipTransferReference = record.SponsorshipTransferReference
		body.SponsorshipTransactionEvidence = &evidence
		body.SponsorshipTerminalProfile = request.ProviderQuote.Body.SponsorshipTerminalProfile
	}
	return body
}

func authorizeRelayAgreementBody(t *testing.T, fixture *relayFixture,
	body agentcommerce.AgentAgreementBody) agentcommerce.AgentAgreement {
	t.Helper()
	for index := range body.AuthorizationPredicates {
		body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	prepared, err := agentcommerce.PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest, err := agentcommerce.AgreementBodyDigest(prepared)
	if err != nil {
		t.Fatal(err)
	}
	evidence := make([]agentcommerce.AgreementAuthorizationEvidence, 0, len(prepared.AuthorizationPredicates))
	for _, predicate := range prepared.AuthorizationPredicates {
		var key ed25519.PrivateKey
		switch predicate.AuthoritySubject.SubjectIdentifier {
		case "agent:client":
			key = fixture.clientKey
		case "agent:provider":
			key = fixture.providerKey
		default:
			t.Fatalf("unexpected Agreement authorizer %q", predicate.AuthoritySubject.SubjectIdentifier)
		}
		acceptance, signErr := agentcommerce.SignAgreementAcceptance(agentcommerce.AgreementAcceptanceBody{
			AgreementID: prepared.AgreementID, AgreementVersion: prepared.Version, AgreementBodyDigest: bodyDigest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: predicate.ExpiresAtUnix}, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		converted, evidenceErr := agentcommerce.AgentSignatureEvidence(prepared, acceptance)
		if evidenceErr != nil {
			t.Fatal(evidenceErr)
		}
		evidence = append(evidence, converted)
	}
	return agentcommerce.AgentAgreement{Body: prepared, AuthorizationEvidence: evidence}
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func sponsorshipRecoveryHandle(request RelayExecutionRequest, token string) SponsorshipRecoveryHandle {
	payment := sponsorshipPaymentRequest(request)
	paymentDigest, _ := agentcommerce.AgreementPaymentRequestDigest(payment)
	canonical, _, _ := agentcommerce.PaymentAuthorizationMaterial(payment)
	exactDigest, _ := agentcommerce.ExactRequestDigest(canonical)
	return SponsorshipRecoveryHandle{AgreementPaymentRequestDigest: paymentDigest,
		StableActionID: payment.StableActionID, ExactRequestDigest: exactDigest,
		ValidUntilUnix: payment.ExpiresAtUnix, OpaqueToken: []byte(token)}
}

func sponsorshipPaymentRequest(request RelayExecutionRequest) agentcommerce.AgreementPaymentRequest {
	reserved := *request.ProviderQuote.Body.ReservedSponsorship
	amount := agentcommerce.AgreementAmount{AssetNamespace: reserved.Asset.AssetNamespace,
		AssetIdentifier: reserved.Asset.AssetIdentifier, Unit: reserved.Asset.Unit,
		AmountAtomic: reserved.AmountAtomic}
	obligation := agentcommerce.SettlementObligation{AgreementBodyDigest: request.AgreementBodyDigest,
		AgreementObligationID: request.SponsorshipObligationID, ObligationInstanceID: digest("6"), Sequence: 1,
		PayerAgentID: request.QuoteRequest.Body.ProviderAgentID, PayeeAgentID: request.QuoteRequest.Body.RequesterAgentID,
		Amount: amount, MaximumAggregateAmount: amount, ExpiresAtUnix: request.ExpiresAtUnix,
		SettlementAdapterURI: DirectPaymentAdapterURI, SettlementParametersDigest: digest("5"), StableActionID: digest("4")}
	networkDigest, _ := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	payment, _ := agentcommerce.BuildDomainBoundAgreementPaymentRequest("owner:provider",
		request.QuoteRequest.Body.ProviderAgentID, request.QuoteRequest.Body.Network.NetworkID, networkDigest,
		[]byte(request.QuoteRequest.Body.SourceAccount), obligation)
	return payment
}

func sponsorshipTransactionEvidence(request RelayExecutionRequest, recovery SponsorshipRecoveryHandle,
	observedAt time.Time) RelaySponsorshipTransactionEvidence {
	payment := sponsorshipPaymentRequest(request)
	networkDigest, _ := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	proofBundle, _ := codec.Marshal(map[string]any{"schema": "tos.test.sponsorship-proof-bundle.v1",
		"stable_action_id": recovery.StableActionID})
	proofBundleDigest, _ := RelaySponsorshipProofBundleDigest(proofBundle)
	portable := ""
	if request.QuoteRequest.Body.AssuranceLevel == AssuranceAutonomousDecentralized {
		portable = "content:sha256:" + strings.Repeat("e", 64)
	}
	terminalProfile := request.ProviderQuote.Body.SponsorshipTerminalProfile
	terminalClass := terminalProfile.TerminalEvidenceClass
	return RelaySponsorshipTransactionEvidence{SchemaVersion: 1,
		TerminalEvidenceClass:               terminalClass,
		ValidatorAuthenticatedPortableProof: terminalClass == SponsorshipTerminalValidatorFinality,
		NetworkDigest:                       networkDigest,
		AgreementPaymentRequest:             payment, AgreementPaymentRequestDigest: recovery.AgreementPaymentRequestDigest,
		SponsorshipStableActionID: recovery.StableActionID, SponsorshipExactRequestDigest: recovery.ExactRequestDigest,
		ProviderSponsorSourceAccount: "account:provider", ProviderSponsorSourceSequence: 7,
		ProviderSponsorValidUntilUnix: recovery.ValidUntilUnix, SignedTopUpTransactionDigest: digest("a"),
		SignedTopUpTransactionCellHash:       "tvm-cell-sha256:" + strings.Repeat("b", 64),
		SponsorshipPaymentCommitmentCellHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
		DestinationSourceAccount:             request.QuoteRequest.Body.SourceAccount,
		Amount:                               *request.ProviderQuote.Body.ReservedSponsorship, SubmittedTransactionHash: "sponsorship:final",
		SourceExecutionReference:    "execution:sponsorship:final",
		DestinationCreditReferences: []string{digest("1"), digest("2"), digest("3")},
		FinalizedCheckpointID:       "checkpoint:sponsorship", FinalizedCheckpointSequence: 9,
		FinalizedCheckpointUnix:          uint64(observedAt.Unix()),
		ConfirmationDepth:                terminalProfile.MinimumConfirmationDepth,
		SponsorshipTerminalProfileDigest: terminalProfile.ProfileDigest,
		ObservationDigests:               []string{digest("1"), digest("2"), digest("3")}, ProofBundleDigest: proofBundleDigest,
		ProofBundle:          proofBundle,
		PortableProofLocator: portable, ObservedAtUnix: uint64(observedAt.Unix())}
}

func sponsorshipCreditObservation(request RelayExecutionRequest, recovery SponsorshipRecoveryHandle,
	observedAt time.Time) RelaySponsorshipCreditObservation {
	payment := sponsorshipPaymentRequest(request)
	networkDigest, _ := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	return RelaySponsorshipCreditObservation{SchemaVersion: 1, NetworkDigest: networkDigest,
		AgreementPaymentRequest: payment, AgreementPaymentRequestDigest: recovery.AgreementPaymentRequestDigest,
		SponsorshipStableActionID: recovery.StableActionID, SponsorshipExactRequestDigest: recovery.ExactRequestDigest,
		ProviderSponsorSourceAccount: "account:provider", ProviderSponsorSourceSequence: 7,
		ProviderSponsorValidUntilUnix: recovery.ValidUntilUnix, SignedTopUpTransactionDigest: digest("a"),
		SignedTopUpTransactionCellHash:       "tvm-cell-sha256:" + strings.Repeat("b", 64),
		SponsorshipPaymentCommitmentCellHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
		DestinationSourceAccount:             request.QuoteRequest.Body.SourceAccount,
		Amount:                               *request.ProviderQuote.Body.ReservedSponsorship, SubmittedTransactionHash: "sponsorship:final",
		SourceExecutionReference:    "execution:sponsorship:final",
		DestinationCreditReferences: []string{digest("1"), digest("2"), digest("3")},
		EvidenceProfileURI:          RPCCorroborationEvidenceProfileURI, EvidenceProfileDigest: digest("c"),
		ObservedCheckpointID: "checkpoint:rpc-observed", ObservedCheckpointSequence: 9,
		ObservedCheckpointUnix: uint64(observedAt.Unix()),
		ObservationDigests:     []string{digest("1"), digest("2"), digest("3")},
		ObservedAtUnix:         uint64(observedAt.Unix())}
}

func finalizedAbsentSponsorshipResolution(request RelayExecutionRequest,
	recovery SponsorshipRecoveryHandle) SponsorshipResolution {
	outcome := OutcomeFinalizedAbsent
	status := SponsorshipResolutionFinalizedAbsent
	if request.ProviderQuote.Body.SponsorshipTerminalProfile != nil &&
		request.ProviderQuote.Body.SponsorshipTerminalProfile.TerminalEvidenceClass ==
			SponsorshipTerminalClientCorroborated {
		outcome = OutcomeCorroboratedAbsent
		status = SponsorshipResolutionCorroboratedAbsent
	}
	sponsorship, transaction := absenceObservationReferences(request, recovery, outcome)
	if request.QuoteRequest.Body.Mode == ModeSponsorOnly {
		transaction = nil
	}
	bundleDigest, bundle := testAbsenceProofBundle(sponsorship, transaction)
	return SponsorshipResolution{Status: status,
		AbsenceOutcome: outcome, SponsorshipAbsenceObservations: sponsorship,
		TransactionAbsenceObservations: transaction,
		AbsenceProofBundleDigest:       bundleDigest, AbsenceProofBundle: bundle}
}

func absenceObservationReferences(request RelayExecutionRequest, recovery SponsorshipRecoveryHandle,
	outcome TerminalOutcome) ([]RelayAbsenceObservationReference, []RelayAbsenceObservationReference) {
	networkDigest, _ := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	executionDigest, _ := RelayExecutionRequestDigest(request)
	base := RelayAbsenceObservationReference{SchemaVersion: 1,
		ProviderAgentID: request.ProviderQuote.Body.ProviderAgentID, NetworkDigest: networkDigest,
		RelayStableActionID:     request.AuthorizedAction.StableActionID,
		RelayExactRequestDigest: request.AuthorizedAction.ExactRequestDigest,
		RelayExecutionDigest:    executionDigest, SponsorshipStableActionID: recovery.StableActionID,
		SponsorshipExactRequestDigest:    recovery.ExactRequestDigest,
		SponsorshipValidUntilUnix:        recovery.ValidUntilUnix,
		SignedTransactionDigest:          request.QuoteRequest.Body.SignedTransactionDigest,
		SignedTransactionCellHash:        request.QuoteRequest.Body.SignedTransactionCellHash,
		ObservationEvidenceProfileURI:    request.QuoteRequest.Body.SponsorshipReleaseProfileURI,
		ObservationEvidenceProfileDigest: request.QuoteRequest.Body.SponsorshipReleaseProfileDigest}
	makeSet := func(kind RelayAbsenceObservationKind, conclusion RelayAbsenceConclusion,
		prefix string, proofs []string) []RelayAbsenceObservationReference {
		profile := request.ProviderQuote.Body.SponsorshipTerminalProfile
		validUntil := recovery.ValidUntilUnix
		checkpointSequence := uint64(1)
		if kind == AbsenceObservationClientTransaction && request.ProviderQuote.Body.RelayFinalityProfile != nil {
			profile = request.ProviderQuote.Body.RelayFinalityProfile
		}
		if kind == AbsenceObservationClientTransaction {
			validUntil = request.QuoteRequest.Body.TransactionValidUntilUnix
			checkpointSequence = 2
		}
		checkpointUnix := validUntil + uint64(profile.ReorgWindowSeconds) + 1
		result := make([]RelayAbsenceObservationReference, 3)
		for index := range result {
			result[index] = base
			result[index].FinalizedCheckpointID = "checkpoint:absence:" + prefix
			result[index].FinalizedCheckpointSequence = checkpointSequence
			result[index].FinalizedCheckpointUnix = checkpointUnix
			result[index].ObservedAtUnix = checkpointUnix
			result[index].TerminalProfileURI = profile.ProfileURI
			result[index].TerminalProfileDigest = profile.ProfileDigest
			result[index].TerminalEvidenceClass = profile.TerminalEvidenceClass
			result[index].ObservationKind = kind
			result[index].Conclusion = conclusion
			result[index].ObserverID = "observer:" + prefix + ":" + string(rune('1'+index))
			result[index].OperatorDomainID = "operator-domain:" + string(rune('1'+index%2))
			result[index].ObservationDigest = digest(proofs[index])
		}
		sortRelayAbsenceObservationReferences(result)
		return result
	}
	return makeSet(AbsenceObservationSponsorshipAction, AbsenceConclusionExpiredWithoutInclusion, "sponsor", []string{"a", "b", "c"}),
		makeSet(AbsenceObservationClientTransaction, transactionConclusion(outcome), "transaction", []string{"d", "e", "f"})
}

func TestRelayEvidenceSetDigestBindsTheCanonicalObservationSet(t *testing.T) {
	first := []string{digest("1"), digest("2"), digest("3")}
	value, err := RelayEvidenceSetDigest(first)
	if err != nil || value == "" {
		t.Fatalf("canonical evidence set was rejected: digest=%q err=%v", value, err)
	}
	changed, err := RelayEvidenceSetDigest([]string{digest("1"), digest("2"), digest("4")})
	if err != nil || changed == value {
		t.Fatalf("evidence-set mutation did not change the commitment: digest=%q err=%v", changed, err)
	}
	for name, invalid := range map[string][]string{
		"empty":     nil,
		"unsorted":  {digest("2"), digest("1")},
		"duplicate": {digest("1"), digest("1")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RelayEvidenceSetDigest(invalid); err == nil {
				t.Fatal("invalid evidence set was accepted")
			}
		})
	}
}

func TestRelayAbsenceBundleRejectsNullEmptyAndInapplicableComponentFields(t *testing.T) {
	fixture := newRelayFixture(t)
	profile := sponsorshipProfile(fixture.profile, "50", "50")
	request, quote := sponsorshipQuotePair(t, fixture, profile, "request:presence", "quote:presence", "50",
		fixture.now.Add(4*time.Minute))
	execution := sponsorshipExecution(fixture.execution, request, quote)
	recovery := sponsorshipRecoveryHandle(execution, "presence-recovery")
	sponsorship, transaction := absenceObservationReferences(execution, recovery, OutcomeFinalizedAbsent)
	_, canonical := testAbsenceProofBundle(sponsorship, nil)
	if len(canonical) == 0 {
		t.Fatal("valid sponsorship-only absence bundle was not encoded")
	}
	if _, err := RelayAbsenceProofBundleDigest(canonical); err != nil {
		t.Fatalf("valid sponsorship-only absence bundle was rejected: %v", err)
	}
	var base map[string]interface{}
	if err := codec.Unmarshal(canonical, &base); err != nil {
		t.Fatal(err)
	}
	if _, present := base["transaction_absence_observations"]; present {
		t.Fatal("inapplicable transaction component was encoded in sponsorship-only bundle")
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"applicable null": func(fields map[string]interface{}) {
			fields["sponsorship_absence_observations"] = nil
		},
		"applicable empty": func(fields map[string]interface{}) {
			fields["sponsorship_absence_observations"] = []interface{}{}
		},
		"inapplicable null": func(fields map[string]interface{}) {
			fields["transaction_absence_observations"] = nil
		},
		"inapplicable empty": func(fields map[string]interface{}) {
			fields["transaction_absence_observations"] = []interface{}{}
		},
		"inapplicable populated": func(fields map[string]interface{}) {
			fields["transaction_absence_observations"] = transaction
		},
	} {
		t.Run(name, func(t *testing.T) {
			fields := make(map[string]interface{}, len(base)+1)
			for key, value := range base {
				fields[key] = value
			}
			mutate(fields)
			encoded, err := codec.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RelayAbsenceProofBundleDigest(encoded); err == nil {
				t.Fatal("invalid component field presence was accepted")
			}
		})
	}
}

func TestRelayEd25519TextEncodingIsCanonical(t *testing.T) {
	fixture := newRelayFixture(t)
	upperKey := "ed25519:" + strings.ToUpper(strings.TrimPrefix(fixture.request.PublicKey, "ed25519:"))
	if _, err := parsePublicKey(upperKey); err == nil {
		t.Fatal("uppercase Ed25519 public key text was accepted")
	}
	encoded := strings.TrimPrefix(fixture.request.Signature, "ed25519:")
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	if last < 0 {
		t.Fatal("test signature is not base64url")
	}
	// A 64-byte signature leaves two unused bits in the last base64url
	// character. Flip only those bits so permissive decoders recover the same
	// bytes; exact re-encoding must nevertheless reject the alternate spelling.
	alternate := encoded[:len(encoded)-1] + string(alphabet[(last&^3)|((last+1)&3)])
	if alternate == encoded {
		t.Fatal("failed to construct alternate base64url spelling")
	}
	if _, err := parseSignature("ed25519:" + alternate); err == nil {
		t.Fatal("non-canonical Ed25519 signature text was accepted")
	}
}
