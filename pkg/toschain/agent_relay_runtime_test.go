package toschain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type fixedFinalizedAgentAccountReader struct {
	account agentgift.FinalizedAgentAccount
	at      uint32
	err     error
}

func (reader fixedFinalizedAgentAccountReader) FinalizedAgentAccount(context.Context,
	string) (agentgift.FinalizedAgentAccount, uint32, error) {
	return reader.account, reader.at, reader.err
}

func TestAgentGiftFinalizedAgentAccountResolverRequiresOwnerPinnedPrincipal(t *testing.T) {
	fixture, _, key := loadRelayRustFixture(t)
	network := relayTestNetwork()
	account := agentgift.FinalizedAgentAccount{Active: true, Address: fixture.Account,
		OwnerAddress: fixture.Target, CodeHash: agentgift.AgentAccountCodeHash, DeploymentID: shaDigest("d"),
		GlobalID: fixture.GlobalID, TVMVersion: agentgift.MinimumAgentAccountTVMVersion,
		ControllerPublicKey: append(ed25519.PublicKey(nil), key...), ControllerEpoch: fixture.ControllerEpoch,
		Seqno: fixture.Seqno, BalanceAtomic: 1_000_000, MaxPerTxAtomic: 1_000_000,
		DailyRemainingAtomic: 1_000_000, DefaultTaskTimeoutSecs: 3_600}
	reader := fixedFinalizedAgentAccountReader{account: account, at: 1_900_000_000}
	resolver, err := newAgentGiftFinalizedAgentAccountResolver(reader, network,
		[]AgentAccountAgentBinding{{SourceAccount: fixture.Account, OwnerAddress: fixture.Target,
			AuthorizedAgentID: "agent:buyer"}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveFinalizedAgentAccount(t.Context(), network, fixture.Account)
	if err != nil || resolved.AuthorizedAgentID != "agent:buyer" || resolved.FinalizedTime != reader.at ||
		resolved.Account.Address != fixture.Account {
		t.Fatalf("wrong owner-pinned resolution: %+v err=%v", resolved, err)
	}

	reader.account.OwnerAddress = "0:" + strings.Repeat("f", 64)
	resolver.reader = reader
	if _, err := resolver.ResolveFinalizedAgentAccount(t.Context(), network, fixture.Account); err == nil {
		t.Fatal("changed on-chain owner retained the pinned Agent principal")
	}
	wrongNetwork := network
	wrongNetwork.GlobalID++
	if _, err := resolver.ResolveFinalizedAgentAccount(t.Context(), wrongNetwork, fixture.Account); err == nil {
		t.Fatal("cross-network account resolution was accepted")
	}
}

func TestAgentGiftFinalizedAgentAccountResolverRejectsDuplicateOrUnpinnedAccounts(t *testing.T) {
	fixture, _, _ := loadRelayRustFixture(t)
	network := relayTestNetwork()
	binding := AgentAccountAgentBinding{SourceAccount: fixture.Account, OwnerAddress: fixture.Target,
		AuthorizedAgentID: "agent:buyer"}
	if _, err := newAgentGiftFinalizedAgentAccountResolver(fixedFinalizedAgentAccountReader{}, network,
		[]AgentAccountAgentBinding{binding, binding}); err == nil {
		t.Fatal("duplicate account binding was accepted")
	}
	resolver, err := newAgentGiftFinalizedAgentAccountResolver(fixedFinalizedAgentAccountReader{}, network,
		[]AgentAccountAgentBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveFinalizedAgentAccount(t.Context(), network,
		"-1:"+strings.Repeat("e", 64)); err == nil {
		t.Fatal("unbound Agent Account was resolved")
	}
}

func TestProductionTOSRelayResolverBindsObserverProvenanceToConfiguredEndpoints(t *testing.T) {
	fixture, _, _ := loadRelayRustFixture(t)
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(http.ResponseWriter, *http.Request) {})
	adapter := relayTestAdapter(t, servers)
	network := relayTestNetwork()
	reader, err := NewAgentGiftReader(adapter, &nativev1.NetworkDomain{NetworkId: network.NetworkID,
		GenesisRootHash: network.ZeroStateRootHash, GenesisFileHash: network.ZeroStateFileHash})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := NewAgentGiftFinalizedAgentAccountResolver(reader, network,
		[]AgentAccountAgentBinding{{SourceAccount: fixture.Account, OwnerAddress: fixture.Target,
			AuthorizedAgentID: "agent:buyer"}})
	if err != nil {
		t.Fatal(err)
	}
	observers := testRelayObservers()
	for index := range observers {
		observers[index].EndpointAuthorityDigest, err = adapter.nodes[index].client.EndpointAuthorityDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTOSExactRelayResolutionSource(reader, accounts, network, observers,
		directory+"/relay.checkpoint"); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewTOSRelayFinalityVerifier(reader, accounts, network, observers,
		directory+"/client.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := TOSRelayCheckpointQuorumFinalityProfile(network, observers, 1, 2, 2, 0, 60)
	if err != nil {
		t.Fatal(err)
	}
	capability := agentrelay.RelayEvidenceCapability{Mode: agentrelay.ModeRelayExact,
		AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider, Network: network,
		TransactionProfileURI:    AgentAccountNativeSendRelayProfileURI,
		TransactionProfileDigest: AgentAccountNativeSendRelayProfileDigest(),
		UnderlyingActionKind:     "payment.direct", RelayTerminalEvidenceClass: profile.TerminalEvidenceClass,
		RelayFinalityProfile: &profile}
	opaque, err := verifier.FreezeRelayFinalityEvidenceSnapshot(t.Context(), capability)
	if err != nil || verifier.ValidateRelayFinalityEvidenceSnapshot(capability, opaque) != nil {
		t.Fatalf("production TOS verifier did not freeze its exact client RPC snapshot: %v", err)
	}
	mutated := append([]byte(nil), opaque...)
	mutated[len(mutated)-1] ^= 1
	if verifier.ValidateRelayFinalityEvidenceSnapshot(capability, mutated) == nil {
		t.Fatal("mutated client RPC snapshot was accepted")
	}

	// A new runtime may use a rotated endpoint set for new work while an old
	// admitted attempt continues to verify through its protected frozen bytes.
	var rotatedHits [3]atomic.Int32
	rotatedServers := relayRPCServers(t, &rotatedHits, func(http.ResponseWriter, *http.Request) {})
	rotatedAdapter := relayTestAdapter(t, rotatedServers)
	rotatedReader, err := NewAgentGiftReader(rotatedAdapter, &nativev1.NetworkDomain{NetworkId: network.NetworkID,
		GenesisRootHash: network.ZeroStateRootHash, GenesisFileHash: network.ZeroStateFileHash})
	if err != nil {
		t.Fatal(err)
	}
	rotatedAccounts, err := NewAgentGiftFinalizedAgentAccountResolver(rotatedReader, network,
		[]AgentAccountAgentBinding{{SourceAccount: fixture.Account, OwnerAddress: fixture.Target,
			AuthorizedAgentID: "agent:buyer"}})
	if err != nil {
		t.Fatal(err)
	}
	rotatedObservers := testRelayObservers()
	for index := range rotatedObservers {
		rotatedObservers[index].EndpointAuthorityDigest, err =
			rotatedAdapter.nodes[index].client.EndpointAuthorityDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	rotatedVerifier, err := NewTOSRelayFinalityVerifier(rotatedReader, rotatedAccounts, network,
		rotatedObservers, directory+"/client.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	if rotatedVerifier.SupportsRelayEvidenceCapability(capability) {
		t.Fatal("rotated runtime reinterpreted the old capability as its current config")
	}
	if err := rotatedVerifier.ValidateRelayFinalityEvidenceSnapshot(capability, opaque); err != nil {
		t.Fatalf("rotated runtime could not restore the old protected verification snapshot: %v", err)
	}

	// A process restarted with current network B must still reconstruct an
	// already-admitted network-A verifier from A's protected snapshot. Each full
	// network domain owns a distinct rollback high-water under the stable client
	// checkpoint base path; B cannot raise, fork, or replace A's fence.
	networkB := network
	networkB.NetworkID = "tos:other-testnet"
	networkB.GlobalID++
	networkB.ZeroStateRootHash = shaDigest("7")
	networkB.ZeroStateFileHash = shaDigest("8")
	networkBVerifier, err := newTOSRelayFinalityVerifier(&fixedExactRelayCheckpointReader{},
		networkB, testRelayObservers(), 2, directory+"/client.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	restoredA, err := networkBVerifier.verifierFromSnapshot(capability, opaque)
	if err != nil {
		t.Fatalf("network-B restart could not reconstruct frozen network-A verification: %v", err)
	}
	if restoredA.network != network || restoredA.checkpoint.path == networkBVerifier.checkpoint.path {
		t.Fatal("network-A recovery reused network B or its checkpoint namespace")
	}
	if err := restoredA.checkpoint.checkAndAdvance(10, "network-a:checkpoint:10"); err != nil {
		t.Fatal(err)
	}
	if err := networkBVerifier.checkpoint.checkAndAdvance(90, "network-b:checkpoint:90"); err != nil {
		t.Fatal(err)
	}
	restartedB, err := newTOSRelayFinalityVerifier(&fixedExactRelayCheckpointReader{},
		networkB, testRelayObservers(), 2, directory+"/client.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	restoredAAfterRestart, err := restartedB.verifierFromSnapshot(capability, opaque)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoredAAfterRestart.checkpoint.checkAndAdvance(9,
		"network-a:checkpoint:9"); err == nil {
		t.Fatal("network-A checkpoint rollback was accepted after a network-B restart")
	}
	if err := restartedB.checkpoint.checkAndAdvance(89,
		"network-b:checkpoint:89"); err == nil {
		t.Fatal("network-B checkpoint rollback was hidden by network-A recovery")
	}
	observers[0].EndpointAuthorityDigest = shaDigest("f")
	if _, err := NewTOSExactRelayResolutionSource(reader, accounts, network, observers,
		directory+"/other.checkpoint"); err == nil {
		t.Fatal("observer provenance was detached from the configured endpoint")
	}
}

type fixedExactRelayCheckpointReader struct {
	observation tosExactRelayObservation
	err         error
}

func (reader *fixedExactRelayCheckpointReader) ObserveExactAgentNativeSend(context.Context,
	agentrelay.Record) (tosExactRelayObservation, error) {
	return reader.observation, reader.err
}

func (reader *fixedExactRelayCheckpointReader) observeExactAgentNativeSendRequest(context.Context,
	agentrelay.RelayExecutionRequest) (tosExactRelayObservation, error) {
	return reader.observation, reader.err
}

func TestTOSExactRelayResolutionMapsOnlyCheckpointQuorumEvidenceToTerminal(t *testing.T) {
	record := relayRuntimeRecord(t)
	request := record.ExecutionRequest()
	reader := &fixedExactRelayCheckpointReader{observation: tosExactRelayObservation{
		CheckpointID: "tos-masterchain:11:" + shaDigest("1") + ":" + shaDigest("2"), CheckpointSequence: 11,
		DepthAnchorCheckpointID:       "tos-masterchain:10:" + shaDigest("3") + ":" + shaDigest("4"),
		DepthAnchorCheckpointSequence: 10, ObservedAtUnix: request.CreatedAtUnix + 30,
		Outcome: agentrelay.OutcomeFinalizedSuccess, TransactionReference: request.QuoteRequest.Body.SignedTransactionCellHash,
		SourceExecutionReference: "tos-transaction:-1:source:1", DestinationCreditReference: shaDigest("9"),
		AgreedObserverIndexes: []int{0, 1}}}
	source := newTestExactRelayResolutionSource(t, reader, request.QuoteRequest.Body.Network)
	resolution, err := source.ResolveExactRelay(t.Context(), record)
	if err != nil || resolution.State != agentcommerce.ActionTerminal ||
		resolution.TerminalOutcome != agentrelay.OutcomeCorroboratedSuccess ||
		resolution.TransactionReference != request.QuoteRequest.Body.SignedTransactionCellHash ||
		len(resolution.EvidenceRefs) != 2 || !sort.StringsAreSorted(resolution.EvidenceRefs) {
		t.Fatalf("wrong finalized relay resolution: %+v err=%v", resolution, err)
	}
	if resolution.EvidenceRefs[0] == resolution.EvidenceRefs[1] {
		t.Fatal("distinct owner-pinned observers collapsed into one evidence reference")
	}
	stored, err := source.Observation(resolution.EvidenceRefs[0])
	if err != nil {
		t.Fatal(err)
	}
	storedDigest, err := TOSRelayRPCObservationReferenceDigest(stored)
	if err != nil || storedDigest != resolution.EvidenceRefs[0] ||
		stored.SignedTransactionCellHash != request.QuoteRequest.Body.SignedTransactionCellHash {
		t.Fatalf("durable relay evidence did not reproduce its reference: %+v err=%v", stored, err)
	}
}

func TestTOSRelayFinalityEvidenceComesOnlyFromTerminalDurableObservations(t *testing.T) {
	record := relayRuntimeRecord(t)
	request := record.ExecutionRequest()
	reader := &fixedExactRelayCheckpointReader{observation: tosExactRelayObservation{
		CheckpointID: "tos-masterchain:31:" + shaDigest("1") + ":" + shaDigest("2"), CheckpointSequence: 31,
		DepthAnchorCheckpointID:       "tos-masterchain:30:" + shaDigest("3") + ":" + shaDigest("4"),
		DepthAnchorCheckpointSequence: 30, ObservedAtUnix: request.CreatedAtUnix + 30,
		Outcome: agentrelay.OutcomeFinalizedSuccess, TransactionReference: request.QuoteRequest.Body.SignedTransactionCellHash,
		SourceExecutionReference: "tos-transaction:-1:source:31", DestinationCreditReference: shaDigest("e"),
		AgreedObserverIndexes: []int{0, 1}}}
	source := newTestExactRelayResolutionSource(t, reader, request.QuoteRequest.Body.Network)
	resolution, err := source.ResolveExactRelay(t.Context(), record)
	if err != nil {
		t.Fatal(err)
	}
	terminal := restoreTerminalRelayRecord(t, record, resolution)
	// A different action may advance the global observation fence before this
	// archived terminal proof is first fetched. Historical evidence remains
	// valid and must not be compared to the moving high-water.
	if err := source.checkpoint.checkAndAdvance(reader.observation.CheckpointSequence+100,
		"tos-masterchain:newer:"+shaDigest("f")); err != nil {
		t.Fatal(err)
	}
	body, err := source.Evidence(t.Context(), terminal)
	if err != nil {
		t.Fatal(err)
	}
	// ProviderService owns this signature-authority timestamp; the chain
	// evidence source deliberately returns only observation material.
	body.SigningAuthorityAtUnix = body.ObservedAtUnix
	if body.RelayFinalizedCheckpointUnix != reader.observation.ObservedAtUnix ||
		body.ObservedAtUnix != reader.observation.ObservedAtUnix ||
		body.SubmittedTransactionHash != request.QuoteRequest.Body.SignedTransactionCellHash ||
		body.SourceExecutionReference != reader.observation.SourceExecutionReference ||
		len(body.DestinationCreditReferences) != 1 ||
		body.DestinationCreditReferences[0] != reader.observation.DestinationCreditReference ||
		len(body.RelayObservationDigests) != 2 {
		t.Fatalf("wrong terminal TOS relay evidence: %+v", body)
	}
	if _, err := agentrelay.RelayFinalityEvidenceDigest(body); err != nil {
		t.Fatalf("constructed TOS relay evidence is not protocol-valid: %v", err)
	}

	snapshot := terminal.Snapshot()
	snapshot.EvidenceRefs = snapshot.EvidenceRefs[:1]
	insufficient, err := agentrelay.RestoreRecord(snapshot, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Evidence(t.Context(), insufficient); err == nil {
		t.Fatal("terminal evidence below the frozen observer threshold was served")
	}
	snapshot = terminal.Snapshot()
	snapshot.TransactionReference = "tvm-cell-sha256:" + strings.Repeat("f", 64)
	substituted, err := agentrelay.RestoreRecord(snapshot, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Evidence(t.Context(), substituted); err == nil {
		t.Fatal("a substituted terminal transaction reference was served as exact finality evidence")
	}

	stored, err := source.Observation(terminal.EvidenceRefs[0])
	if err != nil {
		t.Fatal(err)
	}
	stored.StableActionID = shaDigest("f")
	substitutedDigest, err := source.evidence.put(stored)
	if err != nil {
		t.Fatal(err)
	}
	snapshot = terminal.Snapshot()
	snapshot.EvidenceRefs = []string{terminal.EvidenceRefs[1], substitutedDigest}
	sort.Strings(snapshot.EvidenceRefs)
	substituted, err = agentrelay.RestoreRecord(snapshot, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Evidence(t.Context(), substituted); err == nil {
		t.Fatal("an observation from a different semantic action was substituted into terminal evidence")
	}
}

func TestTOSRelayFinalityVerifierUsesClientOwnedExactQuorum(t *testing.T) {
	record := relayRuntimeRecord(t)
	request := record.ExecutionRequest()
	observation := tosExactRelayObservation{
		CheckpointID: "tos-masterchain:31:" + shaDigest("1") + ":" + shaDigest("2"), CheckpointSequence: 31,
		DepthAnchorCheckpointID:       "tos-masterchain:30:" + shaDigest("3") + ":" + shaDigest("4"),
		DepthAnchorCheckpointSequence: 30, ObservedAtUnix: request.CreatedAtUnix + 30,
		Outcome: agentrelay.OutcomeFinalizedSuccess, TransactionReference: request.QuoteRequest.Body.SignedTransactionCellHash,
		SourceExecutionReference: "tos-transaction:-1:source:31", DestinationCreditReference: shaDigest("e"),
		AgreedObserverIndexes: []int{0, 1}}
	provider := newTestExactRelayResolutionSource(t,
		&fixedExactRelayCheckpointReader{observation: observation}, request.QuoteRequest.Body.Network)
	resolution, err := provider.ResolveExactRelay(t.Context(), record)
	if err != nil {
		t.Fatal(err)
	}
	body, err := provider.Evidence(t.Context(), restoreTerminalRelayRecord(t, record, resolution))
	if err != nil {
		t.Fatal(err)
	}
	body.SigningAuthorityAtUnix = body.ObservedAtUnix
	clientReader := &fixedExactRelayCheckpointReader{observation: observation}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	verifier, err := newTOSRelayFinalityVerifier(clientReader, request.QuoteRequest.Body.Network,
		testRelayObservers(), 2, directory+"/client.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	capability := agentrelay.RelayEvidenceCapability{Mode: request.QuoteRequest.Body.Mode,
		AssuranceLevel: request.QuoteRequest.Body.AssuranceLevel, Network: request.QuoteRequest.Body.Network,
		TransactionProfileURI:      request.QuoteRequest.Body.TransactionProfileURI,
		TransactionProfileDigest:   request.QuoteRequest.Body.TransactionProfileDigest,
		UnderlyingActionKind:       request.QuoteRequest.Body.UnderlyingActionKind,
		RelayTerminalEvidenceClass: request.QuoteRequest.Body.RelayTerminalEvidenceClass,
		RelayFinalityProfile:       request.ProviderQuote.Body.RelayFinalityProfile}
	if !verifier.SupportsRelayEvidenceCapability(capability) ||
		verifier.SupportsRelayDualAbsenceEvidence(capability) {
		t.Fatal("client verifier advertised the wrong exact capability")
	}
	if err := verifier.VerifyRelayFinality(t.Context(), request,
		agentrelay.SignedRelayFinalityEvidence{Body: body}); err != nil {
		t.Fatalf("client-owned quorum rejected exact relay evidence: %v", err)
	}

	clientReader.observation.Outcome = agentrelay.OutcomeFinalizedExpired
	clientReader.observation.TransactionReference = ""
	clientReader.observation.SourceExecutionReference = ""
	clientReader.observation.DestinationCreditReference = ""
	if err := verifier.VerifyRelayFinality(t.Context(), request,
		agentrelay.SignedRelayFinalityEvidence{Body: body}); err == nil {
		t.Fatal("self-consistent Provider evidence survived a disagreeing client quorum")
	}

	autonomous := capability
	autonomous.AssuranceLevel = agentrelay.AssuranceAutonomousDecentralized
	if verifier.SupportsRelayEvidenceCapability(autonomous) {
		t.Fatal("RPC corroboration was advertised as autonomous validator finality")
	}
	sponsored := capability
	sponsored.Mode = agentrelay.ModeSponsorAndRelay
	if verifier.SupportsRelayEvidenceCapability(sponsored) {
		t.Fatal("relay-only client verifier advertised sponsorship readiness")
	}

	threeObservers := *capability.RelayFinalityProfile
	threeObservers.MinimumObservers = 3
	if err := validateTOSRelayObservationForProfile(observation, threeObservers,
		testRelayObservers()); err == nil {
		t.Fatal("two client votes satisfied a three-observer terminal predicate")
	}
	sameDomainObservers := testRelayObservers()
	sameDomainObservers[1].OperatorDomainID = sameDomainObservers[0].OperatorDomainID
	if err := validateTOSRelayObservationForProfile(observation, *capability.RelayFinalityProfile,
		sameDomainObservers); err == nil {
		t.Fatal("two client votes in one operator domain satisfied the signed diversity predicate")
	}
}

func TestCombinedRelayFreezeAndVerifyFromSnapshotReachesPinnedQuery(t *testing.T) {
	fixture, _, _ := loadRelayRustFixture(t)
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "fixture intentionally has no terminal chain body", http.StatusServiceUnavailable)
	})
	adapter := relayTestAdapter(t, servers)
	network := relayTestNetwork()
	reader, err := NewAgentGiftReader(adapter, &nativev1.NetworkDomain{NetworkId: network.NetworkID,
		GenesisRootHash: network.ZeroStateRootHash, GenesisFileHash: network.ZeroStateFileHash})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := NewAgentGiftFinalizedAgentAccountResolver(reader, network,
		[]AgentAccountAgentBinding{{SourceAccount: fixture.Account, OwnerAddress: fixture.Target,
			AuthorizedAgentID: "agent:buyer"}})
	if err != nil {
		t.Fatal(err)
	}
	observers := testRelayObservers()
	for index := range observers {
		observers[index].EndpointAuthorityDigest, err = adapter.nodes[index].client.EndpointAuthorityDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewTOSRelayFinalityVerifier(reader, accounts, network, observers,
		directory+"/client.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	relayProfile, err := TOSRelayCheckpointQuorumFinalityProfile(network, observers, 1, 2, 2, 0, 60)
	if err != nil {
		t.Fatal(err)
	}
	base, sponsorship := sponsorshipRuntimeRecord(t, agentrelay.ModeSponsorAndRelay)
	execution := base.ExecutionRequest()
	execution.QuoteRequest.Body.RelayFinalityProfileURI = relayProfile.ProfileURI
	execution.QuoteRequest.Body.RelayFinalityProfileDigest = relayProfile.ProfileDigest
	execution.QuoteRequest.Body.RelayTerminalEvidenceClass = relayProfile.TerminalEvidenceClass
	execution.ProviderQuote.Body.RelayFinalityProfile = &relayProfile
	execution.ProviderQuote.Body.RelayTerminalEvidenceClass = relayProfile.TerminalEvidenceClass
	execution = attachRelayRuntimeAdmission(t, execution, execution.CreatedAtUnix,
		execution.QuoteRequest.Body.MaximumTransactionValueAtomic)
	prepared, err := agentrelay.NewPreparedRecord(execution, runtimeVerified(t, execution), time.Unix(int64(execution.CreatedAtUnix), 0))
	if err != nil {
		t.Fatal(err)
	}
	prepared.SponsorshipStableActionID = sponsorship.SponsorshipStableActionID
	prepared.SponsorshipExactRequestDigest = sponsorship.SponsorshipExactRequestDigest
	prepared.SponsorshipAgreementPaymentRequestDigest = sponsorship.AgreementPaymentRequestDigest
	prepared.SponsorshipValidUntilUnix = sponsorship.ProviderSponsorValidUntilUnix
	prepared.SponsorshipTransferReference = sponsorship.SubmittedTransactionHash
	prepared.SponsorshipTransactionEvidence = &sponsorship
	prepared.EvidenceRefs = append([]string(nil), sponsorship.ObservationDigests...)

	observation := tosExactRelayObservation{
		CheckpointID: "tos-masterchain:71:" + shaDigest("1") + ":" + shaDigest("2"), CheckpointSequence: 71,
		DepthAnchorCheckpointID:       "tos-masterchain:71:" + shaDigest("1") + ":" + shaDigest("2"),
		DepthAnchorCheckpointSequence: 71, ObservedAtUnix: execution.CreatedAtUnix + 30,
		Outcome: agentrelay.OutcomeFinalizedSuccess, TransactionReference: execution.QuoteRequest.Body.SignedTransactionCellHash,
		SourceExecutionReference: "tos-transaction:-1:source:71", DestinationCreditReference: shaDigest("e"),
		AgreedObserverIndexes: []int{0, 1}}
	provider, err := newTOSExactRelayResolutionSource(&fixedExactRelayCheckpointReader{observation: observation},
		network, observers, 2, directory+"/provider.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := provider.ResolveExactRelay(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	terminal := runtimeCombinedBothSuccess(prepared, resolution)
	body, err := provider.Evidence(t.Context(), terminal)
	if err != nil {
		t.Fatal(err)
	}
	body.SigningAuthorityAtUnix = body.ObservedAtUnix
	capability := tosRelayEvidenceCapability(execution)
	if !verifier.SupportsRelayEvidenceCapability(capability) ||
		!verifier.SupportsRelayTransactionComponentAbsenceEvidence(capability) {
		t.Fatal("combined lower capability was not derived from the exact execution")
	}
	opaque, err := verifier.FreezeRelayFinalityEvidenceSnapshot(t.Context(), capability)
	if err != nil {
		t.Fatal(err)
	}
	err = verifier.VerifyRelayFinalityFromSnapshot(t.Context(), execution,
		agentrelay.SignedRelayFinalityEvidence{Body: body}, opaque)
	if err == nil {
		t.Fatal("incomplete RPC fixture unexpectedly produced terminal verification")
	}
	if strings.Contains(err.Error(), "does not support the exact signed capability") ||
		strings.Contains(err.Error(), "snapshot does not support") ||
		strings.Contains(err.Error(), "invalid or substituted") {
		t.Fatalf("Freeze/VerifyFromSnapshot failed before the pinned fresh query: %v", err)
	}
}

func TestTOSRelayFinalityEvidenceSupportsExactSponsorshipModes(t *testing.T) {
	for _, mode := range []agentrelay.Mode{agentrelay.ModeSponsorOnly, agentrelay.ModeSponsorAndRelay} {
		t.Run(string(mode), func(t *testing.T) {
			record, evidence := sponsorshipRuntimeRecord(t, mode)
			request := record.ExecutionRequest()
			reader := &fixedExactRelayCheckpointReader{observation: tosExactRelayObservation{
				CheckpointID: "tos-masterchain:41:" + shaDigest("1") + ":" + shaDigest("2"), CheckpointSequence: 41,
				DepthAnchorCheckpointID:       "tos-masterchain:40:" + shaDigest("3") + ":" + shaDigest("4"),
				DepthAnchorCheckpointSequence: 40, ObservedAtUnix: request.CreatedAtUnix + 30,
				Outcome: agentrelay.OutcomeFinalizedSuccess, TransactionReference: request.QuoteRequest.Body.SignedTransactionCellHash,
				SourceExecutionReference: "tos-transaction:-1:source:41", DestinationCreditReference: shaDigest("e"),
				AgreedObserverIndexes: []int{0, 1}}}
			source := newTestExactRelayResolutionSource(t, reader, request.QuoteRequest.Body.Network)
			if mode == agentrelay.ModeSponsorAndRelay {
				resolution, err := source.ResolveExactRelay(t.Context(), record)
				if err != nil {
					t.Fatal(err)
				}
				record.TransactionReference = resolution.TransactionReference
				record.TerminalOutcome = resolution.TerminalOutcome
				record.EvidenceRefs = append(record.EvidenceRefs, resolution.EvidenceRefs...)
				sort.Strings(record.EvidenceRefs)
			} else {
				record.TerminalOutcome = agentrelay.OutcomeCorroboratedSponsorshipOnly
			}
			record.State = agentcommerce.ActionTerminal
			body, err := source.Evidence(t.Context(), record)
			if err != nil {
				t.Fatal(err)
			}
			body.SigningAuthorityAtUnix = body.ObservedAtUnix
			if body.SponsorshipTransactionEvidence == nil ||
				body.SponsorshipTransactionEvidence.AgreementPaymentRequestDigest != evidence.AgreementPaymentRequestDigest ||
				body.SponsorshipTransactionEvidence.ConfirmationDepth <
					body.SponsorshipTerminalProfile.MinimumConfirmationDepth {
				t.Fatalf("sponsorship transaction evidence was omitted or weakened: %+v", body)
			}
			if _, err := agentrelay.RelayFinalityEvidenceDigest(body); err != nil {
				t.Fatalf("constructed sponsorship finality evidence is not protocol-valid: %v", err)
			}
		})
	}
}

func TestTOSRelayEvidenceRendererCarriesAllLowerSponsorshipQuadrants(t *testing.T) {
	profileDigest, err := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	if err != nil || profileDigest != "sha256:f13a22b086f91309ac9ea9abad1d9dcf005e2d7a8818637cb7350734af8c2216" {
		t.Fatalf("stock absence proof profile vector changed: %q err=%v", profileDigest, err)
	}

	combined, sponsorshipEvidence := sponsorshipRuntimeRecord(t, agentrelay.ModeSponsorAndRelay)
	request := combined.ExecutionRequest()
	observation := tosExactRelayObservation{
		CheckpointID: "tos-masterchain:51:" + shaDigest("1") + ":" + shaDigest("2"), CheckpointSequence: 51,
		DepthAnchorCheckpointID:       "tos-masterchain:50:" + shaDigest("3") + ":" + shaDigest("4"),
		DepthAnchorCheckpointSequence: 50, ObservedAtUnix: request.CreatedAtUnix + 30,
		Outcome: agentrelay.OutcomeFinalizedSuccess, TransactionReference: request.QuoteRequest.Body.SignedTransactionCellHash,
		SourceExecutionReference: "tos-transaction:-1:source:51", DestinationCreditReference: shaDigest("e"),
		AgreedObserverIndexes: []int{0, 1}}
	source := newTestExactRelayResolutionSource(t,
		&fixedExactRelayCheckpointReader{observation: observation}, request.QuoteRequest.Body.Network)
	capability := tosRelayEvidenceCapability(request)
	if !source.SupportsRelayEvidenceRendering(capability) ||
		source.SupportsRelayEvidenceCapability(capability) ||
		source.SupportsRelayDualAbsenceEvidence(capability) {
		t.Fatal("renderer confused transport rendering with sponsorship evidence production")
	}
	relayResolution, err := source.ResolveExactRelay(t.Context(), combined)
	if err != nil {
		t.Fatal(err)
	}
	sponsorshipRefs := runtimeAbsenceReferences(t, request, sponsorshipEvidence,
		agentrelay.AbsenceObservationSponsorshipAction, agentrelay.AbsenceConclusionExpiredWithoutInclusion)
	transactionRefs := runtimeAbsenceReferences(t, request, sponsorshipEvidence,
		agentrelay.AbsenceObservationClientTransaction, agentrelay.AbsenceConclusionAbsent)

	tests := []struct {
		name        string
		record      agentrelay.Record
		wantSponsor bool
		wantRelay   bool
		wantSAbs    bool
		wantTAbs    bool
	}{
		{name: "both-success", record: runtimeCombinedBothSuccess(combined, relayResolution),
			wantSponsor: true, wantRelay: true},
		{name: "relay-only", record: runtimeCombinedRelayOnly(t, combined, relayResolution, sponsorshipRefs),
			wantRelay: true, wantSAbs: true},
		{name: "sponsorship-only-pre-submit", record: runtimeSponsorshipOnly(t, combined, nil),
			wantSponsor: true},
		{name: "sponsorship-only-post-submit", record: runtimeSponsorshipOnly(t, combined, transactionRefs),
			wantSponsor: true, wantTAbs: true},
		{name: "whole-negative", record: runtimeWholeNegative(t, combined, sponsorshipRefs, transactionRefs),
			wantSAbs: true, wantTAbs: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, renderErr := source.Evidence(t.Context(), test.record)
			if renderErr != nil {
				t.Fatal(renderErr)
			}
			body.SigningAuthorityAtUnix = body.ObservedAtUnix
			if (body.SponsorshipTransactionEvidence != nil) != test.wantSponsor ||
				(body.SubmittedTransactionHash != "") != test.wantRelay ||
				(len(body.SponsorshipAbsenceObservations) != 0) != test.wantSAbs ||
				(len(body.TransactionAbsenceObservations) != 0) != test.wantTAbs ||
				(test.wantSAbs || test.wantTAbs) != (len(body.AbsenceProofBundle) != 0) {
				t.Fatalf("renderer lost a quadrant component: %+v", body)
			}
			if _, digestErr := agentrelay.RelayFinalityEvidenceDigest(body); digestErr != nil {
				t.Fatalf("rendered quadrant is not protocol-valid: %v", digestErr)
			}
		})
	}

	sponsorOnly, sponsorOnlyEvidence := sponsorshipRuntimeRecord(t, agentrelay.ModeSponsorOnly)
	sponsorOnlyRefs := runtimeAbsenceReferences(t, sponsorOnly.ExecutionRequest(), sponsorOnlyEvidence,
		agentrelay.AbsenceObservationSponsorshipAction, agentrelay.AbsenceConclusionExpiredWithoutInclusion)
	sponsorOnly.SponsorshipTransferReference = ""
	sponsorOnly.SponsorshipTransactionEvidence = nil
	sponsorOnly.State = agentcommerce.ActionTerminal
	sponsorOnly.TerminalOutcome = agentrelay.OutcomeCorroboratedExpired
	setRuntimeAbsenceBundle(t, &sponsorOnly, sponsorOnlyRefs, nil)
	body, err := source.Evidence(t.Context(), sponsorOnly)
	if err != nil || len(body.SponsorshipAbsenceObservations) == 0 ||
		len(body.TransactionAbsenceObservations) != 0 || len(body.AbsenceProofBundle) == 0 {
		t.Fatalf("sponsor-only negative renderer is incomplete: %+v err=%v", body, err)
	}
	body.SigningAuthorityAtUnix = body.ObservedAtUnix
	if _, err := agentrelay.RelayFinalityEvidenceDigest(body); err != nil {
		t.Fatalf("sponsor-only negative body is invalid: %v", err)
	}
}

func runtimeAbsenceReferences(t *testing.T, request agentrelay.RelayExecutionRequest,
	sponsorship agentrelay.RelaySponsorshipTransactionEvidence, kind agentrelay.RelayAbsenceObservationKind,
	conclusion agentrelay.RelayAbsenceConclusion) []agentrelay.RelayAbsenceObservationReference {
	t.Helper()
	networkDigest, err := agentrelay.NetworkDomainDigest(request.QuoteRequest.Body.Network)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := agentrelay.RelayExecutionRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	profile := request.ProviderQuote.Body.SponsorshipTerminalProfile
	validUntil := sponsorship.ProviderSponsorValidUntilUnix
	checkpointSequence := uint64(61)
	if kind == agentrelay.AbsenceObservationClientTransaction {
		profile = request.ProviderQuote.Body.RelayFinalityProfile
		validUntil = request.QuoteRequest.Body.TransactionValidUntilUnix
		checkpointSequence = 62
	}
	if profile == nil {
		t.Fatal("absence reference has no selected terminal profile")
	}
	checkpointUnix := validUntil + uint64(profile.ReorgWindowSeconds) + 1
	result := make([]agentrelay.RelayAbsenceObservationReference, 2)
	for index := range result {
		proofIndex := index + 1
		if kind == agentrelay.AbsenceObservationClientTransaction {
			proofIndex += 2
		}
		result[index] = agentrelay.RelayAbsenceObservationReference{SchemaVersion: 1,
			ObservationKind: kind, Conclusion: conclusion,
			ProviderAgentID: request.ProviderQuote.Body.ProviderAgentID, NetworkDigest: networkDigest,
			RelayStableActionID:     request.AuthorizedAction.StableActionID,
			RelayExactRequestDigest: request.AuthorizedAction.ExactRequestDigest,
			RelayExecutionDigest:    executionDigest, SponsorshipStableActionID: sponsorship.SponsorshipStableActionID,
			SponsorshipExactRequestDigest: sponsorship.SponsorshipExactRequestDigest,
			SponsorshipValidUntilUnix:     sponsorship.ProviderSponsorValidUntilUnix,
			SignedTransactionDigest:       request.QuoteRequest.Body.SignedTransactionDigest,
			SignedTransactionCellHash:     request.QuoteRequest.Body.SignedTransactionCellHash,
			TerminalProfileURI:            profile.ProfileURI, TerminalProfileDigest: profile.ProfileDigest,
			TerminalEvidenceClass:       profile.TerminalEvidenceClass,
			FinalizedCheckpointID:       "tos-masterchain:absence:" + strconv.FormatUint(checkpointSequence, 10),
			FinalizedCheckpointSequence: checkpointSequence, FinalizedCheckpointUnix: checkpointUnix,
			ObserverID:                       "observer:absence:" + strconv.Itoa(index+1),
			OperatorDomainID:                 "operator:absence:" + strconv.Itoa(index+1),
			ObservationEvidenceProfileURI:    request.QuoteRequest.Body.SponsorshipReleaseProfileURI,
			ObservationEvidenceProfileDigest: request.QuoteRequest.Body.SponsorshipReleaseProfileDigest,
			ObservationDigest:                shaDigest(strconv.Itoa(proofIndex)), ObservedAtUnix: checkpointUnix}
	}
	sort.Slice(result, func(left, right int) bool {
		leftDigest, leftErr := agentrelay.RelayAbsenceObservationReferenceDigest(result[left])
		rightDigest, rightErr := agentrelay.RelayAbsenceObservationReferenceDigest(result[right])
		if leftErr != nil || rightErr != nil {
			t.Fatalf("invalid test absence reference: left=%v right=%v", leftErr, rightErr)
		}
		return leftDigest < rightDigest
	})
	return result
}

func setRuntimeAbsenceBundle(t *testing.T, record *agentrelay.Record, sponsorship,
	transaction []agentrelay.RelayAbsenceObservationReference) {
	t.Helper()
	payload, err := codec.Marshal(map[string]any{"schema": "tos.test.relay-absence-proof-payload.v1"})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := codec.DigestCanonical(agentrelay.RelayAbsenceProofPayloadDomainV1, payload)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, err := agentrelay.RelayAbsenceTOSRPCProofProfileDigest()
	if err != nil {
		t.Fatal(err)
	}
	scope := agentrelay.RelayAbsenceProofDual
	if len(sponsorship) != 0 && len(transaction) == 0 {
		scope = agentrelay.RelayAbsenceProofSponsorshipOnly
	} else if len(sponsorship) == 0 && len(transaction) != 0 {
		scope = agentrelay.RelayAbsenceProofTransactionOnly
	}
	bundle, err := codec.Marshal(agentrelay.RelayAbsenceProofBundleV1{SchemaVersion: 1,
		ProofScope: scope, ProofProfileURI: agentrelay.RelayAbsenceTOSRPCProofProfileURI,
		ProofProfileDigest: profileDigest, ProofPayloadDigest: payloadDigest, ProofPayload: payload,
		SponsorshipAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil), sponsorship...),
		TransactionAbsenceObservations: append([]agentrelay.RelayAbsenceObservationReference(nil), transaction...)})
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := agentrelay.RelayAbsenceProofBundleDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	record.SponsorshipAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil), sponsorship...)
	record.TransactionAbsenceObservations = append([]agentrelay.RelayAbsenceObservationReference(nil), transaction...)
	record.SponsorshipAbsenceObservationDigests = runtimeAbsenceDigests(t, sponsorship)
	record.TransactionAbsenceObservationDigests = runtimeAbsenceDigests(t, transaction)
	record.AbsenceProofBundleDigest = bundleDigest
	record.AbsenceProofBundle = bundle
	record.EvidenceRefs = append(record.EvidenceRefs, record.SponsorshipAbsenceObservationDigests...)
	record.EvidenceRefs = append(record.EvidenceRefs, record.TransactionAbsenceObservationDigests...)
	sort.Strings(record.EvidenceRefs)
}

func runtimeAbsenceDigests(t *testing.T,
	references []agentrelay.RelayAbsenceObservationReference) []string {
	t.Helper()
	result := make([]string, len(references))
	for index, reference := range references {
		var err error
		result[index], err = agentrelay.RelayAbsenceObservationReferenceDigest(reference)
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func runtimeCombinedBothSuccess(record agentrelay.Record,
	resolution agentrelay.ChainResolution) agentrelay.Record {
	record.State = agentcommerce.ActionTerminal
	record.TerminalOutcome = agentrelay.OutcomeCorroboratedSuccess
	record.TransactionReference = resolution.TransactionReference
	record.EvidenceRefs = append(record.EvidenceRefs, resolution.EvidenceRefs...)
	sort.Strings(record.EvidenceRefs)
	return record
}

func runtimeCombinedRelayOnly(t *testing.T, record agentrelay.Record, resolution agentrelay.ChainResolution,
	sponsorship []agentrelay.RelayAbsenceObservationReference) agentrelay.Record {
	record.State = agentcommerce.ActionTerminal
	record.TerminalOutcome = agentrelay.OutcomeCorroboratedRelayOnly
	record.TransactionReference = resolution.TransactionReference
	record.SponsorshipTransferReference = ""
	record.SponsorshipTransactionEvidence = nil
	record.EvidenceRefs = append([]string(nil), resolution.EvidenceRefs...)
	setRuntimeAbsenceBundle(t, &record, sponsorship, nil)
	return record
}

func runtimeSponsorshipOnly(t *testing.T, record agentrelay.Record,
	transaction []agentrelay.RelayAbsenceObservationReference) agentrelay.Record {
	record.State = agentcommerce.ActionTerminal
	record.TerminalOutcome = agentrelay.OutcomeCorroboratedSponsorshipOnly
	record.TransactionReference = record.SponsorshipTransferReference
	if len(transaction) != 0 {
		setRuntimeAbsenceBundle(t, &record, nil, transaction)
	}
	return record
}

func runtimeWholeNegative(t *testing.T, record agentrelay.Record, sponsorship,
	transaction []agentrelay.RelayAbsenceObservationReference) agentrelay.Record {
	record.State = agentcommerce.ActionTerminal
	record.TerminalOutcome = agentrelay.OutcomeCorroboratedAbsent
	record.TransactionReference = ""
	record.SponsorshipTransferReference = ""
	record.SponsorshipTransactionEvidence = nil
	record.EvidenceRefs = nil
	setRuntimeAbsenceBundle(t, &record, sponsorship, transaction)
	return record
}

func TestTOSCombinedPartialOutcomeUsesSponsorshipEvidenceWithoutRelayObservations(t *testing.T) {
	record, _ := sponsorshipRuntimeRecord(t, agentrelay.ModeSponsorAndRelay)
	record.State = agentcommerce.ActionTerminal
	record.TerminalOutcome = agentrelay.OutcomeCorroboratedSponsorshipOnly
	request := record.ExecutionRequest()
	source := newTestExactRelayResolutionSource(t, &fixedExactRelayCheckpointReader{}, request.QuoteRequest.Body.Network)
	body, err := source.Evidence(t.Context(), record)
	if err != nil {
		t.Fatal(err)
	}
	body.SigningAuthorityAtUnix = body.ObservedAtUnix
	if body.Outcome != agentrelay.OutcomeCorroboratedSponsorshipOnly || body.SponsorshipTransactionEvidence == nil {
		t.Fatalf("combined partial outcome lost sponsorship evidence: %+v", body)
	}
	if _, err := agentrelay.RelayFinalityEvidenceDigest(body); err != nil {
		t.Fatalf("combined partial sponsorship evidence is invalid: %v", err)
	}
}

func TestTOSExactRelayResolutionKeepsAcknowledgementAndUnknownStateNonterminal(t *testing.T) {
	record := relayRuntimeRecord(t)
	network := record.ExecutionRequest().QuoteRequest.Body.Network
	reader := &fixedExactRelayCheckpointReader{observation: tosExactRelayObservation{
		CheckpointID: "tos-masterchain:11:" + shaDigest("1") + ":" + shaDigest("2"), CheckpointSequence: 11,
		DepthAnchorCheckpointID:       "tos-masterchain:11:" + shaDigest("1") + ":" + shaDigest("2"),
		DepthAnchorCheckpointSequence: 11, ObservedAtUnix: 1_900_000_001}}
	source := newTestExactRelayResolutionSource(t, reader, network)
	resolution, err := source.ResolveExactRelay(t.Context(), record)
	if err != nil || resolution.State != "" || resolution.TransactionReference != "" ||
		len(resolution.EvidenceRefs) != 0 {
		t.Fatalf("an unresolved chain query became final: %+v err=%v", resolution, err)
	}
	reader.observation.SafeToRebroadcastExact = true
	resolution, err = source.ResolveExactRelay(t.Context(), record)
	if err != nil || !resolution.SafeToRebroadcastExact || resolution.State != "" ||
		resolution.TransactionReference != "" || len(resolution.EvidenceRefs) != 0 {
		t.Fatalf("safe exact retry carried false terminal evidence: %+v err=%v", resolution, err)
	}
}

func TestTOSExactRelayResolutionEnforcesObserverDomainsAndCheckpointFence(t *testing.T) {
	record := relayRuntimeRecord(t)
	request := record.ExecutionRequest()
	base := tosExactRelayObservation{CheckpointID: "tos-masterchain:20:" + shaDigest("1") + ":" + shaDigest("2"),
		CheckpointSequence: 20, DepthAnchorCheckpointID: "tos-masterchain:19:" + shaDigest("3") + ":" + shaDigest("4"),
		DepthAnchorCheckpointSequence: 19, ObservedAtUnix: request.CreatedAtUnix + 30,
		Outcome: agentrelay.OutcomeFinalizedExpired, AgreedObserverIndexes: []int{0, 1}}
	reader := &fixedExactRelayCheckpointReader{observation: base}
	source := newTestExactRelayResolutionSource(t, reader, request.QuoteRequest.Body.Network)
	if _, err := source.ResolveExactRelay(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	reader.observation.CheckpointSequence = 19
	reader.observation.CheckpointID = "tos-masterchain:19:" + shaDigest("3") + ":" + shaDigest("4")
	if _, err := source.ResolveExactRelay(t.Context(), record); err == nil {
		t.Fatal("finalized checkpoint rollback was accepted")
	}
	reader.observation = base
	reader.observation.CheckpointID = "tos-masterchain:20:" + shaDigest("a") + ":" + shaDigest("b")
	if _, err := source.ResolveExactRelay(t.Context(), record); err == nil {
		t.Fatal("same-height finalized checkpoint fork was accepted")
	}

	reader.observation = base
	reader.observation.CheckpointSequence = 21
	reader.observation.CheckpointID = "tos-masterchain:21:" + shaDigest("5") + ":" + shaDigest("6")
	reader.observation.DepthAnchorCheckpointSequence = 20
	reader.observation.DepthAnchorCheckpointID = base.CheckpointID
	reader.observation.AgreedObserverIndexes = []int{0, 2}
	sameDomain := testRelayObservers()
	sameDomain[2].OperatorDomainID = sameDomain[0].OperatorDomainID
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	insufficient, err := newTOSExactRelayResolutionSource(reader, request.QuoteRequest.Body.Network,
		sameDomain, 2, directory+"/relay.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insufficient.ResolveExactRelay(t.Context(), record); err == nil {
		t.Fatal("one operator domain was counted as two independent domains")
	}
}

func TestClassifyExactRelayCandidateSeparatesRetryWaitExpiredAndInvalidated(t *testing.T) {
	record := relayRuntimeRecord(t)
	request := record.ExecutionRequest()
	quoted := request.QuoteRequest.Body
	beforeExpiry := time.Unix(int64(request.CreatedAtUnix+10), 0)
	base := relayNodeCandidate{AccountFound: true, CurrentAuthorityDigest: quoted.SourceAccountAuthorityDigest,
		CurrentControllerEpoch: 1, CurrentSequence: uint32(quoted.SourceSequence), ExecutionAbsenceKnown: true,
		CurrentLastTransactionTime: request.CreatedAtUnix}
	if outcome, safe := classifyExactRelayCandidate(base, quoted, request, beforeExpiry); outcome != "" || !safe {
		t.Fatalf("fresh finalized absence was not an exact retry: outcome=%s safe=%v", outcome, safe)
	}
	absentAt := time.Unix(int64(request.ExpiresAtUnix+
		uint64(request.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds)), 0)
	if outcome, safe := classifyExactRelayCandidate(base, quoted, request, absentAt); outcome != "" || safe {
		t.Fatalf("point-in-time absence was incorrectly terminal: outcome=%s safe=%v", outcome, safe)
	}
	expiredAt := time.Unix(int64(quoted.TransactionValidUntilUnix+
		uint64(request.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds)), 0)
	if outcome, _ := classifyExactRelayCandidate(base, quoted, request, expiredAt); outcome != agentrelay.OutcomeFinalizedExpired {
		t.Fatalf("transaction expiry mismatch: %s", outcome)
	}
	invalidated := base
	invalidated.CurrentSequence++
	if outcome, _ := classifyExactRelayCandidate(invalidated, quoted, request,
		time.Unix(int64(invalidated.CurrentLastTransactionTime+
			uint64(request.ProviderQuote.Body.RelayFinalityProfile.ReorgWindowSeconds)), 0)); outcome != agentrelay.OutcomeFinalizedInvalidated {
		t.Fatalf("advanced source sequence mismatch: %s", outcome)
	}
	paid := relayNodeCandidate{ExactExternalFound: true, ExactExternalExecuted: true, ExactOutput: true,
		ExactDestinationCredit: true, DestinationCreditKnown: true, ExecutionTime: uint32(request.CreatedAtUnix)}
	if outcome, _ := classifyExactRelayCandidate(paid, quoted, request,
		time.Unix(int64(request.CreatedAtUnix+30), 0)); outcome != agentrelay.OutcomeFinalizedSuccess {
		t.Fatalf("exact payment finality mismatch: %s", outcome)
	}
}

func TestExactRelayHistoryBindsSourceExecutionAndDestinationCredit(t *testing.T) {
	fixture, boc, _ := loadRelayRustFixture(t)
	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	loader, err := root.BeginParse()
	if err != nil {
		t.Fatal(err)
	}
	var input tlb.Message
	if err := tlb.LoadFromCell(&input, loader); err != nil {
		t.Fatal(err)
	}
	amount, err := strconv.ParseUint(fixture.AmountAtomic, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	output := testGiftMessage(t, tlb.MsgTypeInternal, fixture.Account, fixture.Target, amount)
	sourceTransaction := tlb.Transaction{LT: 10, Now: 200, OutMsgCount: 1,
		Description: successfulGiftDescription(0), Hash: bytes.Repeat([]byte{0x11}, 32)}
	sourceTransaction.IO.In = &input
	sourceTransaction.IO.Out = testGiftOutputs(t, output)
	execution, err := matchRelayExecution([]relayHistoryEntry{{Transaction: sourceTransaction}}, root.Hash(),
		fixture.Account, fixture.Target, amount, 100)
	if err != nil || !execution.Found || !execution.Executed || !execution.ExactOutput ||
		execution.ExecutionReference == "" || execution.OutputHash == "" {
		t.Fatalf("exact relay execution mismatch: %+v err=%v", execution, err)
	}
	creditTransaction := tlb.Transaction{LT: 11, Now: 201, Description: successfulGiftDescription(amount),
		Hash: bytes.Repeat([]byte{0x22}, 32)}
	creditTransaction.IO.In = output
	credit, err := matchRelayCredit([]relayHistoryEntry{{Transaction: creditTransaction}}, fixture.Target,
		execution.OutputHash, amount, 200)
	if err != nil || !credit.Known || !credit.Credited || !canonicalSHA256Digest(credit.Reference) {
		t.Fatalf("exact relay destination credit mismatch: %+v err=%v", credit, err)
	}

	failed := sourceTransaction
	failed.Description = tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{
		Phase: tlb.ComputePhaseVM{Success: false}}}
	execution, err = matchRelayExecution([]relayHistoryEntry{{Transaction: failed}}, root.Hash(),
		fixture.Account, fixture.Target, amount, 100)
	if err != nil || !execution.Found || execution.Executed || !execution.AbsenceKnown {
		t.Fatalf("failed exact external execution was not distinguished: %+v err=%v", execution, err)
	}
}

func newTestExactRelayResolutionSource(t *testing.T, reader exactAgentNativeSendCheckpointReader,
	network agentrelay.NetworkDomain) *TOSExactRelayResolutionSource {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := newTOSExactRelayResolutionSource(reader, network, testRelayObservers(), 2,
		directory+"/relay.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func restoreTerminalRelayRecord(t *testing.T, prepared agentrelay.Record,
	resolution agentrelay.ChainResolution) agentrelay.Record {
	t.Helper()
	snapshot := prepared.Snapshot()
	snapshot.State = agentcommerce.ActionTerminal
	snapshot.StateRevision++
	snapshot.TransactionReference = resolution.TransactionReference
	snapshot.EvidenceRefs = append([]string(nil), resolution.EvidenceRefs...)
	snapshot.TerminalOutcome = resolution.TerminalOutcome
	snapshot.UpdatedAtUnix++
	restored, err := agentrelay.RestoreRecord(snapshot, prepared.ExecutionRequest())
	if err != nil {
		t.Fatal(err)
	}
	return restored
}

func testRelayObservers() []TOSRelayObserverBinding {
	return []TOSRelayObserverBinding{
		{ObserverID: "observer:a", OperatorDomainID: "operator:a", EndpointAuthorityDigest: shaDigest("a")},
		{ObserverID: "observer:b", OperatorDomainID: "operator:b", EndpointAuthorityDigest: shaDigest("b")},
		{ObserverID: "observer:c", OperatorDomainID: "operator:c", EndpointAuthorityDigest: shaDigest("c")},
	}
}

func relayRuntimeRecord(t *testing.T) agentrelay.Record {
	t.Helper()
	fixture, boc, _ := loadRelayRustFixture(t)
	now := uint64(1_900_000_000)
	network := relayTestNetwork()
	asset := agentrelay.AssetIdentity{AssetNamespace: "tos.native", AssetIdentifier: network.NetworkID, Unit: "nanotos"}
	payloadDigest, err := agentrelay.SignedTransactionDigest(boc)
	if err != nil {
		t.Fatal(err)
	}
	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	finality, err := TOSRelayCheckpointQuorumFinalityProfile(network, testRelayObservers(), 2, 2, 2, 10, 120)
	if err != nil {
		t.Fatal(err)
	}
	quoteRequest := agentrelay.RelayQuoteRequestBody{SchemaVersion: 1, RequestID: "relay-request:test",
		RequesterAgentID: "agent:buyer", ProviderAgentID: "agent:relay", Network: network,
		Mode: agentrelay.ModeRelayExact, AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider,
		SourceAccount: fixture.Account, SourceAccountAuthorityDigest: shaDigest("5"),
		TransactionProfileURI:    AgentAccountNativeSendRelayProfileURI,
		TransactionProfileDigest: AgentAccountNativeSendRelayProfileDigest(), UnderlyingActionKind: "payment.direct",
		StableActionID: shaDigest("6"), ExactRequestDigest: shaDigest("7"), SignedTransactionDigest: payloadDigest,
		SignedTransactionSize:   uint32(len(boc)),
		TransactionIntentDigest: shaDigest("8"), SourceSequence: uint64(fixture.Seqno),
		TransactionValidUntilUnix: now + 600, MaximumServiceFee: agentrelay.AssetAmount{Asset: asset, AmountAtomic: "10"},
		MaximumNetworkFeeAtomic: "1000000", MaximumTransactionValueAtomic: fixture.AmountAtomic,
		RelayFinalityProfileURI: finality.ProfileURI, RelayFinalityProfileDigest: finality.ProfileDigest,
		RelayTerminalEvidenceClass: finality.TerminalEvidenceClass,
		CreatedAtUnix:              now, ExpiresAtUnix: now + 300}
	quoteRequest.SignedTransactionCellHash = "tvm-cell-sha256:" + strings.ToLower(fmtHex(root.Hash()))
	requestDigest, err := agentrelay.RelayQuoteRequestDigest(quoteRequest)
	if err != nil {
		t.Fatal(err)
	}
	providerQuote := agentrelay.ProviderRelayQuoteBody{SchemaVersion: 1, QuoteID: "relay-quote:test",
		QuoteRequestDigest: requestDigest, ServiceProfileDigest: shaDigest("9"), ProviderAgentID: "agent:relay",
		Mode: agentrelay.ModeRelayExact, AssuranceLevel: quoteRequest.AssuranceLevel,
		FeeLines: []agentrelay.FeeLine{{Kind: agentrelay.ObligationRelayFee,
			Amount: agentrelay.AssetAmount{Asset: asset, AmountAtomic: "3"}}}, MaximumNetworkFeeAtomic: "1000000",
		MaximumTransactionValueAtomic: fixture.AmountAtomic, MaximumRequestBytes: agentrelay.MaxSignedTransactionBytes,
		RelayTerminalEvidenceClass: finality.TerminalEvidenceClass,
		RelayFinalityProfile:       &finality, StatusEndpoint: "https://relay.example/resolve", ProviderPolicyRevision: 1,
		ValidFromUnix: now, ExpiresAtUnix: now + 240}
	request := agentrelay.RelayExecutionRequest{SchemaVersion: 1,
		QuoteRequest:  agentrelay.SignedRelayQuoteRequest{Body: quoteRequest},
		ProviderQuote: agentrelay.SignedProviderRelayQuote{Body: providerQuote}, SignedTransactionBytes: boc,
		AgreementBodyDigest: shaDigest("a"), AgreementExpiresAtUnix: now + 270,
		RelayObligationID: "obligation:relay", FeeObligationIDs: []string{"obligation:fee"},
		UnderlyingActionRequest: []byte{0xa1, 0x01, 0x02}, AuthorizedAction: agentcommerce.AuthorizedAction{
			ActionKind: "payment.direct", StableActionID: quoteRequest.StableActionID,
			ExactRequestDigest: quoteRequest.ExactRequestDigest}, CreatedAtUnix: now, ExpiresAtUnix: now + 180}
	request = attachRelayRuntimeAdmission(t, request, now, fixture.AmountAtomic)
	record, err := agentrelay.NewPreparedRecord(request, runtimeVerified(t, request), time.Unix(int64(now), 0))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func sponsorshipRuntimeRecord(t *testing.T, mode agentrelay.Mode) (agentrelay.Record,
	agentrelay.RelaySponsorshipTransactionEvidence) {
	t.Helper()
	base := relayRuntimeRecord(t)
	request := base.ExecutionRequest()
	now := request.CreatedAtUnix
	asset := request.QuoteRequest.Body.MaximumServiceFee.Asset
	amount := agentrelay.AssetAmount{Asset: asset, AmountAtomic: "10"}
	request.QuoteRequest.Body.Mode = mode
	request.QuoteRequest.Body.RequestedSponsorship = &amount
	request.QuoteRequest.Body.SponsorshipReleaseEvidenceClass = agentrelay.SponsorshipReleaseObservedUnproven
	request.QuoteRequest.Body.SponsorshipReleaseProfileURI = agentrelay.RPCCorroborationEvidenceProfileURI
	request.QuoteRequest.Body.SponsorshipReleaseProfileDigest = shaDigest("d")
	sponsorshipFinality := *request.ProviderQuote.Body.RelayFinalityProfile
	sponsorshipFinality.ProfileURI = agentrelay.ClientCorroboratedTerminalProfileURI
	sponsorshipFinality.ProfileDigest = shaDigest("e")
	sponsorshipFinality.TerminalEvidenceClass = agentrelay.SponsorshipTerminalClientCorroborated
	request.QuoteRequest.Body.SponsorshipTerminalEvidenceClass = sponsorshipFinality.TerminalEvidenceClass
	request.QuoteRequest.Body.SponsorshipTerminalProfileURI = sponsorshipFinality.ProfileURI
	request.QuoteRequest.Body.SponsorshipTerminalProfileDigest = sponsorshipFinality.ProfileDigest
	request.ProviderQuote.Body.Mode = mode
	request.ProviderQuote.Body.ReservedSponsorship = &amount
	request.ProviderQuote.Body.SponsorshipReleaseEvidenceClass = request.QuoteRequest.Body.SponsorshipReleaseEvidenceClass
	request.ProviderQuote.Body.SponsorshipReleaseProfileURI = request.QuoteRequest.Body.SponsorshipReleaseProfileURI
	request.ProviderQuote.Body.SponsorshipReleaseProfileDigest = request.QuoteRequest.Body.SponsorshipReleaseProfileDigest
	request.ProviderQuote.Body.SponsorshipTerminalEvidenceClass = sponsorshipFinality.TerminalEvidenceClass
	request.ProviderQuote.Body.SponsorshipTerminalProfile = &sponsorshipFinality
	request.SponsorshipObligationID = "obligation:sponsorship"
	request.ProviderQuote.Body.FeeLines = []agentrelay.FeeLine{{Kind: agentrelay.ObligationSponsorshipFee,
		Amount: agentrelay.AssetAmount{Asset: asset, AmountAtomic: "1"}}}
	request.FeeObligationIDs = []string{"obligation:sponsorship-fee"}
	if mode == agentrelay.ModeSponsorOnly {
		request.RelayObligationID = ""
		request.QuoteRequest.Body.RelayFinalityProfileURI = ""
		request.QuoteRequest.Body.RelayFinalityProfileDigest = ""
		request.QuoteRequest.Body.RelayTerminalEvidenceClass = ""
		request.ProviderQuote.Body.RelayFinalityProfile = nil
		request.ProviderQuote.Body.RelayTerminalEvidenceClass = ""
	} else {
		request.ProviderQuote.Body.FeeLines = append(request.ProviderQuote.Body.FeeLines,
			agentrelay.FeeLine{Kind: agentrelay.ObligationRelayFee,
				Amount: agentrelay.AssetAmount{Asset: asset, AmountAtomic: "1"}})
		request.FeeObligationIDs = []string{"obligation:relay-fee", "obligation:sponsorship-fee"}
		sort.Strings(request.FeeObligationIDs)
	}
	request = attachRelayRuntimeAdmission(t, request, now, request.QuoteRequest.Body.MaximumTransactionValueAtomic)
	record, err := agentrelay.NewPreparedRecord(request, runtimeVerified(t, request), time.Unix(int64(now), 0))
	if err != nil {
		t.Fatal(err)
	}
	reserved := *request.ProviderQuote.Body.ReservedSponsorship
	paymentAmount := agentcommerce.AgreementAmount{AssetNamespace: reserved.Asset.AssetNamespace,
		AssetIdentifier: reserved.Asset.AssetIdentifier, Unit: reserved.Asset.Unit, AmountAtomic: reserved.AmountAtomic}
	obligation := agentcommerce.SettlementObligation{AgreementBodyDigest: request.AgreementBodyDigest,
		AgreementObligationID: request.SponsorshipObligationID, ObligationInstanceID: shaDigest("1"), Sequence: 1,
		PayerAgentID: request.QuoteRequest.Body.ProviderAgentID, PayeeAgentID: request.QuoteRequest.Body.RequesterAgentID,
		Amount: paymentAmount, MaximumAggregateAmount: paymentAmount, ExpiresAtUnix: request.ExpiresAtUnix,
		SettlementAdapterURI: agentrelay.DirectPaymentAdapterURI, SettlementParametersDigest: shaDigest("2"),
		StableActionID: shaDigest("3")}
	networkDigest, err := agentrelay.NetworkDomainDigest(request.QuoteRequest.Body.Network)
	if err != nil {
		t.Fatal(err)
	}
	payment, err := agentcommerce.BuildDomainBoundAgreementPaymentRequest("owner:relay",
		request.QuoteRequest.Body.ProviderAgentID, request.QuoteRequest.Body.Network.NetworkID, networkDigest,
		[]byte(request.QuoteRequest.Body.SourceAccount), obligation)
	if err != nil {
		t.Fatal(err)
	}
	paymentDigest, err := agentcommerce.AgreementPaymentRequestDigest(payment)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := agentcommerce.PaymentAuthorizationMaterial(payment)
	if err != nil {
		t.Fatal(err)
	}
	exactDigest, err := agentcommerce.ExactRequestDigest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	proofBundle := []byte{0xa0}
	proofBundleDigest, err := agentrelay.RelaySponsorshipProofBundleDigest(proofBundle)
	if err != nil {
		t.Fatal(err)
	}
	evidence := agentrelay.RelaySponsorshipTransactionEvidence{SchemaVersion: 1,
		TerminalEvidenceClass:               agentrelay.SponsorshipTerminalClientCorroborated,
		ValidatorAuthenticatedPortableProof: false, NetworkDigest: networkDigest,
		AgreementPaymentRequest: payment, AgreementPaymentRequestDigest: paymentDigest,
		SponsorshipStableActionID: payment.StableActionID, SponsorshipExactRequestDigest: exactDigest,
		ProviderSponsorSourceAccount: "account:provider", ProviderSponsorSourceSequence: 7,
		ProviderSponsorValidUntilUnix: payment.ExpiresAtUnix, SignedTopUpTransactionDigest: shaDigest("4"),
		SignedTopUpTransactionCellHash:       "tvm-cell-sha256:" + strings.Repeat("5", 64),
		SponsorshipPaymentCommitmentCellHash: "tvm-cell-sha256:" + strings.Repeat("6", 64),
		DestinationSourceAccount:             request.QuoteRequest.Body.SourceAccount, Amount: reserved,
		SubmittedTransactionHash: "tos-sponsorship:exact", SourceExecutionReference: "tos-transaction:-1:sponsor:1",
		DestinationCreditReferences: []string{shaDigest("6"), shaDigest("7")},
		FinalizedCheckpointID:       "tos-masterchain:39:" + shaDigest("8") + ":" + shaDigest("9"),
		FinalizedCheckpointSequence: 39, FinalizedCheckpointUnix: now + 20,
		ConfirmationDepth:                sponsorshipFinality.MinimumConfirmationDepth,
		SponsorshipTerminalProfileDigest: sponsorshipFinality.ProfileDigest,
		ObservationDigests:               []string{shaDigest("a"), shaDigest("b")},
		ProofBundleDigest:                proofBundleDigest, ProofBundle: proofBundle,
		ObservedAtUnix: now + 20}
	record.SponsorshipStableActionID = evidence.SponsorshipStableActionID
	record.SponsorshipExactRequestDigest = evidence.SponsorshipExactRequestDigest
	record.SponsorshipAgreementPaymentRequestDigest = evidence.AgreementPaymentRequestDigest
	record.SponsorshipValidUntilUnix = evidence.ProviderSponsorValidUntilUnix
	record.SponsorshipTransferReference = evidence.SubmittedTransactionHash
	record.SponsorshipTransactionEvidence = &evidence
	record.EvidenceRefs = append([]string(nil), evidence.ObservationDigests...)
	return record, evidence
}

func attachRelayRuntimeAdmission(t *testing.T, request agentrelay.RelayExecutionRequest,
	now uint64, amountAtomic string) agentrelay.RelayExecutionRequest {
	t.Helper()
	// The Action Authority signs through the in-process test Fake; these
	// tests check relay bindings, not ML-DSA-44 bytes.
	authoritySigner, authorityController := &mldsa44test.Fake{}, "authority"
	authorityKeyID := authoritySigner.KeyID(authorityController)
	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	providerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id":               agentcommerce.ID("owner:buyer"),
		"agent_id":               agentcommerce.ID(request.QuoteRequest.Body.RequesterAgentID),
		"agreement_body_digest":  agentcommerce.Digest32(request.AgreementBodyDigest),
		"obligation_instance_id": agentcommerce.Digest32(shaDigest("b")),
		"payer_id":               agentcommerce.ID(request.QuoteRequest.Body.RequesterAgentID),
		"payee_id":               agentcommerce.ID("agent:merchant"),
		"network_id":             agentcommerce.ID(request.QuoteRequest.Body.Network.NetworkID),
		"asset_digest":           agentcommerce.Digest32(shaDigest("c")),
		"amount_atomic":          agentcommerce.ID(amountAtomic),
		"destination_digest":     agentcommerce.Digest32(shaDigest("d")),
	}
	fence, err := agentcommerce.SignWriterFence(context.Background(), agentcommerce.WriterFenceBody{SchemaVersion: 1,
		OwnerID: "owner:buyer", AgentID: request.QuoteRequest.Body.RequesterAgentID,
		InstanceID: "instance:runtime-test", LeaseID: "lease:runtime-test", WriterGeneration: 1,
		IssuedAtUnix: now - 60, ExpiresAtUnix: request.AgreementExpiresAtUnix,
		AuthorityID: "authority:runtime-test", Scope: []string{request.QuoteRequest.Body.UnderlyingActionKind}}, authoritySigner, authorityController)
	if err != nil {
		t.Fatal(err)
	}
	action, err := agentcommerce.BuildAuthorizedAction("owner:buyer", request.QuoteRequest.Body.RequesterAgentID,
		request.QuoteRequest.Body.UnderlyingActionKind, fields, request.UnderlyingActionRequest, fence, 1,
		shaDigest("e"), "", "unknown", request.ExpiresAtUnix)
	if err != nil {
		t.Fatal(err)
	}
	action, err = agentcommerce.SignAuthorizedAction(context.Background(), action, authorityKeyID, authoritySigner, authorityController)
	if err != nil {
		t.Fatal(err)
	}
	request.SemanticFields, err = agentcommerce.ExportSemanticFields(request.QuoteRequest.Body.UnderlyingActionKind, fields)
	if err != nil {
		t.Fatal(err)
	}
	request.AuthorizedAction = action
	request.WriterFence = fence
	request.QuoteRequest.Body.StableActionID = action.StableActionID
	request.QuoteRequest.Body.ExactRequestDigest = action.ExactRequestDigest
	request.QuoteRequest, err = agentrelay.SignRelayQuoteRequest(request.QuoteRequest.Body, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	request.ProviderQuote.Body.QuoteRequestDigest, err = agentrelay.RelayQuoteRequestDigest(request.QuoteRequest.Body)
	if err != nil {
		t.Fatal(err)
	}
	request.ProviderQuote, err = agentrelay.SignProviderRelayQuote(request.ProviderQuote.Body, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionDescriptorForPrincipal(request, "principal:runtime-test")
	if err != nil {
		t.Fatal(err)
	}
	receiptBody, err := agentrelay.BuildRelaySideEffectAdmissionReceiptBody(descriptor, 1, now, now+30)
	if err != nil {
		t.Fatal(err)
	}
	request.AdmissionReceipt, err = agentrelay.SignRelaySideEffectAdmissionReceipt(context.Background(), receiptBody, authoritySigner, authorityController)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func fmtHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2], result[index*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(result)
}

// runtimeVerified is the Action Authority check of a runtime test receipt,
// signed by the test Fake controller "authority".
func runtimeVerified(t *testing.T, request agentrelay.RelayExecutionRequest) agentrelay.VerifiedRelayAdmissionReceipt {
	t.Helper()
	fake := &mldsa44test.Fake{}
	resolver := mldsa44test.ActionAuthorityResolver{Verifier: fake,
		Keys: map[string][][]byte{request.AdmissionReceipt.Body.AuthorityID: {fake.PublicKey("authority")}}}
	verified, err := agentrelay.VerifyRelaySideEffectAdmissionReceiptAuthority(request.AdmissionReceipt, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}
