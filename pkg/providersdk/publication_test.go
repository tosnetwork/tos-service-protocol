package providersdk

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// scriptedClient is a Gateway whose finalized state the test controls. The
// Capability exists only once capability is set; onSubmit may set it to model
// a relay that lands.
type scriptedClient struct {
	mu          sync.Mutex
	ownerID     string
	owner       *nativev1.NativeStateV1
	capability  *nativev1.NativeStateV1
	submitErr   error
	catalogErr  error
	onSubmit    func(*scriptedClient)
	submissions []*nativev1.SubmitNativeActionRequest
	catalogs    []*nativev1.PublishSoftwareWorkManifestRequest
}

func (c *scriptedClient) SubmitNativeAction(_ context.Context, request *nativev1.SubmitNativeActionRequest) (*nativev1.SubmitNativeActionResponse, error) {
	c.mu.Lock()
	c.submissions = append(c.submissions, proto.Clone(request).(*nativev1.SubmitNativeActionRequest))
	hook, failure := c.onSubmit, c.submitErr
	c.mu.Unlock()
	if hook != nil {
		hook(c)
	}
	if failure != nil {
		return nil, failure
	}
	built, err := nativecore.BuildAction(request.Submission.Action)
	if err != nil {
		return nil, err
	}
	return &nativev1.SubmitNativeActionResponse{ActionHash: built.HashString, RelayAccepted: true}, nil
}

func (c *scriptedClient) ResolveNativeState(_ context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if request.ObjectId == c.ownerID && c.owner != nil {
		return &nativev1.ResolveNativeStateResponse{Found: true, State: proto.Clone(c.owner).(*nativev1.NativeStateV1)}, nil
	}
	if c.capability != nil && request.ObjectId == c.capability.GetCapability().CapabilityId {
		return &nativev1.ResolveNativeStateResponse{Found: true, State: proto.Clone(c.capability).(*nativev1.NativeStateV1)}, nil
	}
	return &nativev1.ResolveNativeStateResponse{}, nil
}

func (c *scriptedClient) PublishSoftwareWorkManifest(_ context.Context, request *nativev1.PublishSoftwareWorkManifestRequest) (*nativev1.PublishSoftwareWorkManifestResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.catalogs = append(c.catalogs, proto.Clone(request).(*nativev1.PublishSoftwareWorkManifestRequest))
	if c.catalogErr != nil {
		return nil, c.catalogErr
	}
	return &nativev1.PublishSoftwareWorkManifestResponse{ManifestDigest: c.capability.GetCapability().Versions[0].ManifestDigest,
		Capability: proto.Clone(c.capability).(*nativev1.NativeStateV1)}, nil
}

func (c *scriptedClient) submitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.submissions)
}

type journalFixture struct {
	network      *nativev1.NetworkDomain
	codeHash     string
	ownerID      string
	manifestJSON []byte
	client       *scriptedClient
	directory    string
}

func newJournalFixture(t *testing.T, manifestJSON []byte) *journalFixture {
	t.Helper()
	if manifestJSON == nil {
		raw, err := servicefixture.ManifestDocumentJSON()
		if err != nil {
			t.Fatal(err)
		}
		manifestJSON = extractManifest(t, raw)
	}
	network := &nativev1.NetworkDomain{NetworkId: "journal", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 1,
		Controllers: []*nativev1.ControllerV1{{KeyId: fakeKeys.KeyID("fixture"), Mldsa44PublicKey: fakeKeys.PublicKey("fixture"), Weight: 1,
			PurposeMask: 15, Recovery: true}}}
	ownerID, err := nativecore.DeriveAgentID(network, bytes32(1), policy)
	if err != nil {
		t.Fatal(err)
	}
	codeHash := "tvm-cell-sha256:" + strings.Repeat("33", 32)
	directory := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return &journalFixture{network: network, codeHash: codeHash, ownerID: ownerID, manifestJSON: manifestJSON, directory: directory,
		client: &scriptedClient{ownerID: ownerID, owner: agentState(network, codeHash, ownerID, policy)}}
}

// provider builds a fresh provider, as a restarted process would.
func (f *journalFixture) provider(t *testing.T) *Provider {
	t.Helper()
	provider, err := New(Config{Client: f.client, Verifier: fakeKeys, Network: f.network, RegistryCodeHash: f.codeHash,
		CallerID: f.ownerID, PollInterval: 10 * time.Millisecond, FinalityTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

// reopen opens the journal again, as a restarted process would.
func (f *journalFixture) reopen(t *testing.T) *PublicationJournal {
	t.Helper()
	journal, err := OpenPublicationJournal(f.directory, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func (f *journalFixture) sign(t *testing.T, record PublicationRecord, controller string) *nativev1.SignedNativeActionV1 {
	t.Helper()
	prepared, err := record.Prepared()
	if err != nil {
		t.Fatal(err)
	}
	built, err := nativecore.BuildAction(prepared.Action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := nativecore.SignAction(context.Background(), fakeKeys, controller, built)
	if err != nil {
		t.Fatal(err)
	}
	return &nativev1.SignedNativeActionV1{Action: prepared.Action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}
}

// finalizedCapability is the finalized state the exact publication produces.
func (f *journalFixture) finalizedCapability(t *testing.T, record PublicationRecord) *nativev1.NativeStateV1 {
	t.Helper()
	return &nativev1.NativeStateV1{Network: proto.Clone(f.network).(*nativev1.NetworkDomain),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("77", 32),
		Reference:    &nativev1.ChainReference{ContractCodeHash: f.codeHash, FinalizedCheckpoint: 42},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: record.CapabilityID,
			Generation: 1, Sequence: 1, LastActionHash: record.ActionHash, OwnerAgentId: f.ownerID,
			Versions: []*nativev1.CapabilityVersionV1{{Version: record.CapabilityVersion, ManifestDigest: record.ManifestDigest}}}}}
}

func (f *journalFixture) prepare(t *testing.T) PublicationRecord {
	t.Helper()
	record, created, err := f.provider(t).PrepareJournaledPublication(f.reopen(t), f.manifestJSON, f.ownerID, PublicationOptions{})
	if err != nil || !created || record.Phase != PublicationPrepared {
		t.Fatalf("prepare: created=%v phase=%s err=%v", created, record.Phase, err)
	}
	return record
}

func TestJournaledPublicationConvergesAcrossRestartsAtEveryPhase(t *testing.T) {
	f := newJournalFixture(t, nil)
	ctx := context.Background()
	record := f.prepare(t)
	info, err := os.Lstat(filepath.Join(f.directory, "publication-"+strings.TrimPrefix(record.ActionHash, "sha256:")+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("prepared record is not an owner-private file before signing: %v %v", info, err)
	}

	// Crash after prepare: re-running prepare without nonces resumes the
	// journaled action instead of deriving a second Capability.
	again, created, err := f.provider(t).PrepareJournaledPublication(f.reopen(t), f.manifestJSON, f.ownerID, PublicationOptions{})
	if err != nil || created || again.ActionHash != record.ActionHash || again.CapabilityIdempotencyKey != record.CapabilityIdempotencyKey {
		t.Fatalf("re-prepare did not converge: created=%v %s %v", created, again.ActionHash, err)
	}
	if _, _, err := f.provider(t).PrepareJournaledPublication(f.reopen(t), f.manifestJSON, f.ownerID,
		PublicationOptions{CapabilityIdempotencyKey: "replacement-key"}); err == nil {
		t.Fatal("re-prepare replaced the journaled retry key")
	}
	if _, err := f.provider(t).ApplyPublication(ctx, f.reopen(t), record.ActionHash, nil); !errors.Is(err, ErrSignatureRequired) {
		t.Fatalf("apply without signatures: %v", err)
	}

	// Crash during the first relay: the relay errors, the record is
	// ambiguous and the signed action is durable.
	signed := f.sign(t, record, "fixture")
	f.client.submitErr = errors.New("connection reset")
	got, err := f.provider(t).ApplyPublication(ctx, f.reopen(t), record.ActionHash, signed)
	if err == nil || got.Phase != PublicationAmbiguous || got.SubmitAttempts != 1 || len(got.SignedAction) == 0 {
		t.Fatalf("failed relay: phase=%s attempts=%d err=%v", got.Phase, got.SubmitAttempts, err)
	}

	// Crash while journaled as submitting: reopening recovers ambiguous.
	if _, err := f.reopen(t).Transition(record.ActionHash, []PublicationPhase{PublicationAmbiguous}, func(r *PublicationRecord) error {
		r.Phase, r.SubmitAttempts = PublicationSubmitting, r.SubmitAttempts+1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.reopen(t).Read(record.ActionHash); err != nil || got.Phase != PublicationAmbiguous {
		t.Fatalf("submitting record was not recovered as ambiguous: %s %v", got.Phase, err)
	}

	// Resume with no signed action: finalized absence re-relays the stored
	// signed action under the same retry key, the relay lands, and catalog
	// admission fails after finality.
	f.client.submitErr = nil
	f.client.catalogErr = errors.New("catalog unavailable")
	f.client.onSubmit = func(c *scriptedClient) {
		c.mu.Lock()
		c.capability = f.finalizedCapability(t, record)
		c.mu.Unlock()
	}
	got, err = f.provider(t).ApplyPublication(ctx, f.reopen(t), record.ActionHash, nil)
	if err == nil || got.Phase != PublicationFinalized || got.FinalizedCheckpoint != 42 {
		t.Fatalf("resume to finality: phase=%s err=%v", got.Phase, err)
	}
	if f.client.submitCount() != 2 {
		t.Fatalf("relays = %d, want 2", f.client.submitCount())
	}
	first, second := f.client.submissions[0], f.client.submissions[1]
	if !proto.Equal(first.Submission, second.Submission) || first.Context.IdempotencyKey != record.CapabilityIdempotencyKey ||
		second.Context.IdempotencyKey != record.CapabilityIdempotencyKey {
		t.Fatal("the re-relay changed the signed action or its retry key")
	}

	// Crash after finality: resuming publishes the catalog only.
	f.client.catalogErr = nil
	got, err = f.provider(t).ApplyPublication(ctx, f.reopen(t), record.ActionHash, nil)
	if err != nil || got.Phase != PublicationCataloged || got.CatalogCheckpoint != 42 || f.client.submitCount() != 2 {
		t.Fatalf("resume to catalog: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
	if last := f.client.catalogs[len(f.client.catalogs)-1]; last.Context.IdempotencyKey != record.ManifestIdempotencyKey ||
		string(last.CanonicalCbor) != string(record.ManifestCBOR) {
		t.Fatal("catalog admission did not use the journaled manifest and retry key")
	}
	// A completed publication is idempotent and makes no further calls.
	catalogs := len(f.client.catalogs)
	got, err = f.provider(t).ApplyPublication(ctx, f.reopen(t), record.ActionHash, nil)
	if err != nil || got.Phase != PublicationCataloged || f.client.submitCount() != 2 || len(f.client.catalogs) != catalogs {
		t.Fatalf("re-run after completion: phase=%s err=%v", got.Phase, err)
	}
}

func TestAmbiguousPublicationSettlesFromFinalizedStateBeforeAnyRelay(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	f.client.submitErr = errors.New("timeout after send")
	if _, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "fixture")); err == nil {
		t.Fatal("failed relay reported success")
	}
	// The first relay did land.
	f.client.capability = f.finalizedCapability(t, record)
	f.client.submitErr = nil
	got, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, nil)
	if err != nil || got.Phase != PublicationCataloged {
		t.Fatalf("settle ambiguous: phase=%s err=%v", got.Phase, err)
	}
	if f.client.submitCount() != 1 {
		t.Fatalf("an ambiguous publication already finalized was relayed again: %d relays", f.client.submitCount())
	}
}

func TestAmbiguousPublicationRefusesConflictingFinalizedState(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	f.client.submitErr = errors.New("timeout after send")
	if _, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "fixture")); err == nil {
		t.Fatal("failed relay reported success")
	}
	conflict := f.finalizedCapability(t, record)
	conflict.GetCapability().LastActionHash = "sha256:" + strings.Repeat("99", 32)
	f.client.capability, f.client.submitErr = conflict, nil
	got, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, nil)
	if err == nil || got.Phase != PublicationAmbiguous || f.client.submitCount() != 1 {
		t.Fatalf("conflicting finalized state: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
}

func TestSubmittedPublicationBecomesAmbiguousAfterFinalityTimeout(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	got, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "fixture"))
	if !errors.Is(err, context.DeadlineExceeded) || got.Phase != PublicationAmbiguous || f.client.submitCount() != 1 {
		t.Fatalf("finality timeout: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
}

func TestApplyNeverSubstitutesTheJournaledSignedAction(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	f.client.submitErr = errors.New("unreachable")
	if _, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "fixture")); err == nil {
		t.Fatal("failed relay reported success")
	}
	relays := f.client.submitCount()
	other := f.sign(t, record, "fixture")
	other.AuthoritySignatures[0].Mldsa44Signature = append([]byte(nil), other.AuthoritySignatures[0].Mldsa44Signature...)
	other.AuthoritySignatures[0].Mldsa44Signature[0] ^= 0xff
	if _, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, other); err == nil {
		t.Fatal("a different signature set replaced the journaled one")
	}
	changed := f.sign(t, record, "fixture")
	changed.Action = proto.Clone(changed.Action).(*nativev1.NativeActionV1)
	changed.Action.Nonce[0] ^= 0xff
	if _, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, changed); err == nil {
		t.Fatal("a signed action for another action was accepted")
	}
	if f.client.submitCount() != relays {
		t.Fatal("a substituted signed action reached the Gateway")
	}
}

func TestPreparedPublicationRefusesSignaturesOutsideOwnerPolicy(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	got, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "stranger"))
	if err == nil || got.Phase != PublicationPrepared || f.client.submitCount() != 0 {
		t.Fatalf("stranger signature: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
}

func TestApplyRefusesJournalForAnotherNetwork(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	f.network = proto.Clone(f.network).(*nativev1.NetworkDomain)
	f.network.NetworkId = "other"
	if _, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "fixture")); err == nil {
		t.Fatal("a provider for another network resumed the journaled publication")
	}
}

func recordPath(f *journalFixture, record PublicationRecord) string {
	return filepath.Join(f.directory, "publication-"+strings.TrimPrefix(record.ActionHash, "sha256:")+".json")
}

func TestPublicationJournalRejectsCorruptAndUnknownRecords(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	path := recordPath(f, record)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(edit func(map[string]any)) []byte {
		var value map[string]any
		if err := json.Unmarshal(original, &value); err != nil {
			t.Fatal(err)
		}
		edit(value)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := map[string][]byte{
		"unknown schema version": mutate(func(v map[string]any) { v["schema"] = "tos.service.provider-publication.v2" }),
		"unknown field":          mutate(func(v map[string]any) { v["extra"] = true }),
		"unknown phase":          mutate(func(v map[string]any) { v["phase"] = "published" }),
		"trailing data":          append(append([]byte(nil), original...), []byte("{}")...),
		"changed nonce":          mutate(func(v map[string]any) { v["action_nonce"] = strings.Repeat("ab", 32) }),
		"changed capability":     mutate(func(v map[string]any) { v["capability_id"] = "capability_" + strings.Repeat("0", 64) }),
		"changed manifest bytes": mutate(func(v map[string]any) { v["manifest_cbor"] = "AAAA" }),
		"unknown action field": mutate(func(v map[string]any) {
			v["action"].(map[string]any)["future_field"] = 1
		}),
		"signed action while prepared": mutate(func(v map[string]any) { v["signed_action"] = map[string]any{"action": v["action"]} }),
		"finalized without checkpoint": mutate(func(v map[string]any) { v["phase"] = string(PublicationFinalized) }),
		"equal retry keys":             mutate(func(v map[string]any) { v["manifest_idempotency_key"] = v["capability_idempotency_key"] }),
		"not json":                     []byte("not json"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rawJournal(f).Read(record.ActionHash); err == nil {
				t.Fatal("corrupt publication record was read")
			}
			if _, err := OpenPublicationJournal(f.directory, time.Now()); err == nil {
				t.Fatal("journal with a corrupt record was opened")
			}
		})
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.reopen(t).Read(record.ActionHash); err != nil {
		t.Fatalf("restored record: %v", err)
	}
}

func TestPublicationJournalRefusesSymlinksAndBroadPermissions(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	path := recordPath(f, record)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := rawJournal(f).Read(record.ActionHash); err == nil {
		t.Fatal("group-readable publication record was read")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
	if _, err := rawJournal(f).Read(record.ActionHash); err == nil {
		t.Fatal("symlinked publication record was read")
	}
	// Restore a valid record so the directory checks below are the only
	// reason the journal can be refused.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, path); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	if err := os.Chmod(f.directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPublicationJournal(f.directory, time.Now()); err == nil {
		t.Fatal("group-accessible journal directory was opened")
	}
	if err := os.Chmod(f.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "journal-link")
	if err := os.Symlink(f.directory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPublicationJournal(link, time.Now()); err == nil {
		t.Fatal("symlinked journal directory was opened")
	}
	if _, err := OpenPublicationJournal("relative/journal", time.Now()); err == nil {
		t.Fatal("relative journal directory was opened")
	}
}

func TestPublicationJournalTransitionsCannotRewriteTheReview(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	journal := f.reopen(t)
	for name, edit := range map[string]func(*PublicationRecord){
		"retry key":   func(r *PublicationRecord) { r.CapabilityIdempotencyKey = "other-key" },
		"nonce":       func(r *PublicationRecord) { r.ObjectNonce = strings.Repeat("cd", 32) },
		"phase skips": func(r *PublicationRecord) { r.Phase = PublicationCataloged },
	} {
		if _, err := journal.Transition(record.ActionHash, []PublicationPhase{PublicationPrepared}, func(r *PublicationRecord) error {
			edit(r)
			return nil
		}); err == nil {
			t.Fatalf("transition changing the %s was stored", name)
		}
	}
	if _, err := journal.Transition(record.ActionHash, []PublicationPhase{PublicationSigned}, func(*PublicationRecord) error { return nil }); err == nil {
		t.Fatal("transition from a phase the record is not in was stored")
	}
}

// previewManifest rewrites the fixture manifest's attestor to a key the test
// holds, so the actor's stored key can derive the manifest key id.
func previewManifest(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw, err := servicefixture.ManifestDocumentJSON()
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(extractManifest(t, raw), &manifest); err != nil {
		t.Fatal(err)
	}
	attestorKey := fakeKeys.PublicKey("attestor")
	id, err := mldsa44.KeyID(attestorKey)
	if err != nil {
		t.Fatal(err)
	}
	text := mldsa44.KeyIDText(id)
	manifest["settlement"].(map[string]any)["attestor_key"] = text
	manifest["execution_signer_authorization"] = nativecore.SettlementAttestorAuthorization(text)
	result, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return result, attestorKey
}

type staticActors struct {
	observation ServiceActorObservation
	err         error
	asked       string
}

func (s *staticActors) ObserveServiceActor(_ context.Context, actor string) (ServiceActorObservation, error) {
	s.asked = actor
	return s.observation, s.err
}

func liveActor(t *testing.T, record PublicationRecord, attestorKey []byte) *staticActors {
	t.Helper()
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(record.ManifestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	id, err := mldsa44.KeyID(attestorKey)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: record.Network(),
		CapabilityID: record.CapabilityID, ProviderAgentID: record.OwnerAgentID, CapabilityVersion: record.CapabilityVersion,
		ManifestDigest: record.ManifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := nativecore.StandardAddress("0:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	codeHash := "tvm-cell-sha256:" + hex.EncodeToString(manifest.Settlement.ActorCodeHash)
	policy := nativecore.ServiceActorPolicyV1{PolicyVersion: 3, PricePerCall: big.NewInt(1_000_000),
		CleanupBounty: big.NewInt(nativecore.ServiceActorMinimumCleanupBounty),
		StorageFee:    big.NewInt(nativecore.ServiceActorMinimumStorageFee + nativecore.ServiceActorMinimumCleanupBounty),
		ResponseSLA:   nativecore.ServiceActorMinimumWindowSeconds, RefundClaimWindow: nativecore.ServiceActorMinimumWindowSeconds,
		OpenAccess: true, MetadataHash: metadata, ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme,
		HasAttestor: true, AttestorKeyID: id, AttestorKey: attestorKey}
	return &staticActors{observation: ServiceActorObservation{Checkpoint: 50, PinnedCodeHash: codeHash,
		Account: &toschain.ActorAccount{Address: "0:" + hex.EncodeToString(manifest.Settlement.ActorAccountID), CodeHash: codeHash,
			BalanceNano: 5, Data: &nativecore.ServiceActorDataV1{Owner: owner, Active: true, Policy: policy}}}}
}

// previewJSONFields decodes a preview and returns its PreviewField members.
func previewJSONFields(t *testing.T, preview *PublicationPreview) map[string]PreviewField {
	t.Helper()
	raw, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	result := map[string]PreviewField{}
	for name, value := range generic {
		if len(value) == 0 || value[0] != '{' {
			continue
		}
		var parsed PreviewField
		decoder := json.NewDecoder(strings.NewReader(string(value)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&parsed); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		result[name] = parsed
	}
	return result
}

// requiredPreviewFields are the values an operator must see before signing.
var requiredPreviewFields = []string{"signing_purpose", "network_id", "genesis_root_hash", "genesis_file_hash", "registry_code_hash",
	"owner_agent_id", "owner_agent_state", "capability_id", "capability_version", "manifest_digest", "operation",
	"endpoint_commitment", "transport_binding", "service_actor_address", "service_actor_code_hash", "service_actor_account",
	"service_actor_owner", "attestor_key", "attestor_authorization", "actor_attestor", "actor_metadata_binding",
	"actor_proof_scheme", "terms_hash", "policy_version", "price_per_call_nanotos", "storage_fee_nanotos",
	"cleanup_bounty_nanotos", "response_sla_seconds", "refund_claim_window_seconds", "caller_access", "policy_bounds",
	"publication_fee", "capability_idempotency_key", "manifest_idempotency_key"}

func TestPreviewShowsEveryFieldAndMarksUnresolvedOnesExplicitly(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	preview, err := f.provider(t).PreviewPublication(context.Background(), record, PreviewSources{})
	if err != nil {
		t.Fatal(err)
	}
	fields := previewJSONFields(t, preview)
	if len(fields) != len(requiredPreviewFields) {
		t.Fatalf("preview has %d fields, want %d", len(fields), len(requiredPreviewFields))
	}
	attention := map[string]bool{}
	for _, name := range preview.Attention {
		attention[name] = true
	}
	for _, name := range requiredPreviewFields {
		value, ok := fields[name]
		if !ok || value.Status == "" || value.Source == "" {
			t.Fatalf("preview field %s is missing or has no status/source: %+v", name, value)
		}
		unresolved := value.Status == PreviewUnknown || value.Status == PreviewAbsent || value.Status == PreviewMismatch
		if unresolved != attention[name] {
			t.Fatalf("preview field %s status %s attention %v", name, value.Status, attention[name])
		}
		if unresolved && value.Detail == "" {
			t.Fatalf("unresolved preview field %s gives no reason", name)
		}
	}
	for name, want := range map[string]string{"capability_id": record.CapabilityID, "manifest_digest": record.ManifestDigest,
		"network_id": record.NetworkID, "owner_agent_id": record.OwnerAgentID, "capability_version": record.CapabilityVersion,
		"capability_idempotency_key": record.CapabilityIdempotencyKey} {
		if fields[name].Value != want {
			t.Fatalf("preview %s = %q, want %q", name, fields[name].Value, want)
		}
	}
	if fields["owner_agent_state"].Status != PreviewVerified {
		t.Fatalf("live owner Agent not verified: %+v", fields["owner_agent_state"])
	}
	for _, name := range []string{"terms_hash", "price_per_call_nanotos", "storage_fee_nanotos", "actor_attestor", "transport_binding", "publication_fee"} {
		if fields[name].Status != PreviewUnknown {
			t.Fatalf("without an actor reader %s should be unknown, got %+v", name, fields[name])
		}
	}
	var text strings.Builder
	if err := preview.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, name := range requiredPreviewFields {
		if !strings.Contains(text.String(), "  "+name+" ") {
			t.Fatalf("human preview omits %s", name)
		}
	}
}

func TestPreviewVerifiesServiceActorBindingAgainstFinalizedState(t *testing.T) {
	manifestJSON, attestorKey := previewManifest(t)
	f := newJournalFixture(t, manifestJSON)
	record := f.prepare(t)
	actors := liveActor(t, record, attestorKey)
	preview, err := f.provider(t).PreviewPublication(context.Background(), record, withActors(actors))
	if err != nil {
		t.Fatal(err)
	}
	fields := previewJSONFields(t, preview)
	for _, name := range []string{"service_actor_code_hash", "service_actor_account", "actor_attestor", "actor_metadata_binding",
		"actor_proof_scheme", "policy_bounds", "owner_agent_state"} {
		if fields[name].Status != PreviewVerified {
			t.Fatalf("%s not verified: %+v", name, fields[name])
		}
	}
	policy := actors.observation.Account.Data.Policy
	terms, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	if fields["terms_hash"].Value != hex.EncodeToString(terms[:]) || fields["price_per_call_nanotos"].Value != "1000000" ||
		fields["storage_fee_nanotos"].Value != policy.StorageFee.String() || fields["caller_access"].Value != "open" ||
		fields["service_actor_owner"].Value != "0:"+strings.Repeat("ab", 32) {
		t.Fatalf("actor terms not shown: %+v", fields)
	}
	if actors.asked != fields["service_actor_address"].Value {
		t.Fatalf("preview read actor %s, manifest names %s", actors.asked, fields["service_actor_address"].Value)
	}
	if strings.Join(preview.Attention, ",") != "transport_binding,publication_fee" {
		t.Fatalf("attention = %v", preview.Attention)
	}

	// Each binding the actor can break is reported as a mismatch.
	for name, edit := range map[string]func(*staticActors){
		"actor_metadata_binding": func(a *staticActors) { a.observation.Account.Data.Policy.MetadataHash[0] ^= 0xff },
		"actor_attestor": func(a *staticActors) {
			other := fakeKeys.PublicKey("other-attestor")
			id, _ := mldsa44.KeyID(other)
			a.observation.Account.Data.Policy.AttestorKey, a.observation.Account.Data.Policy.AttestorKeyID = other, id
		},
		"service_actor_code_hash": func(a *staticActors) { a.observation.Account.CodeHash = "tvm-cell-sha256:" + strings.Repeat("44", 32) },
		"service_actor_account":   func(a *staticActors) { a.observation.Account.Data.Active = false },
		"actor_proof_scheme":      func(a *staticActors) { a.observation.Account.Data.Policy.ProofSchemeHash[0] ^= 0xff },
		"policy_bounds":           func(a *staticActors) { a.observation.Account.Data.Policy.PricePerCall = big.NewInt(0) },
	} {
		broken := liveActor(t, record, attestorKey)
		edit(broken)
		preview, err := f.provider(t).PreviewPublication(context.Background(), record, withActors(broken))
		if err != nil {
			t.Fatal(err)
		}
		if got := previewJSONFields(t, preview)[name]; got.Status != PreviewMismatch {
			t.Fatalf("broken %s reported %+v", name, got)
		}
	}

	absent := liveActor(t, record, attestorKey)
	absent.observation.Account = nil
	preview, err = f.provider(t).PreviewPublication(context.Background(), record, withActors(absent))
	if err != nil {
		t.Fatal(err)
	}
	if got := previewJSONFields(t, preview)["terms_hash"]; got.Status != PreviewAbsent {
		t.Fatalf("undeployed actor terms reported %+v", got)
	}
	failing := &staticActors{err: errors.New("quorum unavailable")}
	preview, err = f.provider(t).PreviewPublication(context.Background(), record, withActors(failing))
	if err != nil {
		t.Fatal(err)
	}
	if got := previewJSONFields(t, preview)["price_per_call_nanotos"]; got.Status != PreviewUnknown || !strings.Contains(got.Detail, "quorum unavailable") {
		t.Fatalf("failed actor read reported %+v", got)
	}
}

func TestPreviewReportsAbsentOrTombstonedOwner(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	owner := f.client.owner
	f.client.owner = nil
	preview, err := f.provider(t).PreviewPublication(context.Background(), record, PreviewSources{})
	if err != nil {
		t.Fatal(err)
	}
	if got := previewJSONFields(t, preview)["owner_agent_state"]; got.Status != PreviewAbsent {
		t.Fatalf("absent owner reported %+v", got)
	}
	f.client.owner = proto.Clone(owner).(*nativev1.NativeStateV1)
	f.client.owner.GetAgent().Tombstoned = true
	preview, err = f.provider(t).PreviewPublication(context.Background(), record, PreviewSources{})
	if err != nil {
		t.Fatal(err)
	}
	if got := previewJSONFields(t, preview)["owner_agent_state"]; got.Status != PreviewMismatch {
		t.Fatalf("tombstoned owner reported %+v", got)
	}
}

// rawJournal reads records without the open-time scan, so a single corrupt
// record's own rejection is observed rather than the scan's.
func rawJournal(f *journalFixture) *PublicationJournal {
	return &PublicationJournal{directory: f.directory}
}

func TestSignedPublicationNeverRelaysASubstitutedSignatureSet(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	// A process stopped after storing the verified signatures and before
	// journaling the relay.
	stored := f.sign(t, record, "fixture")
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.reopen(t).Transition(record.ActionHash, []PublicationPhase{PublicationPrepared}, func(r *PublicationRecord) error {
		r.SignedAction, r.Phase = raw, PublicationSigned
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other := f.sign(t, record, "fixture")
	other.AuthoritySignatures = append(other.AuthoritySignatures, proto.Clone(other.AuthoritySignatures[0]).(*nativev1.SignatureV1))
	got, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, other)
	if err == nil || got.Phase != PublicationSigned || f.client.submitCount() != 0 {
		t.Fatalf("substituted signatures in the signed phase: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
}

func TestAmbiguousPublicationAfterPolicyRotationNamesTheRecovery(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	f.client.submitErr = errors.New("unreachable")
	if _, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "fixture")); err == nil {
		t.Fatal("failed relay reported success")
	}
	// The owner rotated its controllers; the stored signatures are stale.
	rotated := proto.Clone(f.client.owner).(*nativev1.NativeStateV1)
	rotated.GetAgent().Policy.Controllers[0].KeyId = fakeKeys.KeyID("rotated")
	rotated.GetAgent().Policy.Controllers[0].Mldsa44PublicKey = fakeKeys.PublicKey("rotated")
	f.client.owner, f.client.submitErr = rotated, nil
	got, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, nil)
	if err == nil || !strings.Contains(err.Error(), "explicit fresh nonces") || got.Phase != PublicationAmbiguous || f.client.submitCount() != 1 {
		t.Fatalf("stale signatures after rotation: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
}

// withActors pins the release the static reader reports, as the command
// does when it builds the reader from the same --actor-code-hash.
func withActors(actors *staticActors) PreviewSources {
	return PreviewSources{Actors: actors, PinnedActorCodeHash: actors.observation.PinnedCodeHash}
}

func TestPreviewComparesThePinWithoutAnyChainRead(t *testing.T) {
	manifestJSON, attestorKey := previewManifest(t)
	f := newJournalFixture(t, manifestJSON)
	record := f.prepare(t)
	wrongPin := "tvm-cell-sha256:" + strings.Repeat("44", 32)
	for name, sources := range map[string]PreviewSources{
		"no reader":   {PinnedActorCodeHash: wrongPin},
		"read failed": {PinnedActorCodeHash: wrongPin, Actors: &staticActors{err: errors.New("quorum unavailable")}},
	} {
		preview, err := f.provider(t).PreviewPublication(context.Background(), record, sources)
		if err != nil {
			t.Fatal(err)
		}
		if got := previewJSONFields(t, preview)["service_actor_code_hash"]; got.Status != PreviewMismatch {
			t.Fatalf("%s: a manifest naming another release than the pin reported %+v", name, got)
		}
	}
	preview, err := f.provider(t).PreviewPublication(context.Background(), record, PreviewSources{})
	if err != nil {
		t.Fatal(err)
	}
	if got := previewJSONFields(t, preview)["service_actor_code_hash"]; got.Status != PreviewKnown || !strings.Contains(got.Detail, "not compared") {
		t.Fatalf("without a pin the code hash reported %+v", got)
	}

	// The account runs the manifest's code, but the operator pinned another
	// release: the message must not blame the account.
	actors := liveActor(t, record, attestorKey)
	actors.observation.PinnedCodeHash = wrongPin
	preview, err = f.provider(t).PreviewPublication(context.Background(), record, withActors(actors))
	if err != nil {
		t.Fatal(err)
	}
	got := previewJSONFields(t, preview)["service_actor_code_hash"]
	if got.Status != PreviewMismatch || !strings.Contains(got.Detail, "equals manifest key 21") || !strings.Contains(got.Detail, "pinned release") {
		t.Fatalf("pin mismatch with a matching account reported %+v", got)
	}
}

func TestPreviewRedactsCredentialsFromReadErrors(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	failing := &staticActors{err: errors.New(`Post "https://operator:hunter2@rpc.example/api?token=s3cret#frag": dial tcp: refused`)}
	preview, err := f.provider(t).PreviewPublication(context.Background(), record, PreviewSources{Actors: failing})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	if err := preview.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(raw), text.String()} {
		for _, secret := range []string{"operator", "hunter2", "s3cret", "frag"} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("preview leaked %q", secret)
			}
		}
		if !strings.Contains(rendered, "rpc.example") {
			t.Fatal("redaction removed the host an operator needs to act on")
		}
	}
	if got := redactURLs("dial grpc://a:b@[::1]:9/x?y=1 and http://plain.example/ok"); strings.Contains(got, "a:b") || strings.Contains(got, "y=1") ||
		!strings.Contains(got, "http://plain.example/ok") {
		t.Fatalf("redactURLs = %q", got)
	}
}

func TestPreviewDoesNotClaimChainVerificationForManifestConsistency(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	preview, err := f.provider(t).PreviewPublication(context.Background(), record, PreviewSources{})
	if err != nil {
		t.Fatal(err)
	}
	if got := previewJSONFields(t, preview)["attestor_authorization"]; got.Status != PreviewKnown || got.Source != SourceManifest {
		t.Fatalf("manifest-internal key 18/21 check reported %+v", got)
	}
}

func TestPrepareRefusesAManifestOffThePinBeforeJournaling(t *testing.T) {
	f := newJournalFixture(t, nil)
	_, _, err := f.provider(t).PrepareJournaledPublication(f.reopen(t), f.manifestJSON, f.ownerID,
		PublicationOptions{PinnedActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32)})
	if err == nil {
		t.Fatal("a manifest naming another Service Actor release was prepared")
	}
	records, err := f.reopen(t).Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("a refused manifest left %d journaled records (%v)", len(records), err)
	}
	if _, _, err := f.provider(t).PrepareJournaledPublication(f.reopen(t), f.manifestJSON, f.ownerID,
		PublicationOptions{PinnedActorCodeHash: "not-a-hash"}); err == nil {
		t.Fatal("a malformed pin was accepted")
	}
}

func TestConcurrentNoncelessPreparesJournalOneCapability(t *testing.T) {
	f := newJournalFixture(t, nil)
	const workers = 8
	start := make(chan struct{})
	hashes := make([]string, workers)
	errs := make([]error, workers)
	var wait sync.WaitGroup
	for worker := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			// Each worker has its own journal handle, as separate processes do.
			journal, err := OpenPublicationJournal(f.directory, time.Now())
			if err != nil {
				errs[worker] = err
				return
			}
			<-start
			record, _, err := f.provider(t).PrepareJournaledPublication(journal, f.manifestJSON, f.ownerID, PublicationOptions{})
			hashes[worker], errs[worker] = record.ActionHash, err
		}()
	}
	close(start)
	wait.Wait()
	for worker := range workers {
		if errs[worker] != nil || hashes[worker] != hashes[0] {
			t.Fatalf("worker %d: %s %v (worker 0: %s)", worker, hashes[worker], errs[worker], hashes[0])
		}
	}
	records, err := f.reopen(t).Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("concurrent prepares journaled %d records (%v)", len(records), err)
	}
}

func TestApplyReportsTheDurablePhaseWhenATransitionFails(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	// Another writer moves the record while this process is inside the
	// relay, so the relay's own submitting -> submitted step fails.
	f.client.onSubmit = func(*scriptedClient) {
		if _, err := rawJournal(f).Transition(record.ActionHash, []PublicationPhase{PublicationSubmitting}, func(r *PublicationRecord) error {
			r.Phase = PublicationAmbiguous
			return nil
		}); err != nil {
			t.Error(err)
		}
	}
	got, err := f.provider(t).ApplyPublication(context.Background(), f.reopen(t), record.ActionHash, f.sign(t, record, "fixture"))
	if err == nil || got.ActionHash != record.ActionHash || got.Phase != PublicationAmbiguous {
		t.Fatalf("failed transition returned phase=%q hash=%q err=%v", got.Phase, got.ActionHash, err)
	}
}
