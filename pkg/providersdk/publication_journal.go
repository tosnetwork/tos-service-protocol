package providersdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// PublicationPhase is a Capability publication's position in the provider
// journal. Phases only move forward; the journal never rebuilds an action.
type PublicationPhase string

const (
	// PublicationPrepared: the exact action is durable and may already be
	// with the external signer. No signature is stored.
	PublicationPrepared PublicationPhase = "prepared"
	// PublicationSigned: authority signatures over the exact action were
	// verified against the finalized owner policy and stored.
	PublicationSigned PublicationPhase = "signed"
	// PublicationSubmitting: durably recorded before the relay starts; a
	// record found here when the journal is opened is ambiguous.
	PublicationSubmitting PublicationPhase = "submitting"
	// PublicationSubmitted: the Gateway acknowledged the exact action hash.
	// This is transport only, never publication.
	PublicationSubmitted PublicationPhase = "submitted"
	// PublicationAmbiguous: the relay may or may not have reached the chain.
	// It is settled from finalized state first; only a finalized absence
	// re-relays, and then only the same signed action under the same retry
	// key.
	PublicationAmbiguous PublicationPhase = "ambiguous"
	// PublicationFinalized: finalized Capability state matches the action.
	PublicationFinalized PublicationPhase = "finalized"
	// PublicationCataloged: the Gateway's derived catalog admitted the
	// exact manifest against finalized state. Catalog admission is a
	// projection, recorded separately from chain publication.
	PublicationCataloged PublicationPhase = "cataloged"
)

const publicationRecordSchema = "tos.service.provider-publication.v1"

// maxPublicationRecordBytes bounds one record file. The manifest is at most
// 1 MiB of canonical CBOR and is stored base64-encoded, so the bound leaves
// room for that and the action; the writer enforces it before publishing so
// a record the reader would refuse is never written.
const maxPublicationRecordBytes = 2 << 20

// PublicationRecord is everything needed to resume one publication without
// re-deriving or re-signing anything. The action hash names the record.
type PublicationRecord struct {
	Schema                   string           `json:"schema"`
	ActionHash               string           `json:"action_hash"`
	Phase                    PublicationPhase `json:"phase"`
	NetworkID                string           `json:"network_id"`
	GenesisRootHash          string           `json:"genesis_root_hash"`
	GenesisFileHash          string           `json:"genesis_file_hash"`
	RegistryCodeHash         string           `json:"registry_code_hash"`
	OwnerAgentID             string           `json:"owner_agent_id"`
	CapabilityID             string           `json:"capability_id"`
	CapabilityVersion        string           `json:"capability_version"`
	ManifestDigest           string           `json:"manifest_digest"`
	ManifestCBOR             []byte           `json:"manifest_cbor"`
	ObjectNonce              string           `json:"object_nonce"`
	ActionNonce              string           `json:"action_nonce"`
	Action                   json.RawMessage  `json:"action"`
	CapabilityIdempotencyKey string           `json:"capability_idempotency_key"`
	ManifestIdempotencyKey   string           `json:"manifest_idempotency_key"`
	SignedAction             json.RawMessage  `json:"signed_action,omitempty"`
	SubmitAttempts           uint32           `json:"submit_attempts"`
	CreatedUnix              int64            `json:"created_unix"`
	UpdatedUnix              int64            `json:"updated_unix"`
	FinalizedCheckpoint      uint64           `json:"finalized_checkpoint,omitempty"`
	FinalizedTVMStateHash    string           `json:"finalized_tvm_state_hash,omitempty"`
	CatalogCheckpoint        uint64           `json:"catalog_checkpoint,omitempty"`
}

var publicationPhases = map[PublicationPhase]int{PublicationPrepared: 0, PublicationSigned: 1, PublicationSubmitting: 2,
	PublicationSubmitted: 3, PublicationAmbiguous: 3, PublicationFinalized: 4, PublicationCataloged: 5}

// Network returns the record's network domain.
func (r PublicationRecord) Network() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: r.NetworkID, GenesisRootHash: r.GenesisRootHash, GenesisFileHash: r.GenesisFileHash}
}

// Prepared returns the reviewed publication the record holds, after checking
// every field against the stored action.
func (r PublicationRecord) Prepared() (*PreparedPublication, error) {
	action, err := r.decodeAction()
	if err != nil {
		return nil, err
	}
	return &PreparedPublication{CapabilityID: r.CapabilityID, ManifestDigest: r.ManifestDigest,
		ManifestCBOR: append([]byte(nil), r.ManifestCBOR...), ActionHash: r.ActionHash, Action: action}, nil
}

// Signed returns the stored signed action, or nil before the signed phase.
func (r PublicationRecord) Signed() (*nativev1.SignedNativeActionV1, error) {
	if len(r.SignedAction) == 0 {
		return nil, nil
	}
	var signed nativev1.SignedNativeActionV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(r.SignedAction, &signed); err != nil {
		return nil, fmt.Errorf("publication record signed action does not decode: %w", err)
	}
	return &signed, nil
}

func (r PublicationRecord) decodeAction() (*nativev1.NativeActionV1, error) {
	var action nativev1.NativeActionV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(r.Action, &action); err != nil {
		return nil, fmt.Errorf("publication record action does not decode: %w", err)
	}
	return &action, nil
}

// validate re-derives every binding the record claims. A record that fails
// is refused whole: it is never repaired or partially used.
func (r PublicationRecord) validate() error {
	if r.Schema != publicationRecordSchema {
		return fmt.Errorf("publication record schema %q is not %s", r.Schema, publicationRecordSchema)
	}
	if _, ok := publicationPhases[r.Phase]; !ok {
		return fmt.Errorf("publication record phase %q is unknown", r.Phase)
	}
	if !validActionHash(r.ActionHash) {
		return errors.New("publication record action hash is not canonical")
	}
	if !validRetryKey(r.CapabilityIdempotencyKey) || !validRetryKey(r.ManifestIdempotencyKey) ||
		r.CapabilityIdempotencyKey == r.ManifestIdempotencyKey {
		return errors.New("publication record retry keys must be two distinct bounded keys")
	}
	manifestHash := sha256.Sum256(r.ManifestCBOR)
	if "sha256:"+hex.EncodeToString(manifestHash[:]) != r.ManifestDigest {
		return errors.New("publication record manifest bytes do not match its digest")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(r.ManifestCBOR)
	if err != nil {
		return fmt.Errorf("publication record manifest is not canonical: %w", err)
	}
	if manifest.Version != r.CapabilityVersion {
		return errors.New("publication record version is not the manifest version")
	}
	action, err := r.decodeAction()
	if err != nil {
		return err
	}
	built, err := nativecore.BuildAction(action)
	registration := action.GetRegisterCapability()
	if err != nil || built.Kind != nativecore.KindRegisterCapability || registration == nil || registration.InitialVersion == nil {
		return errors.New("publication record action is not a Capability registration")
	}
	if built.HashString != r.ActionHash || action.TargetObjectId != r.CapabilityID ||
		!proto.Equal(action.Network, r.Network()) || action.TargetContractCodeHash != r.RegistryCodeHash ||
		registration.OwnerAgentId != r.OwnerAgentID || hex.EncodeToString(registration.ObjectNonce) != r.ObjectNonce ||
		hex.EncodeToString(action.Nonce) != r.ActionNonce || registration.InitialVersion.Version != r.CapabilityVersion ||
		registration.InitialVersion.ManifestDigest != r.ManifestDigest {
		return errors.New("publication record fields do not match its action")
	}
	derived, err := nativecore.DeriveCapabilityID(r.Network(), registration.ObjectNonce, r.OwnerAgentID, registration.InitialVersion)
	if err != nil || derived != r.CapabilityID {
		return errors.New("publication record Capability ID is not derived from its action")
	}
	signed, err := r.Signed()
	if err != nil {
		return err
	}
	if r.Phase == PublicationPrepared {
		if signed != nil {
			return errors.New("a prepared publication record carries a signed action")
		}
	} else if signed == nil || !proto.Equal(signed.Action, action) || len(signed.CounterpartySignatures) != 0 ||
		len(signed.AuthoritySignatures) == 0 || len(signed.AuthoritySignatures) > nativecore.MaxSignatures {
		return errors.New("publication record signed action is missing or is not the exact action")
	}
	finalized := r.Phase == PublicationFinalized || r.Phase == PublicationCataloged
	if finalized != (r.FinalizedCheckpoint != 0) || finalized != (r.FinalizedTVMStateHash != "") ||
		(r.Phase == PublicationCataloged) != (r.CatalogCheckpoint != 0) {
		return errors.New("publication record finality fields do not match its phase")
	}
	if r.Phase != PublicationPrepared && r.Phase != PublicationSigned && r.SubmitAttempts == 0 {
		return errors.New("publication record past signing records no submission attempt")
	}
	return nil
}

// immutableEqual reports whether two records describe the same reviewed
// publication, ignoring the fields that advance with its phase.
func (r PublicationRecord) immutableEqual(other PublicationRecord) bool {
	return r.ActionHash == other.ActionHash && r.NetworkID == other.NetworkID && r.GenesisRootHash == other.GenesisRootHash &&
		r.GenesisFileHash == other.GenesisFileHash && r.RegistryCodeHash == other.RegistryCodeHash &&
		r.OwnerAgentID == other.OwnerAgentID && r.CapabilityID == other.CapabilityID &&
		r.CapabilityVersion == other.CapabilityVersion && r.ManifestDigest == other.ManifestDigest &&
		bytes.Equal(r.ManifestCBOR, other.ManifestCBOR) && r.ObjectNonce == other.ObjectNonce && r.ActionNonce == other.ActionNonce
}

func validActionHash(value string) bool {
	digest, ok := strings.CutPrefix(value, "sha256:")
	return ok && validHex32(digest)
}

func validHex32(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func validRetryKey(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

// PublicationJournal is an owner-private directory of publication records.
// Every read-modify-write holds one exclusive file lock across processes,
// and every write is an atomic, synced replacement.
type PublicationJournal struct{ directory string }

// OpenPublicationJournal opens the journal and recovers every abandoned
// relay: a record left in the submitting phase whose relay lock no live
// process holds becomes ambiguous, because the process that wrote it may
// have reached the Gateway before it stopped. A record whose relay is still
// running is left alone.
func OpenPublicationJournal(directory string, now time.Time) (*PublicationJournal, error) {
	if !osguard.OwnerPrivateStorageSupported() {
		return nil, errors.New("provider publication journal requires owner-private storage")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("provider publication journal directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, errors.New("provider publication journal directory must be an owner-private directory, not a symlink")
	}
	journal := &PublicationJournal{directory: directory}
	err = journal.withLock(func() error {
		records, err := journal.recordsUnlocked()
		if err != nil {
			return err
		}
		for _, record := range records {
			if _, err := journal.recoverAbandonedUnlocked(record, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return journal, nil
}

func (j *PublicationJournal) relayLockPath(actionHash string) string {
	return filepath.Join(j.directory, "publication-"+strings.TrimPrefix(actionHash, "sha256:")+".relay")
}

// acquireRelay takes the record's relay lock without waiting. The holder is
// the only process that may move the record into, or out of, submitting;
// the lock is released by the operating system if that process dies.
func (j *PublicationJournal) acquireRelay(actionHash string) (func(), error) {
	if !validActionHash(actionHash) {
		return nil, errors.New("invalid publication action hash")
	}
	release, acquired, err := osguard.TryExclusiveFileLock(j.relayLockPath(actionHash), 0o600)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, ErrRelayInProgress
	}
	return release, nil
}

// ErrRelayInProgress reports a publication another live process is relaying.
var ErrRelayInProgress = errors.New("another process is relaying this publication; retry after it finishes")

// recoverAbandonedUnlocked turns a submitting record into ambiguous only
// when no live process holds its relay lock. The caller holds the journal
// lock; the relay lock is only tried, never waited for, so the two locks
// cannot deadlock.
func (j *PublicationJournal) recoverAbandonedUnlocked(record PublicationRecord, now time.Time) (PublicationRecord, error) {
	if record.Phase != PublicationSubmitting {
		return record, nil
	}
	release, err := j.acquireRelay(record.ActionHash)
	if errors.Is(err, ErrRelayInProgress) {
		return record, nil
	}
	if err != nil {
		return record, err
	}
	defer release()
	record.Phase, record.UpdatedUnix = PublicationAmbiguous, now.Unix()
	if err := j.writeUnlocked(record); err != nil {
		return record, err
	}
	return record, nil
}

// RecoverAbandonedRelay re-checks one record, for a long-lived journal whose
// relaying process may have died after the journal was opened.
func (j *PublicationJournal) RecoverAbandonedRelay(actionHash string, now time.Time) (PublicationRecord, error) {
	var result PublicationRecord
	err := j.withLock(func() error {
		record, err := j.readUnlocked(actionHash)
		if err != nil {
			return err
		}
		result, err = j.recoverAbandonedUnlocked(record, now)
		return err
	})
	return result, err
}

// Directory returns the journal directory.
func (j *PublicationJournal) Directory() string { return j.directory }

func (j *PublicationJournal) withLock(fn func() error) error {
	return osguard.WithExclusiveFileLock(filepath.Join(j.directory, "publication.lock"), 0o600, fn)
}

func (j *PublicationJournal) path(actionHash string) string {
	return filepath.Join(j.directory, "publication-"+strings.TrimPrefix(actionHash, "sha256:")+".json")
}

// CreateOrMatch stores a new prepared record, or returns the stored record
// when one already describes the same reviewed publication. A stored record
// is never overwritten: re-running prepare after a crash converges on it,
// whatever phase it has reached.
func (j *PublicationJournal) CreateOrMatch(record PublicationRecord) (PublicationRecord, bool, error) {
	return j.createOrResume(record, false)
}

// createOrResume is CreateOrMatch, optionally first resuming the one record
// that publishes the same manifest for the same owner, network and
// Registry. The lookup and the write hold one lock, so concurrent prepares
// of one manifest never journal two Capabilities.
func (j *PublicationJournal) createOrResume(record PublicationRecord, resumeByManifest bool) (PublicationRecord, bool, error) {
	if record.Phase != PublicationPrepared {
		return PublicationRecord{}, false, errors.New("a new publication record must be prepared")
	}
	if err := record.validate(); err != nil {
		return PublicationRecord{}, false, err
	}
	var result PublicationRecord
	created := false
	err := j.withLock(func() error {
		if resumeByManifest {
			records, err := j.recordsUnlocked()
			if err != nil {
				return err
			}
			var matches []PublicationRecord
			for _, existing := range records {
				if existing.NetworkID == record.NetworkID && existing.GenesisRootHash == record.GenesisRootHash &&
					existing.GenesisFileHash == record.GenesisFileHash && existing.RegistryCodeHash == record.RegistryCodeHash &&
					existing.OwnerAgentID == record.OwnerAgentID && existing.ManifestDigest == record.ManifestDigest {
					matches = append(matches, existing)
				}
			}
			switch len(matches) {
			case 0:
			case 1:
				result = matches[0]
				return nil
			default:
				return fmt.Errorf("%d journaled publications carry manifest %s; give the nonces of the one to resume", len(matches), record.ManifestDigest)
			}
		}
		existing, err := j.readUnlocked(record.ActionHash)
		if err == nil {
			if !existing.immutableEqual(record) {
				return errors.New("a different publication is journaled under this action hash")
			}
			result = existing
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := j.writeUnlocked(record); err != nil {
			return err
		}
		result, created = record, true
		return nil
	})
	return result, created, err
}

// Transition moves a record from one of the allowed phases under the lock,
// so two processes never both start the same step.
func (j *PublicationJournal) Transition(actionHash string, from []PublicationPhase, update func(*PublicationRecord) error) (PublicationRecord, error) {
	var result PublicationRecord
	err := j.withLock(func() error {
		record, err := j.readUnlocked(actionHash)
		if err != nil {
			return err
		}
		allowed := false
		for _, phase := range from {
			allowed = allowed || record.Phase == phase
		}
		if !allowed {
			return fmt.Errorf("publication %s is %s", actionHash, record.Phase)
		}
		before := record
		if err := update(&record); err != nil {
			return err
		}
		if !record.immutableEqual(before) || record.Schema != before.Schema ||
			record.CapabilityIdempotencyKey != before.CapabilityIdempotencyKey ||
			record.ManifestIdempotencyKey != before.ManifestIdempotencyKey || !bytes.Equal(record.Action, before.Action) ||
			(len(before.SignedAction) != 0 && !bytes.Equal(record.SignedAction, before.SignedAction)) {
			return errors.New("a publication transition may not change the reviewed publication")
		}
		// The one backward step is ambiguous -> submitting: a finalized
		// absence re-relays the same signed action under the same key.
		reRelay := before.Phase == PublicationAmbiguous && record.Phase == PublicationSubmitting
		if publicationPhases[record.Phase] < publicationPhases[before.Phase] && !reRelay {
			return fmt.Errorf("publication %s cannot move back from %s to %s", actionHash, before.Phase, record.Phase)
		}
		if err := record.validate(); err != nil {
			return err
		}
		if err := j.writeUnlocked(record); err != nil {
			return err
		}
		result = record
		return nil
	})
	return result, err
}

// Read returns one record.
func (j *PublicationJournal) Read(actionHash string) (PublicationRecord, error) {
	var result PublicationRecord
	err := j.withLock(func() error {
		record, err := j.readUnlocked(actionHash)
		result = record
		return err
	})
	return result, err
}

// Records returns every record ordered by action hash.
func (j *PublicationJournal) Records() ([]PublicationRecord, error) {
	var result []PublicationRecord
	err := j.withLock(func() error {
		records, err := j.recordsUnlocked()
		result = records
		return err
	})
	return result, err
}

func (j *PublicationJournal) recordsUnlocked() ([]PublicationRecord, error) {
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return nil, err
	}
	var records []PublicationRecord
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "publication-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		record, err := j.readUnlocked("sha256:" + strings.TrimSuffix(strings.TrimPrefix(name, "publication-"), ".json"))
		if err != nil {
			return nil, fmt.Errorf("journal entry %s: %w", name, err)
		}
		records = append(records, record)
	}
	sort.Slice(records, func(a, b int) bool { return records[a].ActionHash < records[b].ActionHash })
	return records, nil
}

func (j *PublicationJournal) readUnlocked(actionHash string) (PublicationRecord, error) {
	var record PublicationRecord
	if !validActionHash(actionHash) {
		return record, errors.New("invalid publication action hash")
	}
	path := j.path(actionHash)
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) || info.Size() > maxPublicationRecordBytes {
		return record, errors.New("publication record is not an owner-private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("publication record %s does not decode: %w", actionHash, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return record, errors.New("publication record has trailing data")
	}
	if record.ActionHash != actionHash {
		return record, errors.New("publication record names another action")
	}
	if err := record.validate(); err != nil {
		return record, err
	}
	return record, nil
}

func (j *PublicationJournal) writeUnlocked(record PublicationRecord) error {
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if len(raw)+1 > maxPublicationRecordBytes {
		return fmt.Errorf("publication record is %d bytes, above the %d-byte limit", len(raw)+1, maxPublicationRecordBytes)
	}
	file, err := os.CreateTemp(j.directory, ".publication-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, j.path(record.ActionHash)); err != nil {
		return err
	}
	directory, err := os.Open(j.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
