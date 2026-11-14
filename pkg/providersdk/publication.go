package providersdk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ErrSignatureRequired reports a publication still waiting for the
// externally produced controller signatures.
var ErrSignatureRequired = errors.New("the publication is prepared; supply the externally signed action")

// PublicationOptions are the operator-retained inputs of a journaled
// publication. Empty values are generated and journaled before the action
// leaves this process.
type PublicationOptions struct {
	// ObjectNonce and ActionNonce are both given or both omitted. Omitted,
	// a journaled publication of the same manifest by the same owner on the
	// same network is resumed; otherwise fresh nonces are generated.
	ObjectNonce, ActionNonce []byte
	// CapabilityIdempotencyKey and ManifestIdempotencyKey are the durable
	// Gateway retry keys for the relay and the catalog admission.
	CapabilityIdempotencyKey, ManifestIdempotencyKey string
	// PinnedActorCodeHash, when set, is the tvm-cell-sha256 Service Actor
	// release the manifest's key 21 must name. A manifest naming another
	// release is refused before anything is journaled: an immutable
	// manifest cannot be repaired after publication.
	PinnedActorCodeHash string
}

// CheckManifestActorPin refuses a manifest whose key 21 Service Actor code
// hash is not the pinned release. It reads no chain state.
func CheckManifestActorPin(manifestJSON []byte, pinnedActorCodeHash string) error {
	if len(manifestJSON) == 0 || len(manifestJSON) > MaxManifestJSONBytes {
		return errors.New("invalid provider manifest input")
	}
	digest, ok := cutPrefix(pinnedActorCodeHash, "tvm-cell-sha256:")
	if !ok || !validHex32(digest) {
		return errors.New("the pinned Service Actor code hash must be tvm-cell-sha256:<lowercase hex>")
	}
	manifest, err := nativecore.DecodeSoftwareWorkManifestJSON(manifestJSON)
	if err != nil {
		return fmt.Errorf("decode provider manifest: %w", err)
	}
	if hex.EncodeToString(manifest.Settlement.ActorCodeHash) != digest {
		return fmt.Errorf("manifest key 21 names Service Actor code tvm-cell-sha256:%x, not the pinned release %s; an immutable manifest cannot be fixed after publication",
			manifest.Settlement.ActorCodeHash, pinnedActorCodeHash)
	}
	return nil
}

func cutPrefix(value, prefix string) (string, bool) {
	if len(value) < len(prefix) || value[:len(prefix)] != prefix {
		return "", false
	}
	return value[len(prefix):], true
}

// PrepareJournaledPublication prepares a Capability publication and makes it
// durable before returning, so the action handed to the external signer is
// always recoverable. created is false when an existing record was resumed;
// that record is returned in whatever phase it has reached.
func (p *Provider) PrepareJournaledPublication(journal *PublicationJournal, manifestJSON []byte, ownerAgentID string,
	options PublicationOptions) (PublicationRecord, bool, error) {
	if p == nil || journal == nil {
		return PublicationRecord{}, false, errors.New("invalid journaled publication request")
	}
	for _, key := range []string{options.CapabilityIdempotencyKey, options.ManifestIdempotencyKey} {
		if key != "" && !validRetryKey(key) {
			return PublicationRecord{}, false, errors.New("publication retry keys must be bounded single-line values")
		}
	}
	if options.CapabilityIdempotencyKey != "" && options.CapabilityIdempotencyKey == options.ManifestIdempotencyKey {
		return PublicationRecord{}, false, errors.New("publication retry keys must differ")
	}
	if (options.ObjectNonce == nil) != (options.ActionNonce == nil) {
		return PublicationRecord{}, false, errors.New("give both publication nonces or neither")
	}
	if options.PinnedActorCodeHash != "" {
		if err := CheckManifestActorPin(manifestJSON, options.PinnedActorCodeHash); err != nil {
			return PublicationRecord{}, false, err
		}
	}
	// Without nonces the journal resumes the existing publication of this
	// manifest, deciding under the same lock as the write; the fresh nonces
	// below are used only when there is none.
	resumeByManifest := options.ObjectNonce == nil
	if resumeByManifest {
		objectNonce, err := randomNonzero(32)
		if err != nil {
			return PublicationRecord{}, false, err
		}
		actionNonce, err := randomNonzero(32)
		if err != nil {
			return PublicationRecord{}, false, err
		}
		options.ObjectNonce, options.ActionNonce = objectNonce, actionNonce
	}
	prepared, err := p.PrepareCapabilityPublication(manifestJSON, ownerAgentID, options.ObjectNonce, options.ActionNonce)
	if err != nil {
		return PublicationRecord{}, false, err
	}
	capabilityKey, manifestKey := options.CapabilityIdempotencyKey, options.ManifestIdempotencyKey
	if capabilityKey == "" {
		if capabilityKey, err = randomKey("capability-"); err != nil {
			return PublicationRecord{}, false, err
		}
	}
	if manifestKey == "" {
		if manifestKey, err = randomKey("manifest-"); err != nil {
			return PublicationRecord{}, false, err
		}
	}
	action, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(prepared.Action)
	if err != nil {
		return PublicationRecord{}, false, err
	}
	registration := prepared.Action.GetRegisterCapability()
	now := p.now().Unix()
	record := PublicationRecord{Schema: publicationRecordSchema, ActionHash: prepared.ActionHash, Phase: PublicationPrepared,
		NetworkID: p.network.NetworkId, GenesisRootHash: p.network.GenesisRootHash, GenesisFileHash: p.network.GenesisFileHash,
		RegistryCodeHash: p.registryCodeHash, OwnerAgentID: ownerAgentID, CapabilityID: prepared.CapabilityID,
		CapabilityVersion: registration.InitialVersion.Version, ManifestDigest: prepared.ManifestDigest,
		ManifestCBOR: prepared.ManifestCBOR, ObjectNonce: hex.EncodeToString(options.ObjectNonce),
		ActionNonce: hex.EncodeToString(options.ActionNonce), Action: action,
		CapabilityIdempotencyKey: capabilityKey, ManifestIdempotencyKey: manifestKey, CreatedUnix: now, UpdatedUnix: now}
	stored, created, err := journal.createOrResume(record, resumeByManifest)
	if err != nil {
		return PublicationRecord{}, false, err
	}
	if !created {
		if err := matchRetryKeys(stored, options); err != nil {
			return PublicationRecord{}, false, err
		}
	}
	return stored, created, nil
}

func matchRetryKeys(record PublicationRecord, options PublicationOptions) error {
	if (options.CapabilityIdempotencyKey != "" && options.CapabilityIdempotencyKey != record.CapabilityIdempotencyKey) ||
		(options.ManifestIdempotencyKey != "" && options.ManifestIdempotencyKey != record.ManifestIdempotencyKey) {
		return errors.New("the journaled publication uses other retry keys; a retry key is never replaced")
	}
	return nil
}

func randomNonzero(size int) ([]byte, error) {
	value := make([]byte, size)
	for {
		if _, err := rand.Read(value); err != nil {
			return nil, errors.New("generate publication nonce")
		}
		for _, b := range value {
			if b != 0 {
				return value, nil
			}
		}
	}
}

func randomKey(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("generate publication retry key")
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

// advance applies one journal transition. On failure it returns the
// record as the journal now holds it, so a caller never reports a phase
// older than the durable one; previous is returned only when the journal
// cannot be read either.
func (p *Provider) advance(journal *PublicationJournal, previous PublicationRecord, from []PublicationPhase,
	update func(*PublicationRecord) error) (PublicationRecord, error) {
	record, err := journal.Transition(previous.ActionHash, from, update)
	if err == nil {
		return record, nil
	}
	if current, readErr := journal.Read(previous.ActionHash); readErr == nil {
		return current, err
	}
	return previous, err
}

// ApplyPublication advances one journaled publication as far as it can and
// returns the record in its latest durable phase, also when it fails. It
// never rebuilds the action or accepts a different signature set once one is
// stored; every re-run, after a crash at any phase, continues the same
// action:
//
//   - prepared: requires signed, verifies it against the finalized owner
//     policy and stores it.
//   - signed: takes the record's relay lock, journals the attempt as
//     submitting, relays once and records the Gateway acknowledgement
//     (transport only) as submitted.
//   - submitting: another live process holds the relay lock; nothing is
//     done. If that process has died, the record becomes ambiguous.
//   - submitted: waits for exact finalized state. A finality timeout makes
//     the record ambiguous.
//   - ambiguous: settles from finalized state first. Only a finalized
//     absence re-relays, with the stored signed action and the same retry
//     key.
//   - finalized: publishes the stored manifest to the derived catalog.
//
// signed may be nil once the record is past prepared.
func (p *Provider) ApplyPublication(ctx context.Context, journal *PublicationJournal, actionHash string,
	signed *nativev1.SignedNativeActionV1) (PublicationRecord, error) {
	if p == nil || ctx == nil || journal == nil {
		return PublicationRecord{}, errors.New("invalid journaled publication request")
	}
	record, err := journal.Read(actionHash)
	if err != nil {
		return PublicationRecord{}, err
	}
	if !proto.Equal(record.Network(), p.network) || record.RegistryCodeHash != p.registryCodeHash {
		return record, errors.New("the journaled publication targets another network or Registry than this provider")
	}
	prepared, err := record.Prepared()
	if err != nil {
		return record, err
	}
	if signed != nil && (!proto.Equal(signed.Action, prepared.Action) || len(signed.CounterpartySignatures) != 0 ||
		len(signed.AuthoritySignatures) == 0 || len(signed.AuthoritySignatures) > nativecore.MaxSignatures) {
		return record, errors.New("signed Capability action differs from the journaled reviewed publication")
	}
	for {
		switch record.Phase {
		case PublicationPrepared:
			if signed == nil {
				return record, ErrSignatureRequired
			}
			if err := p.VerifyPublicationSignatures(ctx, prepared, signed.AuthoritySignatures); err != nil {
				return record, err
			}
			raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(signed)
			if err != nil {
				return record, err
			}
			if record, err = p.advance(journal, record, []PublicationPhase{PublicationPrepared}, func(r *PublicationRecord) error {
				r.SignedAction, r.Phase, r.UpdatedUnix = raw, PublicationSigned, p.now().Unix()
				return nil
			}); err != nil {
				return record, err
			}
		case PublicationSigned:
			stored, err := record.Signed()
			if err != nil {
				return record, err
			}
			if signed != nil && !proto.Equal(signed, stored) {
				return record, errors.New("a different signed action is already journaled; it is never replaced")
			}
			if record, err = p.relayJournaled(ctx, journal, record, prepared, stored); err != nil {
				return record, err
			}
		case PublicationSubmitting:
			recovered, err := journal.RecoverAbandonedRelay(actionHash, p.now())
			if err != nil {
				return record, err
			}
			if recovered.Phase == PublicationSubmitting {
				return recovered, ErrRelayInProgress
			}
			record = recovered
		case PublicationSubmitted:
			state, err := p.WaitForPublication(ctx, prepared)
			if err != nil {
				// The finality timeout elapsed while the caller still waits:
				// the acknowledged relay is no longer evidence of anything.
				if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
					record, _ = p.advance(journal, record, []PublicationPhase{PublicationSubmitted}, func(r *PublicationRecord) error {
						r.Phase, r.UpdatedUnix = PublicationAmbiguous, p.now().Unix()
						return nil
					})
				}
				return record, fmt.Errorf("wait for finalized Capability state: %w", err)
			}
			if record, err = p.finalizeJournaled(journal, record, state); err != nil {
				return record, err
			}
		case PublicationAmbiguous:
			state, found, err := p.ResolvePublication(ctx, prepared)
			if err != nil {
				return record, fmt.Errorf("settle ambiguous publication from finalized state: %w", err)
			}
			if found {
				if record, err = p.finalizeJournaled(journal, record, state); err != nil {
					return record, err
				}
				continue
			}
			stored, err := record.Signed()
			if err != nil {
				return record, err
			}
			if signed != nil && !proto.Equal(signed, stored) {
				return record, errors.New("a different signed action is already journaled; it is never replaced")
			}
			if record, err = p.relayJournaled(ctx, journal, record, prepared, stored); err != nil {
				return record, err
			}
		case PublicationFinalized:
			catalog, err := p.PublishManifest(ctx, prepared, record.ManifestIdempotencyKey)
			if err != nil {
				return record, fmt.Errorf("catalog admission (the Capability is already finalized): %w", err)
			}
			if record, err = p.advance(journal, record, []PublicationPhase{PublicationFinalized}, func(r *PublicationRecord) error {
				r.Phase, r.CatalogCheckpoint, r.UpdatedUnix = PublicationCataloged, catalog.GetReference().GetFinalizedCheckpoint(), p.now().Unix()
				return nil
			}); err != nil {
				return record, err
			}
		case PublicationCataloged:
			return record, nil
		default:
			return record, fmt.Errorf("publication phase %q is unknown", record.Phase)
		}
	}
}

// relayJournaled holds the record's relay lock from journaling the attempt
// as submitting until the outcome is journaled, so no other process can
// treat the attempt as abandoned while it runs. It verifies the stored
// signatures against the current owner policy and relays the stored signed
// action under the journaled retry key. A failed relay leaves the record
// ambiguous.
func (p *Provider) relayJournaled(ctx context.Context, journal *PublicationJournal, record PublicationRecord,
	prepared *PreparedPublication, signed *nativev1.SignedNativeActionV1) (PublicationRecord, error) {
	if signed == nil {
		return record, errors.New("the journaled publication has no signed action")
	}
	if err := p.VerifyPublicationSignatures(ctx, prepared, signed.AuthoritySignatures); err != nil {
		if record.Phase == PublicationAmbiguous {
			return record, fmt.Errorf("the journaled signatures no longer satisfy the finalized owner policy and finalized state shows no Capability; "+
				"prepare a new publication with explicit fresh nonces: %w", err)
		}
		return record, err
	}
	release, err := journal.acquireRelay(record.ActionHash)
	if err != nil {
		return record, err
	}
	defer release()
	from := record.Phase
	record, err = p.advance(journal, record, []PublicationPhase{from}, func(r *PublicationRecord) error {
		r.Phase, r.SubmitAttempts, r.UpdatedUnix = PublicationSubmitting, r.SubmitAttempts+1, p.now().Unix()
		if r.SubmitAttempts == 0 {
			return errors.New("publication submission attempts overflowed")
		}
		return nil
	})
	if err != nil {
		return record, err
	}
	relayErr := p.relayCapability(ctx, prepared, signed.AuthoritySignatures, record.CapabilityIdempotencyKey)
	next := PublicationSubmitted
	if relayErr != nil {
		next = PublicationAmbiguous
	}
	record, err = p.advance(journal, record, []PublicationPhase{PublicationSubmitting}, func(r *PublicationRecord) error {
		r.Phase, r.UpdatedUnix = next, p.now().Unix()
		return nil
	})
	if err != nil {
		return record, err
	}
	if relayErr != nil {
		return record, fmt.Errorf("relay outcome is ambiguous and will be settled from finalized state: %w", relayErr)
	}
	return record, nil
}

func (p *Provider) finalizeJournaled(journal *PublicationJournal, record PublicationRecord, state *nativev1.NativeStateV1) (PublicationRecord, error) {
	return p.advance(journal, record, []PublicationPhase{PublicationSubmitted, PublicationAmbiguous}, func(r *PublicationRecord) error {
		r.Phase, r.FinalizedCheckpoint, r.FinalizedTVMStateHash, r.UpdatedUnix =
			PublicationFinalized, state.GetReference().GetFinalizedCheckpoint(), state.GetTvmStateHash(), p.now().Unix()
		return nil
	})
}
