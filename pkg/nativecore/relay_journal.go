package nativecore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RelayJournal provides three independent uniqueness boundaries. Request keys
// are retry aliases, state slots are canonical fee-spend claims, and action
// identities bind the action occupying a slot.
//
// The operation is the action, never its signature bytes: ML-DSA-44 signing
// may be hedged, so one action can arrive with different, equally valid
// signature sets and therefore different bodies. A slot records the exact
// body it was claimed with; a later body for the same action is the same
// operation and matches the slot. While the slot is prepared (never
// broadcast) its recorded body is replaced only through AcquireBroadcastLease,
// when the caller found the recorded signatures no longer authorize; once
// broadcasting or complete it is never replaced.
type RelayJournal interface {
	Lookup(requestKey, actionIdentity string, intent RelayIntent) (found, complete bool, existingHash string, err error)
	Begin(requestKey, actionIdentity string, intent RelayIntent, body []byte, limits RelaySpendLimits, now time.Time) (complete bool, existingHash string, err error)
	RecordedBody(actionIdentity string, intent RelayIntent) (body []byte, prepared bool, err error)
	AcquireBroadcastLease(actionIdentity string, intent RelayIntent, expectedBodyHash string, replacement []byte) (acquired, complete bool, body []byte, err error)
	Complete(actionIdentity string, intent RelayIntent) error
}

// MaxRelayBodyBytes bounds the outbound body BOC a slot records. The
// Registry's largest message is far below it.
const MaxRelayBodyBytes = 128 << 10

type RelaySpendLimits struct {
	Window                     time.Duration
	MaxActionsPerTarget        uint64
	MaxFundingPerTargetNanoTOS uint64
	MaxActionsPerWallet        uint64
	MaxFundingPerWalletNanoTOS uint64
}

func (l RelaySpendLimits) valid() bool {
	return l.Window >= time.Minute && l.Window <= 31*24*time.Hour &&
		l.MaxActionsPerTarget > 0 && l.MaxFundingPerTargetNanoTOS > 0 &&
		l.MaxActionsPerWallet > 0 && l.MaxFundingPerWalletNanoTOS > 0 &&
		l.MaxActionsPerTarget <= l.MaxActionsPerWallet &&
		l.MaxFundingPerTargetNanoTOS <= l.MaxFundingPerWalletNanoTOS
}

func (l RelaySpendLimits) permitsSingle(funding uint64) bool {
	return l.valid() && funding <= l.MaxFundingPerTargetNanoTOS && funding <= l.MaxFundingPerWalletNanoTOS
}

type RelayIntent struct {
	ActionHash        string `json:"action_hash"`
	Destination       string `json:"destination"`
	QueryID           uint64 `json:"query_id"`
	BodyHash          string `json:"body_hash"`
	StateInitHash     string `json:"state_init_hash"`
	FundingNanoTOS    uint64 `json:"funding_nano_tos"`
	StateSlotIdentity string `json:"state_slot_identity"`
	TargetObjectID    string `json:"target_object_id"`
}

func (i RelayIntent) valid() bool {
	return i.ActionHash != "" && i.Destination != "" && i.QueryID != 0 &&
		i.BodyHash != "" && i.StateInitHash != "" && i.FundingNanoTOS != 0 &&
		i.StateSlotIdentity != "" && i.TargetObjectID != ""
}

type FileRelayJournal struct{ directory string }

type relayRequestRecord struct {
	RequestKey     string `json:"request_key"`
	ActionIdentity string `json:"action_identity"`
}

type relaySlotPhase string

const (
	relaySlotPrepared     relaySlotPhase = "prepared"
	relaySlotBroadcasting relaySlotPhase = "broadcasting"
	relaySlotComplete     relaySlotPhase = "complete"
)

type relaySlotRecord struct {
	StateSlotIdentity string         `json:"state_slot_identity"`
	ActionIdentity    string         `json:"action_identity"`
	Intent            RelayIntent    `json:"intent"`
	BodyBOCBase64     string         `json:"body_boc_base64"`
	Phase             relaySlotPhase `json:"phase"`
	ClaimedUnix       int64          `json:"claimed_unix"`
}

func (r relaySlotRecord) valid() bool {
	_, err := r.body()
	return r.StateSlotIdentity != "" && r.ActionIdentity != "" && r.Intent.valid() && err == nil &&
		r.StateSlotIdentity == r.Intent.StateSlotIdentity && r.ClaimedUnix > 0 &&
		(r.Phase == relaySlotPrepared || r.Phase == relaySlotBroadcasting || r.Phase == relaySlotComplete)
}

// body returns the recorded outbound body, checked against the recorded
// body hash.
func (r relaySlotRecord) body() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(r.BodyBOCBase64)
	if err != nil || len(raw) == 0 || len(raw) > MaxRelayBodyBytes || relayPayloadHash(raw) != r.Intent.BodyHash {
		return nil, errors.New("Native relay slot body does not match its recorded hash")
	}
	return raw, nil
}

// matches reports whether a submission is the operation the slot records:
// the same action identity and the same deterministic outbound intent. The
// body hash is deliberately not compared, because a re-signed body for the
// same action is the same operation; the slot keeps its own recorded body.
func (r relaySlotRecord) matches(actionIdentity string, intent RelayIntent) bool {
	recorded, candidate := r.Intent, intent
	recorded.BodyHash, candidate.BodyHash = "", ""
	return r.ActionIdentity == actionIdentity && r.StateSlotIdentity == intent.StateSlotIdentity && recorded == candidate
}

func NewFileRelayJournal(directory string) (*FileRelayJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("Native relay journal directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || !relayJournalDirectoryIsPrivate(info) {
		return nil, errors.New("Native relay journal directory must be owner-private")
	}
	return &FileRelayJournal{directory: directory}, nil
}

func (j *FileRelayJournal) requestPath(key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(j.directory, "request-"+hex.EncodeToString(hash[:])+".json")
}

func (j *FileRelayJournal) slotPath(identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return filepath.Join(j.directory, "slot-"+hex.EncodeToString(hash[:])+".json")
}

func (j *FileRelayJournal) Lookup(requestKey, actionIdentity string, intent RelayIntent) (bool, bool, string, error) {
	if requestKey == "" || actionIdentity == "" || !intent.valid() {
		return false, false, "", errors.New("empty Native relay journal identity")
	}
	if request, found, err := j.readRequest(requestKey); err != nil {
		return false, false, "", err
	} else if found && request.ActionIdentity != actionIdentity {
		return false, false, "", errors.New("Native idempotency key was reused for a different action")
	}
	slot, found, err := j.readSlot(intent.StateSlotIdentity)
	if err != nil {
		return false, false, "", err
	}
	if !found {
		return false, false, "", nil
	}
	if slot.ActionIdentity != actionIdentity {
		return true, false, slot.Intent.ActionHash, errors.New("Native state slot is already claimed by a different action")
	}
	if !slot.matches(actionIdentity, intent) {
		return true, false, slot.Intent.ActionHash, errors.New("Native state slot record does not match its outbound intent")
	}
	switch slot.Phase {
	case relaySlotPrepared:
		// No caller can enter the sender until it atomically advances this record
		// to broadcasting, so prepared is safely recoverable after preflight.
		return false, false, "", nil
	case relaySlotBroadcasting:
		return true, false, slot.Intent.ActionHash, nil
	case relaySlotComplete:
		return true, true, slot.Intent.ActionHash, nil
	default:
		return true, false, slot.Intent.ActionHash, errors.New("invalid Native relay state-slot phase")
	}
}

func (j *FileRelayJournal) Begin(requestKey, actionIdentity string, intent RelayIntent, body []byte, limits RelaySpendLimits, now time.Time) (bool, string, error) {
	if requestKey == "" || actionIdentity == "" || !intent.valid() || !limits.permitsSingle(intent.FundingNanoTOS) || now.IsZero() {
		return false, "", errors.New("empty Native relay journal identity")
	}
	if len(body) == 0 || len(body) > MaxRelayBodyBytes || relayPayloadHash(body) != intent.BodyHash {
		return false, "", errors.New("Native relay body does not match its intent")
	}
	var complete bool
	var existingHash string
	err := j.withExclusiveLock(func() error {
		var err error
		complete, existingHash, err = j.beginLocked(requestKey, actionIdentity, intent, body, limits, now.UTC())
		return err
	})
	return complete, existingHash, err
}

func (j *FileRelayJournal) beginLocked(requestKey, actionIdentity string, intent RelayIntent, body []byte, limits RelaySpendLimits, now time.Time) (bool, string, error) {
	if request, found, err := j.readRequest(requestKey); err != nil {
		return false, "", err
	} else if found && request.ActionIdentity != actionIdentity {
		return false, "", errors.New("Native idempotency key was reused for a different action")
	}
	slot, slotFound, err := j.readSlot(intent.StateSlotIdentity)
	if err != nil {
		return false, "", err
	}
	if slotFound && slot.ActionIdentity != actionIdentity {
		return false, slot.Intent.ActionHash, errors.New("Native state slot is already claimed by a different action")
	}
	if slotFound && !slot.matches(actionIdentity, intent) {
		return false, slot.Intent.ActionHash, errors.New("Native state slot record does not match its outbound intent")
	}
	if !slotFound {
		if err := j.enforceSpendLimits(intent, limits, now); err != nil {
			return false, "", err
		}
		slot = relaySlotRecord{StateSlotIdentity: intent.StateSlotIdentity, ActionIdentity: actionIdentity,
			Intent: intent, BodyBOCBase64: base64.StdEncoding.EncodeToString(body), Phase: relaySlotPrepared, ClaimedUnix: now.Unix()}
		raw, err := json.Marshal(slot)
		if err != nil {
			return false, "", err
		}
		if created, err := j.atomicCreate(j.slotPath(intent.StateSlotIdentity), raw); err != nil || !created {
			return false, "", errors.New("failed to claim Native state slot")
		}
	}
	request := relayRequestRecord{RequestKey: requestKey, ActionIdentity: actionIdentity}
	requestRaw, err := json.Marshal(request)
	if err != nil {
		return false, "", err
	}
	if created, err := j.atomicCreate(j.requestPath(requestKey), requestRaw); err != nil {
		return false, "", err
	} else if !created {
		existing, found, err := j.readRequest(requestKey)
		if err != nil || !found || existing != request {
			return false, "", errors.New("Native idempotency key was reused for a different action")
		}
	}
	switch slot.Phase {
	case relaySlotPrepared:
		return false, "", nil
	case relaySlotBroadcasting:
		return false, slot.Intent.ActionHash, nil
	case relaySlotComplete:
		return true, slot.Intent.ActionHash, nil
	default:
		return false, slot.Intent.ActionHash, errors.New("invalid Native relay state-slot phase")
	}
}

// RecordedBody returns a slot's recorded body and whether the slot is still
// prepared.
func (j *FileRelayJournal) RecordedBody(actionIdentity string, intent RelayIntent) ([]byte, bool, error) {
	if actionIdentity == "" || !intent.valid() {
		return nil, false, errors.New("empty Native relay journal identity")
	}
	var body []byte
	var prepared bool
	err := j.withExclusiveLock(func() error {
		slot, found, err := j.readSlot(intent.StateSlotIdentity)
		if err != nil || !found || !slot.matches(actionIdentity, intent) {
			return errors.New("Native relay slot does not record this operation")
		}
		body, err = slot.body()
		prepared = slot.Phase == relaySlotPrepared
		return err
	})
	return body, prepared, err
}

// AcquireBroadcastLease moves a prepared slot to broadcasting and returns the
// only body the caller may broadcast. The slot must still record a body
// hashing to expectedBodyHash, or a concurrent recovery changed it and no
// lease is given. A non-nil replacement, which must be the caller's own
// verified body for this intent, becomes the slot's body in the same atomic
// transition. A slot already broadcasting or complete yields no lease and no
// body and is never changed.
func (j *FileRelayJournal) AcquireBroadcastLease(actionIdentity string, intent RelayIntent, expectedBodyHash string, replacement []byte) (bool, bool, []byte, error) {
	if actionIdentity == "" || !intent.valid() || expectedBodyHash == "" {
		return false, false, nil, errors.New("empty Native relay broadcast lease identity")
	}
	if replacement != nil && (len(replacement) == 0 || len(replacement) > MaxRelayBodyBytes || relayPayloadHash(replacement) != intent.BodyHash) {
		return false, false, nil, errors.New("Native relay replacement body does not match its intent")
	}
	var acquired, complete bool
	var body []byte
	err := j.withExclusiveLock(func() error {
		slot, found, err := j.readSlot(intent.StateSlotIdentity)
		if err != nil || !found || !slot.matches(actionIdentity, intent) {
			return errors.New("Native relay broadcast lease mismatch")
		}
		switch slot.Phase {
		case relaySlotPrepared:
			recorded, err := slot.body()
			if err != nil {
				return err
			}
			if slot.Intent.BodyHash != expectedBodyHash {
				return errors.New("Native relay slot body changed during recovery")
			}
			if replacement != nil {
				recorded = append([]byte(nil), replacement...)
				slot.BodyBOCBase64 = base64.StdEncoding.EncodeToString(recorded)
				slot.Intent.BodyHash = intent.BodyHash
			}
			slot.Phase = relaySlotBroadcasting
			raw, err := json.Marshal(slot)
			if err != nil {
				return err
			}
			if err := j.atomicReplace(j.slotPath(intent.StateSlotIdentity), raw); err != nil {
				return err
			}
			acquired, body = true, recorded
		case relaySlotBroadcasting:
		case relaySlotComplete:
			complete = true
		default:
			return errors.New("invalid Native relay state-slot phase")
		}
		return nil
	})
	if err != nil {
		return false, false, nil, err
	}
	return acquired, complete, body, nil
}

func (j *FileRelayJournal) Complete(actionIdentity string, intent RelayIntent) error {
	if actionIdentity == "" || !intent.valid() {
		return errors.New("Native relay journal completion mismatch")
	}
	return j.withExclusiveLock(func() error {
		slot, found, err := j.readSlot(intent.StateSlotIdentity)
		if err != nil || !found || !slot.matches(actionIdentity, intent) {
			return errors.New("Native relay journal completion mismatch")
		}
		if slot.Phase == relaySlotComplete {
			return nil
		}
		if slot.Phase != relaySlotBroadcasting {
			return errors.New("Native relay journal completed without a broadcast lease")
		}
		slot.Phase = relaySlotComplete
		raw, err := json.Marshal(slot)
		if err != nil {
			return err
		}
		return j.atomicReplace(j.slotPath(intent.StateSlotIdentity), raw)
	})
}

func (j *FileRelayJournal) enforceSpendLimits(intent RelayIntent, limits RelaySpendLimits, now time.Time) error {
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return err
	}
	cutoff := now.Add(-limits.Window).Unix()
	var walletActions, walletFunding, targetActions, targetFunding uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "slot-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(j.directory, entry.Name()))
		if err != nil {
			return err
		}
		var slot relaySlotRecord
		if json.Unmarshal(raw, &slot) != nil || !slot.valid() {
			return errors.New("invalid Native relay state-slot record")
		}
		if slot.ClaimedUnix < cutoff {
			continue
		}
		if walletActions == ^uint64(0) || walletFunding > ^uint64(0)-slot.Intent.FundingNanoTOS {
			return errors.New("Native relay wallet budget counter overflow")
		}
		walletActions++
		walletFunding += slot.Intent.FundingNanoTOS
		if slot.Intent.TargetObjectID == intent.TargetObjectID {
			if targetActions == ^uint64(0) || targetFunding > ^uint64(0)-slot.Intent.FundingNanoTOS {
				return errors.New("Native relay target budget counter overflow")
			}
			targetActions++
			targetFunding += slot.Intent.FundingNanoTOS
		}
	}
	if walletActions >= limits.MaxActionsPerWallet || walletFunding > limits.MaxFundingPerWalletNanoTOS-intent.FundingNanoTOS {
		return errors.New("Native relay wallet spend limit exceeded")
	}
	if targetActions >= limits.MaxActionsPerTarget || targetFunding > limits.MaxFundingPerTargetNanoTOS-intent.FundingNanoTOS {
		return errors.New("Native relay target spend limit exceeded")
	}
	return nil
}

func (j *FileRelayJournal) withExclusiveLock(fn func() error) error {
	path := filepath.Join(j.directory, ".relay-journal.lock")
	return withRelayJournalFileLock(path, fn)
}

func (j *FileRelayJournal) readSlot(identity string) (relaySlotRecord, bool, error) {
	var record relaySlotRecord
	raw, err := os.ReadFile(j.slotPath(identity))
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil || json.Unmarshal(raw, &record) != nil || !record.valid() || record.StateSlotIdentity != identity {
		return relaySlotRecord{}, false, errors.New("invalid Native relay state-slot record")
	}
	return record, true, nil
}

func (j *FileRelayJournal) readRequest(key string) (relayRequestRecord, bool, error) {
	var record relayRequestRecord
	raw, err := os.ReadFile(j.requestPath(key))
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil || json.Unmarshal(raw, &record) != nil || record.RequestKey != key || record.ActionIdentity == "" {
		return relayRequestRecord{}, false, errors.New("invalid Native relay request record")
	}
	return record, true, nil
}

func (j *FileRelayJournal) atomicCreate(path string, raw []byte) (bool, error) {
	tempPath, err := j.writeTemporary(raw)
	if err != nil {
		return false, err
	}
	defer os.Remove(tempPath)
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, syncDirectory(j.directory)
}

func (j *FileRelayJournal) atomicReplace(path string, raw []byte) error {
	tempPath, err := j.writeTemporary(raw)
	if err != nil {
		return err
	}
	defer os.Remove(tempPath)
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(j.directory)
}

func (j *FileRelayJournal) writeTemporary(raw []byte) (string, error) {
	temp, err := os.CreateTemp(j.directory, ".relay-")
	if err != nil {
		return "", err
	}
	path := temp.Name()
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.Write(append(raw, '\n'))
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
