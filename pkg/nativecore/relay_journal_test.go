package nativecore

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var journalTestLimits = RelaySpendLimits{Window: time.Hour, MaxActionsPerTarget: 10,
	MaxFundingPerTargetNanoTOS: 10 * MinimumRelayFundingNanoTOS, MaxActionsPerWallet: 100,
	MaxFundingPerWalletNanoTOS: 100 * MinimumRelayFundingNanoTOS}

// journalTestBody is the outbound body every test intent was claimed with.
var journalTestBody = []byte("recorded-outbound-body")

func journalTestIntent(actionHash string) RelayIntent {
	return RelayIntent{ActionHash: actionHash, Destination: "0:destination", QueryID: 7,
		BodyHash: relayPayloadHash(journalTestBody), StateInitHash: "sha256:state-init", FundingNanoTOS: MinimumRelayFundingNanoTOS,
		StateSlotIdentity: "sha256:slot", TargetObjectID: "agent_target"}
}

func journalIntentFor(actionHash, slot, target string) RelayIntent {
	intent := journalTestIntent(actionHash)
	intent.StateSlotIdentity = slot
	intent.TargetObjectID = target
	return intent
}

func TestFileRelayJournalIsDurableAndConflictSafe(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	intent := journalTestIntent("sha256:first")
	complete, existing, err := first.Begin("request-1", "sha256:action-one", intent, journalTestBody, journalTestLimits, time.Unix(1_700_000_000, 0))
	if err != nil || complete || existing != "" {
		t.Fatalf("first begin = (%v, %q, %v)", complete, existing, err)
	}
	second, _ := NewFileRelayJournal(directory)
	complete, existing, err = second.Begin("request-1", "sha256:action-one", intent, journalTestBody, journalTestLimits, time.Unix(1_700_000_001, 0))
	if err != nil || complete || existing != "" {
		t.Fatalf("pending restart = (%v, %q, %v)", complete, existing, err)
	}
	different := intent
	different.FundingNanoTOS++
	if _, _, err := second.Begin("request-1", "sha256:action-one", different, journalTestBody, journalTestLimits, time.Unix(1_700_000_002, 0)); err == nil {
		t.Fatal("idempotency key accepted different semantics")
	}
	if _, _, err := second.Begin("request-1", "sha256:action-two", journalTestIntent("sha256:second"), journalTestBody, journalTestLimits, time.Unix(1_700_000_002, 0)); err == nil {
		t.Fatal("idempotency key accepted a different canonical action")
	}
	acquired, complete, _, err := second.AcquireBroadcastLease("sha256:action-one", intent, intent.BodyHash, nil)
	if err != nil || !acquired || complete {
		t.Fatalf("prepared recovery lease = (%v, %v, %v)", acquired, complete, err)
	}
	third, _ := NewFileRelayJournal(filepath.Clean(directory))
	complete, existing, err = third.Begin("request-1", "sha256:action-one", intent, journalTestBody, journalTestLimits, time.Unix(1_700_000_003, 0))
	if err != nil || complete || existing != "sha256:first" {
		t.Fatalf("broadcasting restart = (%v, %q, %v)", complete, existing, err)
	}
	acquired, complete, _, err = third.AcquireBroadcastLease("sha256:action-one", intent, intent.BodyHash, nil)
	if err != nil || acquired || complete {
		t.Fatalf("broadcasting restart reacquired a lease = (%v, %v, %v)", acquired, complete, err)
	}
	if err := first.Complete("sha256:action-one", intent); err != nil {
		t.Fatal(err)
	}
	fourth, _ := NewFileRelayJournal(filepath.Clean(directory))
	complete, existing, err = fourth.Begin("request-1", "sha256:action-one", intent, journalTestBody, journalTestLimits, time.Unix(1_700_000_004, 0))
	if err != nil || !complete || existing != "sha256:first" {
		t.Fatalf("completed restart = (%v, %q, %v)", complete, existing, err)
	}
}

func TestFileRelayJournalFencesConcurrentBroadcasters(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journals := make([]*FileRelayJournal, 2)
	for i := range journals {
		journal, err := NewFileRelayJournal(directory)
		if err != nil {
			t.Fatal(err)
		}
		journals[i] = journal
	}
	intent := journalTestIntent("sha256:action")
	if _, _, err := journals[0].Begin("race-a", "sha256:canonical-action", intent,
		journalTestBody, journalTestLimits, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		acquired bool
		complete bool
		err      error
	}
	outcomes := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, journal := range journals {
		go func(j *FileRelayJournal) {
			start.Wait()
			acquired, complete, _, err := j.AcquireBroadcastLease("sha256:canonical-action", intent, intent.BodyHash, nil)
			outcomes <- outcome{acquired: acquired, complete: complete, err: err}
		}(journal)
	}
	start.Done()
	first, second := <-outcomes, <-outcomes
	if first.err != nil || second.err != nil {
		t.Fatalf("race outcomes: %+v %+v", first, second)
	}
	if first.complete || second.complete || first.acquired == second.acquired {
		t.Fatalf("exactly one broadcaster must own the new intent: %+v %+v", first, second)
	}
}

func TestFileRelayJournalPreparedCrashIsRecoverable(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	intent := journalTestIntent("sha256:action")
	beforeCrash, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if complete, existing, err := beforeCrash.Begin("crash-before-send", "sha256:action-identity", intent,
		journalTestBody, journalTestLimits, time.Unix(1_700_000_000, 0)); err != nil || complete || existing != "" {
		t.Fatalf("initial prepare = (%v, %q, %v)", complete, existing, err)
	}
	slot, found, err := beforeCrash.readSlot(intent.StateSlotIdentity)
	if err != nil || !found || !slot.matches("sha256:action-identity", intent) || slot.Phase != relaySlotPrepared {
		t.Fatalf("unified prepared slot = (%+v, %v, %v)", slot, found, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "action-") {
			t.Fatalf("separate action record survived unified journal design: %s", entry.Name())
		}
	}
	if err := beforeCrash.Complete("sha256:action-identity", intent); err == nil {
		t.Fatal("prepared slot completed without acquiring a broadcast lease")
	}
	afterRestart, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if complete, existing, err := afterRestart.Begin("crash-before-send", "sha256:action-identity", intent,
		journalTestBody, journalTestLimits, time.Unix(1_700_000_001, 0)); err != nil || complete || existing != "" {
		t.Fatalf("prepared recovery must return a new broadcast candidate, got (%v, %q, %v)", complete, existing, err)
	}
	acquired, complete, _, err := afterRestart.AcquireBroadcastLease("sha256:action-identity", intent, intent.BodyHash, nil)
	if err != nil || !acquired || complete {
		t.Fatalf("prepared recovery must acquire one broadcast lease, got (%v, %v, %v)", acquired, complete, err)
	}
}

func TestFileRelayJournalFencesConflictingActionsForOneStateSlot(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journals := make([]*FileRelayJournal, 2)
	for i := range journals {
		journal, err := NewFileRelayJournal(directory)
		if err != nil {
			t.Fatal(err)
		}
		journals[i] = journal
	}
	type outcome struct {
		existing string
		err      error
	}
	outcomes := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := range journals {
		go func(index int, journal *FileRelayJournal) {
			start.Wait()
			action := "sha256:action-" + string(rune('a'+index))
			intent := journalIntentFor(action, "sha256:shared-slot", "agent_shared")
			_, existing, err := journal.Begin("conflict-"+string(rune('a'+index)), action, intent,
				journalTestBody, journalTestLimits, time.Unix(1_700_000_000, 0))
			outcomes <- outcome{existing: existing, err: err}
		}(i, journals[i])
	}
	start.Done()
	first, second := <-outcomes, <-outcomes
	if (first.err == nil) == (second.err == nil) {
		t.Fatalf("exactly one conflicting action must claim the state slot: %+v %+v", first, second)
	}
}

func TestFileRelayJournalEnforcesDurableSpendLimits(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	limits := RelaySpendLimits{Window: time.Hour, MaxActionsPerTarget: 1,
		MaxFundingPerTargetNanoTOS: MinimumRelayFundingNanoTOS, MaxActionsPerWallet: 2,
		MaxFundingPerWalletNanoTOS: 2 * MinimumRelayFundingNanoTOS}
	now := time.Unix(1_700_000_000, 0)
	first := journalIntentFor("sha256:first", "sha256:slot-one", "agent_one")
	if _, _, err := journal.Begin("budget-1", "sha256:intent-one", first, journalTestBody, limits, now); err != nil {
		t.Fatal(err)
	}
	sameTarget := journalIntentFor("sha256:second", "sha256:slot-two", "agent_one")
	if _, _, err := journal.Begin("budget-2", "sha256:intent-two", sameTarget, journalTestBody, limits, now); err == nil {
		t.Fatal("per-target relay budget accepted a second paid slot")
	}
	otherTarget := journalIntentFor("sha256:third", "sha256:slot-three", "agent_two")
	if _, _, err := journal.Begin("budget-3", "sha256:intent-three", otherTarget, journalTestBody, limits, now); err != nil {
		t.Fatal(err)
	}
	thirdTarget := journalIntentFor("sha256:fourth", "sha256:slot-four", "agent_three")
	if _, _, err := journal.Begin("budget-4", "sha256:intent-four", thirdTarget, journalTestBody, limits, now); err == nil {
		t.Fatal("relay-wallet budget accepted a third paid slot")
	}
	restarted, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Begin("budget-5", "sha256:intent-five",
		journalIntentFor("sha256:fifth", "sha256:slot-five", "agent_four"), journalTestBody, limits, now); err == nil {
		t.Fatal("relay-wallet budget did not survive process restart")
	}
}

func TestFileRelayJournalSerializesConcurrentWalletBudget(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	limits := RelaySpendLimits{Window: time.Hour, MaxActionsPerTarget: 1,
		MaxFundingPerTargetNanoTOS: MinimumRelayFundingNanoTOS, MaxActionsPerWallet: 1,
		MaxFundingPerWalletNanoTOS: MinimumRelayFundingNanoTOS}
	results := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < 2; i++ {
		journal, err := NewFileRelayJournal(directory)
		if err != nil {
			t.Fatal(err)
		}
		go func(index int, j *FileRelayJournal) {
			start.Wait()
			suffix := string(rune('a' + index))
			_, _, err := j.Begin("wallet-"+suffix, "sha256:intent-"+suffix,
				journalIntentFor("sha256:action-"+suffix, "sha256:slot-"+suffix, "agent_"+suffix),
				journalTestBody, limits, time.Unix(1_700_000_000, 0))
			results <- err
		}(i, journal)
	}
	start.Done()
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("exactly one concurrent intent must fit the wallet budget: %v / %v", first, second)
	}
}
