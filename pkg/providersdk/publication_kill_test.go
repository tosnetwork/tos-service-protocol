//go:build unix

package providersdk

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const (
	killChildDirectory = "PROVIDERSDK_KILL_CHILD_JOURNAL"
	killChildAction    = "PROVIDERSDK_KILL_CHILD_ACTION"
)

// TestPublicationKillChild is the child half of the kill test. It is inert
// unless the parent test names a journal; it relays and then blocks inside
// the Gateway call until it is killed.
func TestPublicationKillChild(t *testing.T) {
	directory, actionHash := os.Getenv(killChildDirectory), os.Getenv(killChildAction)
	if directory == "" {
		return
	}
	f := newJournalFixture(t, nil)
	f.directory = directory
	record, err := f.reopen(t).Read(actionHash)
	if err != nil {
		t.Fatal(err)
	}
	f.client.onSubmit = func(*scriptedClient) {
		if err := os.WriteFile(filepath.Join(filepath.Dir(directory), "relaying"), nil, 0o600); err != nil {
			t.Error(err)
		}
		select {}
	}
	_, err = f.provider(t).ApplyPublication(context.Background(), f.reopen(t), actionHash, f.sign(t, record, "fixture"))
	t.Fatalf("child returned instead of being killed: %v", err)
}

// startRelayingChild starts a child process that journals the relay and then
// blocks inside the Gateway call, and waits until it is there.
func startRelayingChild(t *testing.T, f *journalFixture, record PublicationRecord) *exec.Cmd {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=^TestPublicationKillChild$", "-test.count=1")
	child.Env = append(os.Environ(), killChildDirectory+"="+f.directory, killChildAction+"="+record.ActionHash)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	marker := filepath.Join(filepath.Dir(f.directory), "relaying")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			return child
		}
		if time.Now().After(deadline) {
			t.Fatal("child never reached the relay")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLiveRelayIsNotTreatedAsAbandoned runs two live processes: one is
// inside the relay, the other opens the journal and applies. The second
// must neither recover the record as ambiguous nor relay it again; once the
// first dies, an already-open journal handle recovers it.
func TestLiveRelayIsNotTreatedAsAbandoned(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	child := startRelayingChild(t, f, record)
	journal := f.reopen(t)
	if got, err := journal.Read(record.ActionHash); err != nil || got.Phase != PublicationSubmitting {
		t.Fatalf("opening the journal during a live relay left phase=%s err=%v", got.Phase, err)
	}
	got, err := f.provider(t).ApplyPublication(context.Background(), journal, record.ActionHash, nil)
	if !errors.Is(err, ErrRelayInProgress) || got.Phase != PublicationSubmitting || f.client.submitCount() != 0 {
		t.Fatalf("apply during a live relay: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	f.client.capability = f.finalizedCapability(t, record)
	got, err = f.provider(t).ApplyPublication(context.Background(), journal, record.ActionHash, nil)
	if err != nil || got.Phase != PublicationCataloged || f.client.submitCount() != 0 {
		t.Fatalf("apply after the relaying process died: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
}

// TestPublicationSurvivesKillDuringRelay kills a real process while it is
// inside the Gateway relay and checks that the restarted process settles the
// journaled action from finalized state without relaying it again.
func TestPublicationSurvivesKillDuringRelay(t *testing.T) {
	f := newJournalFixture(t, nil)
	record := f.prepare(t)
	child := exec.Command(os.Args[0], "-test.run=^TestPublicationKillChild$", "-test.count=1")
	child.Env = append(os.Environ(), killChildDirectory+"="+f.directory, killChildAction+"="+record.ActionHash)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(filepath.Dir(f.directory), "relaying")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = child.Process.Kill()
			t.Fatal("child never reached the relay")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("killed child exited cleanly")
	}
	if got, err := rawJournal(f).Read(record.ActionHash); err != nil || got.Phase != PublicationSubmitting || got.SubmitAttempts != 1 {
		t.Fatalf("killed relay left phase=%s attempts=%d err=%v", got.Phase, got.SubmitAttempts, err)
	}
	// The killed relay landed on chain.
	f.client.capability = f.finalizedCapability(t, record)
	journal := f.reopen(t)
	if got, err := journal.Read(record.ActionHash); err != nil || got.Phase != PublicationAmbiguous {
		t.Fatalf("restart did not recover the killed relay as ambiguous: %s %v", got.Phase, err)
	}
	got, err := f.provider(t).ApplyPublication(context.Background(), journal, record.ActionHash, nil)
	if err != nil || got.Phase != PublicationCataloged || f.client.submitCount() != 0 {
		t.Fatalf("restart: phase=%s relays=%d err=%v", got.Phase, f.client.submitCount(), err)
	}
}
