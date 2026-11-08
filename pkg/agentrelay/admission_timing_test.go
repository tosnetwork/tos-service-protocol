package agentrelay

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// testClock is a service clock the test moves while a call is blocked.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) get() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) set(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

// blockingAdmissionAuthority holds the authoritative admission lookup until
// the test releases it.
type blockingAdmissionAuthority struct {
	inner   *testRelayAdmissionAuthority
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (authority *blockingAdmissionAuthority) AdmitRelaySideEffects(ctx context.Context,
	descriptor RelaySideEffectAdmissionDescriptor) (SignedRelaySideEffectAdmissionReceipt, error) {
	return authority.inner.AdmitRelaySideEffects(ctx, descriptor)
}

func (authority *blockingAdmissionAuthority) ResolveRelaySideEffectAdmission(ctx context.Context,
	lookup RelaySideEffectAdmissionLookup) (SignedRelaySideEffectAdmissionReceipt, error) {
	blocked := false
	authority.once.Do(func() { blocked = true })
	if blocked {
		close(authority.entered)
		<-authority.release
	}
	return authority.inner.ResolveRelaySideEffectAdmission(ctx, lookup)
}

// countingVerifyResolver counts, and on request blocks, the Action Authority
// verifications of one exact message.
type countingVerifyResolver struct {
	relayResolver
	message []byte
	mu      *sync.Mutex
	count   *int
	entered chan struct{}
	release chan struct{}
}

func (resolver countingVerifyResolver) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if bytes.Equal(payload, resolver.message) {
		resolver.mu.Lock()
		*resolver.count++
		first := *resolver.count == 1
		resolver.mu.Unlock()
		if first && resolver.entered != nil {
			close(resolver.entered)
			<-resolver.release
		}
	}
	return resolver.relayResolver.Verify(ctx, use, payload, publicKey, signature)
}

// prepareSubmission reserves a quote in the service journal and returns the
// execution, its Agreement and a broadcaster that accepts it.
func prepareSubmission(t *testing.T, fixture *relayFixture) (RelayExecutionRequest, agentcommerce.AgentAgreement) {
	t.Helper()
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	agreement := fixture.agreement(t, quote)
	fixture.execution.AgreementBodyDigest, _ = agentcommerce.AgreementBodyDigest(agreement.Body)
	fixture.execution.AgreementExpiresAtUnix = agreement.Body.ExpiresAtUnix
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	fixture.service.Broadcaster = &recordingBroadcaster{result: BroadcastResult{Status: BroadcastAccepted,
		TransactionReference: "tx:timing"}}
	return fixture.execution, agreement
}

// The final start-window check follows the authoritative admission lookup:
// a lookup that stalls until the receipt's exclusive start boundary leaves no
// record and no consumed reservation, while one that returns a second before
// the boundary admits.
func TestRelayAdmissionStartWindowIsCheckedAfterTheAuthoritativeLookup(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		offset   time.Duration
		admitted bool
	}{{"at the boundary", 0, false}, {"one second before", -time.Second, true}} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newRelayFixture(t)
			clock := &testClock{now: fixture.now}
			fixture.service.Now = clock.get
			execution, agreement := prepareSubmission(t, fixture)
			blocking := &blockingAdmissionAuthority{inner: fixture.admissionAuthority,
				entered: make(chan struct{}), release: make(chan struct{})}
			fixture.service.AdmissionAuthority = blocking
			type outcome struct {
				record Record
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				record, err := fixture.service.Submit(context.Background(), execution, agreement)
				done <- outcome{record, err}
			}()
			<-blocking.entered
			boundary := time.Unix(int64(execution.AdmissionReceipt.Body.StartNotAfterUnix), 0).UTC()
			clock.set(boundary.Add(testCase.offset))
			close(blocking.release)
			result := <-done
			_, resolveErr := fixture.service.Journal.Resolve(execution.AuthorizedAction.StableActionID,
				execution.AuthorizedAction.ExactRequestDigest)
			if testCase.admitted {
				if result.err != nil || resolveErr != nil {
					t.Fatalf("admission a second before the boundary failed: submit=%v resolve=%v", result.err, resolveErr)
				}
				return
			}
			if result.err == nil || !errors.Is(resolveErr, ErrRelayUnknown) {
				t.Fatalf("a receipt past its start boundary was admitted: submit=%v resolve=%v", result.err, resolveErr)
			}
			// The reservation was not consumed: a fresh receipt for the same
			// quote still admits.
			clock.set(fixture.now)
			fresh := attachRelayTestAdmission(t, execution, fixture.authorityKey, fixture.now, 2)
			fixture.admissionAuthority.remember(t, fresh)
			if _, err := fixture.service.Submit(context.Background(), fresh, agreement); err != nil {
				t.Fatalf("the reservation was consumed by a refused admission: %v", err)
			}
		})
	}
}

// MemoryJournal judges the start boundary after its lock wait: a caller whose
// time was a second before the boundary, but who waited past it for the lock,
// is refused and leaves no record.
func TestMemoryJournalChecksTheStartBoundaryAfterTheLockWait(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	journal := NewMemoryJournal()
	if _, created, err := journal.ReserveQuote(fixture.profile, fixture.request, quote, fixture.now); err != nil || !created {
		t.Fatalf("quote reservation failed: created=%v err=%v", created, err)
	}
	verified := verifiedTestReceipt(t, fixture.execution, fixture.resolver)
	boundary := time.Unix(int64(fixture.execution.AdmissionReceipt.Body.StartNotAfterUnix), 0).UTC()
	journal.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, _, err := journal.Admit(fixture.execution, verified, boundary.Add(-time.Second))
		done <- err
	}()
	time.Sleep(1100 * time.Millisecond)
	journal.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("an admission that waited past the start boundary for the lock was accepted")
	}
	if _, err := journal.Resolve(fixture.execution.AuthorizedAction.StableActionID,
		fixture.execution.AuthorizedAction.ExactRequestDigest); !errors.Is(err, ErrRelayUnknown) {
		t.Fatalf("a refused admission left a record: %v", err)
	}
	if _, created, err := journal.Admit(fixture.execution, verified, fixture.now); err != nil || !created {
		t.Fatalf("a timely admission of the same receipt failed: created=%v err=%v", created, err)
	}
}

// A journal admits only a receipt whose Action Authority check produced the
// token for exactly that signed receipt.
func TestMemoryJournalRefusesAZeroOrForeignVerificationToken(t *testing.T) {
	fixture := newRelayFixture(t)
	quote, err := fixture.service.Quote(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.execution.ProviderQuote = quote
	fixture.execution = fixture.withAdmission(t, fixture.execution)
	journal := NewMemoryJournal()
	if _, _, err := journal.ReserveQuote(fixture.profile, fixture.request, quote, fixture.now); err != nil {
		t.Fatal(err)
	}
	other := attachRelayTestAdmission(t, fixture.execution, fixture.authorityKey, fixture.now, 2)
	foreign := verifiedTestReceipt(t, other, fixture.resolver)
	resigned := fixture.execution
	resigned.AdmissionReceipt.Signature = other.AdmissionReceipt.Signature
	for name, token := range map[string]VerifiedRelayAdmissionReceipt{"zero": {}, "other receipt": foreign} {
		if _, _, err := journal.Admit(fixture.execution, token, fixture.now); err == nil {
			t.Fatalf("a %s token admitted the receipt", name)
		}
	}
	verified := verifiedTestReceipt(t, fixture.execution, fixture.resolver)
	if _, _, err := journal.Admit(resigned, verified, fixture.now); err == nil {
		t.Fatal("a token admitted a receipt carrying another signature")
	}
	if _, created, err := journal.Admit(fixture.execution, verified, fixture.now); err != nil || !created {
		t.Fatalf("the verified receipt was refused: created=%v err=%v", created, err)
	}
}

// The receipt's Action Authority signature is verified exactly once per first
// admission, and while that verification is blocked the journal stays
// available.
func TestRelayReceiptAuthorityIsVerifiedOnceAndOutsideTheJournal(t *testing.T) {
	fixture := newRelayFixture(t)
	execution, agreement := prepareSubmission(t, fixture)
	message, err := RelaySideEffectAdmissionReceiptSignatureMessage(execution.AdmissionReceipt.Body)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	resolver := countingVerifyResolver{relayResolver: fixture.resolver, message: message, mu: &sync.Mutex{}, count: &count,
		entered: make(chan struct{}), release: make(chan struct{})}
	fixture.service.FenceResolver = resolver
	done := make(chan error, 1)
	go func() {
		_, err := fixture.service.Submit(context.Background(), execution, agreement)
		done <- err
	}()
	<-resolver.entered
	journalDone := make(chan error, 1)
	go func() {
		_, err := fixture.service.Journal.Resolve(execution.AuthorizedAction.StableActionID,
			execution.AuthorizedAction.ExactRequestDigest)
		if errors.Is(err, ErrRelayUnknown) {
			_, _, err = fixture.service.Journal.Admit(execution, VerifiedRelayAdmissionReceipt{}, fixture.now)
			if err != nil {
				err = nil
			} else {
				err = errors.New("a zero token was admitted")
			}
		}
		journalDone <- err
	}()
	select {
	case err := <-journalDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the journal was blocked while the receipt authority was being verified")
	}
	close(resolver.release)
	if err := <-done; err != nil {
		t.Fatalf("submission failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("the receipt authority was verified %d times, want exactly once", count)
	}
}
