package agentrelay

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// The Action Authority size budget (SEMANTIC_ACTION_IDENTITY_V1 section 9.4),
// measured on the real encodings: a key ID text is 72 bytes, a signature text
// 3,235, and replacing a 94-byte signature text by it grows each signed object
// by exactly 3,142 canonical bytes. A relay execution request at its largest
// underlying request and signed transaction still fits the 1 MiB canonical
// bound.
func TestActionAuthorityObjectSizesFitTheirBounds(t *testing.T) {
	fixture := newRelayFixture(t)
	execution := fixture.execution
	action, fence, receipt := execution.AuthorizedAction, execution.WriterFence, execution.AdmissionReceipt
	for name, text := range map[string]string{"fence key ID": fence.KeyID, "action key ID": action.AuthorityKeyID,
		"receipt key ID": receipt.KeyID} {
		if len(text) != 72 {
			t.Fatalf("%s is %d bytes, want 72", name, len(text))
		}
	}
	for name, text := range map[string]string{"fence proof": fence.Proof, "action proof": action.AuthorizationProof,
		"receipt signature": receipt.Signature} {
		if len(text) != 3235 {
			t.Fatalf("%s is %d bytes, want 3,235", name, len(text))
		}
	}
	removedSuiteText := "ed25519:" + strings.Repeat("A", 86)
	measure := func(value any) int {
		t.Helper()
		encoded, err := codec.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return len(encoded)
	}
	shortFence, shortAction, shortReceipt := fence, action, receipt
	shortFence.Proof, shortAction.AuthorizationProof, shortReceipt.Signature = removedSuiteText, removedSuiteText, removedSuiteText
	for name, delta := range map[string]int{
		"writer fence":      measure(fence) - measure(shortFence),
		"authorized action": measure(action) - measure(shortAction),
		"admission receipt": measure(receipt) - measure(shortReceipt),
	} {
		if delta != 3142 {
			t.Fatalf("%s grows by %d canonical bytes, want 3,142", name, delta)
		}
	}
	// Byte strings travel through the codec's JSON stage as Base64 text, so
	// the remaining room of each byte-string bound costs four thirds.
	base := measure(execution)
	worst := base + (MaxRelayActionRequestBytes-len(execution.UnderlyingActionRequest))*4/3 + 4 +
		(MaxSignedTransactionBytes-len(execution.SignedTransactionBytes))*4/3 + 4
	if worst >= codec.MaxCanonicalBytes {
		t.Fatalf("a maximal relay execution request is about %d canonical bytes, over the %d bound", worst, codec.MaxCanonicalBytes)
	}
	t.Logf("relay execution request: %d bytes measured, about %d at its largest; bound %d", base, worst, codec.MaxCanonicalBytes)
}
