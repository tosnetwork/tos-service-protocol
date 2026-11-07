package agentguarantor

import (
	"errors"
	"testing"
	"time"
)

type immutableEvidenceTestResolver struct {
	nativeTestAuthority
	wire []byte
	err  error
}

func (immutableEvidenceTestResolver) ResolveGuarantorAuthority(AuthorityResolutionScopeV1, string, time.Time, []byte) error {
	return nil
}

func (resolver immutableEvidenceTestResolver) ResolveImmutableGuarantorEvidence(ImmutableEvidenceDescriptorV1) ([]byte, error) {
	return append([]byte(nil), resolver.wire...), resolver.err
}

type signatureOnlyEvidenceTestResolver struct{ nativeTestAuthority }

func (signatureOnlyEvidenceTestResolver) ResolveGuarantorAuthority(AuthorityResolutionScopeV1, string, time.Time, []byte) error {
	return nil
}

func TestImmutableEvidenceResolutionIsRequiredAndExactlySized(t *testing.T) {
	descriptor := ImmutableEvidenceDescriptorV1{ContentType: "application/cbor",
		ContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContentSize:   3, RetrievalPolicyDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if _, err := resolveImmutableEvidenceV1(signatureOnlyEvidenceTestResolver{}, descriptor, true); err == nil {
		t.Fatal("independently enforced proof accepted without immutable retrieval")
	}
	if wire, err := resolveImmutableEvidenceV1(signatureOnlyEvidenceTestResolver{}, descriptor, false); err != nil || wire != nil {
		t.Fatalf("lower assurance should permit unavailable immutable retrieval: wire=%x err=%v", wire, err)
	}
	if _, err := resolveImmutableEvidenceV1(immutableEvidenceTestResolver{wire: []byte("too-long")}, descriptor, true); err == nil {
		t.Fatal("immutable evidence accepted a substituted size")
	}
	if _, err := resolveImmutableEvidenceV1(immutableEvidenceTestResolver{err: errors.New("offline")}, descriptor, true); err == nil {
		t.Fatal("immutable evidence accepted a failed store")
	}
	wire, err := resolveImmutableEvidenceV1(immutableEvidenceTestResolver{wire: []byte("abc")}, descriptor, true)
	if err != nil || string(wire) != "abc" {
		t.Fatalf("exact immutable evidence was not returned: wire=%x err=%v", wire, err)
	}
}
