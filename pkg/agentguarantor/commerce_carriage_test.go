package agentguarantor

import (
	"context"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

type testImmutableGuarantorPublisher struct {
	descriptor commerce.CommerceObjectDescriptorV1
	seen       []byte
}

func (publisher *testImmutableGuarantorPublisher) PublishImmutableCommerceObject(_ context.Context,
	contentType, digest string, canonical []byte) (commerce.CommerceObjectDescriptorV1, error) {
	publisher.seen = append([]byte(nil), canonical...)
	result := publisher.descriptor
	if result.ContentType == "" {
		result = commerce.CommerceObjectDescriptorV1{ContentType: contentType, ContentDigest: digest,
			ContentSize: uint64(len(canonical)), RetrievalHints: []string{"https://storage.example/immutable/object"}}
	}
	return result, nil
}

func TestGuarantorCommerceCarriageDispatchIsClosedAndDomainBound(t *testing.T) {
	request := AuthorizedCoverageQuoteRequestV1{}
	canonical, err := codec.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := codec.Digest(QuoteRequestDomain, request)
	if err != nil {
		t.Fatal(err)
	}
	verifier := CommerceObjectVerifierV1{}
	mediaType := "application/vnd.tos.service.agent-guarantor-quote-request.v1+cbor"
	if err := verifier.VerifyCommerceObject(ProfileURI, 1, "quote-request", mediaType, digest, canonical); err != nil {
		t.Fatalf("exact registered carriage object was rejected: %v", err)
	}
	for name, candidate := range map[string]struct {
		profile, kind, media, digest string
		version                      uint64
	}{
		"profile": {profile: "tos.service.agent-guarantor.v1", version: 1, kind: "quote-request", media: mediaType, digest: digest},
		"version": {profile: ProfileURI, version: 2, kind: "quote-request", media: mediaType, digest: digest},
		"kind":    {profile: ProfileURI, version: 1, kind: "quote", media: mediaType, digest: digest},
		"media":   {profile: ProfileURI, version: 1, kind: "quote-request", media: "application/cbor", digest: digest},
		"domain":  {profile: ProfileURI, version: 1, kind: "quote-request", media: mediaType, digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		if err := verifier.VerifyCommerceObject(candidate.profile, candidate.version, candidate.kind,
			candidate.media, candidate.digest, canonical); err == nil {
			t.Fatalf("%s substitution was accepted", name)
		}
	}
	if len(ReleasedCommerceCarriageObjectsV1()) != 23 {
		t.Fatal("released Guarantor Messenger dispatch table changed without a profile version")
	}
}

func TestBuildGuarantorCommerceEventSelectsExactCarriage(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	request := AuthorizedCoverageQuoteRequestV1{}
	event, err := BuildCommerceProfileEventV1(context.Background(), "quote-request", request,
		CommerceEventContextV1{CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, nil)
	if err != nil || event.CarriageKind != "inline" || len(event.CanonicalObjectBytes) == 0 || event.ObjectDescriptor != nil {
		t.Fatalf("small object did not select exact inline carriage: %#v err=%v", event, err)
	}

	large := request
	// Two authorizations at the native maximum: a 2,420-byte signature and a
	// historical proof at its bound each.
	signatureText, err := NativeAuthorizationSignatureText(make([]byte, mldsa44.SignatureSize))
	if err != nil {
		t.Fatal(err)
	}
	large.Authorizations = []ProfileQualifiedObjectAuthorizationV1{
		{Evidence: NativeMLDSA44AgentAuthorizationEvidenceV1{KeyID: "mldsa44:" + strings.Repeat("a1", 32),
			Signature: signatureText, HistoricalAuthorityProof: []byte(strings.Repeat("a", MaxHistoricalAuthorityProofBytes))}},
		{Evidence: NativeMLDSA44AgentAuthorizationEvidenceV1{KeyID: "mldsa44:" + strings.Repeat("b2", 32),
			Signature: signatureText, HistoricalAuthorityProof: []byte(strings.Repeat("b", MaxHistoricalAuthorityProofBytes))}},
	}
	if _, err := BuildCommerceProfileEventV1(context.Background(), "quote-request", large,
		CommerceEventContextV1{CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, nil); err == nil {
		t.Fatal("large Guarantor object was allowed without immutable storage")
	}
	publisher := &testImmutableGuarantorPublisher{}
	event, err = BuildCommerceProfileEventV1(context.Background(), "quote-request", large,
		CommerceEventContextV1{CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, publisher)
	if err != nil || event.CarriageKind != "content_addressed" || event.ObjectDescriptor == nil ||
		len(event.CanonicalObjectBytes) != 0 || len(publisher.seen) <= commerce.MaxInlineProfileEventBytes {
		t.Fatalf("large object did not select exact immutable carriage: %#v err=%v", event, err)
	}

	publisher = &testImmutableGuarantorPublisher{descriptor: commerce.CommerceObjectDescriptorV1{
		ContentType: event.ObjectContentType, ContentDigest: "sha256:" + strings.Repeat("f", 64),
		ContentSize: event.ObjectSizeBytes, RetrievalHints: []string{"https://storage.example/substitution"}}}
	if _, err := BuildCommerceProfileEventV1(context.Background(), "quote-request", large,
		CommerceEventContextV1{CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, publisher); err == nil {
		t.Fatal("immutable publisher substituted an object digest")
	}
}
