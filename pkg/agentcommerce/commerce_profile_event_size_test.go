package agentcommerce

import (
	"strings"
	"testing"
	"time"
)

func contentAddressedEventOfSize(now time.Time, size uint64) CommerceProfileEventV1 {
	digest := "sha256:" + strings.Repeat("3", 64)
	contentType := "application/vnd.tos.test.receipt.v1+cbor"
	return CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "receipt", ObjectContentType: contentType, ObjectDigest: digest, ObjectSizeBytes: size,
		CarriageKind: "content_addressed", ObjectDescriptor: &CommerceObjectDescriptorV1{ContentType: contentType,
			ContentDigest: digest, ContentSize: size, RetrievalHints: []string{"https://store.example/receipt"}},
		CreatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
}

func TestCommerceProfileEventObjectBoundIsTheLargestProfileCeiling(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	if MaxProfileEventBytes != 1<<20 {
		t.Fatalf("the encoded-event bound moved to %d", MaxProfileEventBytes)
	}
	atLimit := contentAddressedEventOfSize(now, MaxProfileEventObjectBytes)
	encoded, err := CanonicalCommerceProfileEventV1(atLimit, now)
	if err != nil {
		t.Fatalf("an event naming a %d-byte object was refused: %v", MaxProfileEventObjectBytes, err)
	}
	if len(encoded) > MaxProfileEventBytes {
		t.Fatalf("the descriptor event itself is %d bytes", len(encoded))
	}
	if _, err := DecodeCommerceProfileEventV1(encoded, now); err != nil {
		t.Fatalf("an event naming a %d-byte object failed to decode: %v", MaxProfileEventObjectBytes, err)
	}
	if err := ValidateCommerceProfileEventV1(contentAddressedEventOfSize(now, MaxProfileEventObjectBytes+1), now); err == nil {
		t.Fatal("an event naming an object over the profile-event object bound was accepted")
	}
	descriptor := *atLimit.ObjectDescriptor
	descriptor.ContentSize = MaxProfileEventObjectBytes + 1
	if err := ValidateCommerceObjectDescriptorV1(descriptor); err == nil {
		t.Fatal("a descriptor over the profile-event object bound was accepted")
	}
	inline := atLimit
	inline.CarriageKind, inline.ObjectDescriptor = "inline", nil
	inline.ObjectSizeBytes = MaxInlineProfileEventBytes + 1
	inline.CanonicalObjectBytes = make([]byte, MaxInlineProfileEventBytes+1)
	if err := ValidateCommerceProfileEventV1(inline, now); err == nil {
		t.Fatal("an inline object over the inline bound was accepted")
	}
}
