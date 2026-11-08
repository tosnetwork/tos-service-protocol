package agentcommerce

import (
	"bytes"
	"errors"
	"math"
	"net/url"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const CommerceProfileEventContentType = "application/vnd.tos.service.commerce-profile-event.v1+cbor"

type CommerceObjectDescriptorV1 struct {
	ContentType    string   `json:"content_type"`
	ContentDigest  string   `json:"content_digest"`
	ContentSize    uint64   `json:"content_size"`
	RetrievalHints []string `json:"retrieval_hints,omitempty"`
}

type CommerceProfileEventV1 struct {
	SchemaVersion        uint16                      `json:"schema_version"`
	ProfileURI           string                      `json:"profile_uri"`
	ProfileVersion       uint64                      `json:"profile_version"`
	ObjectKind           string                      `json:"object_kind"`
	ObjectContentType    string                      `json:"object_content_type"`
	ObjectDigest         string                      `json:"object_digest"`
	ObjectSizeBytes      uint64                      `json:"object_size_bytes"`
	CarriageKind         string                      `json:"carriage_kind"`
	RelatedIntentDigest  string                      `json:"related_intent_digest,omitempty"`
	AgreementBodyDigest  string                      `json:"agreement_body_digest,omitempty"`
	ObligationIDs        []string                    `json:"obligation_ids,omitempty"`
	CanonicalObjectBytes []byte                      `json:"canonical_object_bytes,omitempty"`
	ObjectDescriptor     *CommerceObjectDescriptorV1 `json:"object_descriptor,omitempty"`
	CreatedAtUnix        uint64                      `json:"created_at_unix"`
	ExpiresAtUnix        uint64                      `json:"expires_at_unix"`
}

// CommerceObjectVerifier resolves the profile-qualified object kind to its
// immutable digest domain and strict decoder. The transport never guesses a
// digest domain from a display token.
type CommerceObjectVerifier interface {
	VerifyCommerceObject(profileURI string, profileVersion uint64, objectKind, contentType, digest string, canonical []byte) error
}

func ValidateCommerceObjectDescriptorV1(descriptor CommerceObjectDescriptorV1) error {
	if !boundedMediaType(descriptor.ContentType) || !canonicalDigestPattern.MatchString(descriptor.ContentDigest) ||
		descriptor.ContentSize == 0 || descriptor.ContentSize > MaxProfileEventObjectBytes ||
		len(descriptor.RetrievalHints) > MaxProfileRetrievalHints {
		return errors.New("commerce object descriptor is invalid")
	}
	for _, hint := range descriptor.RetrievalHints {
		parsed, err := url.Parse(hint)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || len(hint) > 2048 {
			return errors.New("commerce retrieval hint is invalid")
		}
	}
	return nil
}

func ValidateCommerceProfileEventV1(event CommerceProfileEventV1, now time.Time) error {
	if event.SchemaVersion != 1 || !boundedIdentifier(event.ProfileURI, 256) || event.ProfileVersion == 0 ||
		!boundedIdentifier(event.ObjectKind, 128) || !boundedMediaType(event.ObjectContentType) ||
		!canonicalDigestPattern.MatchString(event.ObjectDigest) || event.ObjectSizeBytes == 0 ||
		event.ObjectSizeBytes > MaxProfileEventObjectBytes || event.CreatedAtUnix == 0 || event.ExpiresAtUnix <= event.CreatedAtUnix ||
		event.CreatedAtUnix > math.MaxInt64 || event.ExpiresAtUnix > math.MaxInt64 ||
		event.ExpiresAtUnix-event.CreatedAtUnix > uint64((30*24*time.Hour)/time.Second) ||
		event.CreatedAtUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) || uint64(now.UTC().Unix()) >= event.ExpiresAtUnix ||
		event.RelatedIntentDigest != "" && !canonicalDigestPattern.MatchString(event.RelatedIntentDigest) ||
		event.AgreementBodyDigest != "" && !canonicalDigestPattern.MatchString(event.AgreementBodyDigest) ||
		!sortedUniqueStrings(event.ObligationIDs, MaxProfileObligationIDs, func(value string) bool { return boundedIdentifier(value, 128) }) {
		return errors.New("commerce profile event is invalid")
	}
	switch event.CarriageKind {
	case "inline":
		if event.ObjectDescriptor != nil || len(event.CanonicalObjectBytes) == 0 ||
			uint64(len(event.CanonicalObjectBytes)) != event.ObjectSizeBytes || len(event.CanonicalObjectBytes) > MaxInlineProfileEventBytes {
			return errors.New("inline commerce event has invalid field presence")
		}
	case "content_addressed":
		if len(event.CanonicalObjectBytes) != 0 || event.ObjectDescriptor == nil ||
			ValidateCommerceObjectDescriptorV1(*event.ObjectDescriptor) != nil ||
			event.ObjectDescriptor.ContentType != event.ObjectContentType ||
			event.ObjectDescriptor.ContentDigest != event.ObjectDigest ||
			event.ObjectDescriptor.ContentSize != event.ObjectSizeBytes {
			return errors.New("content-addressed commerce event has invalid descriptor")
		}
	default:
		return errors.New("commerce carriage kind is unknown")
	}
	return nil
}

func VerifyCommerceProfileEventV1(event CommerceProfileEventV1, now time.Time, verifier CommerceObjectVerifier) error {
	if err := ValidateCommerceProfileEventV1(event, now); err != nil {
		return err
	}
	if verifier == nil {
		return errors.New("commerce object verifier is required")
	}
	if event.CarriageKind == "inline" {
		return verifier.VerifyCommerceObject(event.ProfileURI, event.ProfileVersion, event.ObjectKind,
			event.ObjectContentType, event.ObjectDigest, event.CanonicalObjectBytes)
	}
	return nil
}

func CanonicalCommerceProfileEventV1(event CommerceProfileEventV1, now time.Time) ([]byte, error) {
	if err := ValidateCommerceProfileEventV1(event, now); err != nil {
		return nil, err
	}
	return codec.Marshal(event)
}

func DecodeCommerceProfileEventV1(canonical []byte, now time.Time) (CommerceProfileEventV1, error) {
	var event CommerceProfileEventV1
	if err := codec.Unmarshal(canonical, &event); err != nil {
		return event, err
	}
	if err := ValidateCommerceProfileEventV1(event, now); err != nil {
		return event, err
	}
	reencoded, err := codec.Marshal(event)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return event, errors.New("commerce profile event is not canonical")
	}
	return event, nil
}
