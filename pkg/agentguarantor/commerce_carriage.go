package agentguarantor

import (
	"context"
	"errors"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// CommerceCarriageObjectV1 is one immutable entry in the Messenger dispatch
// table. Carriage kinds are deliberately separate from the wider verifier
// registry: only authority-changing objects that peers exchange directly are
// admitted here.
type CommerceCarriageObjectV1 struct {
	ObjectKind     string `json:"object_kind"`
	RegistryKind   string `json:"registry_kind"`
	ContentType    string `json:"content_type"`
	EnvelopeDomain string `json:"envelope_domain"`
}

var commerceCarriageObjectsV1 = []CommerceCarriageObjectV1{
	{"quote-request", "quote-request", "application/vnd.tos.service.agent-guarantor-quote-request.v1+cbor", QuoteRequestDomain},
	{"firm-offer", "firm-offer", "application/vnd.tos.service.agent-guarantor-firm-offer.v1+cbor", FirmOfferDomain},
	{"offer-non-acceptance-evidence", "offer-non-acceptance", "application/vnd.tos.service.agent-guarantor-offer-non-acceptance.v1+cbor", OfferNonAcceptanceDomain},
	{"pre-acceptance-exposure-release-receipt", "pre-acceptance-exposure-release", "application/vnd.tos.service.agent-guarantor-pre-acceptance-release-receipt.v1+cbor", PreAcceptanceReleaseDomain},
	{"acceptance-request", "acceptance-request", "application/vnd.tos.service.agent-guarantor-acceptance-request.v1+cbor", AcceptanceRequestDomain},
	{"acceptance-receipt", "acceptance-receipt", "application/vnd.tos.service.agent-guarantor-acceptance-receipt.v1+cbor", AcceptanceReceiptDomain},
	{"activation-evidence", "activation-evidence", "application/vnd.tos.service.agent-guarantor-activation-evidence.v1+cbor", ActivationEvidenceDomain},
	{"non-activation-evidence", "non-activation-evidence", "application/vnd.tos.service.agent-guarantor-non-activation-evidence.v1+cbor", "tos.service.agent-guarantor-non-activation-evidence-envelope.v1"},
	{"cancellation-request", "cancellation-request", "application/vnd.tos.service.agent-guarantor-cancellation-request.v1+cbor", CancellationRequestDomain},
	{"cancellation-receipt", "cancellation-receipt", "application/vnd.tos.service.agent-guarantor-cancellation-receipt.v1+cbor", CancellationReceiptDomain},
	{"collateral-control-evidence", "collateral-control-evidence", "application/vnd.tos.service.agent-guarantor-collateral-control-evidence.v1+cbor", CollateralControlEvidenceDomainV1},
	{"collateral-evidence", "collateral-evidence", "application/vnd.tos.service.agent-guarantor-collateral-evidence.v1+cbor", CollateralDomain},
	{"claim", "claim", "application/vnd.tos.service.agent-guarantor-claim.v1+cbor", ClaimDomain},
	{"claim-ingress-receipt", "claim-ingress-receipt", "application/vnd.tos.service.agent-guarantor-claim-ingress-receipt.v1+cbor", ClaimIngressReceiptEnvelopeDomain},
	{"claim-admission-receipt", "claim-admission-receipt", "application/vnd.tos.service.agent-guarantor-claim-admission.v1+cbor", ClaimAdmissionReceiptEnvelopeDomain},
	{"claim-filing-close-receipt", "claim-filing-close-receipt", "application/vnd.tos.service.agent-guarantor-claim-filing-close.v1+cbor", ClaimFilingCloseDomain},
	{"claim-decision", "claim-decision", "application/vnd.tos.service.agent-guarantor-claim-decision.v1+cbor", ClaimDecisionDomain},
	{"claim-decision-admission-receipt", "claim-decision-admission-receipt", "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor", ClaimDecisionAdmissionReceiptDomainV1},
	{"claim-decision-application-receipt", "claim-decision-application-receipt", "application/vnd.tos.service.agent-guarantor-decision-application.v1+cbor", ClaimDecisionApplicationReceiptDomainV1},
	{"claim-state-transition-receipt", "claim-state-transition-receipt", "application/vnd.tos.service.agent-guarantor-claim-state-transition.v1+cbor", ClaimStateTransitionReceiptDomainV1},
	{"terminal-claim-set", "terminal-claim-set", "application/vnd.tos.service.agent-guarantor-terminal-claim-set.v1+cbor", TerminalClaimSetDomain},
	{"exposure-release-receipt", "exposure-release-receipt", "application/vnd.tos.service.agent-guarantor-exposure-release-receipt.v1+cbor", ExposureReleaseDomain},
	{"coverage-resolution", "coverage-resolution", "application/vnd.tos.service.agent-guarantor-resolution.v1+cbor", CoverageResolutionDomain},
}

// ReleasedCommerceCarriageObjectsV1 returns the closed, ordered dispatch table.
func ReleasedCommerceCarriageObjectsV1() []CommerceCarriageObjectV1 {
	return append([]CommerceCarriageObjectV1(nil), commerceCarriageObjectsV1...)
}

// ImmutableCommerceObjectPublisher is the only path by which a large object
// becomes content-addressed carriage. Implementations must durably commit the
// exact bytes before returning owner-approved HTTPS retrieval hints. The
// descriptor is verified again here; a storage service cannot substitute the
// digest, media type, or length chosen by the profile codec.
type ImmutableCommerceObjectPublisher interface {
	PublishImmutableCommerceObject(context.Context, string, string, []byte) (commerce.CommerceObjectDescriptorV1, error)
}

// CommerceEventContextV1 contains transport context only. None of these fields
// authorizes the embedded Guarantor object or changes its lifecycle meaning.
type CommerceEventContextV1 struct {
	RelatedIntentDigest string
	AgreementBodyDigest string
	ObligationIDs       []string
	CreatedAtUnix       uint64
	ExpiresAtUnix       uint64
}

// BuildCommerceProfileEventV1 canonicalizes and verifies a released carriage
// object, computes its registry-domain envelope digest, and deterministically
// selects inline or immutable content-addressed carriage. It never accepts a
// caller-supplied digest or media type.
func BuildCommerceProfileEventV1(ctx context.Context, objectKind string, object any,
	metadata CommerceEventContextV1, publisher ImmutableCommerceObjectPublisher) (commerce.CommerceProfileEventV1, error) {
	var entry *CommerceCarriageObjectV1
	for index := range commerceCarriageObjectsV1 {
		if commerceCarriageObjectsV1[index].ObjectKind == objectKind {
			entry = &commerceCarriageObjectsV1[index]
			break
		}
	}
	if entry == nil || object == nil {
		return commerce.CommerceProfileEventV1{}, errors.New("unsupported Guarantor commerce object")
	}
	canonical, err := guarantorCodec.Marshal(object)
	if err != nil {
		return commerce.CommerceProfileEventV1{}, err
	}
	decoded, err := DecodeRegisteredObjectV1(entry.RegistryKind, canonical)
	if err != nil {
		return commerce.CommerceProfileEventV1{}, err
	}
	digest, err := guarantorCodec.Digest(entry.EnvelopeDomain, decoded)
	if err != nil {
		return commerce.CommerceProfileEventV1{}, err
	}
	event := commerce.CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: ProfileURI, ProfileVersion: 1,
		ObjectKind: objectKind, ObjectContentType: entry.ContentType, ObjectDigest: digest,
		ObjectSizeBytes: uint64(len(canonical)), RelatedIntentDigest: metadata.RelatedIntentDigest,
		AgreementBodyDigest: metadata.AgreementBodyDigest, ObligationIDs: append([]string(nil), metadata.ObligationIDs...),
		CreatedAtUnix: metadata.CreatedAtUnix, ExpiresAtUnix: metadata.ExpiresAtUnix}
	if len(canonical) <= commerce.MaxInlineProfileEventBytes {
		event.CarriageKind = "inline"
		event.CanonicalObjectBytes = canonical
	} else {
		if publisher == nil {
			return commerce.CommerceProfileEventV1{}, errors.New("large Guarantor object requires immutable publication")
		}
		descriptor, publishErr := publisher.PublishImmutableCommerceObject(ctx, entry.ContentType, digest,
			append([]byte(nil), canonical...))
		if publishErr != nil {
			return commerce.CommerceProfileEventV1{}, publishErr
		}
		if commerce.ValidateCommerceObjectDescriptorV1(descriptor) != nil || descriptor.ContentType != entry.ContentType ||
			descriptor.ContentDigest != digest || descriptor.ContentSize != uint64(len(canonical)) || len(descriptor.RetrievalHints) == 0 {
			return commerce.CommerceProfileEventV1{}, errors.New("immutable publisher returned a substituted Guarantor descriptor")
		}
		event.CarriageKind = "content_addressed"
		event.ObjectDescriptor = &descriptor
	}
	if err := commerce.VerifyCommerceProfileEventV1(event,
		time.Unix(int64(metadata.CreatedAtUnix), 0).UTC(), CommerceObjectVerifierV1{}); err != nil {
		return commerce.CommerceProfileEventV1{}, err
	}
	return event, nil
}

// CommerceObjectVerifierV1 implements agentcommerce.CommerceObjectVerifier.
// It verifies profile identity, exact media type, strict canonical decoding,
// and the registered complete-envelope digest. Context-dependent signatures
// and state predicates are checked by the lifecycle coordinator before any
// economic mutation.
type CommerceObjectVerifierV1 struct{}

func (CommerceObjectVerifierV1) VerifyCommerceObject(profileURI string, profileVersion uint64,
	objectKind, contentType, digest string, canonical []byte) error {
	if profileURI != ProfileURI || profileVersion != 1 {
		return errors.New("unsupported Guarantor commerce profile")
	}
	var entry *CommerceCarriageObjectV1
	for index := range commerceCarriageObjectsV1 {
		if commerceCarriageObjectsV1[index].ObjectKind == objectKind {
			entry = &commerceCarriageObjectsV1[index]
			break
		}
	}
	if entry == nil || contentType != entry.ContentType {
		return errors.New("unsupported Guarantor commerce object kind or media type")
	}
	value, err := DecodeRegisteredObjectV1(entry.RegistryKind, canonical)
	if err != nil {
		return err
	}
	want, err := guarantorCodec.Digest(entry.EnvelopeDomain, value)
	if err != nil || want != digest {
		return errors.New("Guarantor commerce object digest differs")
	}
	return nil
}
