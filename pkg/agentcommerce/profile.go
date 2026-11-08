package agentcommerce

import (
	"bytes"
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxProfileURIBytes     = 256
	MaxProfilePayloadBytes = 64 << 10
	// MaxProfileEventBytes bounds one encoded CommerceProfileEventV1.
	MaxProfileEventBytes = 1 << 20
	// MaxProfileEventObjectBytes bounds the complete object an event names
	// (object_size_bytes and the descriptor content_size). It is the largest
	// complete-object ceiling of a profile that uses commerce profile events:
	// Agent Guarantor V1, 2,000,000 bytes. A profile's own verifier enforces
	// its own ceiling; the event itself stays within MaxProfileEventBytes.
	MaxProfileEventObjectBytes = 2_000_000
	// Inline profile objects must leave room for the signed Messenger envelope,
	// event metadata and canonical wrapper under Messenger's 128 KiB body cap.
	// Larger objects use the content-addressed descriptor form.
	MaxInlineProfileEventBytes = 96 << 10
	MaxProfileObligationIDs    = 256
	MaxProfileRetrievalHints   = 8
)

// ProfileRefV1 selects one immutable verifier or Adapter profile. URI-only
// dispatch is intentionally impossible at every authority boundary.
type ProfileRefV1 struct {
	ProfileURI     string `json:"profile_uri"`
	ProfileVersion uint64 `json:"profile_version"`
	ProfileDigest  string `json:"profile_digest"`
}

type PolicyRefV1 struct {
	ContentType   string `json:"content_type"`
	ContentDigest string `json:"content_digest"`
	ContentSize   uint64 `json:"content_size"`
}

type AssetIdentityV1 struct {
	AssetNamespace  string `json:"asset_namespace"`
	AssetIdentifier string `json:"asset_identifier"`
	Unit            string `json:"unit"`
}

type AtomicAmountV1 struct {
	Asset        AssetIdentityV1 `json:"asset"`
	AmountAtomic string          `json:"amount_atomic"`
}

type AtomicAmountRangeV1 struct {
	Minimum AtomicAmountV1 `json:"minimum"`
	Maximum AtomicAmountV1 `json:"maximum"`
}

type PayoutDestinationV1 struct {
	SchemaVersion            uint16          `json:"schema_version"`
	SettlementAdapterProfile ProfileRefV1    `json:"settlement_adapter_profile"`
	BeneficiarySubject       string          `json:"beneficiary_subject"`
	Asset                    AssetIdentityV1 `json:"asset"`
	NetworkOrSystemDigest    string          `json:"network_or_system_digest"`
	DestinationEncoding      string          `json:"destination_encoding"`
	DestinationBytes         []byte          `json:"destination_bytes"`
	RoutingParameters        []byte          `json:"routing_parameters,omitempty"`
}

type PayoutDestinationBindingV1 struct {
	Mode                                string              `json:"mode"`
	DestinationAuthorizationPredicateID string              `json:"destination_authorization_predicate_id"`
	PayoutDestination                   PayoutDestinationV1 `json:"payout_destination"`
}

func ValidateProfileRefV1(ref ProfileRefV1) error {
	if !boundedIdentifier(ref.ProfileURI, MaxProfileURIBytes) || ref.ProfileVersion == 0 ||
		!canonicalDigestPattern.MatchString(ref.ProfileDigest) {
		return errors.New("profile reference is invalid")
	}
	return nil
}

func ValidatePolicyRefV1(ref PolicyRefV1) error {
	if !boundedMediaType(ref.ContentType) || !canonicalDigestPattern.MatchString(ref.ContentDigest) ||
		ref.ContentSize == 0 || ref.ContentSize > MaxProfilePayloadBytes {
		return errors.New("policy reference is invalid")
	}
	return nil
}

func ValidateAssetIdentityV1(asset AssetIdentityV1) error {
	if !boundedIdentifier(asset.AssetNamespace, 128) || !boundedIdentifier(asset.AssetIdentifier, 256) ||
		!boundedIdentifier(asset.Unit, 64) {
		return errors.New("asset identity is invalid")
	}
	return nil
}

func ValidateAtomicAmountV1(amount AtomicAmountV1, positive bool) error {
	if ValidateAssetIdentityV1(amount.Asset) != nil || !canonicalUnsignedDecimal(amount.AmountAtomic) ||
		positive && amount.AmountAtomic == "0" {
		return errors.New("atomic amount is invalid")
	}
	return nil
}

func ValidateAtomicAmountRangeV1(value AtomicAmountRangeV1) error {
	if ValidateAtomicAmountV1(value.Minimum, false) != nil || ValidateAtomicAmountV1(value.Maximum, true) != nil ||
		value.Minimum.Asset != value.Maximum.Asset || compareCanonicalUnsigned(value.Minimum.AmountAtomic, value.Maximum.AmountAtomic) > 0 {
		return errors.New("atomic amount range is invalid")
	}
	return nil
}

func ValidatePayoutDestinationV1(destination PayoutDestinationV1) error {
	if destination.SchemaVersion != 1 || ValidateProfileRefV1(destination.SettlementAdapterProfile) != nil ||
		!boundedIdentifier(destination.BeneficiarySubject, 256) || ValidateAssetIdentityV1(destination.Asset) != nil ||
		!canonicalDigestPattern.MatchString(destination.NetworkOrSystemDigest) ||
		!boundedIdentifier(destination.DestinationEncoding, 64) || len(destination.DestinationBytes) == 0 ||
		len(destination.DestinationBytes) > 64<<10 || len(destination.RoutingParameters) > 16<<10 {
		return errors.New("payout destination is invalid")
	}
	return nil
}

func ValidatePayoutDestinationBindingV1(binding PayoutDestinationBindingV1) error {
	if binding.Mode != "agreement_fixed" || !boundedIdentifier(binding.DestinationAuthorizationPredicateID, 128) ||
		ValidatePayoutDestinationV1(binding.PayoutDestination) != nil {
		return errors.New("payout destination binding is invalid")
	}
	return nil
}

func ProfileRefDigestV1(ref ProfileRefV1) (string, error) {
	if err := ValidateProfileRefV1(ref); err != nil {
		return "", err
	}
	return codec.Digest("tos.service.profile-ref.v1", ref)
}

func PayoutDestinationDigestV1(destination PayoutDestinationV1) (string, error) {
	if err := ValidatePayoutDestinationV1(destination); err != nil {
		return "", err
	}
	return codec.Digest("tos.service.agent-guarantor-payout-destination.v1", destination)
}

func boundedMediaType(value string) bool {
	return len(value) > 0 && len(value) <= 256 && utf8.ValidString(value) && !bytes.ContainsRune([]byte(value), 0)
}

func compareCanonicalUnsigned(left, right string) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return bytes.Compare([]byte(left), []byte(right))
}

func sortedUniqueStrings(values []string, maximum int, validator func(string) bool) bool {
	if len(values) > maximum || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !validator(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}
