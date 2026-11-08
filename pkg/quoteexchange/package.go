// Package quoteexchange validates portable, complete-preimage Quote Proposal
// packages. A valid package is still non-canonical; only the finalized
// Service Actor call transaction establishes an Accepted Quote.
package quoteexchange

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const MaxPackageBytes = 2 << 20

type Validated struct {
	Proposal         *nativev1.QuoteProposalV1
	Manifest         nativecore.SoftwareWorkManifestV1
	Rail             nativecore.ServiceActorQuoteRailV1
	TransportBinding nativecore.TransportBindingV1
}

// Validate proves that every digest in the proposal has the exact preimage
// carried in the package and that the request identity is unchanged.
func Validate(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest,
	value *nativev1.QuoteProposalPackageV1, now time.Time) (*Validated, error) {
	validated, err := validatePortable(network, request, value)
	if err != nil || now.IsZero() ||
		value.Proposal.ExpiresAtUnixSeconds <= uint64(now.Unix()) ||
		value.Proposal.ExpiresAtUnixSeconds > uint64(now.Add(time.Hour).Unix()) {
		return nil, errors.New("invalid Quote Proposal package identity or expiry")
	}
	return validated, nil
}

// ValidatePortable proves the immutable Quote preimages without applying the
// pre-acceptance freshness window. It is intended for post-acceptance audit and
// recovery, where the finalized call transaction, not a gateway clock, is
// authoritative.
func ValidatePortable(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest,
	value *nativev1.QuoteProposalPackageV1) (*Validated, error) {
	return validatePortable(network, request, value)
}

func validatePortable(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest,
	value *nativev1.QuoteProposalPackageV1) (*Validated, error) {
	if network == nil || request == nil || value == nil || value.Proposal == nil ||
		request.CapabilityId == "" || request.CapabilityVersion == "" || request.BuyerAddress == "" ||
		value.Proposal.CapabilityId != request.CapabilityId || value.Proposal.CapabilityVersion != request.CapabilityVersion ||
		value.Proposal.ProposalId == "" || len(value.Proposal.ProposalId) > 256 ||
		strings.TrimSpace(value.Proposal.ProposalId) != value.Proposal.ProposalId ||
		value.Proposal.ExpiresAtUnixSeconds == 0 {
		return nil, errors.New("invalid Quote Proposal package identity")
	}
	total := len(value.CanonicalManifestCbor) + len(value.TransportBindingBoc)
	if total <= 0 || total > MaxPackageBytes {
		return nil, errors.New("Quote Proposal package is outside size bounds")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(value.CanonicalManifestCbor)
	if err != nil {
		return nil, errors.New("Quote Proposal carries a non-canonical manifest")
	}
	canonical, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, value.CanonicalManifestCbor) || manifestDigest != value.Proposal.ManifestDigest ||
		manifest.Version != value.Proposal.CapabilityVersion {
		return nil, errors.New("Quote Proposal manifest preimage mismatch")
	}
	rail, err := nativecore.ParseServiceActorQuoteRail(value.Proposal)
	if err != nil {
		return nil, fmt.Errorf("Quote Proposal rail: %w", err)
	}
	// Manifest key 21 is the owner Agent's statement of the settling actor;
	// the proposal must name exactly that actor, code and attestor.
	settlement := manifest.Settlement
	if settlement.ActorWorkchain != 0 || rail.Actor != "0:"+hex.EncodeToString(settlement.ActorAccountID) ||
		!bytes.Equal(rail.ActorCodeHash[:], settlement.ActorCodeHash) || value.Proposal.AttestorKeyId != settlement.AttestorKey {
		return nil, errors.New("Quote Proposal rail differs from manifest key 21")
	}
	transportCell, err := canonicalCell(value.TransportBindingBoc)
	if err != nil || "sha256:"+hexHash(transportCell) != value.Proposal.TransportBindingDigest {
		return nil, errors.New("Quote Proposal transport preimage mismatch")
	}
	transport, err := nativecore.DecodeTransportBindingCellV1(transportCell)
	if err != nil {
		return nil, errors.New("Quote Proposal transport binding is invalid")
	}
	if transport.SecurityMode == nativecore.TransportAgentPacket {
		// Agent Packets go to the Capability owner Agent and to nobody else.
		recipient, err := transport.AgentPacketRecipient()
		if err != nil || recipient != value.Proposal.ProviderAgentId {
			return nil, errors.New("Quote Proposal Agent Packet transport names another Agent than the provider")
		}
	}
	if _, _, err := nativecore.BuildAcceptedQuoteCommitment(network, value.Proposal); err != nil {
		return nil, errors.New("Quote Proposal fields are not canonically encodable")
	}
	return &Validated{Proposal: value.Proposal, Manifest: manifest, Rail: rail, TransportBinding: transport}, nil
}

func canonicalCell(raw []byte) (*cell.Cell, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, errors.New("cell BOC outside bounds")
	}
	roots, err := cell.FromBOCMultiRoot(raw)
	if err != nil || len(roots) != 1 || roots[0] == nil || !bytes.Equal(roots[0].ToBOC(), raw) {
		return nil, errors.New("cell BOC is not canonical single-root encoding")
	}
	return roots[0], nil
}

func hexHash(root *cell.Cell) string {
	const digits = "0123456789abcdef"
	raw := root.Hash()
	encoded := make([]byte, len(raw)*2)
	for i, value := range raw {
		encoded[i*2], encoded[i*2+1] = digits[value>>4], digits[value&15]
	}
	return string(encoded)
}
