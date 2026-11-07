package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const acceptedQuoteMagic = 0x4e415131 // NAQ1

var (
	positiveNanoTOSPattern = regexp.MustCompile(`^[1-9][0-9]{0,39}$`)
	lowerHex64Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// AcceptedQuoteTermsV1 is a decoded rail Accepted Quote.
type AcceptedQuoteTermsV1 struct {
	Network  *nativev1.NetworkDomain
	Proposal *nativev1.QuoteProposalV1
}

// ServiceActorQuoteRailV1 is the parsed rail of a Quote Proposal.
type ServiceActorQuoteRailV1 struct {
	Actor         string // raw "0:<hex>"
	ActorCodeHash [32]byte
	PolicyVersion uint32
	TermsHash     [32]byte
	Price         *big.Int
	StorageFee    *big.Int
	AttestorKeyID [32]byte
}

// ParseServiceActorQuoteRail validates proposal fields 11-17 exactly as
// ACCEPTED_QUOTE_TVM_V1 bounds them.
func ParseServiceActorQuoteRail(proposal *nativev1.QuoteProposalV1) (ServiceActorQuoteRailV1, error) {
	var rail ServiceActorQuoteRailV1
	if proposal == nil || proposal.Actor == nil || proposal.Actor.Workchain != 0 || len(proposal.Actor.AccountId) != 32 {
		return rail, errors.New("Quote actor is not a workchain 0 account")
	}
	rail.Actor = "0:" + hex.EncodeToString(proposal.Actor.AccountId)
	code, err := digestBytes(proposal.ActorCodeHash, "tvm-cell-sha256:", false)
	if err != nil {
		return rail, errors.New("invalid Quote actor code hash")
	}
	copy(rail.ActorCodeHash[:], code)
	rail.PolicyVersion = proposal.PolicyVersion
	if !lowerHex64Pattern.MatchString(proposal.TermsHash) {
		return rail, errors.New("invalid Quote terms hash")
	}
	terms, _ := hex.DecodeString(proposal.TermsHash)
	copy(rail.TermsHash[:], terms)
	if rail.TermsHash == ([32]byte{}) {
		return rail, errors.New("zero Quote terms hash")
	}
	if rail.Price, err = parsePositiveNanoTOS(proposal.PriceNanotos); err != nil {
		return rail, fmt.Errorf("Quote price: %w", err)
	}
	if rail.StorageFee, err = parsePositiveNanoTOS(proposal.StorageFeeNanotos); err != nil {
		return rail, fmt.Errorf("Quote storage fee: %w", err)
	}
	if rail.AttestorKeyID, err = mldsa44.ParseKeyIDText(proposal.AttestorKeyId); err != nil {
		return rail, errors.New("invalid Quote attestor key id")
	}
	return rail, nil
}

func parsePositiveNanoTOS(value string) (*big.Int, error) {
	if !positiveNanoTOSPattern.MatchString(value) {
		return nil, errors.New("amount is not a positive canonical decimal")
	}
	amount, ok := new(big.Int).SetString(value, 10)
	if !ok || amount.Cmp(MaxServiceActorCoins) >= 0 {
		return nil, errors.New("amount is not below 2^120")
	}
	return amount, nil
}

// BuildAcceptedQuoteCommitment converts a gateway-local proposal into the
// rail Accepted Quote cell. proposal_id is excluded, so gateways never become
// part of canonical commercial identity.
func BuildAcceptedQuoteCommitment(network *nativev1.NetworkDomain, proposal *nativev1.QuoteProposalV1) (*cell.Cell, string, error) {
	domain, err := domainCell(network)
	if err != nil {
		return nil, "", err
	}
	if proposal == nil || proposal.ExpiresAtUnixSeconds == 0 || !validProtocolText(proposal.CapabilityVersion, 128) {
		return nil, "", errors.New("invalid Native Quote Proposal")
	}
	capability, kind, err := objectID(proposal.CapabilityId)
	if err != nil || kind != 2 {
		return nil, "", errors.New("invalid Native Quote Capability")
	}
	provider, kind, err := objectID(proposal.ProviderAgentId)
	if err != nil || kind != 1 {
		return nil, "", errors.New("invalid Native Quote provider")
	}
	manifest, err := digestBytes(proposal.ManifestDigest, "sha256:", false)
	if err != nil {
		return nil, "", errors.New("invalid Native Quote manifest digest")
	}
	transport, err := digestBytes(proposal.TransportBindingDigest, "sha256:", false)
	if err != nil {
		return nil, "", errors.New("invalid Native Quote transport digest")
	}
	rail, err := ParseServiceActorQuoteRail(proposal)
	if err != nil {
		return nil, "", err
	}
	actor, err := StandardAddress(rail.Actor)
	if err != nil {
		return nil, "", err
	}
	versionHash := sha256.Sum256([]byte(proposal.CapabilityVersion))
	version := cell.BeginCell().MustStoreSlice(versionHash[:], 256).MustStoreSlice(manifest, 256).
		MustStoreSlice(transport, 256).MustStoreUInt(proposal.ExpiresAtUnixSeconds, 64).
		MustStoreRef(stringCell(proposal.CapabilityVersion)).EndCell()
	identity := cell.BeginCell().MustStoreSlice(capability, 256).MustStoreSlice(provider, 256).MustStoreRef(version).EndCell()
	termsBuilder := cell.BeginCell().MustStoreSlice(rail.TermsHash[:], 256)
	if err := storeServiceActorCoins(termsBuilder, rail.Price); err != nil {
		return nil, "", err
	}
	if err := storeServiceActorCoins(termsBuilder, rail.StorageFee); err != nil {
		return nil, "", err
	}
	railCell := cell.BeginCell().MustStoreSlice(actor.Bits, actor.BitLen).MustStoreSlice(rail.ActorCodeHash[:], 256).
		MustStoreUInt(uint64(rail.PolicyVersion), 32).MustStoreRef(termsBuilder.EndCell()).EndCell()
	authority := cell.BeginCell().MustStoreSlice(rail.AttestorKeyID[:], 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(acceptedQuoteMagic, 32).MustStoreUInt(1, 16).
		MustStoreRef(domain).MustStoreRef(identity).MustStoreRef(railCell).MustStoreRef(authority).EndCell()
	return root, "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), nil
}

// DecodeAcceptedQuoteV1 returns every committed field and proves that
// re-encoding it produces the exact supplied cell.
func DecodeAcceptedQuoteV1(root *cell.Cell, network *nativev1.NetworkDomain) (*AcceptedQuoteTermsV1, error) {
	expectedDomain, err := domainCell(network)
	if err != nil {
		return nil, err
	}
	s, err := beginOrdinary(root, "Accepted Quote")
	if err != nil {
		return nil, err
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != acceptedQuoteMagic {
		return nil, errors.New("invalid Accepted Quote magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, errors.New("unsupported Accepted Quote schema")
	}
	domain, err := loadRefCell(s, "Accepted Quote network")
	if err != nil || !bytes.Equal(domain.Hash(), expectedDomain.Hash()) {
		return nil, errors.New("Accepted Quote network mismatch")
	}
	identityCell, err := loadRefCell(s, "Quote identity")
	if err != nil {
		return nil, err
	}
	railCell, err := loadRefCell(s, "Quote rail")
	if err != nil {
		return nil, err
	}
	authorityCell, err := loadRefCell(s, "Quote authority")
	if err != nil {
		return nil, err
	}
	if err := exhausted(s, "Accepted Quote"); err != nil {
		return nil, err
	}
	i, err := beginOrdinary(identityCell, "Quote identity")
	if err != nil {
		return nil, err
	}
	capability, err := loadHash(i)
	if err != nil {
		return nil, err
	}
	provider, err := loadHash(i)
	if err != nil {
		return nil, err
	}
	versionCell, err := loadRefCell(i, "Quote version")
	if err != nil {
		return nil, err
	}
	if err := exhausted(i, "Quote identity"); err != nil {
		return nil, err
	}
	v, err := beginOrdinary(versionCell, "Quote version")
	if err != nil {
		return nil, err
	}
	versionHash, err := loadHash(v)
	if err != nil {
		return nil, err
	}
	manifest, err := loadHash(v)
	if err != nil {
		return nil, err
	}
	transport, err := loadHash(v)
	if err != nil {
		return nil, err
	}
	expires, err := v.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid Quote expiry")
	}
	versionTextCell, err := loadRefCell(v, "Quote version text")
	if err != nil {
		return nil, err
	}
	if err := exhausted(v, "Quote version"); err != nil {
		return nil, err
	}
	versionText, err := decodeProtocolText(versionTextCell, 128)
	if err != nil || sha256.Sum256([]byte(versionText)) != versionHash {
		return nil, errors.New("invalid Quote version text")
	}
	r, err := beginOrdinary(railCell, "Quote rail")
	if err != nil {
		return nil, err
	}
	actor, err := loadMsgAddressInt(r)
	if err != nil {
		return nil, fmt.Errorf("Quote actor: %w", err)
	}
	actorRaw, ok := actor.RawStandard()
	if !ok || actor.Workchain != 0 {
		return nil, errors.New("Quote actor is not a standard workchain 0 address")
	}
	codeHash, err := loadHash(r)
	if err != nil {
		return nil, err
	}
	policyVersion, err := r.LoadUInt(32)
	if err != nil {
		return nil, errors.New("invalid Quote policy version")
	}
	termsCell, err := loadRefCell(r, "Quote rail terms")
	if err != nil {
		return nil, err
	}
	if err := exhausted(r, "Quote rail"); err != nil {
		return nil, err
	}
	t, err := beginOrdinary(termsCell, "Quote rail terms")
	if err != nil {
		return nil, err
	}
	termsHash, err := loadHash(t)
	if err != nil {
		return nil, err
	}
	price, err := loadServiceActorCoins(t)
	if err != nil {
		return nil, fmt.Errorf("Quote price: %w", err)
	}
	storageFee, err := loadServiceActorCoins(t)
	if err != nil {
		return nil, fmt.Errorf("Quote storage fee: %w", err)
	}
	if err := exhausted(t, "Quote rail terms"); err != nil {
		return nil, err
	}
	a, err := beginOrdinary(authorityCell, "Quote authority")
	if err != nil {
		return nil, err
	}
	keyID, err := loadHash(a)
	if err != nil {
		return nil, err
	}
	if err := exhausted(a, "Quote authority"); err != nil {
		return nil, err
	}
	actorID, _ := hex.DecodeString(actorRaw[2:])
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + hex.EncodeToString(capability[:]),
		CapabilityVersion: versionText, ProviderAgentId: "agent_" + hex.EncodeToString(provider[:]),
		ManifestDigest: "sha256:" + hex.EncodeToString(manifest[:]), TransportBindingDigest: "sha256:" + hex.EncodeToString(transport[:]),
		ExpiresAtUnixSeconds: expires, Actor: &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: actorID},
		ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(codeHash[:]), PolicyVersion: uint32(policyVersion),
		TermsHash: hex.EncodeToString(termsHash[:]), PriceNanotos: price.String(), StorageFeeNanotos: storageFee.String(),
		AttestorKeyId: mldsa44.KeyIDText(keyID)}
	rebuilt, _, err := BuildAcceptedQuoteCommitment(network, proposal)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("Accepted Quote is not canonical")
	}
	return &AcceptedQuoteTermsV1{Network: proto.Clone(network).(*nativev1.NetworkDomain), Proposal: proposal}, nil
}

// ServiceRequestV1 is the NSR1 preimage of a call's request_hash.
type ServiceRequestV1 struct {
	QuoteCommitment [32]byte
	ExecutionID     [32]byte
	InputDigest     [32]byte
}

// BuildServiceRequestCellV1 builds service_request$_ magic:uint32="NSR1"
// schema:uint16=1 quote_commitment execution_id input_digest; every field
// must be non-zero.
func BuildServiceRequestCellV1(value ServiceRequestV1) (*cell.Cell, error) {
	if value.QuoteCommitment == ([32]byte{}) || value.ExecutionID == ([32]byte{}) || value.InputDigest == ([32]byte{}) {
		return nil, errors.New("service request fields must be non-zero")
	}
	return cell.BeginCell().MustStoreUInt(serviceRequestMagic, 32).MustStoreUInt(1, 16).
		MustStoreSlice(value.QuoteCommitment[:], 256).MustStoreSlice(value.ExecutionID[:], 256).
		MustStoreSlice(value.InputDigest[:], 256).EndCell(), nil
}

// DecodeServiceRequestCellV1 decodes an NSR1 cell exactly.
func DecodeServiceRequestCellV1(root *cell.Cell) (ServiceRequestV1, error) {
	var value ServiceRequestV1
	s, err := beginOrdinary(root, "service request")
	if err != nil {
		return value, err
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != serviceRequestMagic {
		return value, errors.New("invalid service request magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return value, errors.New("unsupported service request schema")
	}
	for _, target := range []*[32]byte{&value.QuoteCommitment, &value.ExecutionID, &value.InputDigest} {
		if *target, err = loadHash(s); err != nil {
			return value, err
		}
	}
	if err := exhausted(s, "service request"); err != nil {
		return value, err
	}
	if _, err := BuildServiceRequestCellV1(value); err != nil {
		return value, err
	}
	return value, nil
}
