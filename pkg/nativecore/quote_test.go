package nativecore

import (
	"bytes"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

func testRailProposal() *nativev1.QuoteProposalV1 {
	var keyID [32]byte
	copy(keyID[:], bytes.Repeat([]byte{0x99}, 32))
	return &nativev1.QuoteProposalV1{ProposalId: "gateway-a-local-1", CapabilityId: "cap_" + strings.Repeat("33", 32),
		CapabilityVersion: "1.0.0", ProviderAgentId: "agent_" + strings.Repeat("44", 32),
		ManifestDigest: "sha256:" + strings.Repeat("55", 32), TransportBindingDigest: "sha256:" + strings.Repeat("66", 32),
		ExpiresAtUnixSeconds: 12345, Actor: &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: bytes.Repeat([]byte{0x77}, 32)},
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), PolicyVersion: 4, TermsHash: strings.Repeat("ab", 32),
		PriceNanotos: "300000000", StorageFeeNanotos: "200000000", AttestorKeyId: mldsa44.KeyIDText(keyID)}
}

func TestAcceptedQuoteRailLayout(t *testing.T) {
	network := testNetworkDomain()
	root, commitment, err := BuildAcceptedQuoteCommitment(network, testRailProposal())
	if err != nil {
		t.Fatal(err)
	}
	other := testRailProposal()
	other.ProposalId = "gateway-b-different-local-id"
	if _, second, err := BuildAcceptedQuoteCommitment(network, other); err != nil || second != commitment {
		t.Fatal("the gateway-local proposal ID changed the canonical Accepted Quote")
	}
	// The layout of ACCEPTED_QUOTE_TVM_V1, read field by field.
	s := root.MustBeginParse()
	if s.MustLoadUInt(32) != acceptedQuoteMagic || s.MustLoadUInt(16) != 1 || s.BitsLeft() != 0 || s.RefsNum() != 4 {
		t.Fatal("root is not magic schema ^network ^identity ^rail ^authority")
	}
	domain, _ := domainCell(network)
	if !bytes.Equal(s.MustLoadRef().MustToCell().Hash(), domain.Hash()) {
		t.Fatal("first reference is not the NetworkDomainV1 cell")
	}
	s.MustLoadRef()
	rail := s.MustLoadRef()
	if rail.BitsLeft() != 267+256+32 || rail.RefsNum() != 1 {
		t.Fatalf("rail is %d bits and %d refs, not 555 bits and one ref", rail.BitsLeft(), rail.RefsNum())
	}
	if rail.MustLoadUInt(2) != 2 || rail.MustLoadBoolBit() || rail.MustLoadInt(8) != 0 ||
		!bytes.Equal(rail.MustLoadSlice(256), bytes.Repeat([]byte{0x77}, 32)) ||
		!bytes.Equal(rail.MustLoadSlice(256), bytes.Repeat([]byte{0x88}, 32)) || rail.MustLoadUInt(32) != 4 {
		t.Fatal("rail is not actor:addr_std actor_code_hash policy_version")
	}
	terms := rail.MustLoadRef()
	if !bytes.Equal(terms.MustLoadSlice(256), bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("rail terms do not start with terms_hash")
	}
	if price, err := loadServiceActorCoins(terms); err != nil || price.Int64() != 300000000 {
		t.Fatal("rail terms price is not Coins")
	}
	if fee, err := loadServiceActorCoins(terms); err != nil || fee.Int64() != 200000000 || terms.BitsLeft() != 0 || terms.RefsNum() != 0 {
		t.Fatal("rail terms storage fee is not the last Coins field")
	}
	authority := s.MustLoadRef()
	if authority.BitsLeft() != 256 || authority.RefsNum() != 0 || !bytes.Equal(authority.MustLoadSlice(256), bytes.Repeat([]byte{0x99}, 32)) {
		t.Fatal("authority is not attestor_key_id")
	}

	decoded, err := DecodeAcceptedQuoteV1(root, network)
	if err != nil {
		t.Fatal(err)
	}
	want := testRailProposal()
	want.ProposalId = ""
	if !proto.Equal(decoded.Proposal, want) {
		t.Fatalf("decoded proposal differs:\n%v\n%v", decoded.Proposal, want)
	}
}

func TestAcceptedQuoteRefusesInvalidRails(t *testing.T) {
	network := testNetworkDomain()
	for name, edit := range map[string]func(*nativev1.QuoteProposalV1){
		"masterchain actor": func(p *nativev1.QuoteProposalV1) { p.Actor.Workchain = -1 },
		"short actor":       func(p *nativev1.QuoteProposalV1) { p.Actor.AccountId = p.Actor.AccountId[:31] },
		"missing actor":     func(p *nativev1.QuoteProposalV1) { p.Actor = nil },
		"zero price":        func(p *nativev1.QuoteProposalV1) { p.PriceNanotos = "0" },
		"leading zero":      func(p *nativev1.QuoteProposalV1) { p.PriceNanotos = "0300000000" },
		"price too large":   func(p *nativev1.QuoteProposalV1) { p.PriceNanotos = "1329227995784915872903807060280344576" },
		"zero storage fee":  func(p *nativev1.QuoteProposalV1) { p.StorageFeeNanotos = "0" },
		"upper terms hash":  func(p *nativev1.QuoteProposalV1) { p.TermsHash = strings.Repeat("AB", 32) },
		"zero terms hash":   func(p *nativev1.QuoteProposalV1) { p.TermsHash = strings.Repeat("00", 32) },
		"bad key id":        func(p *nativev1.QuoteProposalV1) { p.AttestorKeyId = "ed25519:" + strings.Repeat("99", 32) },
		"bad code hash":     func(p *nativev1.QuoteProposalV1) { p.ActorCodeHash = "sha256:" + strings.Repeat("88", 32) },
		"no expiry":         func(p *nativev1.QuoteProposalV1) { p.ExpiresAtUnixSeconds = 0 },
	} {
		proposal := testRailProposal()
		edit(proposal)
		if _, _, err := BuildAcceptedQuoteCommitment(network, proposal); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	root, _, err := BuildAcceptedQuoteCommitment(network, testRailProposal())
	if err != nil {
		t.Fatal(err)
	}
	other := testNetworkDomain()
	other.NetworkId = "tos-other"
	if _, err := DecodeAcceptedQuoteV1(root, other); err == nil {
		t.Error("a Quote for another network was accepted")
	}
	s := root.MustBeginParse()
	s.MustLoadUInt(48)
	refs := []*cell.Cell{s.MustLoadRef().MustToCell(), s.MustLoadRef().MustToCell(), s.MustLoadRef().MustToCell(), s.MustLoadRef().MustToCell()}
	rebuild := func(schema uint64, extra bool, replace int, with *cell.Cell) *cell.Cell {
		b := cell.BeginCell().MustStoreUInt(acceptedQuoteMagic, 32).MustStoreUInt(schema, 16)
		for i, ref := range refs {
			if i == replace {
				ref = with
			}
			b.MustStoreRef(ref)
		}
		if extra {
			b.MustStoreBoolBit(false)
		}
		return b.EndCell()
	}
	withTrailing := func(c *cell.Cell) *cell.Cell { return c.ToBuilder().MustStoreBoolBit(true).EndCell() }
	for name, mutated := range map[string]*cell.Cell{
		"schema 2":              rebuild(2, false, -1, nil),
		"root trailing":         rebuild(1, true, -1, nil),
		"identity trailing":     rebuild(1, false, 1, withTrailing(refs[1])),
		"rail trailing":         rebuild(1, false, 2, withTrailing(refs[2])),
		"authority trailing":    rebuild(1, false, 3, withTrailing(refs[3])),
		"rail missing terms":    rebuild(1, false, 2, cell.BeginCell().MustStoreSlice(refs[2].MustBeginParse().MustLoadSlice(555), 555).EndCell()),
		"rail anycast actor":    rebuild(1, false, 2, anycastRail(t, refs[2])),
		"rail terms extra coin": rebuild(1, false, 2, railWithTermsTrailing(refs[2])),
	} {
		if _, err := DecodeAcceptedQuoteV1(mutated, network); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func anycastRail(t *testing.T, rail *cell.Cell) *cell.Cell {
	s := rail.MustBeginParse()
	s.MustLoadUInt(3)
	rest := s.MustLoadSlice(s.BitsLeft())
	bits := uint(267 + 256 + 32 - 3)
	return cell.BeginCell().MustStoreUInt(2, 2).MustStoreBoolBit(true).MustStoreUInt(1, 5).MustStoreBoolBit(true).
		MustStoreSlice(rest, bits).MustStoreRef(rail.MustPeekRef(0)).EndCell()
}

func railWithTermsTrailing(rail *cell.Cell) *cell.Cell {
	s := rail.MustBeginParse()
	head := s.MustLoadSlice(555)
	terms := s.MustLoadRef().MustToCell().ToBuilder().MustStoreUInt(0, 4).EndCell()
	return cell.BeginCell().MustStoreSlice(head, 555).MustStoreRef(terms).EndCell()
}

func TestServiceRequestLayoutAndNonZeroFields(t *testing.T) {
	value := ServiceRequestV1{QuoteCommitment: hash32(1), ExecutionID: hash32(2), InputDigest: hash32(3)}
	root, err := BuildServiceRequestCellV1(value)
	if err != nil {
		t.Fatal(err)
	}
	s := root.MustBeginParse()
	if s.MustLoadUInt(32) != 0x4e535231 || s.MustLoadUInt(16) != 1 || s.BitsLeft() != 768 || s.RefsNum() != 0 {
		t.Fatal("service request is not NSR1 schema quote execution input")
	}
	if decoded, err := DecodeServiceRequestCellV1(root); err != nil || decoded != value {
		t.Fatalf("decode: %+v %v", decoded, err)
	}
	for name, mutated := range map[string]ServiceRequestV1{
		"zero quote":     {ExecutionID: hash32(2), InputDigest: hash32(3)},
		"zero execution": {QuoteCommitment: hash32(1), InputDigest: hash32(3)},
		"zero input":     {QuoteCommitment: hash32(1), ExecutionID: hash32(2)},
	} {
		if _, err := BuildServiceRequestCellV1(mutated); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := DecodeServiceRequestCellV1(root.ToBuilder().MustStoreBoolBit(false).EndCell()); err == nil {
		t.Error("service request with trailing data was accepted")
	}
}
