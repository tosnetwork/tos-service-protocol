package quoteexchange

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

func validPackage(t *testing.T) (*nativev1.NetworkDomain, *nativev1.RequestQuoteProposalRequest, *nativev1.QuoteProposalPackageV1, time.Time) {
	t.Helper()
	settlement := servicefixture.DefaultSettlement()
	manifest := servicefixture.Manifest("1.0.0", settlement)
	manifestCBOR, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(nativecore.TransportBindingV1{
		SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-proposal-1",
		CapabilityId: "cap_" + strings.Repeat("44", 32), CapabilityVersion: manifest.Version,
		ProviderAgentId: "agent_" + strings.Repeat("55", 32), ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: uint64(now.Add(30 * time.Minute).Unix()),
		Actor:         &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: settlement.ActorAccount},
		ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(settlement.ActorCodeHash), PolicyVersion: 2,
		TermsHash: strings.Repeat("ab", 32), PriceNanotos: "300000000", StorageFeeNanotos: "200000000",
		AttestorKeyId: settlement.AttestorKey}
	request := &nativev1.RequestQuoteProposalRequest{CapabilityId: proposal.CapabilityId,
		CapabilityVersion: proposal.CapabilityVersion, BuyerAddress: "0:" + strings.Repeat("11", 32)}
	value := &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR,
		TransportBindingBoc: transport.ToBOC()}
	return servicefixture.Network(), request, value, now
}

func TestValidateCompleteQuoteProposalPackage(t *testing.T) {
	network, request, value, now := validPackage(t)
	validated, err := Validate(network, request, value, now)
	if err != nil || validated.TransportBinding.BaseURL != "https://provider.example" ||
		validated.Rail.Actor != "0:"+strings.Repeat("77", 32) || validated.Rail.Price.Int64() != 300000000 {
		t.Fatalf("validated=%+v err=%v", validated, err)
	}
}

func TestValidateRejectsEveryConflictingPreimage(t *testing.T) {
	mutations := map[string]func(*nativev1.QuoteProposalPackageV1){
		"manifest byte":    func(v *nativev1.QuoteProposalPackageV1) { v.CanonicalManifestCbor[0] ^= 1 },
		"transport byte":   func(v *nativev1.QuoteProposalPackageV1) { v.TransportBindingBoc[0] ^= 1 },
		"actor not key 21": func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.Actor.AccountId = bytes.Repeat([]byte{0x78}, 32) },
		"code not key 21": func(v *nativev1.QuoteProposalPackageV1) {
			v.Proposal.ActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("89", 32)
		},
		"attestor not key 21": func(v *nativev1.QuoteProposalPackageV1) {
			v.Proposal.AttestorKeyId = "mldsa44:" + strings.Repeat("98", 32)
		},
		"masterchain actor": func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.Actor.Workchain = -1 },
		"zero price":        func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.PriceNanotos = "0" },
		"manifest digest": func(v *nativev1.QuoteProposalPackageV1) {
			v.Proposal.ManifestDigest = "sha256:" + strings.Repeat("01", 32)
		},
		"version": func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.CapabilityVersion = "1.0.1" },
	}
	for name, mutate := range mutations {
		network, request, value, now := validPackage(t)
		mutate(value)
		if name == "version" {
			request.CapabilityVersion = "1.0.1"
		}
		if _, err := Validate(network, request, value, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestValidateRejectsExpiredProposal(t *testing.T) {
	network, request, value, now := validPackage(t)
	if _, err := Validate(network, request, value, now.Add(time.Hour)); err == nil {
		t.Fatal("expired proposal accepted")
	}
}

func withAgentPacketTransport(t *testing.T, value *nativev1.QuoteProposalPackageV1, recipient string) {
	t.Helper()
	binding, err := nativecore.AgentPacketTransportBinding(recipient, nativecore.MaxAgentPacketTransportRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	root, digest, err := nativecore.BuildTransportBindingCellV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	value.TransportBindingBoc, value.Proposal.TransportBindingDigest = root.ToBOC(), digest
}

func TestValidateAcceptsAgentPacketTransportToTheProvider(t *testing.T) {
	network, request, value, now := validPackage(t)
	withAgentPacketTransport(t, value, value.Proposal.ProviderAgentId)
	validated, err := Validate(network, request, value, now)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := validated.TransportBinding.AgentPacketRecipient()
	if err != nil || recipient != value.Proposal.ProviderAgentId ||
		validated.TransportBinding.MaxRequestBytes != nativecore.MaxAgentPacketTransportRequestBytes {
		t.Fatalf("binding=%+v recipient=%q err=%v", validated.TransportBinding, recipient, err)
	}
}

func TestValidateRefusesAgentPacketTransportToAnotherAgent(t *testing.T) {
	network, request, value, now := validPackage(t)
	withAgentPacketTransport(t, value, "agent_"+strings.Repeat("56", 32))
	if _, err := Validate(network, request, value, now); err == nil {
		t.Fatal("accepted an Agent Packet transport to another Agent")
	}
	if _, err := ValidatePortable(network, request, value); err == nil || !strings.Contains(err.Error(), "another Agent") {
		t.Fatalf("portable validation of an Agent Packet transport to another Agent: %v", err)
	}
}
