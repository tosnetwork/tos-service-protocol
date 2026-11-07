package nativecore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// The production builders and the independent reference encoder (its own bit
// writer and cell hasher) must agree on every rail cell. This is agreement
// between two Go encoders written from the same TL-B; it is not a
// contract-generated vector.

func derived(seed string, index int) []byte {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(index))
	sum := sha256.Sum256(append([]byte(seed), counter[:]...))
	return sum[:]
}

func derivedCoins(seed string, index int, bits int) *big.Int {
	value := new(big.Int).SetBytes(derived(seed, index))
	value.Rsh(value, uint(256-bits))
	if value.Sign() == 0 {
		value.SetInt64(1)
	}
	return value
}

func TestRailCellsAgreeWithTheIndependentEncoder(t *testing.T) {
	network := testNetworkDomain()
	refNetwork := referencecodec.Network{NetworkID: network.NetworkId, GenesisRootHash: network.GenesisRootHash,
		GenesisFileHash: network.GenesisFileHash}
	for i := 0; i < 64; i++ {
		seed := fmt.Sprintf("rail-%d", i)
		var keyID [32]byte
		copy(keyID[:], derived(seed, 1))
		version := fmt.Sprintf("v%d.%s", i, hex.EncodeToString(derived(seed, 2))[:i%60+1])
		if i%7 == 0 {
			// 127 and 128 bytes cross the one-cell snake boundary.
			version = ("v" + hex.EncodeToString(derived(seed, 3)) + hex.EncodeToString(derived(seed, 4)))[:127+i%2]
		}
		priceBits, feeBits := 1+(i*7)%119, 1+(i*13)%119
		proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + hex.EncodeToString(derived(seed, 5)),
			CapabilityVersion: version, ProviderAgentId: "agent_" + hex.EncodeToString(derived(seed, 6)),
			ManifestDigest: "sha256:" + hex.EncodeToString(derived(seed, 7)), TransportBindingDigest: "sha256:" + hex.EncodeToString(derived(seed, 8)),
			ExpiresAtUnixSeconds: binary.BigEndian.Uint64(derived(seed, 9)) | 1,
			Actor:                &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: derived(seed, 10)},
			ActorCodeHash:        "tvm-cell-sha256:" + hex.EncodeToString(derived(seed, 11)),
			PolicyVersion:        binary.BigEndian.Uint32(derived(seed, 12)), TermsHash: hex.EncodeToString(derived(seed, 13)),
			PriceNanotos: derivedCoins(seed, 14, priceBits).String(), StorageFeeNanotos: derivedCoins(seed, 15, feeBits).String(),
			AttestorKeyId: mldsa44.KeyIDText(keyID)}
		_, production, err := BuildAcceptedQuoteCommitment(network, proposal)
		if err != nil {
			t.Fatalf("%s: %v", seed, err)
		}
		reference, err := referencecodec.ComputeRailAcceptedQuote(refNetwork, referencecodec.RailQuote{
			CapabilityID: proposal.CapabilityId, CapabilityVersion: proposal.CapabilityVersion, ProviderAgentID: proposal.ProviderAgentId,
			ManifestDigest: proposal.ManifestDigest, TransportBindingDigest: proposal.TransportBindingDigest,
			ExpiresAtUnixSeconds: proposal.ExpiresAtUnixSeconds, ActorAccountHex: hex.EncodeToString(proposal.Actor.AccountId),
			ActorCodeHash: proposal.ActorCodeHash, PolicyVersion: proposal.PolicyVersion, TermsHashHex: proposal.TermsHash,
			PriceNanoTOS: proposal.PriceNanotos, StorageFeeNanoTOS: proposal.StorageFeeNanotos, AttestorKeyID: proposal.AttestorKeyId})
		if err != nil || reference != production {
			t.Fatalf("%s: Accepted Quote production %s, reference %s (%v)", seed, production, reference, err)
		}

		var quote, execution, input [32]byte
		copy(quote[:], derived(seed, 16))
		copy(execution[:], derived(seed, 17))
		copy(input[:], derived(seed, 18))
		request, err := BuildServiceRequestCellV1(ServiceRequestV1{QuoteCommitment: quote, ExecutionID: execution, InputDigest: input})
		if err != nil {
			t.Fatal(err)
		}
		referenceRequest, err := referencecodec.ComputeServiceRequest(hex.EncodeToString(quote[:]), hex.EncodeToString(execution[:]), hex.EncodeToString(input[:]))
		if err != nil || referenceRequest != hex.EncodeToString(request.Hash()) {
			t.Fatalf("%s: NSR1 differs (%v)", seed, err)
		}

		terms := ServiceActorTermsV1{PolicyVersion: proposal.PolicyVersion, PricePerCall: derivedCoins(seed, 19, priceBits),
			StorageFee: derivedCoins(seed, 20, feeBits), CleanupBounty: derivedCoins(seed, 21, 1+(i*3)%119),
			ResponseSLA: binary.BigEndian.Uint32(derived(seed, 22)), RefundClaimWindow: binary.BigEndian.Uint32(derived(seed, 23)),
			HasAttestor: i%2 == 0, AttestorKeyID: keyID}
		copy(terms.MetadataHash[:], derived(seed, 24))
		copy(terms.ProofSchemeHash[:], derived(seed, 25))
		termsHash, err := ServiceActorTermsHash(terms)
		if err != nil {
			t.Fatal(err)
		}
		referenceTerms, err := referencecodec.ComputeTermsHash(referencecodec.RailTerms{PolicyVersion: terms.PolicyVersion,
			PricePerCall: terms.PricePerCall, StorageFee: terms.StorageFee, CleanupBounty: terms.CleanupBounty,
			ResponseSLA: terms.ResponseSLA, RefundClaimWindow: terms.RefundClaimWindow,
			MetadataHashHex: hex.EncodeToString(terms.MetadataHash[:]), ProofSchemeHex: hex.EncodeToString(terms.ProofSchemeHash[:]),
			HasAttestor: terms.HasAttestor, AttestorKeyIDHex: hex.EncodeToString(keyID[:])})
		if err != nil || referenceTerms != hex.EncodeToString(termsHash[:]) {
			t.Fatalf("%s: terms hash differs (%v)", seed, err)
		}

		metadata, err := ServiceActorMetadataHash(ServiceActorMetadataInputV1{Network: network, CapabilityID: proposal.CapabilityId,
			ProviderAgentID: proposal.ProviderAgentId, CapabilityVersion: version, ManifestDigest: proposal.ManifestDigest})
		if err != nil {
			t.Fatal(err)
		}
		referenceMetadata, err := referencecodec.ComputeMetadataHash(refNetwork, proposal.CapabilityId, proposal.ProviderAgentId,
			version, proposal.ManifestDigest)
		if err != nil || referenceMetadata != hex.EncodeToString(metadata[:]) {
			t.Fatalf("%s: NSM1 differs (%v)", seed, err)
		}
	}
}
