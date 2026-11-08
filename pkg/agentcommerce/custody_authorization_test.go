package agentcommerce

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCustodyActionAuthorizationV2BindsFullNetworkDomain(t *testing.T) {
	privateKey := newTestCustodyKey("custody-63")
	now := time.Unix(1_800_000_000, 0).UTC()
	domain := &CustodyNetworkDomain{NetworkID: "tos:testnet", GlobalID: 42,
		ZeroStateRootHash: "sha256:" + strings.Repeat("a", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: -1}
	body := CustodyActionAuthorization{SchemaVersion: 2, AuthorityID: "authority:owner", OwnerID: "owner:1", AgentID: "agent:buyer",
		SourceAccount: "-1:source", NetworkID: domain.NetworkID, NetworkGlobalID: domain.GlobalID, NetworkDomain: domain,
		StableActionID: "sha256:" + strings.Repeat("1", 64), ExactRequestDigest: "sha256:" + strings.Repeat("2", 64),
		WriterGeneration: 7, WriterFenceDigest: "sha256:" + strings.Repeat("3", 64), PolicyRevision: 4,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("5", 64), ObligationInstanceID: "sha256:" + strings.Repeat("6", 64),
		Destination: "0:destination", AmountAtomic: 50, ExpiresAtUnix: uint64(now.Unix() + 60)}
	signed, err := privateKey.signPayment(body)
	if err != nil {
		t.Fatal(err)
	}
	resolver := privateKey.pinnedFor("authority:owner", "owner:1", "agent:buyer")
	if err := VerifyRelayCustodyActionAuthorization(signed, resolver, now); err != nil {
		t.Fatal(err)
	}
	uppercaseProof := signed
	uppercaseProof.Proof = signed.Proof + "="
	if err := VerifyRelayCustodyActionAuthorization(uppercaseProof, resolver, now); err == nil {
		t.Fatal("custody authorization accepted a padded, non-canonical proof")
	}
	preimage, err := CustodyActionAuthorizationPreimage(signed)
	if err != nil {
		t.Fatal(err)
	}
	preimageDigest := sha256.Sum256(preimage)
	if got, want := hex.EncodeToString(preimageDigest[:]), "8b2d089f841741ea4157783d141107b49420b98bbe5cae5c0aa74591b14e0502"; got != want {
		t.Fatalf("custody action V2 cross-language preimage digest changed: got %s want %s", got, want)
	}
	v3 := body
	v3.SchemaVersion = 3
	v3.AgreementPaymentRequestDigest = "sha256:" + strings.Repeat("7", 64)
	signedV3, err := privateKey.signPayment(v3)
	if err != nil {
		t.Fatalf("schema-v3 payment-request binding was rejected: %v", err)
	}
	v3Preimage, err := CustodyActionAuthorizationPreimage(signedV3)
	if err != nil {
		t.Fatal(err)
	}
	v3PreimageDigest := sha256.Sum256(v3Preimage)
	if got, want := hex.EncodeToString(v3PreimageDigest[:]), "007e848255182c6b9129c98138275540a9551ac8d0d742e8544ee0d0c51af749"; got != want {
		t.Fatalf("custody action V3 cross-language preimage digest changed: got %s want %s", got, want)
	}
	if err := VerifyRelayCustodyActionAuthorization(signedV3, resolver, now); err != nil {
		t.Fatalf("schema-v3 relay custody proof was unverifiable: %v", err)
	}
	sponsorshipV3 := v3
	sponsorshipV3.SponsorshipFinalityProfileCBORDigest = "sha256:" + strings.Repeat("8", 64)
	sponsorshipV3.SponsorshipReleaseProfileDigest = "sha256:" + strings.Repeat("9", 64)
	sponsorshipV3.SponsorshipCorroborationSnapshotIdentity = "sha256:" + strings.Repeat("a", 64)
	signedSponsorshipV3, err := privateKey.signPayment(sponsorshipV3)
	if err != nil {
		t.Fatalf("schema-v3 sponsorship binding was rejected: %v", err)
	}
	sponsorshipPreimage, err := CustodyActionAuthorizationPreimage(signedSponsorshipV3)
	if err != nil {
		t.Fatal(err)
	}
	sponsorshipPreimageDigest := sha256.Sum256(sponsorshipPreimage)
	if got, want := hex.EncodeToString(sponsorshipPreimageDigest[:]), "bf8b0b09ec57d200f745e2f170abe10c8c3bc6fd3b78e442829d9ef105524ce2"; got != want {
		t.Fatalf("custody sponsorship V3 cross-language preimage digest changed: got %s want %s", got, want)
	}
	mutatedSponsorship := signedSponsorshipV3
	mutatedSponsorship.SponsorshipFinalityProfileCBORDigest = "sha256:" + strings.Repeat("b", 64)
	if err := VerifyRelayCustodyActionAuthorization(mutatedSponsorship, resolver, now); err == nil {
		t.Fatal("finality-profile mutation retained sponsorship custody authority")
	}
	partialSponsorship := v3
	partialSponsorship.SponsorshipFinalityProfileCBORDigest = "sha256:" + strings.Repeat("8", 64)
	if _, err := privateKey.signPayment(partialSponsorship); err == nil {
		t.Fatal("partial sponsorship custody binding was accepted")
	}
	mutatedPayment := signedV3
	mutatedPayment.AgreementPaymentRequestDigest = "sha256:" + strings.Repeat("8", 64)
	if err := VerifyRelayCustodyActionAuthorization(mutatedPayment, resolver, now); err == nil {
		t.Fatal("payment-request digest mutation retained custody authority")
	}
	missingPayment := body
	missingPayment.SchemaVersion = 3
	if _, err := privateKey.signPayment(missingPayment); err == nil {
		t.Fatal("schema-v3 custody authorization omitted its payment-request digest")
	}

	for name, mutate := range map[string]func(*CustodyActionAuthorization){
		"root": func(value *CustodyActionAuthorization) {
			copy := *value.NetworkDomain
			copy.ZeroStateRootHash = "sha256:" + strings.Repeat("c", 64)
			value.NetworkDomain = &copy
		},
		"file": func(value *CustodyActionAuthorization) {
			copy := *value.NetworkDomain
			copy.ZeroStateFileHash = "sha256:" + strings.Repeat("c", 64)
			value.NetworkDomain = &copy
		},
		"workchain": func(value *CustodyActionAuthorization) {
			copy := *value.NetworkDomain
			copy.WorkchainID++
			value.NetworkDomain = &copy
		},
		"global": func(value *CustodyActionAuthorization) {
			copy := *value.NetworkDomain
			copy.GlobalID++
			value.NetworkDomain = &copy
			value.NetworkGlobalID++
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := signed
			mutate(&mutated)
			if err := VerifyRelayCustodyActionAuthorization(mutated, resolver, now); err == nil {
				t.Fatal("network-domain mutation retained relay custody authority")
			}
		})
	}

	legacy := signed
	legacy.SchemaVersion = 1
	legacy.NetworkDomain = nil
	legacy, err = privateKey.signPayment(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyActionAuthorization(legacy, resolver, now); err != nil {
		t.Fatalf("explicit legacy/non-relay authorization stopped decoding: %v", err)
	}
	if err := VerifyRelayCustodyActionAuthorization(legacy, resolver, now); err == nil {
		t.Fatal("legacy custody authorization crossed the production relay boundary")
	}

	zeroGlobal := body
	zeroDomain := *body.NetworkDomain
	zeroDomain.GlobalID = 0
	zeroGlobal.NetworkGlobalID = 0
	zeroGlobal.NetworkDomain = &zeroDomain
	if _, err := privateKey.signPayment(zeroGlobal); err == nil {
		t.Fatal("zero global ID entered a domain-bound custody authorization")
	}
}

func TestCustodyAuthorizationBindsWriterAgreementAndTransfer(t *testing.T) {
	privateKey := newTestCustodyKey("custody-63")
	now := time.Unix(1_800_000_000, 0)
	body := CustodyActionAuthorization{SchemaVersion: 1, AuthorityID: "authority:owner", OwnerID: "owner:1", AgentID: "agent:buyer",
		SourceAccount: "-1:source", NetworkID: "tos:testnet", NetworkGlobalID: 42,
		StableActionID: "sha256:" + strings.Repeat("1", 64), ExactRequestDigest: "sha256:" + strings.Repeat("2", 64),
		WriterGeneration: 7, WriterFenceDigest: "sha256:" + strings.Repeat("3", 64), PolicyRevision: 4,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("5", 64), ObligationInstanceID: "sha256:" + strings.Repeat("6", 64),
		Destination: "0:destination", AmountAtomic: 50, ExpiresAtUnix: uint64(now.Unix() + 60)}
	signed, err := privateKey.signPayment(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyActionAuthorization(signed, privateKey.pinnedFor("authority:owner", "owner:1", "agent:buyer"), now); err != nil {
		t.Fatal(err)
	}
	mutated := signed
	mutated.AmountAtomic++
	if err := VerifyCustodyActionAuthorization(mutated, privateKey.pinnedFor("authority:owner", "owner:1", "agent:buyer"), now); err == nil {
		t.Fatal("changed transfer retained custody authorization")
	}
	mutated = signed
	mutated.WriterGeneration++
	if err := VerifyCustodyActionAuthorization(mutated, privateKey.pinnedFor("authority:owner", "owner:1", "agent:buyer"), now); err == nil {
		t.Fatal("changed writer generation retained custody authorization")
	}
}
