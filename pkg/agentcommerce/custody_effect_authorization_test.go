package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

type custodyEffectResolver struct{ key ed25519.PublicKey }

func (resolver custodyEffectResolver) AuthorizeCustodyKey(_, _, _ string, key ed25519.PublicKey, _ time.Time) error {
	if !resolver.key.Equal(key) {
		return errors.New("wrong custody key")
	}
	return nil
}

func TestCustodyEffectAuthorizationV2BindsFullNetworkDomain(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	domain := &CustodyNetworkDomain{NetworkID: "tos:test", GlobalID: -3,
		ZeroStateRootHash: "sha256:" + strings.Repeat("a", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: 0}
	value := CustodyEffectAuthorization{SchemaVersion: 2, AuthorityID: "authority:one", OwnerID: "owner:one", AgentID: "agent:buyer",
		SourceAccount: "0:" + strings.Repeat("1", 64), NetworkID: domain.NetworkID, NetworkGlobalID: domain.GlobalID,
		NetworkDomain: domain, ActionKind: "escrow.accept", StableActionID: "sha256:" + strings.Repeat("2", 64),
		ExactRequestDigest: "sha256:" + strings.Repeat("3", 64), WriterGeneration: 4,
		WriterFenceDigest: "sha256:" + strings.Repeat("4", 64), PolicyRevision: 5,
		MandateDigest: "sha256:" + strings.Repeat("5", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("6", 64), ObligationID: "payment:one",
		Destination: "0:" + strings.Repeat("7", 64), AmountNanoTOS: 100_000_000,
		BodyHash: "tvm-cell-sha256:" + strings.Repeat("8", 64), StateInitHashOrZero: custodyNoStateInit,
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())}
	signed, err := SignCustodyEffectAuthorization(value, key)
	if err != nil {
		t.Fatal(err)
	}
	resolver := custodyEffectResolver{key: key.Public().(ed25519.PublicKey)}
	if err := VerifyRelayCustodyEffectAuthorization(signed, resolver, now); err != nil {
		t.Fatal(err)
	}
	preimage, err := CustodyEffectAuthorizationPreimage(signed)
	if err != nil {
		t.Fatal(err)
	}
	preimageDigest := sha256.Sum256(preimage)
	if got, want := hex.EncodeToString(preimageDigest[:]), "fe281488a120f3a60e0d7584f5f9a286071df82e7a477acd990d067fc3f8ca47"; got != want {
		t.Fatalf("custody effect V2 cross-language preimage digest changed: got %s want %s", got, want)
	}

	changed := signed
	changedDomain := *changed.NetworkDomain
	changedDomain.WorkchainID = -1
	changed.NetworkDomain = &changedDomain
	if err := VerifyRelayCustodyEffectAuthorization(changed, resolver, now); err == nil {
		t.Fatal("target-workchain mutation retained custody effect authority")
	}
	legacy := signed
	legacy.SchemaVersion = 1
	legacy.NetworkDomain = nil
	legacy, err = SignCustodyEffectAuthorization(legacy, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayCustodyEffectAuthorization(legacy, resolver, now); err == nil {
		t.Fatal("legacy custody effect crossed the production relay boundary")
	}
}

func TestCustodyEffectAuthorizationBindsExactTVMEffect(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	value := CustodyEffectAuthorization{SchemaVersion: 1, AuthorityID: "authority:one", OwnerID: "owner:one", AgentID: "agent:buyer",
		SourceAccount: "0:" + strings.Repeat("1", 64), NetworkID: "tos:test", NetworkGlobalID: -3,
		ActionKind: "payment.direct", StableActionID: "sha256:" + strings.Repeat("2", 64), ExactRequestDigest: "sha256:" + strings.Repeat("3", 64),
		WriterGeneration: 4, WriterFenceDigest: "sha256:" + strings.Repeat("4", 64), PolicyRevision: 5,
		MandateDigest: "sha256:" + strings.Repeat("5", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("6", 64), ObligationID: "payment:one",
		Destination: "0:" + strings.Repeat("7", 64), AmountNanoTOS: 100_000_000,
		BodyHash: "tvm-cell-sha256:" + strings.Repeat("8", 64), StateInitHashOrZero: custodyNoStateInit,
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())}
	signed, err := SignCustodyEffectAuthorization(value, key)
	if err != nil {
		t.Fatal(err)
	}
	resolver := custodyEffectResolver{key: key.Public().(ed25519.PublicKey)}
	if err := VerifyCustodyEffectAuthorization(signed, resolver, now); err != nil {
		t.Fatal(err)
	}
	changed := signed
	changed.BodyHash = "tvm-cell-sha256:" + strings.Repeat("9", 64)
	if err := VerifyCustodyEffectAuthorization(changed, resolver, now); err == nil {
		t.Fatal("changed effect body retained custody authority")
	}
}
