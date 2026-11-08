package agentcommerce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

const custodyE2EAuthority, custodyE2EOwner, custodyE2EAgent = "authority:custody-e2e", "owner:e2e", "agent:e2e"

func custodyE2EDomain() CustodyNetworkDomain {
	return CustodyNetworkDomain{NetworkID: "tos:local", GlobalID: 42,
		ZeroStateRootHash: "sha256:" + strings.Repeat("a", 64),
		ZeroStateFileHash: "sha256:" + strings.Repeat("b", 64), WorkchainID: 0}
}

// The three custody objects the custody host admits, for one owner and Agent
// on one network.
func custodyE2EObjects() (CustodyActionAuthorization, CustodyEffectAuthorization, PredictionCustodyEffectAuthorizationV1) {
	domain := custodyE2EDomain()
	source := "0:" + strings.Repeat("1", 64)
	payment := CustodyActionAuthorization{SchemaVersion: 3, AuthorityID: custodyE2EAuthority, OwnerID: custodyE2EOwner,
		AgentID: custodyE2EAgent, SourceAccount: source, NetworkID: domain.NetworkID, NetworkGlobalID: domain.GlobalID,
		NetworkDomain: &domain, StableActionID: "sha256:" + strings.Repeat("1", 64),
		ExactRequestDigest: "sha256:" + strings.Repeat("2", 64), AgreementPaymentRequestDigest: "sha256:" + strings.Repeat("7", 64),
		WriterGeneration: 7, WriterFenceDigest: "sha256:" + strings.Repeat("3", 64), PolicyRevision: 4,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("5", 64), ObligationInstanceID: "sha256:" + strings.Repeat("6", 64),
		Destination: "0:" + strings.Repeat("7", 64), AmountAtomic: 50, ExpiresAtUnix: 2_000_000_100}
	effect := CustodyEffectAuthorization{SchemaVersion: 2, AuthorityID: custodyE2EAuthority, OwnerID: custodyE2EOwner,
		AgentID: custodyE2EAgent, SourceAccount: source, NetworkID: domain.NetworkID, NetworkGlobalID: domain.GlobalID,
		NetworkDomain: &domain, ActionKind: "escrow.accept", StableActionID: "sha256:" + strings.Repeat("2", 64),
		ExactRequestDigest: "sha256:" + strings.Repeat("3", 64), WriterGeneration: 7,
		WriterFenceDigest: "sha256:" + strings.Repeat("3", 64), PolicyRevision: 4,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("6", 64), ObligationID: "payment:one",
		Destination: "0:" + strings.Repeat("8", 64), AmountNanoTOS: 100_000_000,
		BodyHash: "tvm-cell-sha256:" + strings.Repeat("8", 64), StateInitHashOrZero: custodyNoStateInit,
		ExpiresAtUnix: 2_000_000_100}
	prediction := PredictionCustodyEffectAuthorizationV1{SchemaVersion: 1, Profile: PredictionCustodyEffectProfileV1,
		AuthorityID: custodyE2EAuthority, OwnerID: custodyE2EOwner, AgentID: custodyE2EAgent, SourceAccount: source,
		SourceAgentAccountCodeHash: "tvm-cell-sha256:" + strings.Repeat("2", 64), NetworkDomain: domain,
		ActionKind: "prediction.match.submit", EffectKind: "prediction.match.submit",
		StableActionID: "sha256:" + strings.Repeat("5", 64), ExactRequestDigest: "sha256:" + strings.Repeat("6", 64),
		WriterGeneration: 7, WriterFenceDigest: "sha256:" + strings.Repeat("3", 64), PolicyRevision: 4,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		MarketID: "sha256:" + strings.Repeat("9", 64), MarketAddress: "0:" + strings.Repeat("a", 64),
		Destination: "0:" + strings.Repeat("a", 64), MarketConfigHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
		MarketCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64), AmountNanoTOS: 900_000_000,
		BodyHash: "tvm-cell-sha256:" + strings.Repeat("d", 64), ExpiresAtUnix: 2_000_000_100}
	return payment, effect, prediction
}

// wrongKeyResolver returns a key regardless of the key ID asked for.
type wrongKeyResolver struct {
	mldsa44.Verifier
	key []byte
}

func (r wrongKeyResolver) ResolveCustodyAuthorizationKey(_, _, _ string, _ [mldsa44.KeyIDSize]byte, _ time.Time) ([]byte, error) {
	return append([]byte(nil), r.key...), nil
}

// The three custody authorizations are signed through a real tosctl vault
// controller under TOS-CUSTODY-AUTHORIZATION-V1 and verified through the
// pinned helper; every Ed25519, foreign-context, non-canonical, mismatched-key
// and unpinned variant is refused. With CUSTODY_AUTHORIZATION_GO_SIGNED_OUT
// set, the signed objects and the controller's public key are written for the
// custody host's cross-implementation admission test.
func TestCustodyAuthorizationsSignedThroughCustodyVerifyAndRefuse(t *testing.T) {
	custody := mldsa44test.NewCustody(t, "custody", "action")
	helper := mldsa44test.RequireTosctl(t)
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	payment, effect, prediction := custodyE2EObjects()
	signedPayment, err := SignCustodyActionAuthorization(ctx, payment, custody.Signer, "custody")
	if err != nil {
		t.Fatal(err)
	}
	signedEffect, err := SignCustodyEffectAuthorization(ctx, effect, custody.Signer, "custody")
	if err != nil {
		t.Fatal(err)
	}
	signedPrediction, err := SignPredictionCustodyEffectAuthorizationV1(ctx, prediction, custody.Signer, "custody")
	if err != nil {
		t.Fatal(err)
	}
	keyID := custody.KeyID(t, "custody")
	if signedPayment.KeyID != keyID || signedEffect.KeyID != keyID || signedPrediction.KeyID != keyID ||
		!strings.HasPrefix(signedPayment.Proof, "mldsa44:") || len(signedPayment.Proof) != 3235 {
		t.Fatalf("custody authorization does not carry the controller key ID and proof forms: %q", signedPayment.KeyID)
	}
	signed, err := custody.Signer.Sign(ctx, "custody", mldsa44.UseCustodyAuthorization, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signed.PublicKey
	resolver := mldsa44test.CustodyAuthorizationResolver{Verifier: helper, Keys: map[mldsa44test.CustodyPrincipal][]byte{
		{AuthorityID: custodyE2EAuthority, OwnerID: custodyE2EOwner, AgentID: custodyE2EAgent}: publicKey}}
	if err := VerifyRelayCustodyActionAuthorization(signedPayment, resolver, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayCustodyEffectAuthorization(signedEffect, resolver, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPredictionCustodyEffectAuthorizationV1(signedPrediction, resolver, now); err != nil {
		t.Fatal(err)
	}

	// Ed25519 key IDs and proofs are refused with the diagnostic.
	ed25519Key := signedPayment
	ed25519Key.KeyID = "ed25519:" + strings.Repeat("ab", 32)
	if err := VerifyRelayCustodyActionAuthorization(ed25519Key, resolver, now); !errors.Is(err, ErrEd25519CustodyAuthorization) {
		t.Fatalf("Ed25519 custody key ID was not refused as Ed25519: %v", err)
	}
	ed25519Proof := signedPayment
	ed25519Proof.Proof = "ed25519:" + strings.Repeat("cd", 64)
	if err := VerifyRelayCustodyActionAuthorization(ed25519Proof, resolver, now); !errors.Is(err, ErrEd25519CustodyAuthorization) {
		t.Fatalf("Ed25519 custody proof was not refused as Ed25519: %v", err)
	}
	// Non-canonical key ID and proof text.
	for _, keyIDText := range []string{strings.ToUpper(keyID), "MLDSA44:" + strings.TrimPrefix(keyID, "mldsa44:"),
		keyID[:len(keyID)-2], "mldsa44:" + strings.Repeat("0", 64)} {
		changed := signedPayment
		changed.KeyID = keyIDText
		if err := VerifyRelayCustodyActionAuthorization(changed, resolver, now); err == nil {
			t.Fatalf("non-canonical key ID %q was accepted", keyIDText)
		}
	}
	for _, proof := range []string{signedPayment.Proof + "=", signedPayment.Proof[:len(signedPayment.Proof)-4],
		strings.ReplaceAll(strings.ReplaceAll(signedPayment.Proof, "-", "+"), "_", "/") + "+"} {
		changed := signedPayment
		changed.Proof = proof
		if err := VerifyRelayCustodyActionAuthorization(changed, resolver, now); err == nil {
			t.Fatal("non-canonical proof was accepted")
		}
	}
	// A resolved key that does not derive the carried key ID is refused.
	otherKey := custody.KeyID(t, "action")
	actionSigned, err := custody.Signer.Sign(ctx, "action", mldsa44.UseActionAuthority, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayCustodyActionAuthorization(signedPayment, wrongKeyResolver{Verifier: helper, key: actionSigned.PublicKey}, now); err == nil ||
		!strings.Contains(err.Error(), "does not derive its key ID") {
		t.Fatalf("a resolved key of another ID was accepted: %v", err)
	}
	// An unpinned principal, or the other key named by the authorization, is refused.
	foreign := signedPayment
	foreign.AgentID = "agent:other"
	if err := VerifyRelayCustodyActionAuthorization(foreign, resolver, now); err == nil {
		t.Fatal("an unpinned principal was accepted")
	}
	renamed := signedPayment
	renamed.KeyID = otherKey
	if err := VerifyRelayCustodyActionAuthorization(renamed, resolver, now); err == nil {
		t.Fatal("an authorization naming an unpinned key was accepted")
	}
	// The same controller's Action Authority signature over the custody digest
	// is refused here, and the custody proof is refused as Action Authority.
	preimage, err := CustodyActionAuthorizationPreimage(signedPayment)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(preimage)
	swappedSignature, err := custody.Signer.Sign(ctx, "custody", mldsa44.UseActionAuthority, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	swapped := signedPayment
	if swapped.Proof, err = mldsa44.SignatureText(swappedSignature.Signature); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayCustodyActionAuthorization(swapped, resolver, now); !errors.Is(err, mldsa44.ErrInvalidSignature) {
		t.Fatalf("an Action Authority signature verified as a custody authorization: %v", err)
	}
	both := mldsa44test.ActionAuthorityResolver{Verifier: helper, Keys: map[string][][]byte{custodyE2EAuthority: {publicKey}}}
	if err := VerifyActionAuthoritySignature(both, custodyE2EAuthority, signedPayment.KeyID, signedPayment.Proof, digest[:], now); !errors.Is(err, mldsa44.ErrInvalidSignature) {
		t.Fatalf("a custody proof verified as an Action Authority signature: %v", err)
	}
	// The removed field name is refused by the strict Prediction decoder.
	raw, err := json.Marshal(signedPrediction)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePredictionCustodyEffectAuthorizationV1JSON(raw); err != nil {
		t.Fatalf("signed prediction custody JSON was refused: %v", err)
	}
	legacy := strings.Replace(string(raw), `"key_id":`, `"public_key":`, 1)
	if _, err := DecodePredictionCustodyEffectAuthorizationV1JSON([]byte(legacy)); err == nil {
		t.Fatal("a prediction custody effect with public_key was decoded")
	}

	if out := os.Getenv("CUSTODY_AUTHORIZATION_GO_SIGNED_OUT"); out != "" {
		fixture := map[string]any{
			"schema":         "tos.custody-authorization-go-signed.v1",
			"authority_id":   custodyE2EAuthority,
			"public_key_hex": hex.EncodeToString(publicKey),
			"key_id":         keyID,
			"payment":        signedPayment,
			"effect":         signedEffect,
			"prediction":     signedPrediction,
		}
		encoded, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// The deterministic custody authorization vector produced by tosctl verifies
// through the pinned helper: every message under the custody context, and no
// refusal entry as a custody authorization.
func TestCustodyAuthorizationVectorVerifiesThroughTheHelper(t *testing.T) {
	helper := mldsa44test.RequireTosctl(t)
	raw, err := os.ReadFile("testdata/custody-authorization-signature-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Schema       string `json:"schema"`
		Context      string `json:"context"`
		PublicKeyHex string `json:"public_key_hex"`
		KeyID        string `json:"key_id"`
		Messages     []struct {
			Name        string `json:"name"`
			PreimageHex string `json:"preimage_hex"`
			MessageHex  string `json:"message_hex"`
			Proof       string `json:"proof"`
		} `json:"messages"`
		Refusals []struct {
			Name         string `json:"name"`
			MessageHex   string `json:"message_hex"`
			SignatureHex string `json:"signature_hex"`
		} `json:"refusals"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if context, _ := mldsa44.UseCustodyAuthorization.Context(); vector.Schema != "tos.custody-authorization-signature-vector.v1" ||
		vector.Context != context || len(vector.Messages) != 5 || len(vector.Refusals) != 9 {
		t.Fatalf("unexpected custody vector shape: %s %s %d %d", vector.Schema, vector.Context, len(vector.Messages), len(vector.Refusals))
	}
	publicKey, err := hex.DecodeString(vector.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	id, err := mldsa44.KeyID(publicKey)
	if err != nil || mldsa44.KeyIDText(id) != vector.KeyID {
		t.Fatal("vector key ID does not derive from its key")
	}
	resolver := wrongKeyResolver{Verifier: helper, key: publicKey}
	for _, message := range vector.Messages {
		preimage, err := hex.DecodeString(message.PreimageHex)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(preimage)
		if hex.EncodeToString(digest[:]) != message.MessageHex {
			t.Fatalf("%s: message is not the SHA-256 of its preimage", message.Name)
		}
		if err := verifyCustodyDigest(resolver, "", "", "", vector.KeyID, message.Proof, digest, time.Now()); err != nil {
			t.Fatalf("%s: %v", message.Name, err)
		}
	}
	for _, refusal := range vector.Refusals {
		message, err := hex.DecodeString(refusal.MessageHex)
		if err != nil || len(message) != 32 {
			t.Fatalf("%s: bad message", refusal.Name)
		}
		signature, err := hex.DecodeString(refusal.SignatureHex)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := mldsa44.SignatureText(signature)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyCustodyDigest(resolver, "", "", "", vector.KeyID, proof, [32]byte(message), time.Now()); err == nil {
			t.Fatalf("%s verified as a custody authorization", refusal.Name)
		}
	}
}
