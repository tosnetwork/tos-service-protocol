package agentcommerce

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testPredictionCustodyEffect(now time.Time) PredictionCustodyEffectAuthorizationV1 {
	return PredictionCustodyEffectAuthorizationV1{
		SchemaVersion: 1, Profile: PredictionCustodyEffectProfileV1,
		AuthorityID: "authority:one", OwnerID: "owner:one", AgentID: "agent:solver",
		SourceAccount:              "0:" + strings.Repeat("1", 64),
		SourceAgentAccountCodeHash: "tvm-cell-sha256:" + strings.Repeat("2", 64),
		NetworkDomain: CustodyNetworkDomain{
			NetworkID: "tos:test", GlobalID: -3,
			ZeroStateRootHash: "sha256:" + strings.Repeat("3", 64),
			ZeroStateFileHash: "sha256:" + strings.Repeat("4", 64), WorkchainID: 0,
		},
		ActionKind: "prediction.match.submit", EffectKind: "prediction.match.submit",
		StableActionID:     "sha256:" + strings.Repeat("5", 64),
		ExactRequestDigest: "sha256:" + strings.Repeat("6", 64), WriterGeneration: 7,
		WriterFenceDigest: "sha256:" + strings.Repeat("7", 64), PolicyRevision: 8,
		MandateDigest:        "sha256:" + strings.Repeat("8", 64),
		ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		MarketID:             "sha256:" + strings.Repeat("9", 64),
		MarketAddress:        "0:" + strings.Repeat("a", 64),
		Destination:          "0:" + strings.Repeat("a", 64),
		MarketConfigHash:     "tvm-cell-sha256:" + strings.Repeat("b", 64),
		MarketCodeHash:       "tvm-cell-sha256:" + strings.Repeat("c", 64),
		AmountNanoTOS:        900_000_000, BodyHash: "tvm-cell-sha256:" + strings.Repeat("d", 64),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()),
	}
}

func TestPredictionCustodyEffectAuthorizationBindsClosedExactEffect(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key := newTestCustodyKey("custody-75")
	value := testPredictionCustodyEffect(now)
	signed, err := key.signPrediction(value)
	if err != nil {
		t.Fatal(err)
	}
	resolver := key.pinnedForAny()
	if err := VerifyPredictionCustodyEffectAuthorizationV1(signed, resolver, now); err != nil {
		t.Fatal(err)
	}
	preimage, err := PredictionCustodyEffectAuthorizationPreimageV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(preimage)
	if got, want := hex.EncodeToString(digest[:]), "e33e7e0d50a63acc05a0396c17ab5359a451a62b689cdf3a288e467f61978346"; got != want {
		t.Fatalf("prediction custody V1 preimage digest changed: got %s want %s", got, want)
	}

	mutations := map[string]func(*PredictionCustodyEffectAuthorizationV1){
		"effect kind": func(candidate *PredictionCustodyEffectAuthorizationV1) {
			candidate.EffectKind = "prediction.position.split"
		},
		"source code": func(candidate *PredictionCustodyEffectAuthorizationV1) {
			candidate.SourceAgentAccountCodeHash = "tvm-cell-sha256:" + strings.Repeat("e", 64)
		},
		"market code": func(candidate *PredictionCustodyEffectAuthorizationV1) {
			candidate.MarketCodeHash = "tvm-cell-sha256:" + strings.Repeat("e", 64)
		},
		"body": func(candidate *PredictionCustodyEffectAuthorizationV1) {
			candidate.BodyHash = "tvm-cell-sha256:" + strings.Repeat("e", 64)
		},
		"amount": func(candidate *PredictionCustodyEffectAuthorizationV1) { candidate.AmountNanoTOS++ },
		"network": func(candidate *PredictionCustodyEffectAuthorizationV1) {
			candidate.NetworkDomain.ZeroStateRootHash = "sha256:" + strings.Repeat("e", 64)
		},
		"destination": func(candidate *PredictionCustodyEffectAuthorizationV1) {
			candidate.Destination = "0:" + strings.Repeat("e", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := signed
			mutate(&candidate)
			if err := VerifyPredictionCustodyEffectAuthorizationV1(candidate, resolver, now); err == nil {
				t.Fatal("mutated effect retained prediction custody authority")
			}
		})
	}
}

func TestPredictionCustodyEffectAuthorizationRejectsWrongProfilesAndKinds(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key := newTestCustodyKey("custody-75")
	for name, mutate := range map[string]func(*PredictionCustodyEffectAuthorizationV1){
		"escrow": func(value *PredictionCustodyEffectAuthorizationV1) {
			value.ActionKind, value.EffectKind = "escrow.accept", "escrow.accept"
		},
		"off-chain authorize": func(value *PredictionCustodyEffectAuthorizationV1) {
			value.ActionKind, value.EffectKind = "prediction.order.authorize", "prediction.order.authorize"
		},
		"deploy": func(value *PredictionCustodyEffectAuthorizationV1) {
			value.ActionKind, value.EffectKind = "prediction.market.deploy", "prediction.market.deploy"
		},
		"unknown prefix": func(value *PredictionCustodyEffectAuthorizationV1) {
			value.ActionKind, value.EffectKind = "prediction.future.action", "prediction.future.action"
		},
		"wrong profile": func(value *PredictionCustodyEffectAuthorizationV1) { value.Profile = "tos.escrow.effect.v1" },
		"zero market": func(value *PredictionCustodyEffectAuthorizationV1) {
			value.MarketID = "sha256:" + strings.Repeat("0", 64)
		},
		"oversized amount": func(value *PredictionCustodyEffectAuthorizationV1) {
			value.AmountNanoTOS = maximumAgentSignedActionValue + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := testPredictionCustodyEffect(now)
			mutate(&value)
			if _, err := key.signPrediction(value); err == nil {
				t.Fatal("invalid prediction custody profile was signed")
			}
		})
	}
}

func TestPredictionCustodyEffectAuthorizationStrictJSON(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key := newTestCustodyKey("custody-75")
	signed, err := key.signPrediction(testPredictionCustodyEffect(now))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePredictionCustodyEffectAuthorizationV1JSON(raw)
	if err != nil || decoded.Proof != signed.Proof || decoded.Destination != signed.MarketAddress {
		t.Fatalf("strict round trip failed: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "destination")
	withoutDestination, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePredictionCustodyEffectAuthorizationV1JSON(withoutDestination); err == nil {
		t.Fatal("prediction custody authorization omitted its explicit destination")
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"agreement_body_digest":"sha256:00"}`)...)
	if _, err := DecodePredictionCustodyEffectAuthorizationV1JSON(unknown); err == nil {
		t.Fatal("unknown escrow field entered prediction custody schema")
	}
	if _, err := DecodePredictionCustodyEffectAuthorizationV1JSON(append(raw, raw...)); err == nil {
		t.Fatal("multiple JSON values entered prediction custody schema")
	}
}
