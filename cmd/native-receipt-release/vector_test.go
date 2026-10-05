package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The contract vectors record a release the escrow v2 contract accepted. The
// signing package this command prints for the same funded escrow and outcome
// must ask the signer to sign exactly that intent.
type contractVector struct {
	GlobalID int32 `json:"global_id"`
	Input    struct {
		Network       *nativev1.NetworkDomain `json:"network"`
		EscrowAddress string                  `json:"escrow_address"`
		Quote         string                  `json:"quote_commitment"`
		ReceiptBOC    string                  `json:"receipt_boc_base64"`
		CompletedAt   uint64                  `json:"receipt_completed_at"`
		SignerKey     string                  `json:"signer_public_key_hex"`
	} `json:"input"`
	Deployed struct {
		DataBOC string `json:"data_boc_base64"`
	} `json:"deployed"`
	Funded struct {
		DataBOC string `json:"data_boc_base64"`
	} `json:"funded"`
	Released struct {
		QueryID uint64 `json:"query_id"`
		Intent  string `json:"intent_hash"`
	} `json:"released"`
}

func loadContractVector(t *testing.T) contractVector {
	t.Helper()
	raw, err := os.ReadFile("../../pkg/nativecore/testdata/escrow_v2_contract_vectors.json")
	if err != nil {
		t.Fatalf("the contract vector is required: %v", err)
	}
	var vector contractVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func base64Cell(t *testing.T, encoded string) *cell.Cell {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	value, err := cell.FromBOC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func vectorOutcome(vector contractVector) outcome {
	digest := func(label string) string {
		sum := sha256.Sum256([]byte("tos-escrow-v2-vector-" + label))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return outcome{Quote: vector.Input.Quote, Execution: digest("execution"), Input: digest("input"),
		Result: digest("result"), Source: digest("source"), Toolchain: digest("toolchain"), Sandbox: digest("sandbox"),
		Artifact: descriptor{Digest: digest("artifact")}, Report: descriptor{Digest: digest("report")},
		Completed: vector.Input.CompletedAt}
}

func TestSigningPackageMatchesTheContractAcceptedIntent(t *testing.T) {
	vector := loadContractVector(t)
	release := escrowRelease{Network: vector.Input.Network, GlobalID: vector.GlobalID, Escrow: vector.Input.EscrowAddress,
		Data: base64Cell(t, vector.Funded.DataBOC), QueryID: vector.Released.QueryID}
	value, receipt, err := buildSigningPackage(vectorOutcome(vector), release)
	if err != nil {
		t.Fatal(err)
	}
	if value.SigningPayloadHex != vector.Released.Intent || value.ExecutionSignerPublicKey != vector.Input.SignerKey {
		t.Fatalf("signing payload %s, contract accepted %s", value.SigningPayloadHex, vector.Released.Intent)
	}
	if hex.EncodeToString(receipt.Hash()) != hex.EncodeToString(base64Cell(t, vector.Input.ReceiptBOC).Hash()) {
		t.Fatal("Receipt differs from the one the contract released against")
	}
	release.GlobalID++
	other, _, err := buildSigningPackage(vectorOutcome(vector), release)
	if err != nil || other.SigningPayloadHex == value.SigningPayloadHex {
		t.Fatal("the signing payload does not depend on the network global ID")
	}
}

func TestSigningPackageRefusesAnEscrowThatIsNotFunded(t *testing.T) {
	vector := loadContractVector(t)
	release := escrowRelease{Network: vector.Input.Network, GlobalID: vector.GlobalID, Escrow: vector.Input.EscrowAddress,
		Data: base64Cell(t, vector.Deployed.DataBOC), QueryID: vector.Released.QueryID}
	if _, _, err := buildSigningPackage(vectorOutcome(vector), release); err == nil {
		t.Fatal("signed a release for an escrow awaiting acceptance")
	}
}
