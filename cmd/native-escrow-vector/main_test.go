package main

import (
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func vectorInput(t *testing.T, code *cell.Cell) Input {
	t.Helper()
	return Input{Network: &nativev1.NetworkDomain{NetworkId: "tos:escrow-v2-vector",
		GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		BaseUnix: 1_800_000_000, BuyerAddress: "0:" + strings.Repeat("b1", 32),
		ProviderAddress: "0:" + strings.Repeat("9e", 32), MasterAddress: "0:" + strings.Repeat("5a", 32),
		EscrowCode: code, WalletCode: cell.BeginCell().MustStoreUInt(0x12345678, 32).EndCell(),
		SignerSeed: []byte(strings.Repeat("Q", 32)), AcceptQueryID: 2}
}

func TestBuildUsesOnlyTheReleasedEscrowCode(t *testing.T) {
	code, err := nativecore.EscrowV2Code()
	if err != nil {
		t.Fatal(err)
	}
	output, err := Build(vectorInput(t, code))
	if err != nil {
		t.Fatalf("released code refused: %v", err)
	}
	if output.EscrowCodeHash != nativecore.EscrowV2CodeHash {
		t.Fatalf("escrow built with code %s", output.EscrowCodeHash)
	}
	other := cell.BeginCell().MustStoreUInt(0xabcdef02, 32).EndCell()
	if _, err := Build(vectorInput(t, other)); err == nil {
		t.Fatal("an escrow vector was built for code other than the released contract")
	}
}
