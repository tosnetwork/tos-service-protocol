package toschain

import (
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

func TestEscrowResolverConfigurationFailsClosed(t *testing.T) {
	chain := &Adapter{network: "tos-test"}
	network := &nativev1.NetworkDomain{NetworkId: "tos-test"}
	if _, err := NewEscrowResolver(chain, network, nativecore.EscrowV2CodeHash, t.TempDir()); err != nil {
		t.Fatalf("valid resolver configuration: %v", err)
	}
	for _, codeHash := range []string{"", "sha256:" + strings.Repeat("11", 32), "tvm-cell-sha256:xyz",
		"tvm-cell-sha256:" + strings.Repeat("11", 32), strings.ToUpper(nativecore.EscrowV2CodeHash)} {
		if _, err := NewEscrowResolver(chain, network, codeHash, t.TempDir()); err == nil {
			t.Fatalf("accepted escrow code hash %q", codeHash)
		}
	}
	if _, err := NewEscrowResolver(chain, &nativev1.NetworkDomain{NetworkId: "other"}, nativecore.EscrowV2CodeHash, t.TempDir()); err == nil {
		t.Fatal("accepted a resolver on the wrong network")
	}
}

func TestEscrowResolverRejectsNonCanonicalAddressBeforeNetworkRead(t *testing.T) {
	resolver := &EscrowResolver{}
	if _, _, err := resolver.ResolveFinalizedV2(t.Context(), "not-an-address"); err == nil {
		t.Fatal("accepted invalid escrow address")
	}
}
