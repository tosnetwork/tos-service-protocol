package executiongate

import (
	"errors"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// ChainConfig composes the Gate directly from quorum TOS JSON-RPC endpoints.
// It deliberately has no gateway or provider-database dependency. The escrow
// code hash must be the released escrow v2 contract's.
type ChainConfig struct {
	Gate                  PaidDemandConfig
	Endpoints             []string
	Quorum                int
	RegistryWorkchain     int32
	RegistryCodeBOCBase64 string
	EscrowCodeHash        string
	NativeCheckpointPath  string
	EscrowCheckpointPath  string
}

func NewFromChain(c ChainConfig) (*Gate, error) {
	if c.Gate.Network == nil || c.RegistryCodeBOCBase64 == "" || !cellDigest(c.EscrowCodeHash) ||
		c.NativeCheckpointPath == "" || c.EscrowCheckpointPath == "" {
		return nil, errors.New("invalid chain execution gate configuration")
	}
	chain, err := toschain.New(toschain.Config{
		Network: c.Gate.Network.NetworkId, Endpoints: c.Endpoints, Quorum: c.Quorum,
	})
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(c.Gate.Network, c.RegistryWorkchain,
		c.RegistryCodeBOCBase64, c.Gate.RegistryCodeHash)
	if err != nil {
		return nil, err
	}
	nativeResolver, err := toschain.NewSimplifiedNativeResolver(chain, locator, c.NativeCheckpointPath)
	if err != nil {
		return nil, err
	}
	escrowResolver, err := toschain.NewEscrowResolver(chain, c.Gate.Network, c.EscrowCodeHash, c.EscrowCheckpointPath)
	if err != nil {
		return nil, err
	}
	c.Gate.NativeResolver = nativeResolver
	c.Gate.EscrowResolver = escrowResolver
	return NewPaidDemand(c.Gate)
}
