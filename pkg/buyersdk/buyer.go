// Package buyersdk prepares, deploys, accepts and funds stablecoin escrow v2
// purchases. Every escrow it builds runs the released escrow v2 code; gateways
// remain transport and discovery helpers only.
package buyersdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type NativeClient interface {
	ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error)
}

type AssetObservation = toschain.StablecoinAssetObservation

type AssetResolver interface {
	ResolveBuyerAsset(context.Context, *nativev1.TOSAssetIdentityV1, string) (*AssetObservation, error)
}

type FundingIntent struct {
	NetworkID       string
	EscrowAddress   string
	QuoteCommitment string
	Asset           *nativev1.TOSAssetIdentityV1
	BuyerAddress    string
	BuyerWallet     string
	AmountAtomic    string
	QueryID         uint64
}

type FundingSender interface {
	PrepareStablecoinFunding(context.Context, FundingIntent) (*PreparedFunding, error)
	BroadcastStablecoinFunding(context.Context, *PreparedFunding) error
}

// PreparedFunding binds the exact signed external message to its reviewed
// semantic intent. The buyer acquires its one-way broadcast lease only after
// this object has been constructed and verified.
type PreparedFunding struct {
	Intent           FundingIntent
	MessageBOCBase64 string
	MessageHash      string
}

// buyerBase holds the buyer identity and the finalized-state readers every
// purchase is verified against.
type buyerBase struct {
	nativeClient     NativeClient
	assetResolver    AssetResolver
	limits           BudgetLimits
	network          *nativev1.NetworkDomain
	registryCodeHash string
	buyerAddress     string
	walletCode       *cell.Cell
	callerID         string
	pollInterval     time.Duration
	finalityTimeout  time.Duration
	now              func() time.Time
}

func (b *buyerBase) validateCapability(ctx context.Context, proposal *nativev1.QuoteProposalV1) error {
	capabilityID, ownerAgentID := proposal.CapabilityId, proposal.ProviderAgentId
	version, manifestDigest := proposal.CapabilityVersion, proposal.ManifestDigest
	requestContext, err := b.requestContext()
	if err != nil {
		return err
	}
	response, err := b.nativeClient.ResolveNativeState(ctx, &nativev1.ResolveNativeStateRequest{
		Context: requestContext, ObjectId: capabilityID,
	})
	if err != nil {
		return err
	}
	return validateCapabilityResponse(response, b.network, b.registryCodeHash, CapabilityExpectation{
		CapabilityID: capabilityID, OwnerAgentID: ownerAgentID, Version: version, ManifestDigest: manifestDigest,
	})
}

func (b *buyerBase) resolveAsset(ctx context.Context, proposal *nativev1.QuoteProposalV1) (*AssetObservation, error) {
	if proposal.MaximumPrice == nil || proposal.MaximumPrice.Asset == nil || !b.limits.permits(proposal.MaximumPrice.AtomicAmount) {
		return nil, errors.New("Quote exceeds buyer wallet budget")
	}
	observation, err := b.assetResolver.ResolveBuyerAsset(ctx, proposal.MaximumPrice.Asset, b.buyerAddress)
	if err != nil {
		return nil, err
	}
	expectedMaster := fmt.Sprintf("%d:%s", proposal.MaximumPrice.Asset.Master.Workchain,
		hex.EncodeToString(proposal.MaximumPrice.Asset.Master.AccountId))
	if observation == nil || !proto.Equal(observation.Asset, proposal.MaximumPrice.Asset) ||
		observation.MasterAddress != expectedMaster || observation.BuyerWalletAddress == "" ||
		observation.FinalizedCheckpoint == 0 || positiveAtomic(observation.BuyerBalanceAtomic) == nil ||
		!bytes.Equal(b.walletCode.Hash(), mustDigest(proposal.MaximumPrice.Asset.WalletCodeHash)) {
		return nil, errors.New("stablecoin asset observation does not match Quote")
	}
	return observation, nil
}

func (b *buyerBase) requestContext() (*nativev1.RequestContext, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("generate buyer Native request identity")
	}
	return &nativev1.RequestContext{RequestId: hex.EncodeToString(nonce[:]), CallerId: b.callerID,
		DeadlineUnixMillis: b.now().Add(b.finalityTimeout).UnixMilli()}, nil
}

func mustDigest(value string) []byte {
	raw, _ := hex.DecodeString(strings.TrimPrefix(value, "tvm-cell-sha256:"))
	return raw
}
