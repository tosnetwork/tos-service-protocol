package toschain

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
)

// FinalizedEscrowV2 binds the typed escrow state to the exact finalized
// account transaction and masterchain checkpoint from which it was decoded.
type FinalizedEscrowV2 struct {
	State       *nativecore.EscrowStateV2
	Reference   *nativev1.ChainReference
	FinalizedAt time.Time
}

// EscrowResolver reads escrow accounts running the released escrow v2 code
// from the same quorum and rollback-protected finalized checkpoint model as
// the Native Registry.
type EscrowResolver struct {
	chain      *Adapter
	network    *nativev1.NetworkDomain
	codeHash   string
	mu         sync.Mutex
	highWater  uint64
	checkpoint *checkpointStore
}

func NewEscrowResolver(chain *Adapter, network *nativev1.NetworkDomain, codeHash, checkpointPath string) (*EscrowResolver, error) {
	if chain == nil || network == nil || chain.network != network.NetworkId ||
		!strings.HasPrefix(codeHash, "tvm-cell-sha256:") || len(codeHash) != len("tvm-cell-sha256:")+64 {
		return nil, errors.New("invalid escrow resolver configuration")
	}
	if raw, err := hex.DecodeString(strings.TrimPrefix(codeHash, "tvm-cell-sha256:")); err != nil || len(raw) != 32 {
		return nil, errors.New("invalid escrow contract code hash")
	}
	if err := nativecore.RequireEscrowV2CodeHash(codeHash); err != nil {
		return nil, err
	}
	store, err := newCheckpointStore(checkpointPath)
	if err != nil {
		return nil, err
	}
	return &EscrowResolver{chain: chain, network: network, codeHash: codeHash, checkpoint: store}, nil
}

// ResolveFinalizedV2 returns only contract-code-authenticated, typed escrow
// state from a quorum-finalized account observation. Missing accounts are
// authoritative; malformed, stale, or divergent observations fail closed.
func (r *EscrowResolver) ResolveFinalizedV2(ctx context.Context, escrowAddress string) (*FinalizedEscrowV2, bool, error) {
	if r == nil || ctx == nil {
		return nil, false, errors.New("invalid escrow V2 resolution request")
	}
	parsed, err := address.ParseRawAddr(escrowAddress)
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.Workchain() != 0 || parsed.StringRaw() != escrowAddress {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid escrow V2 address", err)
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := r.chain.validateObservationTime(observation, time.Now()); err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	if observation.seqno == 0 || observation.seqno < r.highWater {
		r.mu.Unlock()
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadSequence, "escrow V2 finalized checkpoint regressed", nil)
	}
	r.mu.Unlock()
	vote, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, escrowAddress, observation.seqno, r.network, r.codeHash)
	})
	if err != nil {
		return nil, false, err
	}
	if !vote.Found {
		if err := r.commitCheckpoint(observation.seqno); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid escrow V2 data BOC", err)
	}
	state, err := nativecore.DecodeEscrowDataV2(data, r.network)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid typed escrow V2 state", err)
	}
	code, err := decodeCellBOC(vote.Code)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid escrow V2 code BOC", err)
	}
	identity, err := nativecore.BuildEscrowStateInitV2(0, code, nativecore.EscrowInitV2{Network: r.network,
		AcceptedQuote: state.AcceptedQuote, Terms: nativecore.EscrowTermsV1{BuyerAddress: state.BuyerAddress,
			ProviderAddress: state.ProviderAddress, FundingDeadline: state.FundingDeadline, RefundAvailableAt: state.RefundAvailableAt},
		ExecutionSignerEd25519: state.ExecutionSignerEd25519, TransportBinding: state.TransportBinding,
		AssetMasterAddress: state.AssetMasterAddress, AssetWalletCode: state.AssetWalletCode})
	if err != nil || identity.Address != escrowAddress {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrWrongContract, "escrow V2 account does not match canonical StateInit", err)
	}
	lt, transactionHash, err := transactionTuple(vote)
	if err != nil {
		return nil, false, err
	}
	reference := &nativev1.ChainReference{Workchain: 0, Account: escrowAddress, LogicalTime: lt,
		TransactionHash: "sha256:" + hex.EncodeToString(transactionHash), ContractCodeHash: r.codeHash,
		FinalizedCheckpoint: observation.seqno}
	if err := r.commitCheckpoint(observation.seqno); err != nil {
		return nil, false, err
	}
	return &FinalizedEscrowV2{State: state, Reference: reference,
		FinalizedAt: time.Unix(int64(vote.TransactionTime), 0).UTC()}, true, nil
}

func (r *EscrowResolver) commitCheckpoint(value uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value == 0 || value < r.highWater || r.checkpoint == nil {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "escrow finalized checkpoint rejected observation", nil)
	}
	if err := r.checkpoint.checkAndAdvance(value); err != nil {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "escrow durable checkpoint rejected observation", err)
	}
	r.highWater = value
	return nil
}
