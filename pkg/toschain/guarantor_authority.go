package toschain

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tlb"
	"google.golang.org/protobuf/proto"
)

const (
	defaultGuarantorAuthorityHistory = 1024
	maxGuarantorAuthorityHistory     = 16_384
	guarantorAuthorityPage           = 64
	// masterchainShard is the masterchain's full shard as the RPC writes it.
	masterchainShard = "-9223372036854775808"
)

// GuarantorAuthorityReader performs the quorum-finalized reads behind a
// native Agent Guarantor historical authority proof. It implements
// agentguarantor.NativeAgentHistoryReader; it reports what the endpoints
// agreed on and leaves every judgement to
// agentguarantor.CheckNativeAgentHistoricalAuthorityV1.
type GuarantorAuthorityReader struct {
	chain      *Adapter
	network    *nativev1.NetworkDomain
	locator    *nativecore.Locator
	maxHistory int
}

// NewGuarantorAuthorityReader pins the reader to the adapter's network and
// the locator's Native Registry code. maxHistory bounds the transactions
// read between the bound and effective checkpoints; zero selects the
// default.
func NewGuarantorAuthorityReader(chain *Adapter, locator *nativecore.Locator, maxHistory int) (*GuarantorAuthorityReader, error) {
	if chain == nil || locator == nil || locator.Network == nil || chain.network != locator.Network.NetworkId {
		return nil, errors.New("invalid Guarantor authority reader configuration")
	}
	if maxHistory == 0 {
		maxHistory = defaultGuarantorAuthorityHistory
	}
	if maxHistory < 1 || maxHistory > maxGuarantorAuthorityHistory {
		return nil, errors.New("Guarantor authority history bound is outside limits")
	}
	return &GuarantorAuthorityReader{chain: chain, network: proto.Clone(locator.Network).(*nativev1.NetworkDomain),
		locator: locator, maxHistory: maxHistory}, nil
}

type guarantorBlockHeader struct {
	Type    string  `json:"@type"`
	ID      blockID `json:"id"`
	GenTime int64   `json:"gen_utime"`
}

type guarantorBoundVote struct {
	Root     string `json:"root"`
	File     string `json:"file"`
	GenUtime uint64 `json:"gen_utime"`
}

type guarantorEffectiveVote struct {
	Found     bool                                    `json:"found"`
	Data      string                                  `json:"data"`
	Root      string                                  `json:"root"`
	File      string                                  `json:"file"`
	Effective agentguarantor.NativeAgentTransactionV1 `json:"effective"`
}

type guarantorHistoryVote struct {
	Root    string                                    `json:"root"`
	File    string                                    `json:"file"`
	Last    agentguarantor.FinalizedTransactionRefV1  `json:"last"`
	History []agentguarantor.NativeAgentTransactionV1 `json:"history"`
}

func transactionRefOf(lt uint64, hash []byte) agentguarantor.FinalizedTransactionRefV1 {
	if lt == 0 {
		return agentguarantor.FinalizedTransactionRefV1{}
	}
	return agentguarantor.FinalizedTransactionRefV1{LogicalTime: lt, TransactionHash: "sha256:" + hex.EncodeToString(hash)}
}

func nativeTransactionOf(transaction tlb.Transaction) agentguarantor.NativeAgentTransactionV1 {
	return agentguarantor.NativeAgentTransactionV1{Transaction: transactionRefOf(transaction.LT, transaction.Hash),
		BlockTimeUnix: uint64(transaction.Now), Previous: transactionRefOf(transaction.PrevTxLT, transaction.PrevTxHash)}
}

func transactionIDOf(ref agentguarantor.FinalizedTransactionRefV1) (transactionID, error) {
	hash, err := hexDigest(ref.TransactionHash, "sha256:")
	if err != nil || ref.LogicalTime == 0 {
		return transactionID{}, errors.New("invalid transaction reference")
	}
	return transactionID{Type: "internal.transactionId", LT: strconv.FormatUint(ref.LogicalTime, 10),
		Hash: base64.StdEncoding.EncodeToString(hash[:])}, nil
}

// ReadNativeAgentHistory implements agentguarantor.NativeAgentHistoryReader.
func (r *GuarantorAuthorityReader) ReadNativeAgentHistory(ctx context.Context,
	proof agentguarantor.NativeAgentHistoricalAuthorityProofV1, subject string) (agentguarantor.NativeAgentHistoryObservationV1, error) {
	var none agentguarantor.NativeAgentHistoryObservationV1
	if r == nil || ctx == nil {
		return none, errors.New("Guarantor authority reader is not configured")
	}
	identity, err := r.locator.Locate(subject)
	if err != nil {
		return none, fmt.Errorf("Guarantor authority subject: %w", err)
	}
	if proof.AgentAccount != identity.Address {
		return none, errors.New("Guarantor authority proof names another account")
	}
	if proof.EffectiveCheckpoint.Sequence == 0 || proof.EffectiveCheckpoint.Sequence > proof.BoundCheckpoint.Sequence {
		return none, errors.New("Guarantor authority checkpoints are out of order")
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return none, err
	}
	if proof.BoundCheckpoint.Sequence > observation.seqno {
		return none, errors.New("Guarantor authority bound checkpoint is not finalized")
	}
	bound, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (guarantorBoundVote, error) {
		var header guarantorBlockHeader
		if err := node.client.Call(ctx, "getBlockHeader", struct {
			Workchain int32  `json:"workchain"`
			Shard     string `json:"shard"`
			Seqno     uint64 `json:"seqno"`
		}{-1, masterchainShard, proof.BoundCheckpoint.Sequence}, &header); err != nil {
			return guarantorBoundVote{}, err
		}
		if header.Type != "blocks.header" || header.ID.Workchain != -1 || header.ID.Seqno != proof.BoundCheckpoint.Sequence ||
			header.GenTime <= 0 {
			return guarantorBoundVote{}, errors.New("Guarantor authority block header is malformed")
		}
		root, file, err := blockHashes(header.ID)
		if err != nil {
			return guarantorBoundVote{}, err
		}
		return guarantorBoundVote{Root: root, File: file, GenUtime: uint64(header.GenTime)}, nil
	})
	if err != nil {
		return none, fmt.Errorf("Guarantor authority bound checkpoint: %w", err)
	}
	effective, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (guarantorEffectiveVote, error) {
		vote, err := readNativeAccountAt(ctx, node, identity.Address, proof.EffectiveCheckpoint.Sequence, r.network, r.locator.CodeHash)
		if err != nil {
			return guarantorEffectiveVote{}, err
		}
		result := guarantorEffectiveVote{Found: vote.Found, Data: vote.Data, Root: vote.BlockRoot, File: vote.BlockFile}
		if !vote.Found {
			return result, nil
		}
		lt, hash, err := transactionTuple(vote)
		if err != nil {
			return guarantorEffectiveVote{}, err
		}
		page, err := historyPageAt(ctx, node, identity.Address, transactionID{Type: "internal.transactionId",
			LT: vote.LT, Hash: vote.TransactionHash}, 1)
		if err != nil || len(page) != 1 || page[0].LT != lt || string(page[0].Hash) != string(hash) {
			return guarantorEffectiveVote{}, errors.New("Guarantor authority effective transaction does not read back")
		}
		result.Effective = nativeTransactionOf(page[0])
		return result, nil
	})
	if err != nil {
		return none, fmt.Errorf("Guarantor authority effective state: %w", err)
	}
	history, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (guarantorHistoryVote, error) {
		last, root, file, err := finalizedActorLastTransaction(ctx, node, identity.Address, proof.BoundCheckpoint.Sequence)
		if err != nil {
			return guarantorHistoryVote{}, err
		}
		lastLT, err := strconv.ParseUint(last.LT, 10, 64)
		if err != nil {
			return guarantorHistoryVote{}, errors.New("Guarantor authority last transaction is malformed")
		}
		lastHash, err := decodeBase64Hash(last.Hash)
		if err != nil {
			return guarantorHistoryVote{}, err
		}
		vote := guarantorHistoryVote{Root: root, File: file, Last: transactionRefOf(lastLT, lastHash)}
		next := last
		for len(vote.History) < r.maxHistory {
			page, err := historyPageAt(ctx, node, identity.Address, next, guarantorAuthorityPage)
			if err != nil {
				return guarantorHistoryVote{}, err
			}
			for _, transaction := range page {
				if len(vote.History) >= r.maxHistory {
					return guarantorHistoryVote{}, errors.New("Guarantor authority history exceeds its bound")
				}
				vote.History = append(vote.History, nativeTransactionOf(transaction))
				// Stop at the effective transaction or anything older; the
				// check decides whether the history reached it exactly.
				if transaction.LT <= proof.EffectiveTransaction.LogicalTime {
					return vote, nil
				}
			}
			oldest := page[len(page)-1]
			if oldest.PrevTxLT == 0 {
				return vote, nil
			}
			next = transactionID{Type: "internal.transactionId", LT: strconv.FormatUint(oldest.PrevTxLT, 10),
				Hash: base64.StdEncoding.EncodeToString(oldest.PrevTxHash)}
		}
		return guarantorHistoryVote{}, errors.New("Guarantor authority history exceeds its bound")
	})
	if err != nil {
		return none, fmt.Errorf("Guarantor authority history: %w", err)
	}
	if history.Root != bound.Root || history.File != bound.File {
		return none, errors.New("Guarantor authority account read and block header name different bound blocks")
	}
	result := agentguarantor.NativeAgentHistoryObservationV1{
		Network: proto.Clone(r.network).(*nativev1.NetworkDomain), RegistryCodeHash: r.locator.CodeHash,
		FinalizedSequence: observation.seqno,
		BoundCheckpoint: agentguarantor.FinalizedCheckpointRefV1{Sequence: proof.BoundCheckpoint.Sequence,
			RootHash: bound.Root, FileHash: bound.File},
		BoundGenerationUnix: bound.GenUtime, BoundLastTransaction: history.Last,
		EffectiveCheckpoint: agentguarantor.FinalizedCheckpointRefV1{Sequence: proof.EffectiveCheckpoint.Sequence,
			RootHash: effective.Root, FileHash: effective.File},
		EffectiveAccount: identity.Address, History: history.History,
	}
	if !effective.Found {
		return result, nil
	}
	result.EffectiveCodeHash = r.locator.CodeHash
	result.EffectiveLastTransaction = effective.Effective
	data, err := decodeCellBOC(effective.Data)
	if err != nil {
		return none, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid Native account data BOC", err)
	}
	state, found, err := r.locator.DecodeData(data, subject)
	if err != nil {
		return none, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid Native typed state", err)
	}
	if found {
		result.State = state
	}
	return result, nil
}

var _ agentguarantor.NativeAgentHistoryReader = (*GuarantorAuthorityReader)(nil)
