package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const (
	defaultActorHistory = 10_000
	maxActorHistory     = 100_000
	actorHistoryPage    = 256
)

// ServiceActorReaderConfig pins what a Service Actor read may trust: the
// network, the Service Actor release code hash, and the Native Registry
// resolver for Capability and Agent state.
type ServiceActorReaderConfig struct {
	Chain          *Adapter
	Network        *nativev1.NetworkDomain
	ActorCodeHash  string
	Registry       *SimplifiedNativeResolver
	CheckpointPath string
	MaxHistory     int
}

// ServiceActorReader reads Service Actor accounts, getters and transaction
// history from quorum-finalized checkpoints.
type ServiceActorReader struct {
	chain      *Adapter
	network    *nativev1.NetworkDomain
	codeHash   string
	registry   *SimplifiedNativeResolver
	maxHistory int
	mu         sync.Mutex
	highWater  uint64
	checkpoint *checkpointStore
}

// NewServiceActorReader refuses a configuration without a pinned
// tvm-cell-sha256 actor code hash.
func NewServiceActorReader(config ServiceActorReaderConfig) (*ServiceActorReader, error) {
	if config.Chain == nil || config.Network == nil || config.Chain.network != config.Network.NetworkId ||
		config.Registry == nil || !proto.Equal(config.Registry.network, config.Network) {
		return nil, errors.New("invalid Service Actor reader configuration")
	}
	if _, err := hexDigest(config.ActorCodeHash, "tvm-cell-sha256:"); err != nil {
		return nil, errors.New("the Service Actor code hash must be pinned as tvm-cell-sha256:<hex>")
	}
	if config.MaxHistory == 0 {
		config.MaxHistory = defaultActorHistory
	}
	if config.MaxHistory < actorHistoryPage || config.MaxHistory > maxActorHistory {
		return nil, errors.New("Service Actor history bound is outside limits")
	}
	store, err := newCheckpointStore(config.CheckpointPath)
	if err != nil {
		return nil, err
	}
	return &ServiceActorReader{chain: config.Chain, network: proto.Clone(config.Network).(*nativev1.NetworkDomain),
		codeHash: config.ActorCodeHash, registry: config.Registry, maxHistory: config.MaxHistory, checkpoint: store}, nil
}

// ActorCodeHash returns the pinned release code hash.
func (r *ServiceActorReader) ActorCodeHash() string { return r.codeHash }

// Network returns the pinned network domain.
func (r *ServiceActorReader) Network() *nativev1.NetworkDomain {
	return proto.Clone(r.network).(*nativev1.NetworkDomain)
}

func hexDigest(value, prefix string) ([32]byte, error) {
	var out [32]byte
	if !strings.HasPrefix(value, prefix) {
		return out, errors.New("invalid digest prefix")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) != 32 || value != prefix+hex.EncodeToString(raw) || bytes.Equal(raw, make([]byte, 32)) {
		return out, errors.New("invalid digest")
	}
	copy(out[:], raw)
	return out, nil
}

// ServiceActorSession is one quorum-finalized checkpoint. Every read through a
// session is taken at its sequence number, and every account read must report
// the same masterchain block identity, so a result composed from a session
// comes from one checkpoint.
type ServiceActorSession struct {
	reader    *ServiceActorReader
	seqno     uint64
	nodes     []*rpcNode
	chainTime time.Time
	mu        sync.Mutex
	root      string
	file      string
}

// Begin opens a session at a fresh finalized checkpoint, refusing a
// checkpoint older than one already served.
func (r *ServiceActorReader) Begin(ctx context.Context) (*ServiceActorSession, error) {
	if r == nil || ctx == nil {
		return nil, errors.New("Service Actor reader is not configured")
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if observation.seqno == 0 || observation.seqno < r.highWater {
		return nil, nativecore.NewProtocolError(nativecore.ErrBadSequence, "Service Actor finalized checkpoint regressed", nil)
	}
	if err := r.checkpoint.checkAndAdvance(observation.seqno); err != nil {
		return nil, nativecore.NewProtocolError(nativecore.ErrBadSequence, "Service Actor durable checkpoint rejected observation", err)
	}
	r.highWater = observation.seqno
	return &ServiceActorSession{reader: r, seqno: observation.seqno, nodes: nodes, chainTime: observation.observedAt}, nil
}

// Checkpoint returns the session's masterchain sequence number.
func (s *ServiceActorSession) Checkpoint() uint64 { return s.seqno }

// ChainTime returns the chain-authored unix time of the checkpoint block.
func (s *ServiceActorSession) ChainTime() time.Time { return s.chainTime }

// BlockHashes returns the pinned block root and file hashes, empty before the
// first account read.
func (s *ServiceActorSession) BlockHashes() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.root, s.file
}

func (s *ServiceActorSession) pin(vote nativeAccountVote) error {
	return s.pinHashes(vote.BlockRoot, vote.BlockFile)
}

// pinHashes records the session's block identity on the first read and
// requires every later read to report the same one.
func (s *ServiceActorSession) pinHashes(root, file string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if root == "" || file == "" {
		return errors.New("read carries no block identity")
	}
	if s.root == "" {
		s.root, s.file = root, file
		return nil
	}
	if s.root != root || s.file != file {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "reads of one session saw different checkpoint blocks", nil)
	}
	return nil
}

func blockHashes(block blockID) (string, string, error) {
	root, err := decodeBase64Hash(block.RootHash)
	if err != nil {
		return "", "", err
	}
	file, err := decodeBase64Hash(block.FileHash)
	if err != nil {
		return "", "", err
	}
	return "sha256:" + hex.EncodeToString(root), "sha256:" + hex.EncodeToString(file), nil
}

// ResolveRegistry resolves a Native Registry object at the session checkpoint.
func (s *ServiceActorSession) ResolveRegistry(ctx context.Context, objectID string) (*nativev1.NativeStateV1, bool, error) {
	registry := s.reader.registry
	identity, err := registry.locator.Locate(objectID)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadAction, "invalid Native object", err)
	}
	vote, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, identity.Address, s.seqno, s.reader.network, registry.locator.CodeHash)
	})
	if err != nil {
		return nil, false, err
	}
	if err := s.pin(vote); err != nil {
		return nil, false, err
	}
	root, err := hexDigest(s.root, "sha256:")
	if err != nil {
		return nil, false, err
	}
	file, err := hexDigest(s.file, "sha256:")
	if err != nil {
		return nil, false, err
	}
	state, found, err := registry.ResolveNativeAtCheckpoint(ctx, identity.Address, &nativev1.DNSCheckpointV1{Workchain: -1,
		Sequence: s.seqno, RootHash: root[:], FileHash: file[:]})
	if err != nil || !found {
		return state, found, err
	}
	if state.GetCapability() != nil && state.GetCapability().CapabilityId != objectID ||
		state.GetAgent() != nil && state.GetAgent().AgentId != objectID {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrWrongContract, "Native account holds another object", nil)
	}
	return state, true, nil
}

// ActorAccount is a finalized Service Actor account.
type ActorAccount struct {
	Address         string
	CodeHash        string
	BalanceNano     uint64
	Data            *nativecore.ServiceActorDataV1
	LastTransaction ActorTxID
}

// ActorTxID names one finalized transaction.
type ActorTxID struct {
	LT   uint64 `json:"lt"`
	Hash string `json:"hash"`
}

// ReadActor reads and decodes the actor account at the session checkpoint.
// The account must be active, run the pinned code and decode exactly, its
// live state must be internally consistent, and get_attestor_key must agree
// with the decoded policy key. found is false only for an inactive account.
func (s *ServiceActorSession) ReadActor(ctx context.Context, actor string) (*ActorAccount, bool, error) {
	canonical, err := CanonicalAddress(actor)
	if err != nil || !strings.HasPrefix(canonical, "0:") {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadAction, "a Service Actor is a raw workchain 0 address", err)
	}
	vote, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, canonical, s.seqno, s.reader.network, s.reader.codeHash)
	})
	if err != nil {
		return nil, false, err
	}
	if err := s.pin(vote); err != nil {
		return nil, false, err
	}
	if !vote.Found {
		return nil, false, nil
	}
	dataCell, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid Service Actor data BOC", err)
	}
	data, err := nativecore.DecodeServiceActorData(dataCell)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "Service Actor data does not decode", err)
	}
	if err := nativecore.ValidateServiceActorLiveState(data); err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "Service Actor live state is inconsistent", err)
	}
	lt, hash, err := transactionTuple(vote)
	if err != nil {
		return nil, false, err
	}
	key, err := s.GetAttestorKey(ctx, canonical)
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(key, data.Policy.AttestorKey) {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "get_attestor_key differs from the decoded policy", nil)
	}
	return &ActorAccount{Address: canonical, CodeHash: s.reader.codeHash, BalanceNano: vote.Balance, Data: data,
		LastTransaction: ActorTxID{LT: lt, Hash: hex.EncodeToString(hash)}}, true, nil
}

// actorGetter runs a getter at the session checkpoint by quorum and returns
// its stack in the getter's declared return order.
func (s *ServiceActorSession) actorGetter(ctx context.Context, actor, method string, arguments []dnsStackInput) ([]nativecore.TVMStackEntryV1, error) {
	result, err := runDNSGetter(ctx, s.nodes, s.reader.chain.quorum, actor, s.seqno, method, arguments)
	if err != nil {
		return nil, fmt.Errorf("Service Actor getter %s: %w", method, err)
	}
	root, file, err := blockHashes(result.BlockID)
	if err != nil || result.BlockID.Workchain != -1 {
		return nil, fmt.Errorf("Service Actor getter %s carries no masterchain block identity", method)
	}
	if err := s.pinHashes(root, file); err != nil {
		return nil, err
	}
	return decodeGetterStack(result.Stack)
}

// decodeGetterStack converts the RPC's top-first stack into return order.
func decodeGetterStack(raw []json.RawMessage) ([]nativecore.TVMStackEntryV1, error) {
	if len(raw) > 64 {
		return nil, errors.New("getter stack is too deep")
	}
	entries := make([]nativecore.TVMStackEntryV1, len(raw))
	for index := range raw {
		position := len(raw) - 1 - index
		kind, _, err := stackPair(raw, index)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "num":
			value, err := stackInt(raw, index)
			if err != nil {
				return nil, err
			}
			entries[position] = nativecore.TVMStackEntryV1{Kind: "num", Number: value}
		case "cell", "slice":
			value, _, err := stackCell(raw, index)
			if err != nil || value == nil {
				return nil, errors.New("invalid getter cell entry")
			}
			entries[position] = nativecore.TVMStackEntryV1{Kind: kind, Cell: value}
		case "null":
			entries[position] = nativecore.TVMStackEntryV1{Kind: "null"}
		default:
			return nil, errors.New("unsupported getter stack entry")
		}
	}
	return entries, nil
}

// GetAttestorKey runs get_attestor_key at the session checkpoint.
func (s *ServiceActorSession) GetAttestorKey(ctx context.Context, actor string) ([]byte, error) {
	stack, err := s.actorGetter(ctx, actor, "get_attestor_key", nil)
	if err != nil {
		return nil, err
	}
	return nativecore.DecodeServiceActorGetAttestorKeyStack(stack)
}

// GetRequest runs get_request(request_id) at the session checkpoint.
func (s *ServiceActorSession) GetRequest(ctx context.Context, actor string, requestID uint64) (*nativecore.ServiceActorRequestViewV1, error) {
	stack, err := s.actorGetter(ctx, actor, "get_request", []dnsStackInput{{"num", strconv.FormatUint(requestID, 10)}})
	if err != nil {
		return nil, err
	}
	return nativecore.DecodeServiceActorGetRequestStack(stack)
}

// GetRefund runs get_refund(request_id) at the session checkpoint.
func (s *ServiceActorSession) GetRefund(ctx context.Context, actor string, requestID uint64) (*nativecore.ServiceActorRefundV1, error) {
	stack, err := s.actorGetter(ctx, actor, "get_refund", []dnsStackInput{{"num", strconv.FormatUint(requestID, 10)}})
	if err != nil {
		return nil, err
	}
	return nativecore.DecodeServiceActorGetRefundStack(stack)
}

// HistoryResult tells how a history walk ended.
type HistoryResult string

const (
	// HistoryComplete reached the account's first transaction.
	HistoryComplete HistoryResult = "complete"
	// HistoryAnchorReached reached the requested anchor (excluded).
	HistoryAnchorReached HistoryResult = "anchor_reached"
	historyAnchorMissing HistoryResult = "anchor_missing"
	historyBoundExceeded HistoryResult = "bound_exceeded"
)

var (
	// ErrHistoryAnchorMissing reports that the walk reached the account's
	// first transaction without meeting the requested anchor.
	ErrHistoryAnchorMissing = errors.New("Service Actor history does not contain the anchor")
	// ErrHistoryBoundExceeded reports that the bound was reached first.
	ErrHistoryBoundExceeded = errors.New("Service Actor history exceeds its bound")
)

// ActorHistory is a classified finalized history, newest first.
type ActorHistory struct {
	Result       HistoryResult      `json:"result"`
	Head         ActorTxID          `json:"head"`
	Transactions []ActorTransaction `json:"transactions"`
	BlockRoot    string             `json:"block_root"`
	BlockFile    string             `json:"block_file"`
}

// History walks the actor's finalized transactions from the account's last
// transaction at the session checkpoint back to anchor (exclusive) or, with a
// nil anchor, to the first transaction. A partial history is never returned.
func (s *ServiceActorSession) History(ctx context.Context, actor string, anchor *ActorTxID) (*ActorHistory, error) {
	canonical, err := CanonicalAddress(actor)
	if err != nil {
		return nil, err
	}
	history, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (ActorHistory, error) {
		last, root, file, err := finalizedActorLastTransaction(ctx, node, canonical, s.seqno)
		if err != nil {
			return ActorHistory{}, err
		}
		raw, result, err := walkActorHistory(ctx, node, canonical, last, anchor, s.reader.maxHistory)
		// An absent anchor or an exhausted bound is a finalized fact the
		// endpoints vote on, not an endpoint failure.
		switch {
		case errors.Is(err, ErrHistoryAnchorMissing):
			return ActorHistory{Result: historyAnchorMissing, BlockRoot: root, BlockFile: file}, nil
		case errors.Is(err, ErrHistoryBoundExceeded):
			return ActorHistory{Result: historyBoundExceeded, BlockRoot: root, BlockFile: file}, nil
		case err != nil:
			return ActorHistory{}, err
		}
		classified, err := ClassifyActorTransactions(canonical, raw)
		if err != nil {
			return ActorHistory{}, err
		}
		head := ActorTxID{}
		if len(raw) > 0 {
			head = ActorTxID{LT: raw[0].LT, Hash: hex.EncodeToString(raw[0].Hash)}
		} else if anchor != nil {
			head = *anchor
		}
		return ActorHistory{Result: result, Head: head, Transactions: classified, BlockRoot: root, BlockFile: file}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.pinHashes(history.BlockRoot, history.BlockFile); err != nil {
		return nil, err
	}
	switch history.Result {
	case historyAnchorMissing:
		return nil, ErrHistoryAnchorMissing
	case historyBoundExceeded:
		return nil, ErrHistoryBoundExceeded
	}
	return &history, nil
}

// finalizedActorLastTransaction reads the account's last transaction and
// the block identity of the checkpoint it was read at.
func finalizedActorLastTransaction(ctx context.Context, node *rpcNode, address string, seqno uint64) (transactionID, string, string, error) {
	var info accountInformation
	if err := node.client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
	}{address, seqno}, &info); err != nil {
		return transactionID{}, "", "", err
	}
	if info.BlockID.Type != "tos.blockIdExt" || info.BlockID.Workchain != -1 || info.BlockID.Seqno != seqno ||
		info.LastTransactionID.Type != "internal.transactionId" {
		return transactionID{}, "", "", errors.New("Service Actor account response is not checkpoint-finalized")
	}
	root, file, err := blockHashes(info.BlockID)
	if err != nil {
		return transactionID{}, "", "", err
	}
	return info.LastTransactionID, root, file, nil
}

// walkActorHistory pages backwards with hash and logical-time continuity.
func walkActorHistory(ctx context.Context, node *rpcNode, address string, last transactionID, anchor *ActorTxID, bound int) ([]tlb.Transaction, HistoryResult, error) {
	var out []tlb.Transaction
	next := last
	if anchor != nil && lastMatches(last, *anchor) {
		return nil, HistoryAnchorReached, nil
	}
	for {
		if next.LT == "0" || next.LT == "" {
			if anchor != nil {
				return nil, "", ErrHistoryAnchorMissing
			}
			return out, HistoryComplete, nil
		}
		page, err := actorHistoryPageAt(ctx, node, address, next)
		if err != nil {
			return nil, "", err
		}
		for _, transaction := range page {
			if anchor != nil && transaction.LT == anchor.LT && hex.EncodeToString(transaction.Hash) == anchor.Hash {
				return out, HistoryAnchorReached, nil
			}
			if anchor != nil && transaction.LT < anchor.LT {
				return nil, "", ErrHistoryAnchorMissing
			}
			if len(out) >= bound {
				return nil, "", ErrHistoryBoundExceeded
			}
			out = append(out, transaction)
		}
		oldest := page[len(page)-1]
		if oldest.PrevTxLT == 0 {
			if anchor != nil {
				return nil, "", ErrHistoryAnchorMissing
			}
			return out, HistoryComplete, nil
		}
		next = transactionID{Type: "internal.transactionId", LT: strconv.FormatUint(oldest.PrevTxLT, 10),
			Hash: base64.StdEncoding.EncodeToString(oldest.PrevTxHash)}
	}
}

func lastMatches(last transactionID, anchor ActorTxID) bool {
	raw, err := base64.StdEncoding.DecodeString(last.Hash)
	return err == nil && last.LT == strconv.FormatUint(anchor.LT, 10) && hex.EncodeToString(raw) == anchor.Hash
}

func actorHistoryPageAt(ctx context.Context, node *rpcNode, address string, start transactionID) ([]tlb.Transaction, error) {
	var values []rawTransaction
	if err := node.client.Call(ctx, "getTransactions", struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{address, actorHistoryPage, start.LT, start.Hash}, &values); err != nil {
		return nil, err
	}
	if len(values) == 0 || len(values) > actorHistoryPage || values[0].TransactionID.LT != start.LT || values[0].TransactionID.Hash != start.Hash {
		return nil, errors.New("Service Actor history page does not start at the requested transaction")
	}
	account := strings.SplitN(address, ":", 2)[1]
	transactions := make([]tlb.Transaction, 0, len(values))
	var previous *tlb.Transaction
	for _, value := range values {
		if value.Type != "raw.transaction" || value.Data == "" || value.TransactionID.Type != "internal.transactionId" ||
			!strings.EqualFold(value.Account, account) {
			return nil, errors.New("malformed Service Actor transaction")
		}
		hash, err := decodeBase64Hash(value.TransactionID.Hash)
		if err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(value.Data)
		if err != nil {
			return nil, err
		}
		root, err := cell.FromBOC(raw)
		if err != nil || !bytes.Equal(root.Hash(), hash) {
			return nil, errors.New("Service Actor transaction hash mismatch")
		}
		slice, err := root.BeginParse()
		if err != nil {
			return nil, errors.New("invalid Service Actor transaction cell")
		}
		var transaction tlb.Transaction
		lt, parseErr := strconv.ParseUint(value.TransactionID.LT, 10, 64)
		if tlb.LoadFromCell(&transaction, slice) != nil || parseErr != nil || transaction.LT != lt {
			return nil, errors.New("invalid Service Actor transaction BOC")
		}
		transaction.Hash = append([]byte(nil), hash...)
		if previous != nil && (previous.PrevTxLT != transaction.LT || !bytes.Equal(previous.PrevTxHash, hash)) {
			return nil, errors.New("discontinuous Service Actor transaction history")
		}
		transactions = append(transactions, transaction)
		previous = &transactions[len(transactions)-1]
	}
	return transactions, nil
}

// CheckEndpointGenesis reads one endpoint, without a quorum, and requires its
// genesis root and file hashes to equal the pinned network domain. It is used
// to vet an endpoint another tool will submit through.
func (r *ServiceActorReader) CheckEndpointGenesis(ctx context.Context, endpoint string) error {
	for index, configured := range r.chain.endpoints {
		if configured != endpoint {
			continue
		}
		var master struct {
			Type string  `json:"@type"`
			Init blockID `json:"init"`
		}
		if err := r.chain.nodes[index].client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
			return err
		}
		root, err := decodeBase64Hash(master.Init.RootHash)
		if err != nil || master.Type != "blocks.masterchainInfo" || "sha256:"+hex.EncodeToString(root) != r.network.GenesisRootHash {
			return nativecore.NewProtocolError(nativecore.ErrWrongNetwork, "endpoint genesis root differs from the network", err)
		}
		file, err := decodeBase64Hash(master.Init.FileHash)
		if err != nil || "sha256:"+hex.EncodeToString(file) != r.network.GenesisFileHash {
			return nativecore.NewProtocolError(nativecore.ErrWrongNetwork, "endpoint genesis file differs from the network", err)
		}
		return nil
	}
	return errors.New("endpoint is not one of the reader's configured endpoints")
}

// Endpoints returns the reader's configured endpoint URLs.
func (r *ServiceActorReader) Endpoints() []string { return append([]string(nil), r.chain.endpoints...) }
