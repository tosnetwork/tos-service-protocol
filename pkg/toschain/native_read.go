package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type blockID struct {
	Type      string `json:"@type"`
	Workchain int32  `json:"workchain"`
	Shard     string `json:"shard"`
	Seqno     uint64 `json:"seqno"`
	RootHash  string `json:"root_hash"`
	FileHash  string `json:"file_hash"`
}

type transactionID struct {
	Type string `json:"@type"`
	LT   string `json:"lt"`
	Hash string `json:"hash"`
}

type accountInformation struct {
	Type              string          `json:"@type"`
	Balance           string          `json:"balance"`
	Code              string          `json:"code"`
	Data              string          `json:"data"`
	LastTransactionID transactionID   `json:"last_transaction_id"`
	BlockID           blockID         `json:"block_id"`
	SyncUtime         int64           `json:"sync_utime"`
	ExtraCurrencies   json.RawMessage `json:"extra_currencies"`
	State             string          `json:"state"`
	FrozenHash        string          `json:"frozen_hash"`
	// StorageStat is the account's storage usage, served beside the state
	// and omitted for an account without storage metadata.
	StorageStat accountStorageStat `json:"storage_stat"`
}

// accountStorageStat is the node's storage.stat object, decoded strictly:
// {"@type":"storage.stat","used_cells":"<u64>","used_bits":"<u64>",
// "last_paid":<u32>,"due_payment":null|"<decimal>"}. Every field is
// required, unknown fields are refused, and an explicit null is refused.
type accountStorageStat struct {
	Present    bool
	UsedCells  uint64
	UsedBits   uint64
	LastPaid   uint32
	DuePayment *big.Int
}

var canonicalDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func (s *accountStorageStat) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("storage_stat is null")
	}
	var fields struct {
		Type      *string `json:"@type"`
		UsedCells *string `json:"used_cells"`
		UsedBits  *string `json:"used_bits"`
		// RawMessage, not a pointer: a JSON null would leave a pointer nil
		// and look absent.
		LastPaid   json.RawMessage `json:"last_paid"`
		DuePayment json.RawMessage `json:"due_payment"`
	}
	if err := jsonstrict.Decode(raw, &fields); err != nil {
		return fmt.Errorf("storage_stat: %w", err)
	}
	if fields.Type == nil || *fields.Type != "storage.stat" || fields.UsedCells == nil || fields.UsedBits == nil ||
		len(fields.LastPaid) == 0 || len(fields.DuePayment) == 0 {
		return errors.New("storage_stat is missing a field or has another type")
	}
	cells, err := canonicalUint(*fields.UsedCells, 64)
	if err != nil {
		return fmt.Errorf("storage_stat used_cells: %w", err)
	}
	bitsUsed, err := canonicalUint(*fields.UsedBits, 64)
	if err != nil {
		return fmt.Errorf("storage_stat used_bits: %w", err)
	}
	lastPaid, err := canonicalUint(string(fields.LastPaid), 32)
	if err != nil {
		return fmt.Errorf("storage_stat last_paid: %w", err)
	}
	var due *big.Int
	if string(fields.DuePayment) != "null" {
		var text string
		if err := json.Unmarshal(fields.DuePayment, &text); err != nil || !canonicalDecimal.MatchString(text) {
			return errors.New("storage_stat due_payment is not null or a canonical decimal string")
		}
		due, _ = new(big.Int).SetString(text, 10)
	}
	*s = accountStorageStat{Present: true, UsedCells: cells, UsedBits: bitsUsed, LastPaid: uint32(lastPaid), DuePayment: due}
	return nil
}

func canonicalUint(text string, width int) (uint64, error) {
	if !canonicalDecimal.MatchString(text) {
		return 0, errors.New("not a canonical unsigned decimal")
	}
	value, err := strconv.ParseUint(text, 10, width)
	if err != nil {
		return 0, errors.New("out of range")
	}
	return value, nil
}

type rawTransaction struct {
	Type            string          `json:"@type"`
	Aborted         bool            `json:"aborted"`
	BlockID         blockID         `json:"block_id"`
	Action          json.RawMessage `json:"action"`
	Compute         json.RawMessage `json:"compute"`
	Data            string          `json:"data"`
	Destroyed       bool            `json:"destroyed"`
	Fee             string          `json:"fee"`
	InMsg           json.RawMessage `json:"in_msg"`
	InMsgHash       string          `json:"in_msg_hash"`
	OutMsgs         json.RawMessage `json:"out_msgs"`
	TransactionType string          `json:"transaction_type"`
	Utime           uint32          `json:"utime"`
	TransactionID   transactionID   `json:"transaction_id"`
	Account         string          `json:"account"`
}

type nativeAccountVote struct {
	Found           bool   `json:"found"`
	Balance         uint64 `json:"balance"`
	Code            string `json:"code"`
	Data            string `json:"data"`
	LT              string `json:"lt"`
	TransactionHash string `json:"transaction_hash"`
	TransactionTime uint64 `json:"transaction_time"`
	BlockRoot       string `json:"block_root"`
	BlockFile       string `json:"block_file"`
}

func readNativeAccountAt(ctx context.Context, node *rpcNode, address string, seqno uint64, network *nativev1.NetworkDomain, allowedCodeHash string) (nativeAccountVote, error) {
	if network == nil {
		return nativeAccountVote{}, nativecore.NewProtocolError(nativecore.ErrWrongNetwork, "Native network is missing", nil)
	}
	var master struct {
		Type          string  `json:"@type"`
		Last          blockID `json:"last"`
		StateRootHash string  `json:"state_root_hash"`
		Init          blockID `json:"init"`
	}
	if err := node.client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
		return nativeAccountVote{}, err
	}
	if master.Type != "blocks.masterchainInfo" || master.Last.Seqno < seqno {
		return nativeAccountVote{}, errors.New("Native endpoint masterchain response is stale or malformed")
	}
	genesisRoot, err := decodeBase64Hash(master.Init.RootHash)
	if err != nil || "sha256:"+hex.EncodeToString(genesisRoot) != network.GenesisRootHash {
		return nativeAccountVote{}, nativecore.NewProtocolError(nativecore.ErrWrongNetwork, "Native endpoint genesis root mismatch", err)
	}
	genesisFile, err := decodeBase64Hash(master.Init.FileHash)
	if err != nil || "sha256:"+hex.EncodeToString(genesisFile) != network.GenesisFileHash {
		return nativeAccountVote{}, nativecore.NewProtocolError(nativecore.ErrWrongNetwork, "Native endpoint genesis file mismatch", err)
	}
	var info accountInformation
	if err := node.client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
	}{address, seqno}, &info); err != nil {
		return nativeAccountVote{}, err
	}
	if info.BlockID.Type != "tos.blockIdExt" || info.BlockID.Workchain != -1 || info.BlockID.Seqno != seqno {
		return nativeAccountVote{}, errors.New("Native account response is not finalized")
	}
	root, err := decodeBase64Hash(info.BlockID.RootHash)
	if err != nil {
		return nativeAccountVote{}, err
	}
	file, err := decodeBase64Hash(info.BlockID.FileHash)
	if err != nil {
		return nativeAccountVote{}, err
	}
	vote := nativeAccountVote{BlockRoot: "sha256:" + hex.EncodeToString(root), BlockFile: "sha256:" + hex.EncodeToString(file)}
	if info.State != "active" {
		return vote, nil
	}
	if info.Code == "" || info.Data == "" {
		return nativeAccountVote{}, errors.New("Native account has incomplete state")
	}
	balance, err := strconv.ParseUint(info.Balance, 10, 64)
	if err != nil {
		return nativeAccountVote{}, errors.New("Native account balance is invalid")
	}
	code, err := decodeCellBOC(info.Code)
	if err != nil || "tvm-cell-sha256:"+hex.EncodeToString(code.Hash()) != allowedCodeHash {
		return nativeAccountVote{}, nativecore.NewProtocolError(nativecore.ErrWrongContract, "Native account code hash mismatch", err)
	}
	vote.Found, vote.Balance, vote.Code, vote.Data = true, balance, info.Code, info.Data
	vote.LT, vote.TransactionHash = info.LastTransactionID.LT, info.LastTransactionID.Hash
	vote.TransactionTime, err = verifyNativeLastTransactionTuple(ctx, node, address, info.LastTransactionID)
	if err != nil {
		return nativeAccountVote{}, err
	}
	return vote, nil
}

func verifyNativeLastTransactionTuple(ctx context.Context, node *rpcNode, address string, id transactionID) (uint64, error) {
	if id.Type != "internal.transactionId" || id.LT == "" || id.Hash == "" {
		return 0, errors.New("Native account last transaction is missing")
	}
	var values []rawTransaction
	if err := node.client.Call(ctx, "getTransactions", struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{address, 1, id.LT, id.Hash}, &values); err != nil {
		return 0, err
	}
	if len(values) != 1 || values[0].Type != "raw.transaction" || values[0].Data == "" || values[0].TransactionID != id {
		return 0, errors.New("Native exact transaction query mismatch")
	}
	rawHash, err := decodeBase64Hash(id.Hash)
	if err != nil {
		return 0, errors.New("invalid Native transaction hash")
	}
	boc, err := base64.StdEncoding.DecodeString(values[0].Data)
	if err != nil {
		return 0, err
	}
	root, err := cell.FromBOC(boc)
	if err != nil || !bytes.Equal(root.Hash(), rawHash) {
		return 0, errors.New("Native transaction BOC hash mismatch")
	}
	rootSlice, err := root.BeginParse()
	if err != nil {
		return 0, errors.New("invalid Native transaction cell")
	}
	var transaction tlb.Transaction
	if err := tlb.LoadFromCell(&transaction, rootSlice); err != nil {
		return 0, err
	}
	lt, err := strconv.ParseUint(id.LT, 10, 64)
	parts := strings.Split(address, ":")
	if err != nil || transaction.LT != lt || len(parts) != 2 || !strings.EqualFold(values[0].Account, parts[1]) {
		return 0, errors.New("Native transaction tuple mismatch")
	}
	if transaction.Now == 0 {
		return 0, errors.New("Native transaction time is missing")
	}
	return uint64(transaction.Now), nil
}

func decodeBase64Hash(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("invalid base64 hash")
	}
	return decoded, nil
}

func decodeCellBOC(value string) (*cell.Cell, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return cell.FromBOC(raw)
}

func transactionTuple(v nativeAccountVote) (uint64, []byte, error) {
	lt, err := strconv.ParseUint(v.LT, 10, 64)
	if err != nil || lt == 0 {
		return 0, nil, errors.New("invalid Native transaction logical time")
	}
	hash, err := decodeBase64Hash(v.TransactionHash)
	if err != nil || bytes.Equal(hash, make([]byte, 32)) {
		return 0, nil, errors.New("invalid Native transaction hash")
	}
	return lt, hash, nil
}
