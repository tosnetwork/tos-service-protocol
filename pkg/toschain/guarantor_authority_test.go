package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentguarantor"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

var guarantorTestNetwork = &nativev1.NetworkDomain{NetworkId: "tos:global-id:2",
	GenesisRootHash: "sha256:" + strings.Repeat("aa", 32), GenesisFileHash: "sha256:" + strings.Repeat("bb", 32)}

const guarantorTestSubject = "agent_5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

func guarantorTestLocator(t *testing.T) *nativecore.Locator {
	t.Helper()
	raw, err := os.ReadFile("../nativecore/testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		CodeHash string `json:"contract_code_hash"`
		CodeBOC  string `json:"contract_code_boc_base64"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	locator, err := nativecore.NewLocator(guarantorTestNetwork, 0, vectors.CodeBOC, vectors.CodeHash)
	if err != nil {
		t.Fatal(err)
	}
	return locator
}

func accountTransaction(t *testing.T, account string, lt uint64, now uint32, prev *tlb.Transaction) tlb.Transaction {
	t.Helper()
	raw, _ := hex.DecodeString(strings.TrimPrefix(account, "0:"))
	transaction := tlb.Transaction{AccountAddr: raw, LT: lt, PrevTxHash: zeroHash32, Now: now,
		OrigStatus: tlb.AccountStatusActive, EndStatus: tlb.AccountStatusActive,
		TotalFees: tlb.CurrencyCollection{Coins: tlb.ZeroCoins}, StateUpdate: tlb.HashUpdate{OldHash: zeroHash32, NewHash: zeroHash32},
		Description: tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{Success: true,
			GasFees: tlb.ZeroCoins, Details: tlb.ComputePhaseVMDetails{GasUsed: big.NewInt(0), GasLimit: big.NewInt(0),
				VMInitStateHash: zeroHash32, VMFinalStateHash: zeroHash32}}}}}
	if prev != nil {
		transaction.PrevTxLT, transaction.PrevTxHash = prev.LT, prev.Hash
	}
	encoded, err := transaction.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	var parsed tlb.Transaction
	if err := tlb.LoadFromCell(&parsed, encoded.MustBeginParse()); err != nil {
		t.Fatal(err)
	}
	parsed.Hash = encoded.Hash()
	return parsed
}

// guarantorChain is one fake finalized endpoint: the Registry account of the
// test subject with transactions at block times 900, 1000 (effective), 2000
// and 3000, an effective checkpoint 10 whose last transaction is lt 200, and
// a bound checkpoint 20 whose last transaction is lt 400.
type guarantorChain struct {
	finalized   uint64
	boundRoot   []byte
	headerRoot  []byte
	genesisRoot []byte
	genUtime    int64
}

type guarantorFixture struct {
	account string
	code    string
	data    string
	history []tlb.Transaction // newest first
}

func newGuarantorFixture(t *testing.T, locator *nativecore.Locator) guarantorFixture {
	t.Helper()
	identity, err := locator.Locate(guarantorTestSubject)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(identity.StateInitBOC)
	if err != nil {
		t.Fatal(err)
	}
	stateInit, err := cell.FromBOC(raw)
	if err != nil {
		t.Fatal(err)
	}
	slice := stateInit.MustBeginParse()
	_, _ = slice.LoadUInt(3)
	code, err := slice.LoadRefCell()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = slice.LoadUInt(1)
	data, err := slice.LoadRefCell()
	if err != nil {
		t.Fatal(err)
	}
	var oldestFirst []tlb.Transaction
	var previous *tlb.Transaction
	for index, now := range []uint32{900, 1000, 2000, 3000} {
		transaction := accountTransaction(t, identity.Address, uint64(100*(index+1)), now, previous)
		oldestFirst = append(oldestFirst, transaction)
		previous = &oldestFirst[len(oldestFirst)-1]
	}
	history := make([]tlb.Transaction, len(oldestFirst))
	for index := range oldestFirst {
		history[len(oldestFirst)-1-index] = oldestFirst[index]
	}
	return guarantorFixture{account: identity.Address, history: history,
		code: base64.StdEncoding.EncodeToString(code.ToBOC()), data: base64.StdEncoding.EncodeToString(data.ToBOC())}
}

func (f guarantorFixture) byLT(lt uint64) int {
	for index, transaction := range f.history {
		if transaction.LT == lt {
			return index
		}
	}
	return -1
}

func blockOf(seqno uint64, root []byte) map[string]any {
	return map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": masterchainShard, "seqno": seqno,
		"root_hash": base64.StdEncoding.EncodeToString(root), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xf1}, 32))}
}

func txID(transaction tlb.Transaction) map[string]string {
	return map[string]string{"@type": "internal.transactionId", "lt": strconv.FormatUint(transaction.LT, 10),
		"hash": base64.StdEncoding.EncodeToString(transaction.Hash)}
}

func (f guarantorFixture) server(t *testing.T, node guarantorChain) string {
	t.Helper()
	genesisRoot, _ := hex.DecodeString(strings.TrimPrefix(guarantorTestNetwork.GenesisRootHash, "sha256:"))
	if node.genesisRoot != nil {
		genesisRoot = node.genesisRoot
	}
	genesisFile, _ := hex.DecodeString(strings.TrimPrefix(guarantorTestNetwork.GenesisFileHash, "sha256:"))
	effectiveRoot := bytes.Repeat([]byte{0xe1}, 32)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		raw, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(raw, &call); err != nil {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		var params struct {
			Address string `json:"address"`
			Seqno   uint64 `json:"seqno"`
			Limit   int    `json:"limit"`
			LT      string `json:"lt"`
		}
		_ = json.Unmarshal(call.Params, &params)
		now := time.Now().Unix()
		var result any
		switch call.Method {
		case "getConsensusBlock":
			result = map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": node.finalized,
				"timestamp": now, "last_block_utime": now}
		case "getMasterchainInfo":
			result = map[string]any{"@type": "blocks.masterchainInfo", "last": blockOf(node.finalized, bytes.Repeat([]byte{1}, 32)),
				"state_root_hash": "", "init": map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": masterchainShard,
					"seqno": 0, "root_hash": base64.StdEncoding.EncodeToString(genesisRoot),
					"file_hash": base64.StdEncoding.EncodeToString(genesisFile)}}
		case "getBlockHeader":
			result = map[string]any{"@type": "blocks.header", "id": blockOf(params.Seqno, node.headerRoot), "gen_utime": node.genUtime}
		case "getAddressInformation":
			last, root := f.history[f.byLT(200)], effectiveRoot
			if params.Seqno == 20 {
				last, root = f.history[0], node.boundRoot
			}
			result = map[string]any{"@type": "raw.fullAccountState", "balance": "1000", "code": f.code, "data": f.data,
				"block_id": blockOf(params.Seqno, root), "state": "active", "last_transaction_id": txID(last),
				"storage_stat": map[string]any{"@type": "storage.stat", "used_cells": "1", "used_bits": "1",
					"last_paid": 1, "due_payment": nil}}
		case "getTransactions":
			start, _ := strconv.ParseUint(params.LT, 10, 64)
			index := f.byLT(start)
			var page []map[string]any
			for index >= 0 && index < len(f.history) && len(page) < params.Limit {
				transaction := f.history[index]
				encoded, _ := transaction.ToCell()
				page = append(page, map[string]any{"@type": "raw.transaction", "data": base64.StdEncoding.EncodeToString(encoded.ToBOC()),
					"account": strings.TrimPrefix(f.account, "0:"), "transaction_id": txID(transaction)})
				index++
			}
			result = page
		default:
			http.Error(response, "unknown method", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func goodGuarantorChain() guarantorChain {
	root := bytes.Repeat([]byte{0xb2}, 32)
	return guarantorChain{finalized: 30, boundRoot: root, headerRoot: root, genUtime: 2100}
}

func guarantorReader(t *testing.T, fixture guarantorFixture, locator *nativecore.Locator, nodes []guarantorChain, maxHistory int) *GuarantorAuthorityReader {
	t.Helper()
	urls := make([]string, 0, len(nodes))
	for _, node := range nodes {
		urls = append(urls, fixture.server(t, node))
	}
	adapter, err := New(Config{Network: guarantorTestNetwork.NetworkId, Endpoints: urls, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewGuarantorAuthorityReader(adapter, locator, maxHistory)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func guarantorProof(fixture guarantorFixture, locator *nativecore.Locator) agentguarantor.NativeAgentHistoricalAuthorityProofV1 {
	effective := fixture.history[fixture.byLT(200)]
	return agentguarantor.NativeAgentHistoricalAuthorityProofV1{SchemaVersion: 1, NetworkID: guarantorTestNetwork.NetworkId,
		GenesisRootHash: guarantorTestNetwork.GenesisRootHash, GenesisFileHash: guarantorTestNetwork.GenesisFileHash,
		RegistryCodeHash: locator.CodeHash, AgentAccount: fixture.account,
		EffectiveTransaction: agentguarantor.FinalizedTransactionRefV1{LogicalTime: 200,
			TransactionHash: "sha256:" + hex.EncodeToString(effective.Hash)},
		EffectiveCheckpoint: agentguarantor.FinalizedCheckpointRefV1{Sequence: 10,
			RootHash: "sha256:" + strings.Repeat("e1", 32), FileHash: "sha256:" + strings.Repeat("f1", 32)},
		BoundCheckpoint: agentguarantor.FinalizedCheckpointRefV1{Sequence: 20,
			RootHash: "sha256:" + strings.Repeat("b2", 32), FileHash: "sha256:" + strings.Repeat("f1", 32)}}
}

// The reader reports, by quorum, the bound block header, the account's state
// and last transaction at the effective checkpoint, and the contiguous
// history between them; the check then accepts exactly that observation.
func TestGuarantorAuthorityReaderReadsTheProvenCheckpoints(t *testing.T) {
	locator := guarantorTestLocator(t)
	fixture := newGuarantorFixture(t, locator)
	good := goodGuarantorChain()
	liar := good
	liar.headerRoot = bytes.Repeat([]byte{0x66}, 32)
	reader := guarantorReader(t, fixture, locator, []guarantorChain{good, good, liar}, 0)
	proof := guarantorProof(fixture, locator)
	observation, err := reader.ReadNativeAgentHistory(context.Background(), proof, guarantorTestSubject)
	if err != nil {
		t.Fatal(err)
	}
	if observation.FinalizedSequence != 30 || observation.BoundGenerationUnix != 2100 ||
		observation.BoundCheckpoint != proof.BoundCheckpoint || observation.EffectiveCheckpoint != proof.EffectiveCheckpoint ||
		observation.EffectiveAccount != fixture.account || observation.EffectiveCodeHash != locator.CodeHash {
		t.Fatalf("unexpected checkpoints: %+v", observation)
	}
	if observation.EffectiveLastTransaction.Transaction != proof.EffectiveTransaction ||
		observation.EffectiveLastTransaction.BlockTimeUnix != 1000 ||
		observation.EffectiveLastTransaction.Previous.LogicalTime != 100 {
		t.Fatalf("unexpected effective transaction: %+v", observation.EffectiveLastTransaction)
	}
	if len(observation.History) != 3 || observation.History[0].Transaction.LogicalTime != 400 ||
		observation.History[2] != observation.EffectiveLastTransaction ||
		observation.BoundLastTransaction != observation.History[0].Transaction {
		t.Fatalf("unexpected history: %+v", observation.History)
	}
	// The served data is the uninitialized Registry account, so it holds no
	// Agent state; the check refuses that, and accepts the same reads once a
	// decoded Agent state with the key is present.
	expected := agentguarantor.NativeAgentAuthorityExpectationV1{Network: guarantorTestNetwork,
		RegistryCodeHash: locator.CodeHash, AgentAccount: fixture.account}
	var keyID [32]byte
	if observation.State != nil {
		t.Fatal("uninitialized account decoded as an Agent")
	}
	if _, err := agentguarantor.CheckNativeAgentHistoricalAuthorityV1(proof, observation, expected, guarantorTestSubject,
		keyID, 1500); err == nil {
		t.Fatal("an account without Agent state authorized a key")
	}
}

func TestGuarantorAuthorityReaderFailsClosed(t *testing.T) {
	locator := guarantorTestLocator(t)
	fixture := newGuarantorFixture(t, locator)
	good := goodGuarantorChain()
	unfinalized := good
	unfinalized.finalized = 19
	splitRoot := good
	splitRoot.boundRoot = bytes.Repeat([]byte{0x67}, 32)
	liar := good
	liar.headerRoot = bytes.Repeat([]byte{0x66}, 32)
	otherLiar := good
	otherLiar.headerRoot = bytes.Repeat([]byte{0x77}, 32)
	otherGenesis := good
	otherGenesis.genesisRoot = bytes.Repeat([]byte{0x99}, 32)
	cases := map[string]struct {
		nodes      []guarantorChain
		maxHistory int
		mutate     func(*agentguarantor.NativeAgentHistoricalAuthorityProofV1)
		want       string
	}{
		"bound checkpoint beyond finality": {nodes: []guarantorChain{unfinalized, unfinalized, unfinalized},
			want: "not finalized"},
		"no header quorum": {nodes: []guarantorChain{good, liar, otherLiar}, want: "quorum not reached"},
		"header agreed by a lying quorum": {nodes: []guarantorChain{good, liar, liar},
			want: "different bound blocks"},
		"account read names another block": {nodes: []guarantorChain{splitRoot, splitRoot, splitRoot},
			want: "different bound blocks"},
		"another genesis": {nodes: []guarantorChain{otherGenesis, otherGenesis, otherGenesis},
			want: "genesis root mismatch"},
		"history beyond its bound": {nodes: []guarantorChain{good, good, good}, maxHistory: 2,
			want: "exceeds its bound"},
		"proof names another account": {nodes: []guarantorChain{good, good, good},
			mutate: func(p *agentguarantor.NativeAgentHistoricalAuthorityProofV1) {
				p.AgentAccount = "0:" + strings.Repeat("c4", 32)
			}, want: "names another account"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			reader := guarantorReader(t, fixture, locator, test.nodes, test.maxHistory)
			proof := guarantorProof(fixture, locator)
			if test.mutate != nil {
				test.mutate(&proof)
			}
			_, err := reader.ReadNativeAgentHistory(context.Background(), proof, guarantorTestSubject)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("%s: want an error containing %q, got %v", name, test.want, err)
			}
		})
	}
	if _, err := NewGuarantorAuthorityReader(nil, locator, 0); err == nil {
		t.Fatal("reader without a chain was built")
	}
}
