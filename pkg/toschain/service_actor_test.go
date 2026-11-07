package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/chain"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

var (
	testActor  = "0:" + strings.Repeat("77", 32)
	testBuyer  = "0:" + strings.Repeat("21", 32)
	testOwner  = "0:" + strings.Repeat("11", 32)
	testKeyID  = bytes.Repeat([]byte{0x99}, 32)
	zeroHash32 = make([]byte, 32)
)

func rawAddress(t *testing.T, value string) *address.Address {
	t.Helper()
	parsed, err := address.ParseRawAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func internalIn(t *testing.T, sender string, body *cell.Cell) *tlb.Message {
	return &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{IHRDisabled: true, Bounce: true,
		SrcAddr: rawAddress(t, sender), DstAddr: rawAddress(t, testActor), Amount: tlb.FromNanoTONU(700_000_000),
		IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins, Body: body}}
}

func payout(t *testing.T, destination string, amount uint64) *tlb.Message {
	return &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{IHRDisabled: true,
		SrcAddr: rawAddress(t, testActor), DstAddr: rawAddress(t, destination), Amount: tlb.FromNanoTONU(amount),
		IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins, Body: cell.BeginCell().EndCell()}}
}

func externalOut(t *testing.T, source string, destination *address.Address, body *cell.Cell) *tlb.Message {
	return &tlb.Message{MsgType: tlb.MsgTypeExternalOut, Msg: &tlb.ExternalMessageOut{SrcAddr: rawAddress(t, source),
		DstAddr: destination, Body: body}}
}

func outputs(t *testing.T, messages ...*tlb.Message) *tlb.MessagesList {
	t.Helper()
	if len(messages) == 0 {
		return nil
	}
	dictionary := cell.NewDict(15)
	for index, message := range messages {
		encoded, err := message.ToCell()
		if err != nil {
			t.Fatal(err)
		}
		if err := dictionary.SetIntKey(big.NewInt(int64(index)), cell.BeginCell().MustStoreRef(encoded).EndCell()); err != nil {
			t.Fatal(err)
		}
	}
	return &tlb.MessagesList{List: dictionary}
}

// buildTransaction serializes a finalized transaction, re-parses it so the
// value is exactly what a reader decodes, and chains it to prev.
func buildTransaction(t *testing.T, lt uint64, now uint32, prev *tlb.Transaction, in *tlb.Message, success bool, exit int32, out ...*tlb.Message) tlb.Transaction {
	t.Helper()
	account, _ := hex.DecodeString(strings.TrimPrefix(testActor, "0:"))
	transaction := tlb.Transaction{AccountAddr: account, LT: lt, PrevTxHash: zeroHash32, Now: now,
		OutMsgCount: uint16(len(out)), OrigStatus: tlb.AccountStatusActive, EndStatus: tlb.AccountStatusActive,
		TotalFees: tlb.CurrencyCollection{Coins: tlb.ZeroCoins}, StateUpdate: tlb.HashUpdate{OldHash: zeroHash32, NewHash: zeroHash32},
		Description: tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{Success: success,
			GasFees: tlb.ZeroCoins, Details: tlb.ComputePhaseVMDetails{GasUsed: big.NewInt(0), GasLimit: big.NewInt(0), ExitCode: exit,
				VMInitStateHash: zeroHash32, VMFinalStateHash: zeroHash32}}}, Aborted: !success}}
	if prev != nil {
		transaction.PrevTxLT, transaction.PrevTxHash = prev.LT, prev.Hash
	}
	transaction.IO.In = in
	transaction.IO.Out = outputs(t, out...)
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

func testTerms(hasAttestor bool) nativecore.ServiceActorTermsV1 {
	terms := nativecore.ServiceActorTermsV1{PolicyVersion: 2, PricePerCall: big.NewInt(300_000_000), StorageFee: big.NewInt(200_000_000),
		CleanupBounty: big.NewInt(100_000_000), ResponseSLA: 3600, RefundClaimWindow: 3600, HasAttestor: hasAttestor,
		ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme}
	copy(terms.MetadataHash[:], bytes.Repeat([]byte{0x66}, 32))
	if hasAttestor {
		copy(terms.AttestorKeyID[:], testKeyID)
	}
	return terms
}

func sar1(t *testing.T, requestID uint64, caller string, requestHash []byte, now uint32, terms nativecore.ServiceActorTermsV1) *cell.Cell {
	t.Helper()
	termsCell, err := nativecore.BuildServiceActorTermsCell(terms)
	if err != nil {
		t.Fatal(err)
	}
	responseDeadline := uint64(now) + uint64(terms.ResponseSLA)
	return cell.BeginCell().MustStoreUInt(nativecore.ServiceActorRequestSnapshotTag, 32).MustStoreUInt(requestID, 64).
		MustStoreAddr(rawAddress(t, caller)).MustStoreSlice(requestHash, 256).MustStoreUInt(responseDeadline, 64).
		MustStoreUInt(responseDeadline+uint64(terms.RefundClaimWindow), 64).MustStoreRef(termsCell).EndCell()
}

func callBodyCell(t *testing.T, query uint64, requestHash []byte, terms nativecore.ServiceActorTermsV1) *cell.Cell {
	termsHash, err := nativecore.ServiceActorTermsHash(terms)
	if err != nil {
		t.Fatal(err)
	}
	var request [32]byte
	copy(request[:], requestHash)
	return nativecore.BuildServiceActorCallBody(query, request, termsHash)
}

func TestClassifyActorTransactions(t *testing.T) {
	terms := testTerms(true)
	request := bytes.Repeat([]byte{0x44}, 32)
	call := buildTransaction(t, 10, 1000, nil, internalIn(t, testBuyer, callBodyCell(t, 5, request, terms)), true, 0,
		externalOut(t, testActor, nil, sar1(t, 0, testBuyer, request, 1000, terms)), payout(t, testBuyer, 1000))
	respond := buildTransaction(t, 11, 1001, &call, internalIn(t, testOwner, cell.BeginCell().
		MustStoreUInt(nativecore.ServiceActorRespondOpcode, 32).MustStoreUInt(1, 64).MustStoreUInt(0, 64).
		MustStoreSlice(bytes.Repeat([]byte{0xcc}, 32), 256).MustStoreRef(cell.BeginCell().EndCell()).EndCell()), true, 0)
	malformed := buildTransaction(t, 12, 1002, &respond, internalIn(t, testBuyer, cell.BeginCell().MustStoreUInt(7, 3).EndCell()), false, 9)
	failedCall := buildTransaction(t, 13, 1003, &malformed, internalIn(t, testBuyer, callBodyCell(t, 6, request, terms)), false, 1926)
	claim := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorClaimRefundOpcode, 32).MustStoreUInt(2, 64).MustStoreUInt(0, 64).
		MustStoreAddr(rawAddress(t, testBuyer)).EndCell()
	claimed := buildTransaction(t, 14, 1004, &failedCall, internalIn(t, testBuyer, claim), true, 0, payout(t, testBuyer, 300_000_000))
	history := []tlb.Transaction{claimed, failedCall, malformed, respond, call}
	got, err := ClassifyActorTransactions(testActor, history)
	if err != nil {
		t.Fatal(err)
	}
	if got[4].Kind != ActorTxCall || got[4].Call.QueryID != 5 || got[4].Snapshot == nil || got[4].Sender != testBuyer {
		t.Fatalf("call: %+v", got[4])
	}
	snapshot, err := got[4].Snapshot.Decode()
	if err != nil || snapshot.RequestID != 0 || snapshot.TermsHash != mustTermsHash(t, terms) {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	if got[3].Kind != ActorTxRespond || !got[3].Signed || got[3].RequestID != 0 || got[3].ResponseHash != strings.Repeat("cc", 32) {
		t.Fatalf("respond: %+v", got[3])
	}
	if got[2].Kind != ActorTxFailed || got[2].ExitCode != 9 || got[2].Call != nil || got[2].BodyBOC == "" {
		t.Fatalf("malformed failed transaction: %+v", got[2])
	}
	if got[1].Kind != ActorTxFailed || got[1].Call == nil || got[1].Call.QueryID != 6 || got[1].ExitCode != 1926 {
		t.Fatalf("failed call: %+v", got[1])
	}
	if got[0].Kind != ActorTxClaim || got[0].Destination != testBuyer || len(got[0].Payouts) != 1 || got[0].Payouts[0].AmountNano != "300000000" {
		t.Fatalf("claim: %+v", got[0])
	}

	refused := map[string]tlb.Transaction{
		"call without snapshot": buildTransaction(t, 20, 1000, nil, internalIn(t, testBuyer, callBodyCell(t, 5, request, terms)), true, 0),
		"call with two snapshots": buildTransaction(t, 20, 1000, nil, internalIn(t, testBuyer, callBodyCell(t, 5, request, terms)), true, 0,
			externalOut(t, testActor, nil, sar1(t, 0, testBuyer, request, 1000, terms)), externalOut(t, testActor, nil, sar1(t, 0, testBuyer, request, 1000, terms))),
		"snapshot from another source": buildTransaction(t, 20, 1000, nil, internalIn(t, testBuyer, callBodyCell(t, 5, request, terms)), true, 0,
			externalOut(t, testBuyer, nil, sar1(t, 0, testBuyer, request, 1000, terms))),
		"snapshot to an address": buildTransaction(t, 20, 1000, nil, internalIn(t, testBuyer, callBodyCell(t, 5, request, terms)), true, 0,
			externalOut(t, testActor, address.NewAddressExt(0, 8, []byte{1}), sar1(t, 0, testBuyer, request, 1000, terms))),
		"malformed snapshot": buildTransaction(t, 20, 1000, nil, internalIn(t, testBuyer, callBodyCell(t, 5, request, terms)), true, 0,
			externalOut(t, testActor, nil, cell.BeginCell().MustStoreUInt(nativecore.ServiceActorRequestSnapshotTag, 32).EndCell())),
		"successful undecodable body": buildTransaction(t, 20, 1000, nil, internalIn(t, testBuyer, cell.BeginCell().MustStoreUInt(7, 3).EndCell()), true, 0),
		"snapshot outside a call": buildTransaction(t, 20, 1000, nil, internalIn(t, testOwner, cell.BeginCell().
			MustStoreUInt(nativecore.ServiceActorExpireOpcode, 32).MustStoreUInt(1, 64).MustStoreUInt(0, 64).EndCell()), true, 0,
			externalOut(t, testActor, nil, sar1(t, 0, testBuyer, request, 1000, terms))),
	}
	for name, transaction := range refused {
		if _, err := ClassifyActorTransactions(testActor, []tlb.Transaction{transaction}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := ClassifyActorTransactions("0:"+strings.Repeat("78", 32), []tlb.Transaction{malformed}); err == nil {
		t.Error("another account's history was accepted")
	}
}

func mustTermsHash(t *testing.T, terms nativecore.ServiceActorTermsV1) [32]byte {
	hash, err := nativecore.ServiceActorTermsHash(terms)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestGetterStackIsReturnedInDeclaredOrder(t *testing.T) {
	raw := []json.RawMessage{json.RawMessage(`["num","3"]`), json.RawMessage(`["null"]`), json.RawMessage(`["num","1"]`)}
	stack, err := decodeGetterStack(raw)
	if err != nil || len(stack) != 3 || stack[0].Number.Int64() != 1 || stack[1].Kind != "null" || stack[2].Number.Int64() != 3 {
		t.Fatalf("stack = %+v, %v", stack, err)
	}
	if _, err := decodeGetterStack([]json.RawMessage{json.RawMessage(`["tuple",{}]`)}); err == nil {
		t.Fatal("an unsupported entry was accepted")
	}
}

// historyServer serves getTransactions pages from a fixed newest-first
// history, optionally corrupting it.
func historyServer(t *testing.T, history []tlb.Transaction, corrupt func([]map[string]any)) *rpcNode {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				Limit int    `json:"limit"`
				LT    string `json:"lt"`
				Hash  string `json:"hash"`
			} `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&call); err != nil || call.Method != "getTransactions" {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		var page []map[string]any
		for index, transaction := range history {
			if strconv.FormatUint(transaction.LT, 10) != call.Params.LT {
				continue
			}
			for _, item := range history[index:] {
				if len(page) == call.Params.Limit {
					break
				}
				encoded, _ := item.ToCell()
				page = append(page, map[string]any{"@type": "raw.transaction", "data": base64.StdEncoding.EncodeToString(encoded.ToBOC()),
					"account": strings.TrimPrefix(testActor, "0:"), "transaction_id": map[string]string{"@type": "internal.transactionId",
						"lt": strconv.FormatUint(item.LT, 10), "hash": base64.StdEncoding.EncodeToString(item.Hash)}})
			}
		}
		if corrupt != nil {
			corrupt(page)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": page})
	}))
	t.Cleanup(server.Close)
	client, err := chain.NewClient(server.URL, 5*time.Second, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	return &rpcNode{client: client}
}

func linearHistory(t *testing.T, count int) []tlb.Transaction {
	t.Helper()
	var previous *tlb.Transaction
	oldestFirst := make([]tlb.Transaction, 0, count)
	for index := 0; index < count; index++ {
		transaction := buildTransaction(t, uint64(10+index), 1000, previous, internalIn(t, testBuyer, cell.BeginCell().EndCell()), true, 0)
		oldestFirst = append(oldestFirst, transaction)
		previous = &oldestFirst[len(oldestFirst)-1]
	}
	newestFirst := make([]tlb.Transaction, count)
	for index := range oldestFirst {
		newestFirst[count-1-index] = oldestFirst[index]
	}
	return newestFirst
}

func headID(transaction tlb.Transaction) transactionID {
	return transactionID{Type: "internal.transactionId", LT: strconv.FormatUint(transaction.LT, 10),
		Hash: base64.StdEncoding.EncodeToString(transaction.Hash)}
}

func TestActorHistoryWalkIsCompleteOrAnchoredNeverPartial(t *testing.T) {
	history := linearHistory(t, 300)
	node := historyServer(t, history, nil)
	ctx := context.Background()
	all, result, err := walkActorHistory(ctx, node, testActor, headID(history[0]), nil, 1000)
	if err != nil || result != HistoryComplete || len(all) != 300 || all[299].PrevTxLT != 0 {
		t.Fatalf("complete walk: %d %s %v", len(all), result, err)
	}
	anchor := &ActorTxID{LT: history[280].LT, Hash: hex.EncodeToString(history[280].Hash)}
	newer, result, err := walkActorHistory(ctx, node, testActor, headID(history[0]), anchor, 1000)
	if err != nil || result != HistoryAnchorReached || len(newer) != 280 {
		t.Fatalf("anchored walk: %d %s %v", len(newer), result, err)
	}
	if got, result, err := walkActorHistory(ctx, node, testActor, headID(history[0]), &ActorTxID{LT: history[0].LT,
		Hash: hex.EncodeToString(history[0].Hash)}, 1000); err != nil || result != HistoryAnchorReached || len(got) != 0 {
		t.Fatalf("anchor at head: %d %s %v", len(got), result, err)
	}
	forged := &ActorTxID{LT: history[280].LT, Hash: strings.Repeat("ab", 32)}
	if _, _, err := walkActorHistory(ctx, node, testActor, headID(history[0]), forged, 1000); !errors.Is(err, ErrHistoryAnchorMissing) {
		t.Fatalf("an anchor absent from the history was not refused: %v", err)
	}
	// A forged anchor inside the walked range is refused as soon as the walk
	// passes its logical time, before the bound is spent.
	early := &ActorTxID{LT: history[20].LT, Hash: strings.Repeat("ab", 32)}
	if _, _, err := walkActorHistory(ctx, node, testActor, headID(history[0]), early, 50); !errors.Is(err, ErrHistoryAnchorMissing) {
		t.Fatalf("a forged anchor was not refused at its logical time: %v", err)
	}
	// An anchor older than the account's first transaction is refused at the
	// origin, never reported as complete.
	beforeOrigin := &ActorTxID{LT: 1, Hash: strings.Repeat("ab", 32)}
	if _, _, err := walkActorHistory(ctx, node, testActor, headID(history[0]), beforeOrigin, 1000); !errors.Is(err, ErrHistoryAnchorMissing) {
		t.Fatalf("an anchor before the origin was not refused: %v", err)
	}
	if _, _, err := walkActorHistory(ctx, node, testActor, headID(history[0]), nil, 299); !errors.Is(err, ErrHistoryBoundExceeded) {
		t.Fatalf("the bound was not enforced: %v", err)
	}
	broken := historyServer(t, history, func(page []map[string]any) {
		if len(page) > 3 {
			page[2], page[3] = page[3], page[2]
		}
	})
	if _, _, err := walkActorHistory(ctx, broken, testActor, headID(history[0]), nil, 1000); err == nil {
		t.Fatal("a discontinuous history was accepted")
	}
	foreign := historyServer(t, history, func(page []map[string]any) {
		if len(page) > 0 {
			page[0]["account"] = strings.Repeat("78", 32)
		}
	})
	if _, _, err := walkActorHistory(ctx, foreign, testActor, headID(history[0]), nil, 1000); err == nil {
		t.Fatal("another account's transaction was accepted")
	}
}
