package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	registryAgent      = "agent_" + "4444444444444444444444444444444444444444444444444444444444444444"
	registryCapability = "cap_" + "3333333333333333333333333333333333333333333333333333333333333333"
	registryOtherCap   = "cap_" + "3434343434343434343434343434343434343434343434343434343434343434"
)

// registryLocator is the Registry locator of the frozen registry vectors.
func registryLocator(t *testing.T) *nativecore.Locator {
	t.Helper()
	raw, err := os.ReadFile("../nativecore/testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		CodeHash string `json:"contract_code_hash"`
		CodeBOC  string `json:"contract_code_boc_base64"`
		Network  struct {
			NetworkID string `json:"network_id"`
			Root      string `json:"genesis_root_hash"`
			File      string `json:"genesis_file_hash"`
		} `json:"network"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	locator, err := nativecore.NewLocator(&nativev1.NetworkDomain{NetworkId: vectors.Network.NetworkID,
		GenesisRootHash: vectors.Network.Root, GenesisFileHash: vectors.Network.File}, 0, vectors.CodeBOC, vectors.CodeHash)
	if err != nil {
		t.Fatal(err)
	}
	return locator
}

// revocationBody is the inbound body of one revocation from the independent
// reference encoder.
func revocationBody(t *testing.T, target, owner, version string, sequence uint64) (*cell.Cell, string) {
	t.Helper()
	result, err := referencecodec.EncodeRevocation(referencecodec.Revocation{
		Network: referencecodec.Network{NetworkID: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
			GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32), Target: target, Generation: 1, Sequence: sequence,
		Predecessor: "tvm-cell-sha256:" + strings.Repeat("66", 32), NonceHex: strings.Repeat("6e", 32),
		OwnerAgentID: owner, Version: version})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(result.BodyBOC)
	if err != nil {
		t.Fatal(err)
	}
	body, err := cell.FromBOC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return body, result.ActionHash
}

// registryStep is one transaction. A successful step has a successful compute
// phase and is not aborted; aborted and computeFailed break exactly one of the
// two, external and noInput replace the internal inbound message.
type registryStep struct {
	body          *cell.Cell
	success       bool
	bounced       bool
	aborted       bool
	computeFailed bool
	external      bool
	noInput       bool
}

// registryHistory builds a finalized newest-first history of account from
// oldest-first steps at logical times 10, 20, 30, ...
func registryHistory(t *testing.T, account string, steps ...registryStep) []tlb.Transaction {
	t.Helper()
	raw, _ := hex.DecodeString(strings.TrimPrefix(account, "0:"))
	oldestFirst := make([]tlb.Transaction, 0, len(steps))
	for index, step := range steps {
		in := &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{IHRDisabled: true, Bounce: true, Bounced: step.bounced,
			SrcAddr: rawAddress(t, testOwner), DstAddr: rawAddress(t, account), Amount: tlb.FromNanoTONU(50_000_000),
			IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins, Body: step.body}}
		if step.external {
			in = &tlb.Message{MsgType: tlb.MsgTypeExternalIn, Msg: &tlb.ExternalMessage{SrcAddr: address.NewAddressNone(),
				DstAddr: rawAddress(t, account), ImportFee: tlb.ZeroCoins, Body: step.body}}
		}
		if step.noInput {
			in = nil
		}
		transaction := tlb.Transaction{AccountAddr: raw, LT: uint64(10 * (index + 1)), PrevTxHash: zeroHash32, Now: 1000,
			OrigStatus: tlb.AccountStatusActive, EndStatus: tlb.AccountStatusActive,
			TotalFees: tlb.CurrencyCollection{Coins: tlb.ZeroCoins}, StateUpdate: tlb.HashUpdate{OldHash: zeroHash32, NewHash: zeroHash32},
			Description: tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{
				Success: step.success && !step.computeFailed,
				GasFees: tlb.ZeroCoins, Details: tlb.ComputePhaseVMDetails{GasUsed: big.NewInt(0), GasLimit: big.NewInt(0),
					VMInitStateHash: zeroHash32, VMFinalStateHash: zeroHash32}}}, Aborted: !step.success || step.aborted}}
		if index > 0 {
			transaction.PrevTxLT, transaction.PrevTxHash = oldestFirst[index-1].LT, oldestFirst[index-1].Hash
		}
		transaction.IO.In = in
		encoded, err := transaction.ToCell()
		if err != nil {
			t.Fatal(err)
		}
		var parsed tlb.Transaction
		if err := tlb.LoadFromCell(&parsed, encoded.MustBeginParse()); err != nil {
			t.Fatal(err)
		}
		parsed.Hash = encoded.Hash()
		oldestFirst = append(oldestFirst, parsed)
	}
	newestFirst := make([]tlb.Transaction, len(oldestFirst))
	for index := range oldestFirst {
		newestFirst[len(oldestFirst)-1-index] = oldestFirst[index]
	}
	return newestFirst
}

// registryServer is a finalized endpoint serving one account's last
// transaction and history at checkpoint 42.
func registryServer(t *testing.T, account string, history []tlb.Transaction, root []byte) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				Address string `json:"address"`
				Limit   int    `json:"limit"`
				LT      string `json:"lt"`
				Hash    string `json:"hash"`
			} `json:"params"`
		}
		raw, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(raw, &call); err != nil || call.Params.Address != account {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		var result any
		switch call.Method {
		case "getAddressInformation":
			last := map[string]string{"@type": "internal.transactionId", "lt": "0", "hash": base64.StdEncoding.EncodeToString(zeroHash32)}
			if len(history) > 0 {
				last["lt"], last["hash"] = strconv.FormatUint(history[0].LT, 10), base64.StdEncoding.EncodeToString(history[0].Hash)
			}
			result = map[string]any{"@type": "raw.fullAccountState", "state": "active", "last_transaction_id": last,
				"block_id": map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": "8000000000000000", "seqno": 42,
					"root_hash": base64.StdEncoding.EncodeToString(root), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xf1}, 32))}}
		case "getTransactions":
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
						"account": strings.TrimPrefix(account, "0:"), "transaction_id": map[string]string{"@type": "internal.transactionId",
							"lt": strconv.FormatUint(item.LT, 10), "hash": base64.StdEncoding.EncodeToString(item.Hash)}})
				}
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

func registrySession(t *testing.T, locator *nativecore.Locator, bound int, urls ...string) *ServiceActorSession {
	t.Helper()
	session := testSession(t, urls...)
	session.reader.registry = &SimplifiedNativeResolver{locator: locator}
	session.reader.maxHistory = bound
	return session
}

func TestRegistryTransitionIsTheEarliestSuccessfulApplication(t *testing.T) {
	ctx := context.Background()
	locator := registryLocator(t)
	address := func(object string) string {
		identity, err := locator.Locate(object)
		if err != nil {
			t.Fatal(err)
		}
		return identity.Address
	}
	root := bytes.Repeat([]byte{0xa1}, 32)
	serve := func(object string, bound int, steps ...registryStep) *ServiceActorSession {
		history := registryHistory(t, address(object), steps...)
		account := address(object)
		return registrySession(t, locator, bound, registryServer(t, account, history, root), registryServer(t, account, history, root),
			registryServer(t, account, history, root))
	}
	transfer := registryStep{body: cell.BeginCell().EndCell(), success: true}
	agentTombstone, agentAction := revocationBody(t, registryAgent, "", "", 4)
	capTombstone, capAction := revocationBody(t, registryCapability, registryAgent, "", 4)
	otherTombstone, _ := revocationBody(t, registryOtherCap, registryAgent, "", 4)
	revoke1, revoke1Action := revocationBody(t, registryCapability, registryAgent, "1.0.0", 3)
	revoke2, _ := revocationBody(t, registryCapability, registryAgent, "2.0.0", 2)

	cases := []struct {
		name    string
		object  string
		kind    nativecore.RegistryTransitionKind
		version string
		steps   []registryStep
		want    *RegistryTransitionTx
	}{
		// A replay of the tombstone after it is the same action succeeding
		// again; the transition is the first application.
		{"agent tombstone then replays", registryAgent, nativecore.RegistryAgentTombstone, "",
			[]registryStep{transfer, {body: agentTombstone, success: true}, transfer, {body: agentTombstone, success: true}},
			&RegistryTransitionTx{LT: 20, ActionHash: agentAction}},
		{"capability tombstone after a failed, a bounced and another object's tombstone", registryCapability,
			nativecore.RegistryCapabilityTombstone, "",
			[]registryStep{{body: capTombstone}, {body: capTombstone, success: true, bounced: true}, {body: otherTombstone, success: true},
				{body: revoke1, success: true}, {body: capTombstone, success: true}, {body: capTombstone, success: true}},
			&RegistryTransitionTx{LT: 50, ActionHash: capAction}},
		{"version revocation among others", registryCapability, nativecore.RegistryVersionRevocation, "1.0.0",
			[]registryStep{{body: revoke2, success: true}, {body: revoke1, success: true}, {body: revoke1, success: true}},
			&RegistryTransitionTx{LT: 20, ActionHash: revoke1Action}},
		{"another version's revocation only", registryCapability, nativecore.RegistryVersionRevocation, "1.0.0",
			[]registryStep{{body: revoke2, success: true}, transfer}, nil},
		{"a version revocation is not a tombstone", registryCapability, nativecore.RegistryCapabilityTombstone, "",
			[]registryStep{{body: revoke1, success: true}}, nil},
		{"failed tombstone", registryAgent, nativecore.RegistryAgentTombstone, "", []registryStep{{body: agentTombstone}}, nil},
		{"aborted tombstone", registryAgent, nativecore.RegistryAgentTombstone, "",
			[]registryStep{{body: agentTombstone, success: true, aborted: true}}, nil},
		{"tombstone whose compute phase failed", registryAgent, nativecore.RegistryAgentTombstone, "",
			[]registryStep{{body: agentTombstone, success: true, computeFailed: true}}, nil},
		{"bounced tombstone", registryAgent, nativecore.RegistryAgentTombstone, "",
			[]registryStep{{body: agentTombstone, success: true, bounced: true}}, nil},
		{"external tombstone", registryAgent, nativecore.RegistryAgentTombstone, "",
			[]registryStep{{body: agentTombstone, success: true, external: true}}, nil},
		{"transaction without an inbound message", registryAgent, nativecore.RegistryAgentTombstone, "",
			[]registryStep{{success: true, noInput: true}}, nil},
		{"another object's tombstone only", registryCapability, nativecore.RegistryCapabilityTombstone, "",
			[]registryStep{{body: otherTombstone, success: true}}, nil},
		{"no history", registryAgent, nativecore.RegistryAgentTombstone, "", nil, nil},
	}
	for _, c := range cases {
		session := serve(c.object, 1000, c.steps...)
		got, err := session.RegistryTransition(ctx, c.object, c.kind, c.version)
		if c.want == nil {
			if !errors.Is(err, ErrRegistryTransitionUnproven) {
				t.Errorf("%s: want unproven, got %+v %v", c.name, got, err)
			}
			continue
		}
		if err != nil || got == nil || got.LT != c.want.LT || got.ActionHash != c.want.ActionHash || len(got.Hash) != 64 {
			t.Errorf("%s: got %+v %v, want %+v", c.name, got, err, c.want)
		}
	}

	// A history longer than the bound proves nothing, even when its newest
	// transactions hold the transition.
	long := serve(registryAgent, 3, transfer, transfer, transfer, registryStep{body: agentTombstone, success: true})
	if got, err := long.RegistryTransition(ctx, registryAgent, nativecore.RegistryAgentTombstone, ""); !errors.Is(err, ErrRegistryTransitionUnproven) {
		t.Fatalf("a bounded history proved a transition: %+v %v", got, err)
	}
	within := serve(registryAgent, 4, transfer, transfer, transfer, registryStep{body: agentTombstone, success: true})
	if got, err := within.RegistryTransition(ctx, registryAgent, nativecore.RegistryAgentTombstone, ""); err != nil || got.LT != 40 {
		t.Fatalf("a history at the bound: %+v %v", got, err)
	}

	for name, request := range map[string]struct {
		object  string
		kind    nativecore.RegistryTransitionKind
		version string
	}{
		"agent kind on a Capability":  {registryCapability, nativecore.RegistryAgentTombstone, ""},
		"capability kind on an Agent": {registryAgent, nativecore.RegistryCapabilityTombstone, ""},
		"version on a tombstone":      {registryCapability, nativecore.RegistryCapabilityTombstone, "1.0.0"},
		"revocation without version":  {registryCapability, nativecore.RegistryVersionRevocation, ""},
		"unknown kind":                {registryAgent, 0, ""},
	} {
		session := serve(registryAgent, 1000)
		if _, err := session.RegistryTransition(ctx, request.object, request.kind, request.version); err == nil ||
			errors.Is(err, ErrRegistryTransitionUnproven) {
			t.Errorf("%s: the request was not refused: %v", name, err)
		}
	}
}

func TestRegistryTransitionRefusesAnotherAccountsTransaction(t *testing.T) {
	tombstone, _ := revocationBody(t, registryAgent, "", "", 4)
	history := registryHistory(t, testActor, registryStep{body: tombstone, success: true})
	if _, found, err := earliestRegistryTransition("0:"+strings.Repeat("78", 32), history, registryAgent,
		nativecore.RegistryAgentTombstone, ""); err == nil || found {
		t.Fatalf("another account's transaction was read: %v %v", found, err)
	}
	if got, found, err := earliestRegistryTransition(testActor, history, registryAgent, nativecore.RegistryAgentTombstone, ""); err != nil ||
		!found || got.LT != 10 {
		t.Fatalf("the account's own transaction: %+v %v %v", got, found, err)
	}
}

func TestRegistryTransitionPinsTheSessionBlock(t *testing.T) {
	locator := registryLocator(t)
	identity, err := locator.Locate(registryAgent)
	if err != nil {
		t.Fatal(err)
	}
	tombstone, _ := revocationBody(t, registryAgent, "", "", 4)
	history := registryHistory(t, identity.Address, registryStep{body: tombstone, success: true})
	other := bytes.Repeat([]byte{0xa2}, 32)
	session := registrySession(t, locator, 1000, registryServer(t, identity.Address, history, other),
		registryServer(t, identity.Address, history, other), registryServer(t, identity.Address, history, other))
	if err := session.pinHashes("sha256:"+strings.Repeat("a1", 32), "sha256:"+strings.Repeat("f1", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.RegistryTransition(context.Background(), registryAgent, nativecore.RegistryAgentTombstone, ""); err == nil {
		t.Fatal("a history read at another block of the same sequence number was accepted")
	}
}
