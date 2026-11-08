package toschain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type fixedRelayResolutionSource struct {
	calls      atomic.Int32
	resolution agentrelay.ChainResolution
}

func (source *fixedRelayResolutionSource) ResolveExactRelay(_ context.Context,
	_ agentrelay.Record) (agentrelay.ChainResolution, error) {
	source.calls.Add(1)
	return source.resolution, nil
}

func TestTOSExactRelayBroadcasterWritesPrimaryOnceAndTreatsHashAsTentative(t *testing.T) {
	_, boc, _ := loadRelayRustFixture(t)
	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			JSONRPC string `json:"jsonrpc"`
			ID      uint64 `json:"id"`
			Method  string `json:"method"`
		}
		if json.NewDecoder(request.Body).Decode(&call) != nil || call.JSONRPC != "2.0" ||
			call.Method != "sendBocReturnHash" {
			http.Error(response, "bad call", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
			"result": map[string]any{"status": 1, "hash": base64.StdEncoding.EncodeToString(root.Hash())}})
	})
	adapter := relayTestAdapter(t, servers)
	network := relayTestNetwork()
	source := &fixedRelayResolutionSource{resolution: agentrelay.ChainResolution{State: agentcommerce.ActionSubmitted}}
	broadcaster, err := NewTOSExactRelayBroadcaster(adapter, network, source)
	if err != nil {
		t.Fatal(err)
	}
	result, err := broadcaster.SubmitExact(t.Context(), relayBroadcasterExecution(t, network, boc))
	if err != nil || result.Status != agentrelay.BroadcastAccepted || result.TransactionReference == "" {
		t.Fatalf("unexpected exact submission: result=%+v err=%v", result, err)
	}
	if hits[0].Load() != 1 || hits[1].Load() != 0 || hits[2].Load() != 0 {
		t.Fatalf("write was not confined to the primary endpoint: %d/%d/%d",
			hits[0].Load(), hits[1].Load(), hits[2].Load())
	}
}

func TestTOSExactRelayBroadcasterNeverFailsOverAmbiguousWrite(t *testing.T) {
	_, boc, _ := loadRelayRustFixture(t)
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "lost acknowledgement", http.StatusServiceUnavailable)
	})
	adapter := relayTestAdapter(t, servers)
	network := relayTestNetwork()
	broadcaster, err := NewTOSExactRelayBroadcaster(adapter, network, &fixedRelayResolutionSource{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := broadcaster.SubmitExact(t.Context(), relayBroadcasterExecution(t, network, boc))
	if err == nil || result.Status != agentrelay.BroadcastUnknown || result.TransactionReference == "" {
		t.Fatalf("ambiguous write was not preserved: result=%+v err=%v", result, err)
	}
	if hits[0].Load() != 1 || hits[1].Load() != 0 || hits[2].Load() != 0 {
		t.Fatal("ambiguous write attempted endpoint failover")
	}
}

func TestTOSExactRelayBroadcasterTreatsZeroNodeStatusAsAmbiguous(t *testing.T) {
	_, boc, _ := loadRelayRustFixture(t)
	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID uint64 `json:"id"`
		}
		_ = json.NewDecoder(request.Body).Decode(&call)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
			"result": map[string]any{"status": 0, "hash": base64.StdEncoding.EncodeToString(root.Hash())}})
	})
	network := relayTestNetwork()
	broadcaster, err := NewTOSExactRelayBroadcaster(relayTestAdapter(t, servers), network,
		&fixedRelayResolutionSource{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := broadcaster.SubmitExact(t.Context(), relayBroadcasterExecution(t, network, boc))
	if err == nil || result.Status != agentrelay.BroadcastUnknown || result.TransactionReference == "" {
		t.Fatalf("undocumented zero status granted retry permission: result=%+v err=%v", result, err)
	}
}

func TestTOSExactRelayBroadcasterTreatsUnknownNodeStatusAsAmbiguous(t *testing.T) {
	_, boc, _ := loadRelayRustFixture(t)
	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID uint64 `json:"id"`
		}
		_ = json.NewDecoder(request.Body).Decode(&call)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
			"result": map[string]any{"status": 2, "hash": base64.StdEncoding.EncodeToString(root.Hash())}})
	})
	network := relayTestNetwork()
	broadcaster, err := NewTOSExactRelayBroadcaster(relayTestAdapter(t, servers), network,
		&fixedRelayResolutionSource{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := broadcaster.SubmitExact(t.Context(), relayBroadcasterExecution(t, network, boc))
	if err == nil || result.Status != agentrelay.BroadcastUnknown || result.TransactionReference == "" {
		t.Fatalf("unknown node status granted retry permission: result=%+v err=%v", result, err)
	}
}

func TestTOSExactRelayBroadcasterRequiresFullPinnedNetworkIdentity(t *testing.T) {
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(http.ResponseWriter, *http.Request) {})
	endpoints := make([]string, len(servers))
	for index := range servers {
		endpoints[index] = servers[index].URL
	}
	network := relayTestNetwork()
	adapter, err := New(Config{Network: network.NetworkID, Endpoints: endpoints, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTOSExactRelayBroadcaster(adapter, network, &fixedRelayResolutionSource{}); err == nil {
		t.Fatal("display-only network configuration authorized a bearer relay write")
	}
	adapter = relayTestAdapter(t, servers)
	wrong := network
	wrong.ZeroStateFileHash = shaDigest("f")
	if _, err := NewTOSExactRelayBroadcaster(adapter, wrong, &fixedRelayResolutionSource{}); err == nil {
		t.Fatal("zero-state substitution authorized a bearer relay write")
	}
}

func TestVerifyPinnedRelayGenesisIsReadOnlyAndQuorumBacked(t *testing.T) {
	var writeHits [3]atomic.Int32
	servers := relayRPCServers(t, &writeHits, func(http.ResponseWriter, *http.Request) {
		t.Fatal("read-only relay genesis verification attempted a bearer write")
	})
	adapter := relayTestAdapter(t, servers)
	if err := adapter.VerifyPinnedRelayGenesis(t.Context(), relayTestNetwork()); err != nil {
		t.Fatal(err)
	}
	if writeHits[0].Load() != 0 || writeHits[1].Load() != 0 || writeHits[2].Load() != 0 {
		t.Fatal("relay genesis verification produced a write")
	}
}

func TestVerifyPinnedRelayGenesisRejectsNoncanonicalZeroStateCoordinates(t *testing.T) {
	for _, test := range []struct {
		name  string
		shard string
		seqno uint64
	}{
		{name: "wrong shard", shard: "0", seqno: 0},
		{name: "nonzero seqno", shard: "-9223372036854775808", seqno: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			servers := make([]*httptest.Server, 0, 3)
			for index := 0; index < 3; index++ {
				server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					var call struct {
						ID     uint64 `json:"id"`
						Method string `json:"method"`
					}
					if json.NewDecoder(request.Body).Decode(&call) != nil || call.Method != "getMasterchainInfo" {
						http.Error(response, "unexpected relay write", http.StatusBadRequest)
						return
					}
					response.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
						"result": map[string]any{"@type": "blocks.masterchainInfo", "last": map[string]any{},
							"state_root_hash": "", "init": map[string]any{"@type": "tos.blockIdExt", "workchain": -1,
								"shard": test.shard, "seqno": test.seqno,
								"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
								"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))}}})
				}))
				t.Cleanup(server.Close)
				servers = append(servers, server)
			}
			if err := relayTestAdapter(t, servers).VerifyPinnedRelayGenesis(t.Context(), relayTestNetwork()); err == nil {
				t.Fatal("noncanonical zero-state coordinates reached the pinned genesis quorum")
			}
		})
	}
}

func TestTOSExactRelayBroadcasterRejectsWrongGenesisBeforeWrite(t *testing.T) {
	_, boc, _ := loadRelayRustFixture(t)
	var writeHits atomic.Int32
	servers := make([]*httptest.Server, 0, 3)
	for index := 0; index < 3; index++ {
		index := index
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			var call struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
			}
			if json.NewDecoder(request.Body).Decode(&call) != nil {
				http.Error(response, "bad call", http.StatusBadRequest)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			if call.Method == "getMasterchainInfo" {
				rootByte := byte(0x11)
				if index < 2 {
					rootByte = 0x33
				}
				_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
					"result": map[string]any{"@type": "blocks.masterchainInfo", "last": map[string]any{},
						"state_root_hash": "", "init": map[string]any{"@type": "tos.blockIdExt", "workchain": -1,
							"shard": "-9223372036854775808", "seqno": 0, "root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{rootByte}, 32)),
							"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))}}})
				return
			}
			writeHits.Add(1)
			http.Error(response, "write must not occur", http.StatusInternalServerError)
		}))
		t.Cleanup(server.Close)
		servers = append(servers, server)
	}
	network := relayTestNetwork()
	broadcaster, err := NewTOSExactRelayBroadcaster(relayTestAdapter(t, servers), network,
		&fixedRelayResolutionSource{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := broadcaster.SubmitExact(t.Context(), relayBroadcasterExecution(t, network, boc))
	if err == nil || result.Status != agentrelay.BroadcastUnknown || writeHits.Load() != 0 {
		t.Fatalf("wrong-genesis quorum reached the bearer write: result=%+v err=%v writes=%d",
			result, err, writeHits.Load())
	}
}

func TestTOSExactRelayBroadcasterRequiresPrimaryToJoinGenesisQuorum(t *testing.T) {
	_, boc, _ := loadRelayRustFixture(t)
	var writeHits atomic.Int32
	servers := make([]*httptest.Server, 0, 3)
	for index := 0; index < 3; index++ {
		index := index
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			var call struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
			}
			if json.NewDecoder(request.Body).Decode(&call) != nil {
				http.Error(response, "bad call", http.StatusBadRequest)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			if call.Method == "getMasterchainInfo" {
				rootByte := byte(0x11)
				if index == 0 {
					rootByte = 0x33
				}
				_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
					"result": map[string]any{"@type": "blocks.masterchainInfo", "last": map[string]any{},
						"state_root_hash": "", "init": map[string]any{"@type": "tos.blockIdExt", "workchain": -1,
							"shard": "-9223372036854775808", "seqno": 0, "root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{rootByte}, 32)),
							"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))}}})
				return
			}
			writeHits.Add(1)
			http.Error(response, "write must not occur", http.StatusInternalServerError)
		}))
		t.Cleanup(server.Close)
		servers = append(servers, server)
	}
	network := relayTestNetwork()
	broadcaster, err := NewTOSExactRelayBroadcaster(relayTestAdapter(t, servers), network,
		&fixedRelayResolutionSource{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := broadcaster.SubmitExact(t.Context(), relayBroadcasterExecution(t, network, boc))
	if err == nil || result.Status != agentrelay.BroadcastUnknown || writeHits.Load() != 0 {
		t.Fatalf("non-quorum primary received bearer bytes: result=%+v err=%v writes=%d",
			result, err, writeHits.Load())
	}
}

func TestTOSExactRelayBroadcasterRejectsHashSubstitutionAndDelegatesResolution(t *testing.T) {
	_, boc, _ := loadRelayRustFixture(t)
	var hits [3]atomic.Int32
	servers := relayRPCServers(t, &hits, func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID uint64 `json:"id"`
		}
		_ = json.NewDecoder(request.Body).Decode(&call)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
			"result": map[string]any{"status": 1, "hash": base64.StdEncoding.EncodeToString(make([]byte, 32))}})
	})
	network := relayTestNetwork()
	source := &fixedRelayResolutionSource{resolution: agentrelay.ChainResolution{State: agentcommerce.ActionAccepted}}
	broadcaster, err := NewTOSExactRelayBroadcaster(relayTestAdapter(t, servers), network, source)
	if err != nil {
		t.Fatal(err)
	}
	result, err := broadcaster.SubmitExact(t.Context(), relayBroadcasterExecution(t, network, boc))
	if err == nil || result.Status != agentrelay.BroadcastUnknown {
		t.Fatal("endpoint hash substitution was accepted")
	}
	record := agentrelay.Record{}
	// RestoreRecord is intentionally the only way to make a record containing
	// protected execution bytes. The network mismatch is rejected before the
	// injected resolution source sees it.
	if _, err := broadcaster.Resolve(t.Context(), record); err == nil || source.calls.Load() != 0 {
		t.Fatal("networkless journal record reached the finality resolver")
	}
}

func relayRPCServers(t *testing.T, hits *[3]atomic.Int32,
	primary http.HandlerFunc) []*httptest.Server {
	t.Helper()
	servers := make([]*httptest.Server, 0, 3)
	for index := 0; index < 3; index++ {
		index := index
		handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			raw, err := io.ReadAll(request.Body)
			if err != nil {
				http.Error(response, "bad call", http.StatusBadRequest)
				return
			}
			var call struct {
				JSONRPC string `json:"jsonrpc"`
				ID      uint64 `json:"id"`
				Method  string `json:"method"`
			}
			if json.Unmarshal(raw, &call) != nil {
				http.Error(response, "bad call", http.StatusBadRequest)
				return
			}
			if call.Method == "getMasterchainInfo" {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
					"result": map[string]any{"@type": "blocks.masterchainInfo", "last": map[string]any{},
						"state_root_hash": "", "init": map[string]any{"@type": "tos.blockIdExt", "workchain": -1,
							"shard": "-9223372036854775808", "seqno": 0, "root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
							"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))}}})
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(raw))
			hits[index].Add(1)
			if index == 0 {
				primary(response, request)
				return
			}
			http.Error(response, "write must not reach failover endpoint", http.StatusInternalServerError)
		})
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		servers = append(servers, server)
	}
	return servers
}

func relayTestAdapter(t *testing.T, servers []*httptest.Server) *Adapter {
	t.Helper()
	endpoints := make([]string, len(servers))
	for index := range servers {
		endpoints[index] = servers[index].URL
	}
	network := relayTestNetwork()
	adapter, err := New(Config{Network: network.NetworkID, PinnedNetworkDomain: &PinnedNetworkDomain{
		NetworkID: network.NetworkID, GlobalID: network.GlobalID, ZeroStateRootHash: network.ZeroStateRootHash,
		ZeroStateFileHash: network.ZeroStateFileHash, WorkchainID: network.WorkchainID}, Endpoints: endpoints, Quorum: 2,
		QueryTimeout: time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func relayBroadcasterExecution(t *testing.T, network agentrelay.NetworkDomain, boc []byte) agentrelay.RelayExecutionRequest {
	t.Helper()
	now := time.Unix(1_900_000_000, 0).UTC()
	// The Action Authority signs through the in-process test Fake; these
	// tests check relay bindings, not ML-DSA-44 bytes.
	authoritySigner, authorityController := &mldsa44test.Fake{}, "authority"
	authorityKeyID := authoritySigner.KeyID(authorityController)
	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	providerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	asset := agentrelay.AssetIdentity{AssetNamespace: "tos.native", AssetIdentifier: network.NetworkID, Unit: "nanotos"}
	finality := agentrelay.FinalityProfile{ProfileURI: TOSRelayProviderCorroboratedTerminalProfileURI,
		ProfileDigest: shaDigest("4"), TerminalEvidenceClass: agentrelay.RelayTerminalProviderCorroborated,
		MinimumConfirmationDepth: 1, MinimumObservers: 1, MinimumOperatorDomains: 1,
		ReorgWindowSeconds: 10, MaximumResolutionSeconds: 30}
	underlying := []byte{0xa1, 0x01, 0x02}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID("owner:buyer"), "agent_id": agentcommerce.ID("agent:buyer"),
		"agreement_body_digest":  agentcommerce.Digest32(shaDigest("5")),
		"obligation_instance_id": agentcommerce.Digest32(shaDigest("6")),
		"payer_id":               agentcommerce.ID("agent:buyer"), "payee_id": agentcommerce.ID("agent:merchant"),
		"network_id": agentcommerce.ID(network.NetworkID), "asset_digest": agentcommerce.Digest32(shaDigest("7")),
		"amount_atomic": agentcommerce.ID("25"), "destination_digest": agentcommerce.Digest32(shaDigest("8")),
	}
	fence, err := agentcommerce.SignWriterFence(context.Background(), agentcommerce.WriterFenceBody{SchemaVersion: 1,
		OwnerID: "owner:buyer", AgentID: "agent:buyer", InstanceID: "instance:test", LeaseID: "lease:test",
		WriterGeneration: 1, IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(4 * time.Minute).Unix()), AuthorityID: "authority:test",
		Scope: []string{"payment.direct"}}, authoritySigner, authorityController)
	if err != nil {
		t.Fatal(err)
	}
	action, err := agentcommerce.BuildAuthorizedAction("owner:buyer", "agent:buyer", "payment.direct", fields,
		underlying, fence, 1, shaDigest("9"), "", "unknown", uint64(now.Add(200*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = agentcommerce.SignAuthorizedAction(context.Background(), action, authorityKeyID, authoritySigner, authorityController)
	if err != nil {
		t.Fatal(err)
	}
	wireFields, err := agentcommerce.ExportSemanticFields("payment.direct", fields)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest, err := agentrelay.SignedTransactionDigest(boc)
	if err != nil {
		t.Fatal(err)
	}
	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	requestBody := agentrelay.RelayQuoteRequestBody{SchemaVersion: 1, RequestID: "relay-request:broadcast-test",
		RequesterAgentID: "agent:buyer", ProviderAgentID: "agent:relay", Network: network,
		Mode: agentrelay.ModeRelayExact, AssuranceLevel: agentrelay.AssuranceAuthorizedSingleProvider,
		SourceAccount: "source:test", SourceAccountAuthorityDigest: shaDigest("a"),
		TransactionProfileURI: "tos.signed-external-boc.v1", TransactionProfileDigest: shaDigest("b"),
		UnderlyingActionKind: "payment.direct", StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, SignedTransactionDigest: payloadDigest,
		SignedTransactionCellHash: "tvm-cell-sha256:" + fmtHex(root.Hash()), SignedTransactionSize: uint32(len(boc)),
		TransactionIntentDigest: shaDigest("c"), SourceSequence: 1,
		TransactionValidUntilUnix: uint64(now.Add(5 * time.Minute).Unix()),
		MaximumServiceFee:         agentrelay.AssetAmount{Asset: asset, AmountAtomic: "10"},
		MaximumNetworkFeeAtomic:   "100", MaximumTransactionValueAtomic: "25",
		RelayFinalityProfileURI: finality.ProfileURI, RelayFinalityProfileDigest: finality.ProfileDigest,
		RelayTerminalEvidenceClass: finality.TerminalEvidenceClass,
		CreatedAtUnix:              uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(3 * time.Minute).Unix())}
	signedRequest, err := agentrelay.SignRelayQuoteRequest(requestBody, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := agentrelay.RelayQuoteRequestDigest(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	quoteBody := agentrelay.ProviderRelayQuoteBody{SchemaVersion: 1, QuoteID: "relay-quote:broadcast-test",
		QuoteRequestDigest: requestDigest, ServiceProfileDigest: shaDigest("d"), ProviderAgentID: "agent:relay",
		Mode: agentrelay.ModeRelayExact, AssuranceLevel: requestBody.AssuranceLevel,
		FeeLines: []agentrelay.FeeLine{{Kind: agentrelay.ObligationRelayFee,
			Amount: agentrelay.AssetAmount{Asset: asset, AmountAtomic: "3"}}}, MaximumNetworkFeeAtomic: "100",
		MaximumTransactionValueAtomic: "25", MaximumRequestBytes: agentrelay.MaxSignedTransactionBytes,
		RelayTerminalEvidenceClass: finality.TerminalEvidenceClass,
		RelayFinalityProfile:       &finality, StatusEndpoint: "https://relay.example/resolve", ProviderPolicyRevision: 1,
		ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(150 * time.Second).Unix())}
	signedQuote, err := agentrelay.SignProviderRelayQuote(quoteBody, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	execution := agentrelay.RelayExecutionRequest{SchemaVersion: 1, QuoteRequest: signedRequest,
		ProviderQuote: signedQuote, SignedTransactionBytes: append([]byte(nil), boc...),
		AgreementBodyDigest: shaDigest("e"), AgreementExpiresAtUnix: uint64(now.Add(160 * time.Second).Unix()),
		RelayObligationID: "obligation:relay", FeeObligationIDs: []string{"obligation:fee"},
		UnderlyingActionRequest: underlying, SemanticFields: wireFields, AuthorizedAction: action, WriterFence: fence,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(2 * time.Minute).Unix())}
	descriptor, err := agentrelay.BuildRelaySideEffectAdmissionDescriptorForPrincipal(execution, "principal:test")
	if err != nil {
		t.Fatal(err)
	}
	body, err := agentrelay.BuildRelaySideEffectAdmissionReceiptBody(descriptor, 1, uint64(now.Unix()),
		uint64(now.Add(30*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	execution.AdmissionReceipt, err = agentrelay.SignRelaySideEffectAdmissionReceipt(context.Background(), body, authoritySigner, authorityController)
	if err != nil {
		t.Fatal(err)
	}
	return execution
}

func relayTestNetwork() agentrelay.NetworkDomain {
	return agentrelay.NetworkDomain{NetworkID: "tos:testnet", GlobalID: 42,
		ZeroStateRootHash: shaDigest("1"), ZeroStateFileHash: shaDigest("2"), WorkchainID: -1}
}
