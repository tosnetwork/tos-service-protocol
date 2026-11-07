package agentpacket

import (
	"context"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func fakeCard(t *testing.T, controller string, card ContactCard, now time.Time) ContactCard {
	t.Helper()
	card.KeyID = keyIDOf(t, fakeKeys.KeyID(controller))
	signed, err := SignContactAt(context.Background(), fakeKeys, controller, card, now)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestContactCardIsFinalizedAndTimeBound(t *testing.T) {
	agent := "agent_" + repeatHex("ab")
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + repeatHex("01"), GenesisFileHash: "sha256:" + repeatHex("02")}
	now := time.Unix(1000, 0)
	card := fakeCard(t, "card", ContactCard{AgentID: agent, Network: network, Endpoint: "https://agent.example/packet", Capabilities: []string{"cap_" + repeatHex("cd")}, ExpiresAtUnix: 1500}, now)
	states := resolver{agent: fakeAgent(agent, "card")}
	ctx := context.Background()
	if err := VerifyContact(ctx, fakeKeys, states, card, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContactForNetwork(ctx, fakeKeys, states, &nativev1.NetworkDomain{NetworkId: "other", GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash}, card, now); err == nil {
		t.Fatal("cross-network Contact Card accepted")
	}
	if err := VerifyContact(ctx, fakeKeys, states, card, time.Unix(1500, 0)); err == nil {
		t.Fatal("expired Contact Card accepted")
	}
	stranger := fakeCard(t, "stranger", ContactCard{AgentID: agent, Network: network, Endpoint: "https://agent.example/packet", ExpiresAtUnix: 1500}, now)
	if err := VerifyContact(ctx, fakeKeys, states, stranger, now); err == nil {
		t.Fatal("Contact Card by a key outside the finalized policy accepted")
	}
	card.Endpoint = "http://public.example/packet"
	if err := VerifyContact(ctx, fakeKeys, states, card, now); err == nil {
		t.Fatal("plaintext public endpoint accepted")
	}
}

func TestContactCardJSONRoundTripIsStrict(t *testing.T) {
	card := fakeCard(t, "card", ContactCard{AgentID: "agent_" + repeatHex("ef"), Network: &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + repeatHex("01"), GenesisFileHash: "sha256:" + repeatHex("02")}, Endpoint: "https://agent.example", ExpiresAtUnix: 1500}, time.Unix(1000, 0))
	raw, err := EncodeContactJSON(card)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeContactJSON(raw)
	if err != nil || decoded.AgentID != card.AgentID || string(decoded.Signature) != string(card.Signature) || decoded.KeyID != card.KeyID {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	if ContactKey(decoded) != card.AgentID+":"+fakeKeys.KeyID("card") {
		t.Fatalf("contact key = %s", ContactKey(decoded))
	}
	for _, mutation := range [][]byte{
		append(raw, []byte("{}")...),
		[]byte(strings.Replace(string(raw), `"key_id":"mldsa44:`, `"key_id":"ed25519:`, 1)),
	} {
		if _, err := DecodeContactJSON(mutation); err == nil {
			t.Fatal("non-strict Contact Card JSON accepted")
		}
	}
}
