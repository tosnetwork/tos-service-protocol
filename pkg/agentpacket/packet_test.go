package agentpacket

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

type resolver map[string]*nativev1.AgentStateV1

func (r resolver) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	value, ok := r[id]
	return value, ok, nil
}

// fakeKeys stands in for the ML-DSA-44 helper in pure-logic tests; it is not
// ML-DSA-44. Real signature bytes are checked with the tosctl helper below.
var fakeKeys = &mldsa44test.Fake{}

func keyIDOf(t *testing.T, text string) [mldsa44.KeyIDSize]byte {
	t.Helper()
	id, err := mldsa44.ParseKeyIDText(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func policyOf(keyID string, key []byte) *nativev1.ControllerPolicyV1 {
	return &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{
		KeyId: keyID, Mldsa44PublicKey: key, Weight: 1, PurposeMask: 15, Recovery: true}}}
}

func fakeAgent(id, controller string) *nativev1.AgentStateV1 {
	return &nativev1.AgentStateV1{AgentId: id, Policy: policyOf(fakeKeys.KeyID(controller), fakeKeys.PublicKey(controller))}
}

func fakePacket(t *testing.T, controller string, packet Packet) Packet {
	t.Helper()
	packet.SenderKeyID = keyIDOf(t, fakeKeys.KeyID(controller))
	signed, err := Sign(context.Background(), fakeKeys, controller, packet)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestPacketAndContactSignaturesThroughCustody signs a packet and a contact
// card with one real ML-DSA-44 controller in tosctl custody and verifies
// both against the key stored in the finalized policy. Each signature fails
// under the other's context and under the registry context.
func TestPacketAndContactSignaturesThroughCustody(t *testing.T) {
	custody := mldsa44test.NewCustody(t, "sender")
	helper := mldsa44test.RequireTosctl(t)
	ctx := context.Background()
	keyIDText := custody.KeyID(t, "sender")
	key := custody.PublicKeys["sender"]
	sender, recipient := "agent_"+repeatHex("11"), "agent_"+repeatHex("22")
	states := resolver{sender: {AgentId: sender, Policy: policyOf(keyIDText, key)}, recipient: {AgentId: recipient}}

	packet, err := Sign(ctx, custody.Signer, "sender", Packet{SenderAgentID: sender, RecipientAgentID: recipient,
		CapabilityID: "cap_" + repeatHex("33"), Sequence: 1, CreatedAtUnix: 100, Payload: []byte("hello"),
		SenderKeyID: keyIDOf(t, keyIDText)})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, helper, states, &ReplayGuard{}, packet, time.Unix(100, 0)); err != nil {
		t.Fatalf("custody-signed packet refused: %v", err)
	}
	now := time.Unix(1000, 0)
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + repeatHex("01"), GenesisFileHash: "sha256:" + repeatHex("02")}
	card, err := SignContactAt(ctx, custody.Signer, "sender", ContactCard{AgentID: sender, Network: network,
		Endpoint: "https://agent.example/packet", ExpiresAtUnix: 1500, KeyID: keyIDOf(t, keyIDText)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyContactForNetwork(ctx, helper, states, network, card, now); err != nil {
		t.Fatalf("custody-signed contact card refused: %v", err)
	}

	for name, check := range map[string]error{
		"packet as contact":  helper.Verify(ctx, mldsa44.UseAgentContact, signingBytes(packet), key, packet.Signature),
		"contact as packet":  helper.Verify(ctx, mldsa44.UseAgentPacket, contactBytes(card), key, card.Signature),
		"packet as registry": helper.Verify(ctx, mldsa44.UseRegistry, registryBOC(t), key, packet.Signature),
	} {
		if !errors.Is(check, mldsa44.ErrInvalidSignature) {
			t.Fatalf("%s: %v", name, check)
		}
	}

	// A packet-context signature over the exact 32 bytes a registry action
	// signs does not authorize that action, and a registry signature over an
	// action does not verify as a packet over its hash.
	policy, built := registryAction(t, keyIDText, key)
	packetOverHash, err := custody.Signer.Sign(ctx, "sender", mldsa44.UseAgentPacket, built.Hash)
	if err != nil {
		t.Fatal(err)
	}
	err = nativecore.VerifySignatures(ctx, helper, policy, []*nativev1.SignatureV1{{KeyId: keyIDText, Mldsa44Signature: packetOverHash.Signature}},
		nativecore.PurposeAgentControl, false, built)
	if code, _ := nativecore.ErrorCodeOf(err); code != nativecore.ErrBadSignature {
		t.Fatalf("packet-context signature authorized a registry action: %v", err)
	}
	registrySignature, err := nativecore.SignAction(ctx, custody.Signer, "sender", built)
	if err != nil {
		t.Fatal(err)
	}
	if err := nativecore.VerifySignatures(ctx, helper, policy, []*nativev1.SignatureV1{registrySignature},
		nativecore.PurposeAgentControl, false, built); err != nil {
		t.Fatalf("positive control: registry signature refused: %v", err)
	}
	for _, use := range []mldsa44.Use{mldsa44.UseAgentPacket, mldsa44.UseAgentContact} {
		if err := helper.Verify(ctx, use, built.Hash, key, registrySignature.Mldsa44Signature); !errors.Is(err, mldsa44.ErrInvalidSignature) {
			t.Fatalf("registry signature verified as %s: %v", use, err)
		}
	}
}

func registryAction(t *testing.T, keyID string, key []byte) (*nativev1.ControllerPolicyV1, nativecore.BuiltAction) {
	t.Helper()
	policy := policyOf(keyID, key)
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + repeatHex("01"), GenesisFileHash: "sha256:" + repeatHex("02")}
	objectNonce := []byte(strings.Repeat("o", 32))
	id, err := nativecore.DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	built, err := nativecore.BuildAction(&nativev1.NativeActionV1{Protocol: nativecore.Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: "tvm-cell-sha256:" + repeatHex("44"), Generation: 1, Sequence: 1, Nonce: []byte(strings.Repeat("n", 32)),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}})
	if err != nil {
		t.Fatal(err)
	}
	return policy, built
}

func registryBOC(t *testing.T) []byte {
	t.Helper()
	_, built := registryAction(t, fakeKeys.KeyID("boc"), fakeKeys.PublicKey("boc"))
	return built.Cell.ToBOC()
}

func TestSignedPacketRequiresFinalizedAgentsAndRejectsReplay(t *testing.T) {
	sender, recipient := "agent_"+repeatHex("11"), "agent_"+repeatHex("22")
	packet := fakePacket(t, "sender", Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("33"), Sequence: 1, CreatedAtUnix: 100, Payload: []byte("hello")})
	guard := &ReplayGuard{TTL: time.Hour}
	states := resolver{sender: fakeAgent(sender, "sender"), recipient: {AgentId: recipient}}
	ctx := context.Background()
	if err := Verify(ctx, fakeKeys, states, guard, packet, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, fakeKeys, states, guard, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("replayed packet accepted")
	}
	packet.Payload[0] ^= 1
	if err := Verify(ctx, fakeKeys, states, &ReplayGuard{}, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("mutated payload accepted")
	}
	if err := Verify(ctx, nil, states, &ReplayGuard{}, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("verification without a verifier passed")
	}
}

func TestPacketRejectsUnauthorizedSenderAndMissingRecipient(t *testing.T) {
	sender, recipient := "agent_"+repeatHex("44"), "agent_"+repeatHex("55")
	packet := fakePacket(t, "sender", Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("66"), Sequence: 1, CreatedAtUnix: 100, Payload: []byte("x")})
	ctx := context.Background()
	if err := Verify(ctx, fakeKeys, resolver{sender: fakeAgent(sender, "sender")}, &ReplayGuard{}, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("missing recipient accepted")
	}
	both := resolver{sender: fakeAgent(sender, "sender"), recipient: {AgentId: recipient}}
	// A key outside the finalized policy, even with a valid signature by it.
	stranger := fakePacket(t, "stranger", Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("66"), Sequence: 1, CreatedAtUnix: 100, Payload: []byte("x")})
	if err := Verify(ctx, fakeKeys, both, &ReplayGuard{}, stranger, time.Unix(100, 0)); err == nil {
		t.Fatal("unauthorized sender accepted")
	}
	// Renaming the signer changes the preimage.
	renamed := packet
	renamed.SenderKeyID = keyIDOf(t, fakeKeys.KeyID("stranger"))
	if err := Verify(ctx, fakeKeys, resolver{sender: {AgentId: sender, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{
		fakeAgent(sender, "sender").Policy.Controllers[0], fakeAgent(sender, "stranger").Policy.Controllers[0]}}}, recipient: {AgentId: recipient}},
		&ReplayGuard{}, renamed, time.Unix(100, 0)); err == nil {
		t.Fatal("a signature was accepted for another controller's key ID")
	}
	// A policy entry whose stored key does not derive its key ID is not used.
	// The packet names the sender's key ID but is signed by the stranger's
	// key, which the forged policy entry stores under the sender's ID.
	forged := fakeAgent(sender, "sender")
	forged.Policy.Controllers[0].Mldsa44PublicKey = fakeKeys.PublicKey("stranger")
	mislabelled := packet
	byStranger, err := fakeKeys.Sign(ctx, "stranger", mldsa44.UseAgentPacket, signingBytes(mislabelled))
	if err != nil {
		t.Fatal(err)
	}
	mislabelled.Signature = byStranger.Signature
	if err := Verify(ctx, fakeKeys, resolver{sender: forged, recipient: {AgentId: recipient}}, &ReplayGuard{}, mislabelled, time.Unix(100, 0)); err == nil {
		t.Fatal("a key that does not derive its declared key ID was trusted")
	}
	honest := forged.Policy.Controllers[0]
	honest.KeyId = fakeKeys.KeyID("stranger")
	if key, ok := controllerKey(&nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{honest}}, keyIDOf(t, fakeKeys.KeyID("stranger"))); !ok || string(key) != string(fakeKeys.PublicKey("stranger")) {
		t.Fatal("positive control: a consistent policy entry was not found")
	}
	// Custody answering with another key is refused at signing.
	if _, err := Sign(ctx, fakeKeys, "stranger", Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("66"),
		Sequence: 1, CreatedAtUnix: 100, Payload: []byte("x"), SenderKeyID: keyIDOf(t, fakeKeys.KeyID("sender"))}); err == nil {
		t.Fatal("a signature by another key was attached to the packet")
	}
}

func TestJSONWireRoundTripAndStrictParsing(t *testing.T) {
	packet := fakePacket(t, "wire", Packet{SenderAgentID: "agent_" + repeatHex("77"), RecipientAgentID: "agent_" + repeatHex("88"),
		CapabilityID: "cap_" + repeatHex("99"), Sequence: 2, CreatedAtUnix: 200, Payload: []byte("wire")})
	raw, err := EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"sender_key_id":"`+fakeKeys.KeyID("wire")+`"`) {
		t.Fatalf("wire packet does not carry the sender key ID: %s", raw)
	}
	decoded, err := DecodeJSON(raw)
	if err != nil || string(decoded.Payload) != "wire" || string(decoded.Signature) != string(packet.Signature) || decoded.SenderKeyID != packet.SenderKeyID {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	for _, mutation := range [][]byte{
		append(raw, []byte("{}")...),
		append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...),
		[]byte(strings.Replace(string(raw), "mldsa44:", "ed25519:", 1)),
		[]byte(strings.Replace(string(raw), `"signature_hex":"`, `"signature_hex":"00`, 1)),
	} {
		if _, err := DecodeJSON(mutation); err == nil {
			t.Fatal("non-strict wire accepted")
		}
	}
}

type receiveStub struct{ count int }

func (r *receiveStub) Receive(context.Context, Packet) error { r.count++; return nil }

func TestHTTPHandlerVerifiesBeforeDeliveryAndPostDisablesRedirects(t *testing.T) {
	sender, recipient := "agent_"+repeatHex("aa"), "agent_"+repeatHex("bb")
	packet := fakePacket(t, "http", Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("cc"), Sequence: 1, CreatedAtUnix: uint64(time.Now().Unix()), Payload: []byte("hello")})
	receiver := &receiveStub{}
	server := httptest.NewServer(Handler(fakeKeys, resolver{sender: fakeAgent(sender, "http"), recipient: {AgentId: recipient}}, &ReplayGuard{}, receiver))
	defer server.Close()
	if err := Post(context.Background(), server.Client(), server.URL, packet); err != nil {
		t.Fatal(err)
	}
	if receiver.count != 1 {
		t.Fatalf("received=%d", receiver.count)
	}
	if err := Post(context.Background(), server.Client(), server.URL, packet); err == nil {
		t.Fatal("replay was delivered")
	}
	redirect := httptest.NewServer(http.RedirectHandler(server.URL, http.StatusTemporaryRedirect))
	defer redirect.Close()
	if err := Post(context.Background(), redirect.Client(), redirect.URL, packet); err == nil {
		t.Fatal("redirect accepted")
	}
}

func repeatHex(value string) string {
	result := ""
	for i := 0; i < 32; i++ {
		result += value
	}
	return result
}
