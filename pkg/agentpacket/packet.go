// Package agentpacket defines an off-chain, chain-authenticated Agent packet.
// Payload bytes never become consensus input; finalized Agent state authorizes
// the signing key and the optional commercial binding.
//
// Packets and contact cards are signed with Pure ML-DSA-44 by one of the
// sending Agent's controller keys, under their own context strings, through
// the tosctl helper; controller private keys stay in tosctl custody.
package agentpacket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

const MaxPayloadBytes = 1 << 20

var (
	agentPattern  = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	capPattern    = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	digestPattern = regexp.MustCompile(`^(?:sha256|tvm-cell-sha256):[0-9a-f]{64}$`)
)

type Packet struct {
	SenderAgentID    string
	RecipientAgentID string
	CapabilityID     string
	QuoteCommitment  string
	Sequence         uint64
	Nonce            [32]byte
	Payload          []byte
	CreatedAtUnix    uint64
	// SenderKeyID is the key ID of the sender controller that signs. It is
	// part of the signed preimage; the key itself is read from the finalized
	// sender policy.
	SenderKeyID [mldsa44.KeyIDSize]byte
	Signature   []byte
}

type AgentResolver interface {
	ResolveAgent(string) (*nativev1.AgentStateV1, bool, error)
}

type wirePacket struct {
	Schema           string `json:"schema"`
	SenderAgentID    string `json:"sender_agent_id"`
	RecipientAgentID string `json:"recipient_agent_id"`
	CapabilityID     string `json:"capability_id"`
	QuoteCommitment  string `json:"quote_commitment,omitempty"`
	Sequence         uint64 `json:"sequence"`
	NonceHex         string `json:"nonce_hex"`
	PayloadBase64    string `json:"payload_base64"`
	CreatedAtUnix    uint64 `json:"created_at_unix"`
	SenderKeyID      string `json:"sender_key_id"`
	Signature        string `json:"signature_hex"`
}

// EncodeJSON returns the strict transport representation. JSON is a wire
// format only; signing always covers the canonical binary preimage above.
func EncodeJSON(packet Packet) ([]byte, error) {
	if err := validate(packet, true); err != nil {
		return nil, err
	}
	value := wirePacket{Schema: "tos.service.agent-packet.v1", SenderAgentID: packet.SenderAgentID,
		RecipientAgentID: packet.RecipientAgentID, CapabilityID: packet.CapabilityID, QuoteCommitment: packet.QuoteCommitment,
		Sequence: packet.Sequence, NonceHex: hex.EncodeToString(packet.Nonce[:]), PayloadBase64: base64.StdEncoding.EncodeToString(packet.Payload),
		CreatedAtUnix: packet.CreatedAtUnix, SenderKeyID: mldsa44.KeyIDText(packet.SenderKeyID), Signature: hex.EncodeToString(packet.Signature)}
	return json.Marshal(value)
}

// DecodeJSON rejects unknown or trailing fields and reconstructs the exact
// signed packet. It does not claim chain authority; Verify must still run.
func DecodeJSON(raw []byte) (Packet, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wirePacket
	if err := decoder.Decode(&value); err != nil {
		return Packet{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Packet{}, errors.New("Agent packet has trailing JSON")
	}
	if value.Schema != "tos.service.agent-packet.v1" {
		return Packet{}, errors.New("unsupported Agent packet schema")
	}
	nonce, err := hex.DecodeString(value.NonceHex)
	if err != nil || len(nonce) != 32 {
		return Packet{}, errors.New("invalid Agent packet nonce")
	}
	keyID, err := mldsa44.ParseKeyIDText(value.SenderKeyID)
	if err != nil {
		return Packet{}, errors.New("invalid Agent packet sender key ID")
	}
	signature, err := hex.DecodeString(value.Signature)
	if err != nil || len(signature) != mldsa44.SignatureSize || value.Signature != hex.EncodeToString(signature) {
		return Packet{}, errors.New("invalid Agent packet signature")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(value.PayloadBase64)
	if err != nil {
		return Packet{}, errors.New("invalid Agent packet payload")
	}
	var nonceValue [32]byte
	copy(nonceValue[:], nonce)
	packet := Packet{SenderAgentID: value.SenderAgentID, RecipientAgentID: value.RecipientAgentID, CapabilityID: value.CapabilityID,
		QuoteCommitment: value.QuoteCommitment, Sequence: value.Sequence, Nonce: nonceValue, Payload: payload,
		CreatedAtUnix: value.CreatedAtUnix, SenderKeyID: keyID, Signature: signature}
	if err := validate(packet, true); err != nil {
		return Packet{}, err
	}
	return packet, nil
}

type ReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
	TTL  time.Duration
}

func (g *ReplayGuard) claim(key string, now time.Time) error {
	if g == nil || key == "" || now.IsZero() {
		return errors.New("invalid packet replay guard")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]time.Time)
	}
	ttl := g.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	for item, at := range g.seen {
		if now.Sub(at) > ttl {
			delete(g.seen, item)
		}
	}
	if _, exists := g.seen[key]; exists {
		return errors.New("Agent packet replay detected")
	}
	g.seen[key] = now
	return nil
}

// Sign asks custody to sign the packet with the named controller, whose key
// ID the packet must already carry in SenderKeyID: the key ID is part of the
// signed preimage. A custody answer for any other key is refused.
func Sign(ctx context.Context, signer mldsa44.Signer, controller string, packet Packet) (Packet, error) {
	packet.Signature = nil
	if err := validate(packet, false); err != nil {
		return Packet{}, err
	}
	signature, err := signAs(ctx, signer, controller, mldsa44.UseAgentPacket, packet.SenderKeyID, signingBytes(packet))
	if err != nil {
		return Packet{}, err
	}
	packet.Signature = signature
	return packet, nil
}

// signAs signs a preimage with a named controller and checks custody signed
// with the controller key the preimage names.
func signAs(ctx context.Context, signer mldsa44.Signer, controller string, use mldsa44.Use, keyID [mldsa44.KeyIDSize]byte, preimage []byte) ([]byte, error) {
	if ctx == nil || signer == nil || controller == "" {
		return nil, errors.New("invalid Agent signing request")
	}
	signature, err := signer.Sign(ctx, controller, use, preimage)
	if err != nil {
		return nil, err
	}
	if err := mldsa44.CheckSignature(signature); err != nil || signature.KeyID != keyID {
		return nil, errors.New("custody signed with a controller key other than the one the preimage names")
	}
	return signature.Signature, nil
}

// controllerKey returns the ML-DSA-44 key the finalized policy stores for a
// key ID, after checking the stored key still derives that ID.
func controllerKey(policy *nativev1.ControllerPolicyV1, keyID [mldsa44.KeyIDSize]byte) ([]byte, bool) {
	if policy == nil {
		return nil, false
	}
	text := mldsa44.KeyIDText(keyID)
	for _, controller := range policy.Controllers {
		if controller == nil || controller.KeyId != text {
			continue
		}
		derived, err := mldsa44.KeyID(controller.Mldsa44PublicKey)
		if err != nil || derived != keyID {
			return nil, false
		}
		return controller.Mldsa44PublicKey, true
	}
	return nil, false
}

// verifyAs checks a signature against the key a finalized policy stores. An
// unavailable verifier is never authorization.
func verifyAs(ctx context.Context, verifier mldsa44.Verifier, policy *nativev1.ControllerPolicyV1, use mldsa44.Use,
	keyID [mldsa44.KeyIDSize]byte, preimage, signature []byte) error {
	key, ok := controllerKey(policy, keyID)
	if !ok {
		return errors.New("signer is not a controller of the finalized Agent policy")
	}
	if err := verifier.Verify(ctx, use, preimage, key, signature); err != nil {
		return fmt.Errorf("signature does not verify against the finalized controller key: %w", err)
	}
	return nil
}

func Verify(ctx context.Context, verifier mldsa44.Verifier, resolver AgentResolver, guard *ReplayGuard, packet Packet, now time.Time) error {
	if ctx == nil || verifier == nil || resolver == nil || guard == nil || now.IsZero() {
		return errors.New("invalid packet verification context")
	}
	if err := validate(packet, true); err != nil {
		return err
	}
	state, found, err := resolver.ResolveAgent(packet.SenderAgentID)
	if err != nil {
		return err
	}
	if !found || state == nil || state.Tombstoned || state.Policy == nil {
		return errors.New("sender Agent is not finalized and live")
	}
	if err := verifyAs(ctx, verifier, state.Policy, mldsa44.UseAgentPacket, packet.SenderKeyID, signingBytes(packet), packet.Signature); err != nil {
		return fmt.Errorf("packet signer is not authorized: %w", err)
	}
	if _, found, err := resolver.ResolveAgent(packet.RecipientAgentID); err != nil {
		return err
	} else if !found {
		return errors.New("recipient Agent is not finalized")
	}
	if err := guard.claim(packetKey(packet), now); err != nil {
		return err
	}
	return nil
}

func validate(packet Packet, signature bool) error {
	if !agentPattern.MatchString(packet.SenderAgentID) || !agentPattern.MatchString(packet.RecipientAgentID) ||
		packet.SenderAgentID == packet.RecipientAgentID || !capPattern.MatchString(packet.CapabilityID) ||
		(packet.QuoteCommitment != "" && !digestPattern.MatchString(packet.QuoteCommitment)) || packet.Sequence == 0 ||
		len(packet.Payload) == 0 || len(packet.Payload) > MaxPayloadBytes || packet.CreatedAtUnix == 0 ||
		packet.SenderKeyID == [mldsa44.KeyIDSize]byte{} || (signature && len(packet.Signature) != mldsa44.SignatureSize) {
		return errors.New("invalid Agent packet shape")
	}
	hash := sha256.Sum256(packet.Payload)
	if bytes.Equal(hash[:], make([]byte, 32)) {
		return errors.New("invalid Agent packet payload digest")
	}
	return nil
}

func signingBytes(packet Packet) []byte {
	payloadHash := sha256.Sum256(packet.Payload)
	buffer := bytes.NewBufferString("tos.service.agent.packet.v1\x00")
	putText := func(value string) {
		binary.Write(buffer, binary.BigEndian, uint32(len(value)))
		buffer.WriteString(value)
	}
	putText(packet.SenderAgentID)
	putText(packet.RecipientAgentID)
	putText(packet.CapabilityID)
	putText(packet.QuoteCommitment)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], packet.Sequence)
	buffer.Write(number[:])
	buffer.Write(packet.Nonce[:])
	binary.BigEndian.PutUint64(number[:], packet.CreatedAtUnix)
	buffer.Write(number[:])
	buffer.Write(packet.SenderKeyID[:])
	buffer.Write(payloadHash[:])
	return buffer.Bytes()
}

func packetKey(packet Packet) string {
	return packet.SenderAgentID + ":" + hex.EncodeToString(packet.Nonce[:])
}
