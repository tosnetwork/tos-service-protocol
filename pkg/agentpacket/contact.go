package agentpacket

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// ContactCard is a signed, non-canonical locator. It can be exchanged through
// any rendezvous mechanism; finalized Agent state remains the authority.
type ContactCard struct {
	AgentID       string
	Network       *nativev1.NetworkDomain
	Endpoint      string
	Capabilities  []string
	ExpiresAtUnix uint64
	// KeyID is the key ID of the Agent controller that signs the card. It is
	// part of the signed preimage; the key itself is read from the finalized
	// Agent policy.
	KeyID     [mldsa44.KeyIDSize]byte
	Signature []byte
}

type wireContactCard struct {
	Schema        string   `json:"schema"`
	AgentID       string   `json:"agent_id"`
	NetworkID     string   `json:"network_id"`
	GenesisRoot   string   `json:"genesis_root_hash"`
	GenesisFile   string   `json:"genesis_file_hash"`
	Endpoint      string   `json:"endpoint"`
	Capabilities  []string `json:"capabilities,omitempty"`
	ExpiresAtUnix uint64   `json:"expires_at_unix"`
	KeyID         string   `json:"key_id"`
	SignatureHex  string   `json:"signature_hex"`
}

func EncodeContactJSON(card ContactCard) ([]byte, error) {
	if err := validateContact(card, true, time.Unix(int64(card.ExpiresAtUnix-1), 0)); err != nil {
		return nil, err
	}
	value := wireContactCard{Schema: "tos.service.agent-contact.v1", AgentID: card.AgentID, NetworkID: card.Network.NetworkId,
		GenesisRoot: card.Network.GenesisRootHash, GenesisFile: card.Network.GenesisFileHash, Endpoint: card.Endpoint,
		Capabilities: card.Capabilities, ExpiresAtUnix: card.ExpiresAtUnix, KeyID: mldsa44.KeyIDText(card.KeyID), SignatureHex: hex.EncodeToString(card.Signature)}
	return json.Marshal(value)
}

func DecodeContactJSON(raw []byte) (ContactCard, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireContactCard
	if err := decoder.Decode(&value); err != nil {
		return ContactCard{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ContactCard{}, errors.New("Contact Card has trailing JSON")
	}
	if value.Schema != "tos.service.agent-contact.v1" {
		return ContactCard{}, errors.New("unsupported Contact Card schema")
	}
	keyID, err := mldsa44.ParseKeyIDText(value.KeyID)
	if err != nil {
		return ContactCard{}, errors.New("invalid Contact Card key ID")
	}
	signature, err := hex.DecodeString(value.SignatureHex)
	if err != nil || len(signature) != mldsa44.SignatureSize || value.SignatureHex != hex.EncodeToString(signature) {
		return ContactCard{}, errors.New("invalid Contact Card signature")
	}
	card := ContactCard{AgentID: value.AgentID, Network: &nativev1.NetworkDomain{NetworkId: value.NetworkID, GenesisRootHash: value.GenesisRoot, GenesisFileHash: value.GenesisFile}, Endpoint: value.Endpoint, Capabilities: value.Capabilities, ExpiresAtUnix: value.ExpiresAtUnix, KeyID: keyID, Signature: signature}
	if err := validateContact(card, true, time.Unix(int64(card.ExpiresAtUnix-1), 0)); err != nil {
		return ContactCard{}, err
	}
	return card, nil
}

// SignContact asks custody to sign the card with the named controller, whose
// key ID the card must already carry in KeyID.
func SignContact(ctx context.Context, signer mldsa44.Signer, controller string, card ContactCard) (ContactCard, error) {
	return SignContactAt(ctx, signer, controller, card, time.Now())
}

// SignContactAt is deterministic-clock support for tests and controlled
// issuance services. Production callers should use SignContact.
func SignContactAt(ctx context.Context, signer mldsa44.Signer, controller string, card ContactCard, now time.Time) (ContactCard, error) {
	card.Signature = nil
	if now.IsZero() {
		return ContactCard{}, errors.New("invalid Contact Card signing time")
	}
	if err := validateContact(card, false, now); err != nil {
		return ContactCard{}, err
	}
	signature, err := signAs(ctx, signer, controller, mldsa44.UseAgentContact, card.KeyID, contactBytes(card))
	if err != nil {
		return ContactCard{}, err
	}
	card.Signature = signature
	return card, nil
}

func VerifyContact(ctx context.Context, verifier mldsa44.Verifier, resolver AgentResolver, card ContactCard, now time.Time) error {
	return VerifyContactForNetwork(ctx, verifier, resolver, nil, card, now)
}

// VerifyContactForNetwork additionally binds the locator to the caller's
// configured TOS network tuple. Pass a non-nil network in production.
func VerifyContactForNetwork(ctx context.Context, verifier mldsa44.Verifier, resolver AgentResolver, network *nativev1.NetworkDomain, card ContactCard, now time.Time) error {
	if ctx == nil || verifier == nil || resolver == nil || now.IsZero() {
		return errors.New("invalid Contact Card verification context")
	}
	if err := validateContact(card, true, now); err != nil {
		return err
	}
	if network != nil && (card.Network == nil || card.Network.NetworkId != network.NetworkId || card.Network.GenesisRootHash != network.GenesisRootHash || card.Network.GenesisFileHash != network.GenesisFileHash) {
		return errors.New("Contact Card network tuple mismatch")
	}
	state, found, err := resolver.ResolveAgent(card.AgentID)
	if err != nil {
		return err
	}
	if !found || state == nil || state.Tombstoned || state.Policy == nil {
		return errors.New("Contact Card Agent is not finalized and live")
	}
	if err := verifyAs(ctx, verifier, state.Policy, mldsa44.UseAgentContact, card.KeyID, contactBytes(card), card.Signature); err != nil {
		return fmt.Errorf("Contact Card signer is not authorized: %w", err)
	}
	return nil
}

func validateContact(card ContactCard, signed bool, now time.Time) error {
	if !agentPattern.MatchString(card.AgentID) || card.Network == nil || strings.TrimSpace(card.Endpoint) != card.Endpoint ||
		card.ExpiresAtUnix == 0 || card.KeyID == [mldsa44.KeyIDSize]byte{} || (signed && len(card.Signature) != mldsa44.SignatureSize) {
		return errors.New("invalid Contact Card shape")
	}
	parsed, err := url.Parse(card.Endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1"))) {
		return errors.New("Contact Card endpoint must use HTTPS outside loopback")
	}
	if now.Unix() >= int64(card.ExpiresAtUnix) || card.ExpiresAtUnix > uint64(now.Add(24*time.Hour).Unix()) {
		return errors.New("Contact Card is expired or exceeds its lifetime")
	}
	seen := make(map[string]struct{}, len(card.Capabilities))
	for _, capability := range card.Capabilities {
		if !capPattern.MatchString(capability) {
			return errors.New("Contact Card contains invalid Capability")
		}
		if _, ok := seen[capability]; ok {
			return errors.New("Contact Card contains duplicate Capability")
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func contactBytes(card ContactCard) []byte {
	buffer := bytes.NewBufferString("tos.service.agent.contact.v1\x00")
	text := func(value string) {
		binary.Write(buffer, binary.BigEndian, uint32(len(value)))
		buffer.WriteString(value)
	}
	text(card.AgentID)
	text(card.Network.NetworkId)
	text(card.Network.GenesisRootHash)
	text(card.Network.GenesisFileHash)
	text(card.Endpoint)
	binary.Write(buffer, binary.BigEndian, uint32(len(card.Capabilities)))
	for _, capability := range card.Capabilities {
		text(capability)
	}
	binary.Write(buffer, binary.BigEndian, card.ExpiresAtUnix)
	buffer.Write(card.KeyID[:])
	return buffer.Bytes()
}

func ContactKey(card ContactCard) string {
	return card.AgentID + ":" + mldsa44.KeyIDText(card.KeyID)
}
