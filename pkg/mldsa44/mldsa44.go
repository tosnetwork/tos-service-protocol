// Package mldsa44 is the ML-DSA-44 (FIPS 204) boundary of tos_service_v1.
//
// This module deliberately links no ML-DSA implementation. Signing and
// verification are delegated to a pinned tosctl binary (see Tosctl), so
// controller private keys stay in tosctl custody and the module never reads,
// receives or passes private key material. Key identity is plain SHA-256 and
// is computed here.
package mldsa44

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// PublicKeySize is the length of an ML-DSA-44 public key.
	PublicKeySize = 1312
	// SignatureSize is the length of an ML-DSA-44 signature.
	SignatureSize = 2420
	// KeyIDSize is the length of a controller key ID.
	KeyIDSize = 32
	// KeyIDPrefix is the text prefix of a controller key ID.
	KeyIDPrefix = "mldsa44:"

	keyIDDomain = "TOS-PQ-CONSENSUS-KEY-v1"
)

// keyIDSuite is suite number 1 (ML-DSA-44) as two little-endian bytes.
var keyIDSuite = []byte{0x01, 0x00}

// Use names what a signature authorizes. Each use has its own FIPS 204
// context string, so a signature for one use never verifies for another.
type Use string

const (
	// UseRegistry signs the 32-byte hash of a Native Registry action cell.
	UseRegistry Use = "registry"
	// UseAgentPacket signs an Agent Packet preimage.
	UseAgentPacket Use = "agent-packet"
	// UseAgentContact signs an Agent contact card preimage.
	UseAgentContact Use = "agent-contact"
	// UseAgentGuarantor signs the 32-byte message digest of an Agent
	// Guarantor object authorization.
	UseAgentGuarantor Use = "agent-guarantor"
	// UseActionAuthority signs the 32-byte framed digest of an Action
	// Authority object: an AuthorizedActionV1, a WriterFenceV1, a relay
	// side-effect admission receipt or a Guarantor stage-action admission.
	UseActionAuthority Use = "action-authority"
)

// AgentGuarantorMessageSize is the exact length of an Agent Guarantor
// message: a SHA-256 digest that already separates the object kind.
const AgentGuarantorMessageSize = 32

// ActionAuthorityMessageSize is the exact length of an Action Authority
// message: a framed SHA-256 digest whose domain separates the object kind.
const ActionAuthorityMessageSize = 32

// SignaturePrefix is the text prefix of an ML-DSA-44 signature.
const SignaturePrefix = "mldsa44:"

// Context returns the FIPS 204 context string of a use, or an error for an
// unknown use.
func (u Use) Context() (string, error) {
	switch u {
	case UseRegistry:
		return "TOS-NATIVE-REGISTRY", nil
	case UseAgentPacket:
		return "TOS-AGENT-PACKET-V1", nil
	case UseAgentContact:
		return "TOS-AGENT-CONTACT-V1", nil
	case UseAgentGuarantor:
		return "TOS-AGENT-GUARANTOR-V1", nil
	case UseActionAuthority:
		return "TOS-ACTION-AUTHORITY-V1", nil
	default:
		return "", errors.New("unknown ML-DSA-44 signature use")
	}
}

var (
	// ErrInvalidSignature reports that a well-formed signature does not
	// verify for the key, use and payload.
	ErrInvalidSignature = errors.New("ML-DSA-44 signature does not verify")
	// ErrMalformed reports a key, signature, payload or response of the wrong
	// shape.
	ErrMalformed = errors.New("malformed ML-DSA-44 input")
	// ErrUnavailable reports that the signing helper could not be run or
	// did not answer. It never means a signature is valid.
	ErrUnavailable = errors.New("ML-DSA-44 helper is unavailable")
)

// Verifier checks one ML-DSA-44 signature. For UseRegistry the payload is
// the BOC of the action cell (the helper signs and verifies the action hash
// it derives itself, never a caller-supplied hash); for the Agent uses it is
// the exact preimage bytes.
type Verifier interface {
	Verify(ctx context.Context, use Use, payload, publicKey, signature []byte) error
}

// Signature is one controller signature as custody returned it.
type Signature struct {
	KeyID     [KeyIDSize]byte
	PublicKey []byte
	Signature []byte
}

// Signer asks key custody to sign a payload with a named controller. The
// controller name refers to custody-held key material that this module never
// sees.
type Signer interface {
	Sign(ctx context.Context, controller string, use Use, payload []byte) (Signature, error)
}

// CheckMessage validates the shape of a non-registry payload: non-empty and
// bounded, exactly AgentGuarantorMessageSize bytes for UseAgentGuarantor and
// exactly ActionAuthorityMessageSize bytes for UseActionAuthority.
func CheckMessage(use Use, payload []byte) error {
	if _, err := use.Context(); err != nil || use == UseRegistry {
		return ErrMalformed
	}
	if len(payload) == 0 || len(payload) > MaxMessageBytes ||
		use == UseAgentGuarantor && len(payload) != AgentGuarantorMessageSize ||
		use == UseActionAuthority && len(payload) != ActionAuthorityMessageSize {
		return ErrMalformed
	}
	return nil
}

// SignatureText renders an ML-DSA-44 signature in its only text form,
// mldsa44:<unpadded URL-safe Base64 of SignatureSize bytes>.
func SignatureText(signature []byte) (string, error) {
	if len(signature) != SignatureSize {
		return "", ErrMalformed
	}
	return SignaturePrefix + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ParseSignatureText parses the exact text form of a signature and refuses
// any other prefix, alphabet, padding, embedded whitespace, non-zero
// trailing bits or length.
func ParseSignatureText(value string) ([]byte, error) {
	if !strings.HasPrefix(value, SignaturePrefix) {
		return nil, ErrMalformed
	}
	encoded := value[len(SignaturePrefix):]
	if len(encoded) != base64.RawURLEncoding.EncodedLen(SignatureSize) {
		return nil, ErrMalformed
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) != SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != encoded {
		return nil, ErrMalformed
	}
	return signature, nil
}

// KeyID derives the controller key ID of an ML-DSA-44 public key:
// SHA-256("TOS-PQ-CONSENSUS-KEY-v1" || 0x01 0x00 || public_key).
func KeyID(publicKey []byte) ([KeyIDSize]byte, error) {
	if len(publicKey) != PublicKeySize {
		return [KeyIDSize]byte{}, ErrMalformed
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(keyIDDomain))
	_, _ = hash.Write(keyIDSuite)
	_, _ = hash.Write(publicKey)
	var id [KeyIDSize]byte
	copy(id[:], hash.Sum(nil))
	return id, nil
}

// KeyIDText renders a key ID in its only text form, mldsa44:<64 lowercase hex>.
func KeyIDText(id [KeyIDSize]byte) string {
	return KeyIDPrefix + hex.EncodeToString(id[:])
}

// ParseKeyIDText parses the exact text form of a key ID and refuses any
// other prefix, case, length or the all-zero ID.
func ParseKeyIDText(value string) ([KeyIDSize]byte, error) {
	var id [KeyIDSize]byte
	if !strings.HasPrefix(value, KeyIDPrefix) || len(value) != len(KeyIDPrefix)+2*KeyIDSize {
		return id, ErrMalformed
	}
	raw, err := hex.DecodeString(value[len(KeyIDPrefix):])
	if err != nil || len(raw) != KeyIDSize || value != KeyIDPrefix+hex.EncodeToString(raw) ||
		bytes.Equal(raw, make([]byte, KeyIDSize)) {
		return id, ErrMalformed
	}
	copy(id[:], raw)
	return id, nil
}

// CheckSignature validates the shape custody returned: key and signature
// lengths and a key ID that matches the key.
func CheckSignature(signature Signature) error {
	if len(signature.PublicKey) != PublicKeySize || len(signature.Signature) != SignatureSize {
		return ErrMalformed
	}
	id, err := KeyID(signature.PublicKey)
	if err != nil || id != signature.KeyID {
		return ErrMalformed
	}
	return nil
}
