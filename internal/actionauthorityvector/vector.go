// Package actionauthorityvector reads the shared Action Authority signature
// vector: Pure ML-DSA-44 signatures under TOS-ACTION-AUTHORITY-V1 made by the
// tosctl test from a fixed public seed with the deterministic FIPS 204
// variant. Fixture generators sign with it so their corpora are byte-stable,
// and tests resolve its key. It holds no private key: it can only replay the
// exact signatures the vector records.
package actionauthorityvector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// Schema is the only accepted vector schema.
const Schema = "tos.action-authority-signature-vector.v1"

// Context is the only accepted signature context.
const Context = "TOS-ACTION-AUTHORITY-V1"

// Domains are the four Action Authority signature domains in vector order.
var Domains = [4]string{
	"tos.writer-fence.v1",
	"tos.authorized-action-proof.v1",
	"tos.agent-relay-side-effect-admission-receipt-signature.v1",
	"tos.service.agent-guarantor-stage-action-admission-signature.v1",
}

// Message is one signed Action Authority object.
type Message struct {
	Name             string `json:"name"`
	SignatureDomain  string `json:"signature_domain"`
	CanonicalCBORHex string `json:"canonical_cbor_hex"`
	MessageHex       string `json:"message_hex"`
	SignatureHex     string `json:"signature_hex"`
}

// Refusal is a signature that is valid in its own mode, context and message
// and must never verify as the vector's first message.
type Refusal struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	Context         string `json:"context"`
	SignatureDomain string `json:"signature_domain"`
	MessageHex      string `json:"message_hex"`
	SignatureHex    string `json:"signature_hex"`
}

// Vector is the parsed vector file.
type Vector struct {
	Schema       string          `json:"schema"`
	SeedHex      string          `json:"seed_hex"`
	Context      string          `json:"context"`
	PublicKeyHex string          `json:"public_key_hex"`
	KeyIDHex     string          `json:"key_id_hex"`
	Messages     []Message       `json:"messages"`
	Refusals     []Refusal       `json:"refusals"`
	Differential json.RawMessage `json:"differential"`

	publicKey  []byte
	keyID      [mldsa44.KeyIDSize]byte
	signatures map[string][]byte
}

// Inputs is the file the tosctl vector test reads to produce a new vector.
type Inputs struct {
	Schema   string    `json:"schema"`
	Messages []Message `json:"messages"`
}

// FramedMessage is SHA-256(domain || 0x00 || uint32_be(len) || canonical).
func FramedMessage(domain string, canonical []byte) ([]byte, error) {
	if uint64(len(canonical)) > uint64(^uint32(0)) {
		return nil, errors.New("canonical object is too large to frame")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(canonical)
	return hash.Sum(nil), nil
}

// Load reads and checks a vector: schema, context, key and key ID, the domain
// order, each message's framing and each signature's length.
func Load(path string) (*Vector, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var vector Vector
	if err := decoder.Decode(&vector); err != nil {
		return nil, fmt.Errorf("Action Authority vector: %w", err)
	}
	if vector.Schema != Schema || vector.Context != Context || len(vector.Messages) != len(Domains) {
		return nil, errors.New("Action Authority vector has the wrong schema, context or message set")
	}
	vector.publicKey, err = hex.DecodeString(vector.PublicKeyHex)
	if err != nil || len(vector.publicKey) != mldsa44.PublicKeySize {
		return nil, errors.New("Action Authority vector public key is malformed")
	}
	vector.keyID, err = mldsa44.KeyID(vector.publicKey)
	if err != nil || hex.EncodeToString(vector.keyID[:]) != vector.KeyIDHex {
		return nil, errors.New("Action Authority vector key ID does not derive from its key")
	}
	vector.signatures = make(map[string][]byte, len(vector.Messages))
	for index, message := range vector.Messages {
		canonical, canonicalErr := hex.DecodeString(message.CanonicalCBORHex)
		signature, signatureErr := hex.DecodeString(message.SignatureHex)
		framed, framedErr := FramedMessage(message.SignatureDomain, canonical)
		if canonicalErr != nil || signatureErr != nil || framedErr != nil || message.SignatureDomain != Domains[index] ||
			hex.EncodeToString(framed) != message.MessageHex || len(signature) != mldsa44.SignatureSize {
			return nil, fmt.Errorf("Action Authority vector message %q is malformed", message.Name)
		}
		vector.signatures[message.MessageHex] = signature
	}
	return &vector, nil
}

// PublicKey returns a copy of the vector key.
func (v *Vector) PublicKey() []byte { return append([]byte(nil), v.publicKey...) }

// KeyID returns the vector key ID.
func (v *Vector) KeyID() [mldsa44.KeyIDSize]byte { return v.keyID }

// KeyIDText returns the vector key ID in its text form.
func (v *Vector) KeyIDText() string { return mldsa44.KeyIDText(v.keyID) }

// Message returns the vector entry for a name.
func (v *Vector) Message(name string) (Message, bool) {
	for _, message := range v.Messages {
		if message.Name == name {
			return message, true
		}
	}
	return Message{}, false
}

// Sign implements mldsa44.Signer by replaying the recorded signature for an
// exact Action Authority message. Any other use, controller or message is
// refused, so a generator can never emit a signature the vector lacks.
func (v *Vector) Sign(_ context.Context, controller string, use mldsa44.Use, payload []byte) (mldsa44.Signature, error) {
	if v == nil || use != mldsa44.UseActionAuthority || controller != "vector" {
		return mldsa44.Signature{}, mldsa44.ErrMalformed
	}
	signature, found := v.signatures[hex.EncodeToString(payload)]
	if !found {
		return mldsa44.Signature{}, fmt.Errorf("%w: message %x is not in the Action Authority vector", mldsa44.ErrMalformed, payload)
	}
	return mldsa44.Signature{KeyID: v.keyID, PublicKey: v.PublicKey(), Signature: append([]byte(nil), signature...)}, nil
}

// Resolver returns an Action Authority resolver that authorizes only the
// vector key, only for authorityID, and verifies through verifier.
func (v *Vector) Resolver(authorityID string, verifier mldsa44.Verifier) Resolver {
	return Resolver{vector: v, authorityID: authorityID, verifier: verifier}
}

// Resolver authorizes only the vector key, for one authority, and verifies
// through the given verifier.
type Resolver struct {
	vector      *Vector
	authorityID string
	verifier    mldsa44.Verifier
}

// Verify implements mldsa44.Verifier.
func (r Resolver) Verify(ctx context.Context, use mldsa44.Use, payload, publicKey, signature []byte) error {
	if r.verifier == nil {
		return mldsa44.ErrUnavailable
	}
	return r.verifier.Verify(ctx, use, payload, publicKey, signature)
}

// ResolveActionAuthorityKey returns the vector key for its authority.
func (r Resolver) ResolveActionAuthorityKey(authorityID string, keyID [mldsa44.KeyIDSize]byte, _ time.Time) ([]byte, error) {
	if r.vector == nil || authorityID != r.authorityID || keyID != r.vector.keyID {
		return nil, errors.New("Action Authority key is not authorized for this authority")
	}
	return r.vector.PublicKey(), nil
}
