package referencecodec

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// This file is an independent encoder for the Service Actor rail cells: the
// Accepted Quote, the NSR1 service request, the NSM1 metadata and the terms
// cell. It writes bits and computes ordinary-cell representation hashes
// itself, so it shares neither the production builders nor the cell library
// with pkg/nativecore.

type refCell struct {
	data  []byte
	nbits int
	refs  []*refCell
}

type bitWriter struct {
	cell *refCell
}

func newWriter() *bitWriter { return &bitWriter{cell: &refCell{}} }

func (w *bitWriter) bit(value bool) {
	if w.cell.nbits%8 == 0 {
		w.cell.data = append(w.cell.data, 0)
	}
	if value {
		w.cell.data[w.cell.nbits/8] |= 0x80 >> (w.cell.nbits % 8)
	}
	w.cell.nbits++
}

func (w *bitWriter) uint(value uint64, width int) {
	for i := width - 1; i >= 0; i-- {
		w.bit(value>>uint(i)&1 == 1)
	}
}

func (w *bitWriter) bytes(value []byte) {
	for _, b := range value {
		w.uint(uint64(b), 8)
	}
}

func (w *bitWriter) ref(child *refCell) { w.cell.refs = append(w.cell.refs, child) }

func (w *bitWriter) done() (*refCell, error) {
	if w.cell.nbits > 1023 || len(w.cell.refs) > 4 {
		return nil, errors.New("reference cell overflow")
	}
	return w.cell, nil
}

func (c *refCell) depth() uint16 {
	var depth uint16
	for _, child := range c.refs {
		if d := child.depth() + 1; d > depth {
			depth = d
		}
	}
	return depth
}

// hash is the standard representation hash of an ordinary level-0 cell.
func (c *refCell) hash() []byte {
	full := c.nbits / 8
	descriptor := []byte{byte(len(c.refs)), byte(full + (c.nbits+7)/8)}
	data := append([]byte(nil), c.data...)
	if c.nbits%8 != 0 {
		data[full] |= 0x80 >> (c.nbits % 8)
	}
	digest := sha256.New()
	digest.Write(descriptor)
	digest.Write(data)
	for _, child := range c.refs {
		var depth [2]byte
		binary.BigEndian.PutUint16(depth[:], child.depth())
		digest.Write(depth[:])
	}
	for _, child := range c.refs {
		digest.Write(child.hash())
	}
	return digest.Sum(nil)
}

func (w *bitWriter) coins(value *big.Int) error {
	if value == nil || value.Sign() < 0 || value.BitLen() > 120 {
		return errors.New("Coins out of range")
	}
	raw := value.Bytes()
	w.uint(uint64(len(raw)), 4)
	w.bytes(raw)
	return nil
}

func nonZeroHex32(value string) ([]byte, error) {
	raw, err := hex32(value)
	if err != nil || zero(raw) {
		return nil, errors.New("invalid non-zero 32-byte hex value")
	}
	return raw, nil
}

func prefixed32(value, prefix string) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("invalid digest prefix")
	}
	return nonZeroHex32(strings.TrimPrefix(value, prefix))
}

func networkCell(network Network) (*refCell, error) {
	root, err := prefixed32(network.GenesisRootHash, "sha256:")
	if err != nil {
		return nil, err
	}
	file, err := prefixed32(network.GenesisFileHash, "sha256:")
	if err != nil {
		return nil, err
	}
	if !validText(network.NetworkID, 64) {
		return nil, errors.New("invalid network id")
	}
	name := sha256.Sum256([]byte(network.NetworkID))
	w := newWriter()
	w.bytes(root)
	w.bytes(file)
	w.bytes(name[:])
	return w.done()
}

func textSnake(value string) (*refCell, error) {
	raw := []byte(value)
	var next *refCell
	for end := len(raw); end > 0; {
		start := ((end - 1) / 127) * 127
		w := newWriter()
		w.bytes(raw[start:end])
		if next != nil {
			w.ref(next)
		}
		cellValue, err := w.done()
		if err != nil {
			return nil, err
		}
		next, end = cellValue, start
	}
	if next == nil {
		return nil, errors.New("empty text")
	}
	return next, nil
}

// RailQuote is the Accepted Quote input in its own wire form.
type RailQuote struct {
	CapabilityID           string `json:"capability_id"`
	CapabilityVersion      string `json:"capability_version"`
	ProviderAgentID        string `json:"provider_agent_id"`
	ManifestDigest         string `json:"manifest_digest"`
	TransportBindingDigest string `json:"transport_binding_digest"`
	ExpiresAtUnixSeconds   uint64 `json:"expires_at_unix_seconds"`
	ActorAccountHex        string `json:"actor_account_hex"`
	ActorCodeHash          string `json:"actor_code_hash"`
	PolicyVersion          uint32 `json:"policy_version"`
	TermsHashHex           string `json:"terms_hash"`
	PriceNanoTOS           string `json:"price_nanotos"`
	StorageFeeNanoTOS      string `json:"storage_fee_nanotos"`
	AttestorKeyID          string `json:"attestor_key_id"`
}

func positiveDecimal(value string) (*big.Int, error) {
	if value == "" || value[0] == '0' || len(value) > 40 {
		return nil, errors.New("invalid positive decimal")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid positive decimal")
		}
	}
	amount, _ := new(big.Int).SetString(value, 10)
	if amount.BitLen() > 120 {
		return nil, errors.New("amount too large")
	}
	return amount, nil
}

// ComputeRailAcceptedQuote returns the rail Accepted Quote commitment as
// tvm-cell-sha256:<hex>.
func ComputeRailAcceptedQuote(network Network, quote RailQuote) (string, error) {
	domain, err := networkCell(network)
	if err != nil {
		return "", err
	}
	capability, err := objectID(quote.CapabilityID, "cap_")
	if err != nil {
		return "", err
	}
	provider, err := objectID(quote.ProviderAgentID, "agent_")
	if err != nil {
		return "", err
	}
	manifest, err := prefixed32(quote.ManifestDigest, "sha256:")
	if err != nil {
		return "", err
	}
	transport, err := prefixed32(quote.TransportBindingDigest, "sha256:")
	if err != nil {
		return "", err
	}
	actor, err := nonZeroHex32(quote.ActorAccountHex)
	if err != nil {
		return "", err
	}
	code, err := prefixed32(quote.ActorCodeHash, "tvm-cell-sha256:")
	if err != nil {
		return "", err
	}
	terms, err := nonZeroHex32(quote.TermsHashHex)
	if err != nil {
		return "", err
	}
	price, err := positiveDecimal(quote.PriceNanoTOS)
	if err != nil {
		return "", err
	}
	fee, err := positiveDecimal(quote.StorageFeeNanoTOS)
	if err != nil {
		return "", err
	}
	keyID, err := prefixed32(quote.AttestorKeyID, "mldsa44:")
	if err != nil {
		return "", err
	}
	if !validText(quote.CapabilityVersion, 128) || quote.ExpiresAtUnixSeconds == 0 {
		return "", errors.New("invalid quote version or expiry")
	}
	versionText, err := textSnake(quote.CapabilityVersion)
	if err != nil {
		return "", err
	}
	versionHash := sha256.Sum256([]byte(quote.CapabilityVersion))
	v := newWriter()
	v.bytes(versionHash[:])
	v.bytes(manifest)
	v.bytes(transport)
	v.uint(quote.ExpiresAtUnixSeconds, 64)
	v.ref(versionText)
	version, err := v.done()
	if err != nil {
		return "", err
	}
	i := newWriter()
	i.bytes(capability)
	i.bytes(provider)
	i.ref(version)
	identity, err := i.done()
	if err != nil {
		return "", err
	}
	rt := newWriter()
	rt.bytes(terms)
	if err := rt.coins(price); err != nil {
		return "", err
	}
	if err := rt.coins(fee); err != nil {
		return "", err
	}
	railTerms, err := rt.done()
	if err != nil {
		return "", err
	}
	r := newWriter()
	r.uint(0b100, 3) // addr_std, no anycast
	r.uint(0, 8)     // workchain 0
	r.bytes(actor)
	r.bytes(code)
	r.uint(uint64(quote.PolicyVersion), 32)
	r.ref(railTerms)
	rail, err := r.done()
	if err != nil {
		return "", err
	}
	a := newWriter()
	a.bytes(keyID)
	authority, err := a.done()
	if err != nil {
		return "", err
	}
	root := newWriter()
	root.uint(0x4e415131, 32)
	root.uint(1, 16)
	root.ref(domain)
	root.ref(identity)
	root.ref(rail)
	root.ref(authority)
	result, err := root.done()
	if err != nil {
		return "", err
	}
	return "tvm-cell-sha256:" + hex.EncodeToString(result.hash()), nil
}

// ComputeServiceRequest returns cell_hash(NSR1) as 64 lowercase hex.
func ComputeServiceRequest(quoteCommitment, executionID, inputDigest string) (string, error) {
	w := newWriter()
	w.uint(0x4e535231, 32)
	w.uint(1, 16)
	for _, value := range []string{quoteCommitment, executionID, inputDigest} {
		raw, err := nonZeroHex32(value)
		if err != nil {
			return "", err
		}
		w.bytes(raw)
	}
	result, err := w.done()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(result.hash()), nil
}

// RailTerms is the terms_hash preimage input.
type RailTerms struct {
	PolicyVersion     uint32
	PricePerCall      *big.Int
	StorageFee        *big.Int
	CleanupBounty     *big.Int
	ResponseSLA       uint32
	RefundClaimWindow uint32
	MetadataHashHex   string
	ProofSchemeHex    string
	HasAttestor       bool
	AttestorKeyIDHex  string
}

// ComputeTermsHash returns cell_hash(terms_cell) as 64 lowercase hex.
func ComputeTermsHash(terms RailTerms) (string, error) {
	metadata, err := hex.DecodeString(terms.MetadataHashHex)
	if err != nil || len(metadata) != 32 {
		return "", errors.New("invalid metadata hash")
	}
	scheme, err := hex.DecodeString(terms.ProofSchemeHex)
	if err != nil || len(scheme) != 32 {
		return "", errors.New("invalid proof scheme hash")
	}
	keyID := make([]byte, 32)
	if terms.HasAttestor {
		if keyID, err = nonZeroHex32(terms.AttestorKeyIDHex); err != nil {
			return "", err
		}
	}
	t := newWriter()
	t.bytes(metadata)
	t.bytes(scheme)
	t.bit(terms.HasAttestor)
	t.bytes(keyID)
	tail, err := t.done()
	if err != nil {
		return "", err
	}
	w := newWriter()
	w.uint(uint64(terms.PolicyVersion), 32)
	for _, value := range []*big.Int{terms.PricePerCall, terms.StorageFee, terms.CleanupBounty} {
		if err := w.coins(value); err != nil {
			return "", err
		}
	}
	w.uint(uint64(terms.ResponseSLA), 32)
	w.uint(uint64(terms.RefundClaimWindow), 32)
	w.ref(tail)
	root, err := w.done()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(root.hash()), nil
}

// ComputeMetadataHash returns cell_hash(NSM1) as 64 lowercase hex.
func ComputeMetadataHash(network Network, capabilityID, providerAgentID, version, manifestDigest string) (string, error) {
	domain, err := networkCell(network)
	if err != nil {
		return "", err
	}
	capability, err := objectID(capabilityID, "cap_")
	if err != nil {
		return "", err
	}
	provider, err := objectID(providerAgentID, "agent_")
	if err != nil {
		return "", err
	}
	manifest, err := prefixed32(manifestDigest, "sha256:")
	if err != nil {
		return "", err
	}
	if !validText(version, 128) {
		return "", errors.New("invalid version")
	}
	versionHash := sha256.Sum256([]byte(version))
	v := newWriter()
	v.bytes(versionHash[:])
	v.bytes(manifest)
	versionCell, err := v.done()
	if err != nil {
		return "", err
	}
	w := newWriter()
	w.uint(0x4e534d31, 32)
	w.uint(1, 16)
	w.bytes(capability)
	w.bytes(provider)
	w.ref(domain)
	w.ref(versionCell)
	root, err := w.done()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(root.hash()), nil
}
