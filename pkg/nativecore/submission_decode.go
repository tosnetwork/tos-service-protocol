package nativecore

import (
	"bytes"
	"errors"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	opSubmit              = 0x4e560001
	opAuthorizeCapability = 0x4e560002
)

// decodeSubmissionBody parses a recorded outbound body BOC and returns its
// signature sets. It refuses anything but the one canonical body for this
// action: a single ordinary root holding exactly opcode:uint32
// query_id:uint64 ^action ^authority ^counterparty, the expected opcode and
// query ID, and the action cell of this exact action.
func decodeSubmissionBody(raw []byte, built BuiltAction, opcode, queryID uint64) ([]*nativev1.SignatureV1, []*nativev1.SignatureV1, error) {
	if len(raw) == 0 || len(raw) > MaxRelayBodyBytes || built.Cell == nil {
		return nil, nil, errors.New("recorded Native body is missing or outside bounds")
	}
	roots, err := cell.FromBOCMultiRoot(raw)
	if err != nil || len(roots) != 1 || roots[0] == nil || roots[0].IsSpecial() {
		return nil, nil, errors.New("recorded Native body is not one ordinary cell")
	}
	s, err := roots[0].BeginParse()
	if err != nil {
		return nil, nil, errors.New("invalid recorded Native body")
	}
	gotOpcode, err := s.LoadUInt(32)
	if err != nil || gotOpcode != opcode {
		return nil, nil, errors.New("recorded Native body has another opcode")
	}
	gotQuery, err := s.LoadUInt(64)
	if err != nil || gotQuery != queryID {
		return nil, nil, errors.New("recorded Native body has another query ID")
	}
	action, err := s.LoadRefCell()
	if err != nil || !bytes.Equal(action.Hash(), built.Hash) {
		return nil, nil, errors.New("recorded Native body carries another action")
	}
	authorityCell, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("recorded Native body has no authority set")
	}
	counterpartyCell, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("recorded Native body has no counterparty set")
	}
	if err := endSlice(s); err != nil {
		return nil, nil, err
	}
	authority, err := decodeSignatureCell(authorityCell, false)
	if err != nil {
		return nil, nil, err
	}
	counterparty, err := decodeSignatureCell(counterpartyCell, true)
	if err != nil {
		return nil, nil, err
	}
	return authority, counterparty, nil
}

// decodeSignatureCell is the strict inverse of SignatureCell and
// EmptySignatureCell: count:uint8 then, for a non-empty set, one reference to
// a chain of key_id:uint256 ^stored_signature [^entry] entries, strictly
// ascending by key ID, each signature stored canonically.
func decodeSignatureCell(value *cell.Cell, allowEmpty bool) ([]*nativev1.SignatureV1, error) {
	if value == nil || value.IsSpecial() {
		return nil, errors.New("Native signature set is not an ordinary cell")
	}
	s, err := value.BeginParse()
	if err != nil {
		return nil, errors.New("invalid Native signature set")
	}
	count, err := s.LoadUInt(8)
	if err != nil || count > MaxSignatures {
		return nil, errors.New("invalid Native signature count")
	}
	if count == 0 {
		if !allowEmpty || endSlice(s) != nil {
			return nil, errors.New("invalid empty Native signature set")
		}
		return nil, nil
	}
	if s.RefsNum() != 1 || s.BitsLeft() != 0 {
		return nil, errors.New("Native signature set has a non-canonical shape")
	}
	cursor, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("Native signature set has no entries")
	}
	result := make([]*nativev1.SignatureV1, 0, count)
	var previous []byte
	for i := uint64(0); i < count; i++ {
		if cursor == nil || cursor.IsSpecial() {
			return nil, errors.New("Native signature entry is not an ordinary cell")
		}
		es, err := cursor.BeginParse()
		if err != nil {
			return nil, errors.New("invalid Native signature entry")
		}
		// The key ID, the stored signature, the continuation exactly when
		// another entry follows, and nothing else (checked by endSlice).
		keyID, err := es.LoadSlice(256)
		if err != nil || previous != nil && bytes.Compare(keyID, previous) <= 0 {
			return nil, errors.New("Native signature entries are not strictly ascending")
		}
		var id [mldsa44.KeyIDSize]byte
		copy(id[:], keyID)
		text := mldsa44.KeyIDText(id)
		if !validKeyID(text) {
			return nil, errors.New("invalid Native signature key ID")
		}
		stored, err := es.LoadRefCell()
		if err != nil {
			return nil, errors.New("Native signature entry has no stored signature")
		}
		signature, err := readStoredBytes(stored, mldsa44.SignatureSize)
		if err != nil {
			return nil, err
		}
		if i+1 < count {
			cursor, err = es.LoadRefCell()
			if err != nil {
				return nil, errors.New("Native signature entry has no continuation")
			}
		}
		if err := endSlice(es); err != nil {
			return nil, err
		}
		result = append(result, &nativev1.SignatureV1{KeyId: text, Mldsa44Signature: signature})
		previous = keyID
	}
	return result, nil
}
