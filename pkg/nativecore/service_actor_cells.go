package nativecore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// MsgAddressV1 is one decoded TL-B MsgAddress exactly as it was stored.
// Bits holds the exact address bits consumed from the slice, so two
// addresses are equal only when their stored encodings are equal, and the
// contract's slice_hash(address) is the hash of a cell holding Bits.
type MsgAddressV1 struct {
	// Kind is 0 addr_none, 1 addr_extern, 2 addr_std, 3 addr_var.
	Kind uint8
	// AnycastDepth is -1 without anycast, otherwise the 5-bit depth.
	AnycastDepth  int
	AnycastPrefix []byte
	Workchain     int32
	AddressBits   uint
	Address       []byte
	Bits          []byte
	BitLen        uint
}

const (
	msgAddressNone   = 0
	msgAddressExtern = 1
	msgAddressStd    = 2
	msgAddressVar    = 3
)

// IsInternal reports addr_std or addr_var.
func (a MsgAddressV1) IsInternal() bool {
	return a.Kind == msgAddressStd || a.Kind == msgAddressVar
}

// RawStandard returns "wc:hex" for an addr_std without anycast and false for
// every other address form.
func (a MsgAddressV1) RawStandard() (string, bool) {
	if a.Kind != msgAddressStd || a.AnycastDepth >= 0 || a.AddressBits != 256 || len(a.Address) != 32 {
		return "", false
	}
	return fmt.Sprintf("%d:%s", a.Workchain, hex.EncodeToString(a.Address)), true
}

// Text is a stable text form of the exact stored address: "wc:hex" for an
// addr_std without anycast, otherwise "raw:<hex bits>/<bit length>".
func (a MsgAddressV1) Text() string {
	if raw, ok := a.RawStandard(); ok {
		return raw
	}
	return fmt.Sprintf("raw:%s/%d", hex.EncodeToString(a.Bits), a.BitLen)
}

// DecodeMsgAddressCell decodes a cell holding exactly one MsgAddress.
func DecodeMsgAddressCell(value *cell.Cell) (MsgAddressV1, error) {
	s, err := beginOrdinary(value, "address")
	if err != nil {
		return MsgAddressV1{}, err
	}
	address, err := loadMsgAddress(s)
	if err != nil {
		return address, err
	}
	return address, exhausted(s, "address")
}

// Equal compares stored encodings bit for bit.
func (a MsgAddressV1) Equal(b MsgAddressV1) bool {
	return a.BitLen == b.BitLen && bytes.Equal(a.Bits, b.Bits)
}

// SliceHash is the contract's slice_hash(address): the hash of an ordinary
// cell holding exactly the address bits.
func (a MsgAddressV1) SliceHash() ([32]byte, error) {
	var out [32]byte
	builder := cell.BeginCell()
	if err := builder.StoreSlice(a.Bits, a.BitLen); err != nil {
		return out, err
	}
	copy(out[:], builder.EndCell().Hash())
	return out, nil
}

// loadMsgAddress mirrors the TL-B MsgAddress grammar the Rust block crate
// decodes: addr_none$00, addr_extern$01 len:(## 9) bits, addr_std$10
// anycast:(Maybe Anycast) workchain:int8 address:bits256, addr_var$11
// anycast:(Maybe Anycast) addr_len:(## 9) workchain:int32 address:bits.
// Anycast is depth:(## 5) rewrite_pfx:(depth * Bit), as the Rust crate reads it.
func loadMsgAddress(s *cell.Slice) (MsgAddressV1, error) {
	start := s.Copy()
	before := s.BitsLeft()
	result := MsgAddressV1{AnycastDepth: -1}
	tag, err := s.LoadUInt(2)
	if err != nil {
		return result, errors.New("address tag is missing")
	}
	result.Kind = uint8(tag)
	switch tag {
	case msgAddressNone:
	case msgAddressExtern:
		length, err := s.LoadUInt(9)
		if err != nil {
			return result, errors.New("external address length is missing")
		}
		value, err := s.LoadSlice(uint(length))
		if err != nil {
			return result, errors.New("external address is truncated")
		}
		result.AddressBits, result.Address = uint(length), value
	case msgAddressStd, msgAddressVar:
		hasAnycast, err := s.LoadBoolBit()
		if err != nil {
			return result, errors.New("address anycast flag is missing")
		}
		if hasAnycast {
			depth, err := s.LoadUInt(5)
			if err != nil {
				return result, errors.New("anycast depth is missing")
			}
			prefix, err := s.LoadSlice(uint(depth))
			if err != nil {
				return result, errors.New("anycast prefix is truncated")
			}
			result.AnycastDepth, result.AnycastPrefix = int(depth), prefix
		}
		if tag == msgAddressStd {
			workchain, err := s.LoadInt(8)
			if err != nil {
				return result, errors.New("address workchain is missing")
			}
			value, err := s.LoadSlice(256)
			if err != nil {
				return result, errors.New("address is truncated")
			}
			result.Workchain, result.AddressBits, result.Address = int32(workchain), 256, value
		} else {
			length, err := s.LoadUInt(9)
			if err != nil {
				return result, errors.New("variable address length is missing")
			}
			workchain, err := s.LoadInt(32)
			if err != nil {
				return result, errors.New("variable address workchain is missing")
			}
			value, err := s.LoadSlice(uint(length))
			if err != nil {
				return result, errors.New("variable address is truncated")
			}
			result.Workchain, result.AddressBits, result.Address = int32(workchain), uint(length), value
		}
	}
	consumed := before - s.BitsLeft()
	raw, err := start.LoadSlice(consumed)
	if err != nil {
		return result, errors.New("address bits cannot be captured")
	}
	result.Bits, result.BitLen = raw, consumed
	return result, nil
}

// loadMsgAddressInt accepts only addr_std and addr_var, as Rust MsgAddressInt.
func loadMsgAddressInt(s *cell.Slice) (MsgAddressV1, error) {
	value, err := loadMsgAddress(s)
	if err != nil {
		return value, err
	}
	if !value.IsInternal() {
		return value, errors.New("address is not an internal address")
	}
	return value, nil
}

// StandardAddress encodes a raw "wc:hex" address as addr_std without anycast.
func StandardAddress(raw string) (MsgAddressV1, error) {
	parsed, err := parseServiceActorRawAddress(raw, false)
	if err != nil {
		return MsgAddressV1{}, err
	}
	builder := cell.BeginCell().MustStoreUInt(msgAddressStd, 2).MustStoreBoolBit(false).
		MustStoreInt(int64(parsed.workchain), 8).MustStoreSlice(parsed.account, 256)
	s := builder.EndCell().MustBeginParse()
	return loadMsgAddressInt(s)
}

type rawAddress struct {
	workchain int32
	account   []byte
}

func parseServiceActorRawAddress(raw string, requireZero bool) (rawAddress, error) {
	var workchain int32
	var account string
	if _, err := fmt.Sscanf(raw, "%d:%64s", &workchain, &account); err != nil {
		return rawAddress{}, errors.New("invalid raw address")
	}
	decoded, err := hex.DecodeString(account)
	if err != nil || len(decoded) != 32 || fmt.Sprintf("%d:%s", workchain, hex.EncodeToString(decoded)) != raw ||
		workchain < -128 || workchain > 127 || requireZero && workchain != 0 {
		return rawAddress{}, errors.New("invalid raw address")
	}
	return rawAddress{workchain: workchain, account: decoded}, nil
}

// MaxServiceActorCoins is the exclusive bound of a Coins value (2^120).
var MaxServiceActorCoins = new(big.Int).Lsh(big.NewInt(1), 120)

// loadServiceActorCoins mirrors the Rust Coins decoder: a 4-bit byte length,
// a value of that many bytes, and refusal of a non-minimal encoding (a
// leading zero byte).
func loadServiceActorCoins(s *cell.Slice) (*big.Int, error) {
	length, err := s.LoadUInt(4)
	if err != nil {
		return nil, errors.New("Coins length is missing")
	}
	if length == 0 {
		return new(big.Int), nil
	}
	raw, err := s.LoadSlice(uint(length) * 8)
	if err != nil {
		return nil, errors.New("Coins value is truncated")
	}
	if raw[0] == 0 {
		return nil, errors.New("non-minimal Coins encoding")
	}
	return new(big.Int).SetBytes(raw), nil
}

// storeServiceActorCoins writes the minimal Coins encoding of value.
func storeServiceActorCoins(builder *cell.Builder, value *big.Int) error {
	if value == nil || value.Sign() < 0 || value.Cmp(MaxServiceActorCoins) >= 0 {
		return errors.New("Coins value is out of range")
	}
	raw := value.Bytes()
	if err := builder.StoreUInt(uint64(len(raw)), 4); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return builder.StoreSlice(raw, uint(len(raw))*8)
}

func loadHash(s *cell.Slice) ([32]byte, error) {
	var out [32]byte
	raw, err := s.LoadSlice(256)
	if err != nil {
		return out, errors.New("256-bit field is truncated")
	}
	copy(out[:], raw)
	return out, nil
}

// beginOrdinary refuses library, pruned, Merkle and every other exotic cell.
func beginOrdinary(value *cell.Cell, what string) (*cell.Slice, error) {
	if value == nil {
		return nil, fmt.Errorf("%s cell is missing", what)
	}
	if value.IsSpecial() {
		return nil, fmt.Errorf("%s cell is not an ordinary cell", what)
	}
	s, err := value.BeginParse()
	if err != nil {
		return nil, fmt.Errorf("%s cell cannot be parsed", what)
	}
	return s, nil
}

func exhausted(s *cell.Slice, what string) error {
	if s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return fmt.Errorf("%s has trailing data", what)
	}
	return nil
}

func loadRefCell(s *cell.Slice, what string) (*cell.Cell, error) {
	value, err := s.LoadRefCell()
	if err != nil {
		return nil, fmt.Errorf("%s reference is missing", what)
	}
	return value, nil
}

// dictLeaf is one leaf of a strictly walked HashmapE.
type dictLeaf struct {
	key   []byte
	value *cell.Slice
}

// walkHashmapE validates and enumerates a HashmapE n X held at the slice
// position: hme_empty$0 or hme_root$1 with the root as a reference. Every
// node must be an ordinary cell; a fork holds exactly its label and two
// references; a leaf holds its label followed by the value, which the
// caller must exhaust. At most limit leaves are accepted.
func walkHashmapE(s *cell.Slice, keyBits uint, limit int, what string) ([]dictLeaf, error) {
	present, err := s.LoadBoolBit()
	if err != nil {
		return nil, fmt.Errorf("%s dictionary flag is missing", what)
	}
	if !present {
		return nil, nil
	}
	root, err := loadRefCell(s, what+" dictionary root")
	if err != nil {
		return nil, err
	}
	var leaves []dictLeaf
	if err := walkHashmapNode(root, keyBits, nil, 0, limit, &leaves, what, 0); err != nil {
		return nil, err
	}
	return leaves, nil
}

func walkHashmapNode(node *cell.Cell, remaining uint, prefix []byte, prefixBits uint, limit int,
	leaves *[]dictLeaf, what string, depth int) error {
	if depth > 1024 {
		return fmt.Errorf("%s dictionary is too deep", what)
	}
	s, err := beginOrdinary(node, what+" dictionary node")
	if err != nil {
		return err
	}
	labelBits, label, err := loadHashmapLabel(s, remaining)
	if err != nil {
		return fmt.Errorf("%s dictionary label: %w", what, err)
	}
	key, keyBits := appendBits(prefix, prefixBits, label, labelBits)
	rest := remaining - labelBits
	if rest == 0 {
		if len(*leaves) >= limit {
			return fmt.Errorf("%s dictionary exceeds %d entries", what, limit)
		}
		*leaves = append(*leaves, dictLeaf{key: key, value: s})
		return nil
	}
	if s.BitsLeft() != 0 || s.RefsNum() != 2 {
		return fmt.Errorf("%s dictionary fork is not exactly two references", what)
	}
	left, err := loadRefCell(s, what+" dictionary left branch")
	if err != nil {
		return err
	}
	right, err := loadRefCell(s, what+" dictionary right branch")
	if err != nil {
		return err
	}
	leftKey, leftBits := appendBits(key, keyBits, []byte{0x00}, 1)
	if err := walkHashmapNode(left, rest-1, leftKey, leftBits, limit, leaves, what, depth+1); err != nil {
		return err
	}
	rightKey, rightBits := appendBits(key, keyBits, []byte{0x80}, 1)
	return walkHashmapNode(right, rest-1, rightKey, rightBits, limit, leaves, what, depth+1)
}

// loadHashmapLabel reads HmLabel ~l m: hml_short$0 Unary bits,
// hml_long$10 (#<= m) bits, hml_same$11 bit (#<= m), with l <= m.
func loadHashmapLabel(s *cell.Slice, m uint) (uint, []byte, error) {
	width := uint(bits.Len(uint(m)))
	first, err := s.LoadBoolBit()
	if err != nil {
		return 0, nil, errors.New("label tag is missing")
	}
	if !first {
		var length uint
		for {
			bit, err := s.LoadBoolBit()
			if err != nil {
				return 0, nil, errors.New("unary label length is truncated")
			}
			if !bit {
				break
			}
			length++
			if length > m {
				return 0, nil, errors.New("label is longer than the remaining key")
			}
		}
		value, err := s.LoadSlice(length)
		if err != nil {
			return 0, nil, errors.New("short label is truncated")
		}
		return length, value, nil
	}
	second, err := s.LoadBoolBit()
	if err != nil {
		return 0, nil, errors.New("label tag is truncated")
	}
	if !second {
		length, err := s.LoadUInt(width)
		if err != nil || uint(length) > m {
			return 0, nil, errors.New("long label length is invalid")
		}
		value, err := s.LoadSlice(uint(length))
		if err != nil {
			return 0, nil, errors.New("long label is truncated")
		}
		return uint(length), value, nil
	}
	bit, err := s.LoadBoolBit()
	if err != nil {
		return 0, nil, errors.New("same label bit is missing")
	}
	length, err := s.LoadUInt(width)
	if err != nil || uint(length) > m {
		return 0, nil, errors.New("same label length is invalid")
	}
	value := make([]byte, (length+7)/8)
	if bit {
		for i := uint64(0); i < length; i++ {
			value[i/8] |= 0x80 >> (i % 8)
		}
	}
	return uint(length), value, nil
}

// appendBits concatenates two left-aligned bit strings.
func appendBits(a []byte, aBits uint, b []byte, bBits uint) ([]byte, uint) {
	total := aBits + bBits
	out := make([]byte, (total+7)/8)
	copy(out, a[:(aBits+7)/8])
	if aBits%8 != 0 {
		out[aBits/8] &= byte(0xff << (8 - aBits%8))
	}
	for i := uint(0); i < bBits; i++ {
		if b[i/8]&(0x80>>(i%8)) != 0 {
			position := aBits + i
			out[position/8] |= 0x80 >> (position % 8)
		}
	}
	return out, total
}
