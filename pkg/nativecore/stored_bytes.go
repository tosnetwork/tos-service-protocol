package nativecore

import (
	"errors"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// storedChunkBytes is the payload of every full cell of a stored byte chain.
const storedChunkBytes = 127

// storedBytesCell encodes key or signature material the way the Registry
// stores it: stored = len:uint32 ^chain, where the chain is byte-aligned
// ordinary cells, each full cell holding exactly 127 bytes and one
// continuation reference, and a final cell holding 1 to 127 bytes and no
// reference. Callers pass validated, non-empty material of a fixed length.
func storedBytesCell(data []byte) *cell.Cell {
	var next *cell.Cell
	for end := len(data); end > 0; {
		start := ((end - 1) / storedChunkBytes) * storedChunkBytes
		builder := cell.BeginCell().MustStoreSlice(data[start:end], uint(8*(end-start)))
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
		end = start
	}
	return cell.BeginCell().MustStoreUInt(uint64(len(data)), 32).MustStoreRef(next).EndCell()
}

// readStoredBytes decodes a stored wrapper and refuses anything but the one
// canonical encoding of exactly expected bytes: a wrapper or chain cell that
// is exotic, a wrong length, a chain cell that is not byte-aligned, empty,
// longer than 127 bytes, a non-final cell shorter than 127 bytes, a cell with
// more than one reference, a final cell with one, or trailing wrapper data.
func readStoredBytes(stored *cell.Cell, expected int) ([]byte, error) {
	if stored == nil || stored.IsSpecial() || expected <= 0 {
		return nil, errors.New("stored Native material is missing or not an ordinary cell")
	}
	wrapper, err := stored.BeginParse()
	if err != nil {
		return nil, errors.New("invalid stored Native material wrapper")
	}
	length, err := wrapper.LoadUInt(32)
	if err != nil || length != uint64(expected) {
		return nil, errors.New("stored Native material has the wrong length")
	}
	cursor, err := wrapper.LoadRefCell()
	if err != nil {
		return nil, errors.New("stored Native material has no chain")
	}
	if err := endSlice(wrapper); err != nil {
		return nil, errors.New("stored Native material wrapper has trailing data")
	}
	out := make([]byte, 0, expected)
	for {
		if cursor == nil || cursor.IsSpecial() {
			return nil, errors.New("stored Native material chain cell is not an ordinary cell")
		}
		s, err := cursor.BeginParse()
		if err != nil {
			return nil, errors.New("invalid stored Native material chain cell")
		}
		bits, refs := s.BitsLeft(), s.RefsNum()
		if bits%8 != 0 || bits == 0 || bits > 8*storedChunkBytes || len(out)+int(bits/8) > expected {
			return nil, errors.New("stored Native material chain cell has a non-canonical length")
		}
		part, err := s.LoadSlice(bits)
		if err != nil {
			return nil, errors.New("invalid stored Native material chain cell")
		}
		out = append(out, part...)
		switch refs {
		case 0:
			if len(out) != expected {
				return nil, errors.New("stored Native material chain is shorter than its length")
			}
			return out, nil
		case 1:
			if bits != 8*storedChunkBytes {
				return nil, errors.New("stored Native material chain continues after a short cell")
			}
			cursor, err = s.LoadRefCell()
			if err != nil {
				return nil, errors.New("invalid stored Native material continuation")
			}
		default:
			return nil, errors.New("stored Native material chain cell has more than one continuation")
		}
	}
}
