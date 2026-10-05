package nativecore

import "encoding/hex"

// weakEd25519SignBitForced lists, with the encoding's sign bit (the top bit of
// the last byte) forced on, every refused key below the 0xec first byte: the
// canonical torsion encodings y = 0, the identity, and the two points of order
// 8, each with either sign bit. It mirrors the contracts' shared predicate.
var weakEd25519SignBitForced = map[string]bool{
	"0000000000000000000000000000000000000000000000000000000000000080": true,
	"0100000000000000000000000000000000000000000000000000000000000080": true,
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85": true,
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa": true,
}

// WeakEd25519PublicKey reports whether a 32-byte Ed25519 public key is one the
// TOS contracts refuse as an independent authority: a small-order point, or a
// non-canonical encoding (y >= 2^255 - 19, or the identity or order-2 point
// spelled with the sign bit set). A signature under such a key can be forged
// without a secret, or the key aliases another. Any other length is weak.
func WeakEd25519PublicKey(key []byte) bool {
	if len(key) != 32 {
		return true
	}
	if key[0] >= 0xec {
		for _, value := range key[1:31] {
			if value != 0xff {
				return false
			}
		}
		return key[31]&0x7f == 0x7f
	}
	forced := append([]byte(nil), key...)
	forced[31] |= 0x80
	return weakEd25519SignBitForced[hex.EncodeToString(forced)]
}
