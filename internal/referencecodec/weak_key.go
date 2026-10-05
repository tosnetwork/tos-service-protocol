package referencecodec

import "math/big"

// weakControllerKey restates the contracts' weak Ed25519 key predicate on the
// 256-bit integer a contract loads with load_uint(256), independently of the
// production codec: keys whose top byte is at least 0xec are weak when every
// following byte but the last is 0xff and the last byte's low seven bits are
// all set (y >= 2^255 - 19, or the order-2 point with its sign bit); any other
// key is weak when, with its sign bit forced on, it equals one of four
// torsion encodings.
func weakControllerKey(key []byte) bool {
	value := new(big.Int).SetBytes(key)
	if new(big.Int).Rsh(value, 248).Cmp(big.NewInt(0xec)) >= 0 {
		ones := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 240), big.NewInt(1))
		middle := new(big.Int).And(new(big.Int).Rsh(value, 8), ones)
		low := new(big.Int).And(value, big.NewInt(127))
		return middle.Cmp(ones) == 0 && low.Cmp(big.NewInt(127)) == 0
	}
	eitherSign := new(big.Int).Or(value, big.NewInt(0x80))
	for _, weak := range []string{
		"80",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	} {
		constant, ok := new(big.Int).SetString(weak, 16)
		if ok && eitherSign.Cmp(constant) == 0 {
			return true
		}
	}
	return false
}
