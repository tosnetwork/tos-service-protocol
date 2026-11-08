package codec

import (
	"bytes"
	"strings"
	"testing"
)

func TestDefaultLimitsAreTheGlobalLimits(t *testing.T) {
	if DefaultLimits() != (Limits{CanonicalBytes: 1 << 20, JSONBytes: 2 << 20, StringBytes: 1 << 20}) {
		t.Fatalf("default limits moved: %+v", DefaultLimits())
	}
	value := map[string]any{"a": strings.Repeat("x", 1000), "b": []any{uint64(1), "y"}}
	global, err := Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := Bounded{Limits: DefaultLimits()}.Marshal(value)
	if err != nil || !bytes.Equal(global, bounded) {
		t.Fatal("bounded encoding differs from the package encoding")
	}
	larger, err := Bounded{Limits: Limits{CanonicalBytes: 4 << 20, JSONBytes: 8 << 20, StringBytes: 4 << 20}}.Marshal(value)
	if err != nil || !bytes.Equal(global, larger) {
		t.Fatal("limits changed the encoding of a value within every limit")
	}
}

func TestInvalidLimitsFailClosed(t *testing.T) {
	for _, limits := range []Limits{
		{},
		{CanonicalBytes: 1 << 20, JSONBytes: 2 << 20, StringBytes: 0},
		{CanonicalBytes: 1 << 20, JSONBytes: 1 << 19, StringBytes: 1 << 20},
		{CanonicalBytes: 1 << 20, JSONBytes: 2 << 20, StringBytes: 2 << 20},
		{CanonicalBytes: MaxProfileCanonicalBytes + 1, JSONBytes: 2 * MaxProfileCanonicalBytes, StringBytes: 1},
	} {
		codec := Bounded{Limits: limits}
		if _, err := codec.Marshal("x"); err == nil {
			t.Fatalf("limits %+v were accepted for encoding", limits)
		}
		if err := codec.Unmarshal([]byte{0x61, 0x78}, new(string)); err == nil {
			t.Fatalf("limits %+v were accepted for decoding", limits)
		}
	}
}

func TestBoundedLimitsAreEnforcedSeparately(t *testing.T) {
	limits := Limits{CanonicalBytes: 1 << 20, JSONBytes: 2 << 20, StringBytes: 1000}
	codec := Bounded{Limits: limits}
	atString, err := codec.Marshal(map[string]any{"s": strings.Repeat("x", 1000)})
	if err != nil {
		t.Fatalf("a string at the string limit was refused: %v", err)
	}
	if _, err := codec.Marshal(map[string]any{"s": strings.Repeat("x", 1001)}); err == nil {
		t.Fatal("a string over the string limit was encoded although the object fits")
	}
	var decoded map[string]any
	if err := codec.Unmarshal(atString, &decoded); err != nil {
		t.Fatalf("a string at the string limit failed to decode: %v", err)
	}
	over, err := Bounded{Limits: DefaultLimits()}.Marshal(map[string]any{"s": strings.Repeat("x", 1001)})
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.Unmarshal(over, &decoded); err == nil {
		t.Fatal("a string over the string limit was decoded")
	}

	object := Bounded{Limits: Limits{CanonicalBytes: 2000, JSONBytes: 4000, StringBytes: 2000}}
	fits := strings.Repeat("y", 2000-3) // 3-byte text header
	encoded, err := object.Marshal(fits)
	if err != nil || len(encoded) != 2000 {
		t.Fatalf("an object at the canonical limit was refused: len=%d err=%v", len(encoded), err)
	}
	if err := object.Unmarshal(encoded, new(string)); err != nil {
		t.Fatalf("an object at the canonical limit failed to decode: %v", err)
	}
	if _, err := object.Marshal(fits + "y"); err == nil {
		t.Fatal("an object one byte over the canonical limit was encoded")
	}
	tooLarge, err := Marshal(fits + "y")
	if err != nil {
		t.Fatal(err)
	}
	if err := object.Unmarshal(tooLarge, new(string)); err == nil {
		t.Fatal("an object one byte over the canonical limit was decoded")
	}
}
