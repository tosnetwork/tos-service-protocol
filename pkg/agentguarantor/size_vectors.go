package agentguarantor

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// SizeVectorDomainV1 separates the digests of the size conformance vectors.
const SizeVectorDomainV1 = "tos.service.agent-guarantor-size-vector.v1"

// SizeVectorConstructionV1 describes a size vector by a rule an independent
// implementation can rebuild without the bytes:
//   - "text-map": {key: "p" * text_length};
//   - "nested-request": {key: base64(canonical({"padding": "p" * text_length}))},
//     the shape of a canonical request carried as text inside a stage result.
type SizeVectorConstructionV1 struct {
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	TextLength int    `json:"text_length"`
}

// SizeVectorV1 is one exact-size conformance vector for the Guarantor limits.
type SizeVectorV1 struct {
	Name                string                   `json:"name"`
	Construction        SizeVectorConstructionV1 `json:"construction"`
	CanonicalBytes      int                      `json:"canonical_bytes"`
	LongestStringBytes  int                      `json:"longest_string_bytes"`
	Digest              string                   `json:"digest"`
	AcceptedByGuarantor bool                     `json:"accepted_by_guarantor"`
	AcceptedByDefault   bool                     `json:"accepted_by_default"`
}

// sizeVectorMeasuringCodec only measures vectors larger than every profile
// limit; it is never used to admit an object.
var sizeVectorMeasuringCodec = codec.Bounded{Limits: codec.Limits{CanonicalBytes: 4 * MaxCanonicalObjectBytes,
	JSONBytes: 8 * MaxCanonicalObjectBytes, StringBytes: 4 * MaxCanonicalObjectBytes}}

// BuildSizeVectorValueV1 rebuilds a vector's logical value from its rule.
func BuildSizeVectorValueV1(construction SizeVectorConstructionV1) (map[string]any, int, error) {
	if construction.Key == "" || construction.TextLength <= 0 {
		return nil, 0, errors.New("size vector construction is invalid")
	}
	text := strings.Repeat("p", construction.TextLength)
	switch construction.Kind {
	case "text-map":
		return map[string]any{construction.Key: text}, len(text), nil
	case "nested-request":
		inner, err := sizeVectorMeasuringCodec.Marshal(map[string]any{"padding": text})
		if err != nil {
			return nil, 0, err
		}
		encoded := base64.StdEncoding.EncodeToString(inner)
		return map[string]any{construction.Key: encoded}, len(encoded), nil
	default:
		return nil, 0, errors.New("size vector construction kind is unknown")
	}
}

// ReleasedSizeVectorsV1 returns the exact-boundary vectors of the Guarantor
// ceiling and the worst-case nested request string. A map {"padding": text}
// with a text longer than 65,535 bytes encodes as 1 (map) + 8 (key) + 5
// (text header) + len(text) bytes.
func ReleasedSizeVectorsV1() ([]SizeVectorV1, error) {
	constructions := []struct {
		name         string
		construction SizeVectorConstructionV1
	}{
		{"guarantor-ceiling-exact", SizeVectorConstructionV1{"text-map", "padding", MaxCanonicalObjectBytes - 14}},
		{"guarantor-ceiling-plus-one", SizeVectorConstructionV1{"text-map", "padding", MaxCanonicalObjectBytes - 13}},
		{"worst-case-nested-request-string", SizeVectorConstructionV1{"nested-request", "canonical_request", 874_006}},
	}
	vectors := make([]SizeVectorV1, 0, len(constructions))
	for _, entry := range constructions {
		value, longest, err := BuildSizeVectorValueV1(entry.construction)
		if err != nil {
			return nil, err
		}
		encoded, err := sizeVectorMeasuringCodec.Marshal(value)
		if err != nil {
			return nil, err
		}
		digest, err := sizeVectorMeasuringCodec.Digest(SizeVectorDomainV1, value)
		if err != nil {
			return nil, err
		}
		_, guarantorErr := guarantorCodec.Marshal(value)
		_, defaultErr := codec.Marshal(value)
		vectors = append(vectors, SizeVectorV1{Name: entry.name, Construction: entry.construction,
			CanonicalBytes: len(encoded), LongestStringBytes: longest, Digest: digest,
			AcceptedByGuarantor: guarantorErr == nil, AcceptedByDefault: defaultErr == nil})
	}
	return vectors, nil
}
