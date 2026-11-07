package nativecore

import (
	"strings"
	"testing"
)

func TestQuotePolicyPreimagesRoundTrip(t *testing.T) {
	transport := TransportBindingV1{
		SecurityMode: TransportLoopbackHTTP, MaxRequestBytes: 16 << 20,
		BaseURL: "http://127.0.0.1:8080",
	}
	root, digest, err := BuildTransportBindingCellV1(transport)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTransportBindingCellV1(root)
	if err != nil || decoded != transport || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("unexpected transport binding: %+v %s %v", decoded, digest, err)
	}
}

func TestQuoteTransportBindingRejectsNonCanonicalOrInsecureEndpoints(t *testing.T) {
	for _, endpoint := range []TransportBindingV1{
		{TransportLoopbackHTTP, 1024, "http://example.com"},
		{TransportHTTPS, 1024, "http://127.0.0.1:8080"},
		{TransportHTTPS, 1024, "https://EXAMPLE.com"},
		{TransportHTTPS, 1024, "https://example.com/"},
		{TransportHTTPS, 0, "https://example.com"},
	} {
		if _, _, err := BuildTransportBindingCellV1(endpoint); err == nil {
			t.Fatalf("accepted invalid transport binding %+v", endpoint)
		}
	}
}
