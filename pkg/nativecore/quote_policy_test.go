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
		{TransportHTTPS, 1024, "https://example.com/rpc/"},
		{TransportHTTPS, 1024, "https://example.com/rpc?x=1"},
		{TransportHTTPS, 1024, "https://example.com/rpc#part"},
		{TransportHTTPS, 1024, "https://user@example.com/rpc"},
		{TransportHTTPS, 1024, "https://example.com//rpc"},
		{TransportHTTPS, 1024, "https://example.com/a/../rpc"},
		{TransportHTTPS, 1024, "https://example.com/./rpc"},
		{TransportHTTPS, 1024, "https://example.com/r%20pc"},
		{TransportLoopbackHTTP, 1024, "http://127.0.0.1:8080/rpc/"},
	} {
		if _, _, err := BuildTransportBindingCellV1(endpoint); err == nil {
			t.Fatalf("accepted invalid transport binding %+v", endpoint)
		}
	}
}

func TestAgentPacketTransportBindingRoundTrips(t *testing.T) {
	provider := "agent_" + strings.Repeat("5a", 32)
	binding, err := AgentPacketTransportBinding(provider, MaxAgentPacketTransportRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if binding.SecurityMode != TransportAgentPacket || binding.BaseURL != "agent-packet:"+provider || len(binding.BaseURL) != 83 {
		t.Fatalf("unexpected binding %+v", binding)
	}
	root, digest, err := BuildTransportBindingCellV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTransportBindingCellV1(root)
	if err != nil || decoded != binding || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("decoded=%+v digest=%s err=%v", decoded, digest, err)
	}
	recipient, err := decoded.AgentPacketRecipient()
	if err != nil || recipient != provider {
		t.Fatalf("recipient=%q err=%v", recipient, err)
	}
}

func TestAgentPacketTransportBindingRefusesEveryOtherShape(t *testing.T) {
	provider := "agent_" + strings.Repeat("5a", 32)
	for name, value := range map[string]TransportBindingV1{
		"over 1 MiB":       {TransportAgentPacket, MaxAgentPacketTransportRequestBytes + 1, "agent-packet:" + provider},
		"zero bound":       {TransportAgentPacket, 0, "agent-packet:" + provider},
		"other prefix":     {TransportAgentPacket, 1024, "agent-packets:" + provider},
		"upper hex":        {TransportAgentPacket, 1024, "agent-packet:agent_" + strings.Repeat("5A", 32)},
		"short id":         {TransportAgentPacket, 1024, "agent-packet:agent_" + strings.Repeat("5a", 31)},
		"trailing data":    {TransportAgentPacket, 1024, "agent-packet:" + provider + "x"},
		"capability id":    {TransportAgentPacket, 1024, "agent-packet:cap_" + strings.Repeat("5a", 32)},
		"https url":        {TransportAgentPacket, 1024, "https://provider.example"},
		"unknown mode":     {3, 1024, "agent-packet:" + provider},
		"https with agent": {TransportHTTPS, 1024, "agent-packet:" + provider},
	} {
		if _, _, err := BuildTransportBindingCellV1(value); err == nil {
			t.Fatalf("%s: accepted %+v", name, value)
		}
	}
	if _, err := AgentPacketTransportBinding("agent_"+strings.Repeat("5a", 31), 1024); err == nil {
		t.Fatal("accepted a short provider Agent id")
	}
	https := TransportBindingV1{TransportHTTPS, 1024, "https://provider.example"}
	if _, err := https.AgentPacketRecipient(); err == nil {
		t.Fatal("an HTTPS binding named an Agent Packet recipient")
	}
}

func TestQuoteTransportBindingAcceptsACanonicalPathPrefix(t *testing.T) {
	for _, endpoint := range []TransportBindingV1{
		{TransportHTTPS, 1024, "https://example.com/rpc"},
		{TransportHTTPS, 1024, "https://example.com:8443/tos/rpc-v1"},
		{TransportLoopbackHTTP, 1024, "http://127.0.0.1:8080/rpc"},
	} {
		root, _, err := BuildTransportBindingCellV1(endpoint)
		if err != nil {
			t.Fatalf("refused canonical transport binding %+v: %v", endpoint, err)
		}
		if decoded, err := DecodeTransportBindingCellV1(root); err != nil || decoded != endpoint {
			t.Fatalf("path prefix did not round-trip: %+v %v", decoded, err)
		}
	}
}
