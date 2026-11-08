package nativecore

import (
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	transportBindingMagic = 0x4e544231 // NTB1
	quotePreimageSchema   = 1
	TransportLoopbackHTTP = 0
	TransportHTTPS        = 1
	// TransportAgentPacket is Agent Packet V1 carried by the Messenger to the
	// Capability owner Agent. Its base URL names that Agent and nothing else;
	// there is no HTTP endpoint or Connect service.
	TransportAgentPacket   = 2
	maxTransportURLBytes   = 120
	maxTransportRequestLen = 16 << 20
	// MaxAgentPacketTransportRequestBytes bounds the inline work input a
	// buyer may deliver over Agent Packets: the Agent Packet payload bound.
	MaxAgentPacketTransportRequestBytes = 1 << 20
	// AgentPacketTransportPrefix starts a mode-2 base URL.
	AgentPacketTransportPrefix = "agent-packet:"
)

var agentPacketTransportPattern = regexp.MustCompile(`^agent-packet:agent_[0-9a-f]{64}$`)

// transportPathPrefixPattern is the optional path prefix of a Connect base
// URL: "/"-separated non-empty segments of RFC 3986 unreserved characters.
var transportPathPrefixPattern = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*$`)

// validTransportPathPrefix admits an empty path or a canonical prefix with no
// dot segments; the trailing slash is refused with the other bounds.
func validTransportPathPrefix(path string) bool {
	if !transportPathPrefixPattern.MatchString(path) {
		return false
	}
	for _, segment := range strings.Split(path, "/")[1:] {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// AgentPacketTransportBinding returns the mode-2 binding that delivers work
// to providerAgentID as Agent Packets, admitting at most maxRequestBytes of
// inline input.
func AgentPacketTransportBinding(providerAgentID string, maxRequestBytes uint32) (TransportBindingV1, error) {
	value := TransportBindingV1{SecurityMode: TransportAgentPacket, MaxRequestBytes: maxRequestBytes,
		BaseURL: AgentPacketTransportPrefix + providerAgentID}
	if err := validateTransportBinding(value); err != nil {
		return TransportBindingV1{}, err
	}
	return value, nil
}

// AgentPacketRecipient returns the provider Agent a mode-2 binding names.
func (value TransportBindingV1) AgentPacketRecipient() (string, error) {
	if value.SecurityMode != TransportAgentPacket || validateTransportBinding(value) != nil {
		return "", errors.New("transport binding is not a valid Agent Packet binding")
	}
	return strings.TrimPrefix(value.BaseURL, AgentPacketTransportPrefix), nil
}

type TransportBindingV1 struct {
	SecurityMode    uint8
	MaxRequestBytes uint32
	BaseURL         string
}

func validLoopbackEndpoint(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateTransportBinding(value TransportBindingV1) error {
	if value.MaxRequestBytes == 0 || value.MaxRequestBytes > maxTransportRequestLen ||
		!validProtocolText(value.BaseURL, maxTransportURLBytes) || strings.HasSuffix(value.BaseURL, "/") {
		return errors.New("invalid transport binding bounds")
	}
	if value.SecurityMode == TransportAgentPacket {
		if value.MaxRequestBytes > MaxAgentPacketTransportRequestBytes {
			return errors.New("Agent Packet transport admits at most 1 MiB of inline input")
		}
		if !agentPacketTransportPattern.MatchString(value.BaseURL) {
			return errors.New("Agent Packet transport must name exactly agent-packet:agent_<64 lowercase hex>")
		}
		return nil
	}
	parsed, err := url.Parse(value.BaseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || !validTransportPathPrefix(parsed.Path) || parsed.RawPath != "" || parsed.Opaque != "" ||
		parsed.ForceQuery || parsed.String() != value.BaseURL || parsed.Host != strings.ToLower(parsed.Host) {
		return errors.New("transport base URL is not canonical")
	}
	switch value.SecurityMode {
	case TransportLoopbackHTTP:
		if parsed.Scheme != "http" || !validLoopbackEndpoint(parsed.Hostname()) {
			return errors.New("plaintext transport must be an explicit loopback endpoint")
		}
	case TransportHTTPS:
		if parsed.Scheme != "https" {
			return errors.New("secure transport must use HTTPS")
		}
	default:
		return errors.New("unsupported transport security mode")
	}
	return nil
}

func BuildTransportBindingCellV1(value TransportBindingV1) (*cell.Cell, string, error) {
	if err := validateTransportBinding(value); err != nil {
		return nil, "", err
	}
	root := cell.BeginCell().MustStoreUInt(transportBindingMagic, 32).
		MustStoreUInt(quotePreimageSchema, 16).MustStoreUInt(uint64(value.SecurityMode), 8).
		MustStoreUInt(uint64(value.MaxRequestBytes), 32).MustStoreRef(stringCell(value.BaseURL)).EndCell()
	return root, "sha256:" + hex.EncodeToString(root.Hash()), nil
}

func DecodeTransportBindingCellV1(root *cell.Cell) (TransportBindingV1, error) {
	if root == nil {
		return TransportBindingV1{}, errors.New("missing transport binding")
	}
	s, err := root.BeginParse()
	if err != nil {
		return TransportBindingV1{}, errors.New("invalid transport binding cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != transportBindingMagic {
		return TransportBindingV1{}, errors.New("invalid transport binding magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != quotePreimageSchema {
		return TransportBindingV1{}, errors.New("unsupported transport binding schema")
	}
	mode, err := s.LoadUInt(8)
	if err != nil {
		return TransportBindingV1{}, errors.New("invalid transport security mode")
	}
	maximum, err := s.LoadUInt(32)
	if err != nil {
		return TransportBindingV1{}, errors.New("invalid transport request bound")
	}
	endpoint, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return TransportBindingV1{}, errors.New("invalid transport binding shape")
	}
	baseURL, err := decodeProtocolText(endpoint, maxTransportURLBytes)
	value := TransportBindingV1{SecurityMode: uint8(mode), MaxRequestBytes: uint32(maximum), BaseURL: baseURL}
	if err != nil || validateTransportBinding(value) != nil {
		return TransportBindingV1{}, errors.New("invalid transport binding")
	}
	return value, nil
}
