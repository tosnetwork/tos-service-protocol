package nativecore

import (
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	transportBindingMagic  = 0x4e544231 // NTB1
	quotePreimageSchema    = 1
	TransportLoopbackHTTP  = 0
	TransportHTTPS         = 1
	maxTransportURLBytes   = 120
	maxTransportRequestLen = 16 << 20
)

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
	parsed, err := url.Parse(value.BaseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.Opaque != "" ||
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
