package nativecore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	dataMagic     = 0x4e564431 // NVD1
	identityMagic = 0x4e564931 // NVI1
)

type ContractIdentity struct {
	Address      string
	CodeHash     string
	StateInitBOC string
}

type Locator struct {
	Network   *nativev1.NetworkDomain
	Workchain int32
	CodeHash  string
	code      *cell.Cell
}

func NewLocator(network *nativev1.NetworkDomain, workchain int32, codeBOCBase64, expectedCodeHash string) (*Locator, error) {
	if _, err := domainCell(network); err != nil {
		return nil, err
	}
	// Registry objects exist in workchain 0 only; the contract refuses to run
	// anywhere else, so an address derived for another workchain names no
	// Registry object.
	if workchain != 0 {
		return nil, errors.New("the Native Registry exists in workchain 0 only")
	}
	raw, err := base64.StdEncoding.DecodeString(codeBOCBase64)
	if err != nil {
		return nil, errors.New("invalid simplified Native code BOC")
	}
	roots, err := cell.FromBOCMultiRoot(raw)
	if err != nil || len(roots) != 1 || roots[0] == nil {
		return nil, errors.New("invalid simplified Native code cell")
	}
	code := roots[0]
	actual := "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())
	if actual != expectedCodeHash {
		return nil, errors.New("simplified Native code hash mismatch")
	}
	return &Locator{Network: network, Workchain: workchain, CodeHash: actual, code: code}, nil
}

func (l *Locator) Locate(value string) (ContractIdentity, error) {
	if l == nil || l.code == nil {
		return ContractIdentity{}, errors.New("simplified Native locator is not configured")
	}
	rawID, kind, err := objectID(value)
	if err != nil {
		return ContractIdentity{}, err
	}
	config, err := l.configCell()
	if err != nil {
		return ContractIdentity{}, err
	}
	data := cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(uint64(kind), 8).MustStoreSlice(rawID, 256).MustStoreRef(config).
		MustStoreBoolBit(false).EndCell()
	stateInit := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(l.code).MustStoreBoolBit(true).MustStoreRef(data).
		MustStoreBoolBit(false).EndCell()
	return ContractIdentity{Address: fmt.Sprintf("%d:%s", l.Workchain, hex.EncodeToString(stateInit.Hash())), CodeHash: l.CodeHash,
		StateInitBOC: base64.StdEncoding.EncodeToString(stateInit.ToBOC())}, nil
}

func DeriveAgentID(network *nativev1.NetworkDomain, nonce []byte, policy *nativev1.ControllerPolicyV1) (string, error) {
	if len(nonce) != 32 || equalBytes(nonce, make([]byte, 32)) {
		return "", errors.New("Agent nonce must be 32 bytes")
	}
	policyCell, err := PolicyCell(policy)
	if err != nil {
		return "", err
	}
	domain, err := domainCell(network)
	if err != nil {
		return "", err
	}
	identity := cell.BeginCell().MustStoreUInt(identityMagic, 32).MustStoreUInt(1, 8).
		MustStoreSlice(nonce, 256).MustStoreSlice(policyCell.Hash(), 256).MustStoreRef(domain).EndCell()
	return "agent_" + hex.EncodeToString(identity.Hash()), nil
}

func DeriveCapabilityID(network *nativev1.NetworkDomain, nonce []byte, ownerAgentID string,
	version *nativev1.CapabilityVersionV1) (string, error) {
	if len(nonce) != 32 || equalBytes(nonce, make([]byte, 32)) {
		return "", errors.New("Capability nonce must be 32 bytes")
	}
	owner, kind, err := objectID(ownerAgentID)
	if err != nil || kind != 1 {
		return "", errors.New("invalid Capability owner")
	}
	versionHash, manifest, err := capabilityVersion(version)
	if err != nil {
		return "", err
	}
	domain, err := domainCell(network)
	if err != nil {
		return "", err
	}
	details := cell.BeginCell().MustStoreSlice(versionHash, 256).MustStoreSlice(manifest, 256).EndCell()
	identity := cell.BeginCell().MustStoreUInt(identityMagic, 32).MustStoreUInt(2, 8).
		MustStoreSlice(nonce, 256).MustStoreSlice(owner, 256).MustStoreRef(domain).MustStoreRef(details).EndCell()
	return "cap_" + hex.EncodeToString(identity.Hash()), nil
}

func (l *Locator) configCell() (*cell.Cell, error) {
	domain, err := domainCell(l.Network)
	if err != nil {
		return nil, err
	}
	s, err := domain.BeginParse()
	if err != nil {
		return nil, errors.New("invalid Native domain cell")
	}
	root, _ := s.LoadSlice(256)
	file, _ := s.LoadSlice(256)
	networkHash, _ := s.LoadSlice(256)
	return cell.BeginCell().MustStoreSlice(root, 256).MustStoreSlice(file, 256).MustStoreSlice(networkHash, 256).
		MustStoreRef(cell.BeginCell().MustStoreInt(int64(l.Workchain), 32).MustStoreSlice(l.code.Hash(), 256).
			MustStoreRef(stringCell(l.Network.NetworkId)).MustStoreRef(l.code).EndCell()).EndCell(), nil
}

func domainCell(network *nativev1.NetworkDomain) (*cell.Cell, error) {
	if network == nil || !validProtocolText(network.NetworkId, 64) {
		return nil, errors.New("invalid Native network")
	}
	root, err := digestBytes(network.GenesisRootHash, "sha256:", false)
	if err != nil {
		return nil, err
	}
	file, err := digestBytes(network.GenesisFileHash, "sha256:", false)
	if err != nil {
		return nil, err
	}
	networkHash := sha256.Sum256([]byte(network.NetworkId))
	return cell.BeginCell().MustStoreSlice(root, 256).MustStoreSlice(file, 256).MustStoreSlice(networkHash[:], 256).EndCell(), nil
}
