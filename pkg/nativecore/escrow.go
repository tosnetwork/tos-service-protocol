package nativecore

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	escrowDataMagic          = 0x4e455331 // NES1
	escrowTermsMagic         = 0x4e455431 // NET1
	escrowAuthorizationMagic = 0x4e454131 // NEA1
	escrowRuntimeMagic       = 0x4e455231 // NER1
	escrowAssetRouteMagic    = 0x4e455031 // NEP1

	// The stablecoin escrow contract stores its root data, runtime and asset
	// route at version 2. The terms and execution-signer authorization cells it
	// commits to are still version 1 in that contract.
	escrowStateVersion         = 2
	escrowTermsVersion         = 1
	escrowAuthorizationVersion = 1

	// EscrowV2CodeHash is the cell hash of the only stablecoin escrow code this
	// module builds, deploys, decodes or settles against: the released
	// tos-service-stablecoin-escrow-v2 contract. Any other code is refused.
	EscrowV2CodeHash = "tvm-cell-sha256:d6d53a11bcda151b2e7d6b4b2f275eeadea8eb9b66496c24b0b7c54453d6d209"
)

// escrowV2CodeBOC is the frozen release artifact of the escrow contract, as
// published by the TOS repository next to its source.
//
//go:embed escrowcode/tos-service-stablecoin-escrow-v2.boc.base64
var escrowV2CodeBOC string

// EscrowV2Code returns the released escrow contract code. It fails closed if
// the embedded artifact does not hash to EscrowV2CodeHash.
func EscrowV2Code() (*cell.Cell, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(escrowV2CodeBOC), ""))
	if err != nil {
		return nil, errors.New("invalid embedded escrow code")
	}
	code, err := cell.FromBOC(raw)
	if err != nil {
		return nil, errors.New("invalid embedded escrow code")
	}
	if err := RequireEscrowV2Code(code); err != nil {
		return nil, err
	}
	return code, nil
}

// RequireEscrowV2Code refuses every escrow code other than the released v2
// contract.
func RequireEscrowV2Code(code *cell.Cell) error {
	if code == nil {
		return errors.New("missing escrow code")
	}
	return RequireEscrowV2CodeHash(digestString(code.Hash()))
}

// RequireEscrowV2CodeHash refuses every escrow code hash other than the
// released v2 contract's.
func RequireEscrowV2CodeHash(codeHash string) error {
	if codeHash != EscrowV2CodeHash {
		return errors.New("escrow code is not the released stablecoin escrow v2 contract")
	}
	return nil
}

// EscrowIdentityV2 is the deterministic result of building an escrow
// StateInit.
type EscrowIdentityV2 struct {
	Address             string
	CodeHash            string
	QuoteCommitment     string
	EscrowTermsDigest   string
	AuthorizationDigest string
	TransportDigest     string
	DisputePolicyDigest string
	StateInitBOC        string
	Data                *cell.Cell
}

// EscrowTermsV1 is the concrete preimage committed by escrow_terms_digest in
// an Accepted Quote. Addresses are canonical raw TOS addresses.
type EscrowTermsV1 struct {
	BuyerAddress      string
	ProviderAddress   string
	FundingDeadline   uint64
	RefundAvailableAt uint64
}

func escrowAddress(value string) (*address.Address, error) {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 ||
		parsed.Workchain() != 0 || parsed.StringRaw() != value {
		return nil, errors.New("escrow addresses must be canonical raw addr_std values")
	}
	return parsed, nil
}

// BuildEscrowTermsCellV1 builds the typed preimage whose cell hash is supplied
// as QuoteProposalV1.escrow_terms_digest.
func BuildEscrowTermsCellV1(value EscrowTermsV1) (*cell.Cell, error) {
	buyer, err := escrowAddress(value.BuyerAddress)
	if err != nil {
		return nil, err
	}
	provider, err := escrowAddress(value.ProviderAddress)
	if err != nil {
		return nil, err
	}
	if value.FundingDeadline == 0 || value.RefundAvailableAt <= value.FundingDeadline {
		return nil, errors.New("invalid escrow deadlines")
	}
	return cell.BeginCell().MustStoreUInt(escrowTermsMagic, 32).MustStoreUInt(escrowTermsVersion, 16).
		MustStoreAddr(buyer).MustStoreAddr(provider).MustStoreUInt(value.FundingDeadline, 64).
		MustStoreUInt(value.RefundAvailableAt, 64).EndCell(), nil
}

// BuildEscrowAuthorizationCellV1 builds the typed preimage whose cell hash is
// supplied as AcceptedQuoteV1.execution_signer_authorization.
func BuildEscrowAuthorizationCellV1(publicKey []byte) (*cell.Cell, error) {
	if len(publicKey) != 32 || equalBytes(publicKey, make([]byte, 32)) {
		return nil, errors.New("execution signer must be a non-zero Ed25519 public key")
	}
	return cell.BeginCell().MustStoreUInt(escrowAuthorizationMagic, 32).MustStoreUInt(escrowAuthorizationVersion, 16).
		MustStoreSlice(publicKey, 256).EndCell(), nil
}

func decodeEscrowTerms(value *cell.Cell) (EscrowTermsV1, error) {
	s, err := value.BeginParse()
	if err != nil {
		return EscrowTermsV1{}, errors.New("invalid escrow terms cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowTermsMagic {
		return EscrowTermsV1{}, errors.New("invalid escrow terms magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowTermsVersion {
		return EscrowTermsV1{}, errors.New("unsupported escrow terms schema")
	}
	buyer, err := s.LoadAddr()
	if err != nil || buyer == nil || buyer.Type() != address.StdAddress || buyer.Workchain() != 0 {
		return EscrowTermsV1{}, errors.New("invalid escrow buyer")
	}
	provider, err := s.LoadAddr()
	if err != nil || provider == nil || provider.Type() != address.StdAddress || provider.Workchain() != 0 {
		return EscrowTermsV1{}, errors.New("invalid escrow provider")
	}
	funding, err := s.LoadUInt(64)
	if err != nil {
		return EscrowTermsV1{}, errors.New("invalid funding deadline")
	}
	refund, err := s.LoadUInt(64)
	if err != nil || funding == 0 || refund <= funding || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return EscrowTermsV1{}, errors.New("invalid escrow deadlines or shape")
	}
	return EscrowTermsV1{buyer.StringRaw(), provider.StringRaw(), funding, refund}, nil
}

// DecodeEscrowTermsCellV1 validates and exposes the complete typed Quote
// preimage transported by a non-canonical Quote Proposal package.
func DecodeEscrowTermsCellV1(value *cell.Cell) (EscrowTermsV1, error) {
	if value == nil {
		return EscrowTermsV1{}, errors.New("missing escrow terms")
	}
	return decodeEscrowTerms(value)
}

func decodeEscrowAuthorization(value *cell.Cell) ([]byte, error) {
	s, err := value.BeginParse()
	if err != nil {
		return nil, errors.New("invalid execution authorization cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowAuthorizationMagic {
		return nil, errors.New("invalid execution authorization magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowAuthorizationVersion {
		return nil, errors.New("unsupported execution authorization schema")
	}
	key, err := s.LoadSlice(256)
	if err != nil || equalBytes(key, make([]byte, 32)) || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, errors.New("invalid execution authorization")
	}
	return key, nil
}

// DeriveEscrowAssetWalletV2 reproduces the stablecoin wallet address the
// escrow contract derives for itself: the wallet StateInit with zero balance,
// unlocked status, the escrow as owner and the committed master and wallet
// code. Live balance is account state, not address identity.
func DeriveEscrowAssetWalletV2(escrowAccount string, state *EscrowStateV2) (string, error) {
	owner, err := escrowAddress(escrowAccount)
	if err != nil || state == nil || state.AssetWalletCode == nil {
		return "", errors.New("invalid escrow wallet derivation input")
	}
	master, err := escrowAddress(state.AssetMasterAddress)
	if err != nil {
		return "", err
	}
	data := cell.BeginCell().MustStoreUInt(0, 4).MustStoreCoins(0).
		MustStoreAddr(owner).MustStoreAddr(master).EndCell()
	init := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(state.AssetWalletCode).
		MustStoreBoolBit(true).MustStoreRef(data).MustStoreBoolBit(false).EndCell()
	return address.NewAddress(0, 0, init.Hash()).StringRaw(), nil
}

func digestString(value []byte) string { return "tvm-cell-sha256:" + hex.EncodeToString(value) }
