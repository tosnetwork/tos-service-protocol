package nativecore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	EscrowStatusPendingAcceptanceV2 uint8 = 0
	EscrowStatusAwaitingFundingV2   uint8 = 1
	EscrowStatusFundedV2            uint8 = 2
	EscrowStatusReleasePendingV2    uint8 = 3
	EscrowStatusRefundPendingV2     uint8 = 4

	PaidDemandAcceptOperationV2 = 0x4e450003
)

type EscrowInitV2 struct {
	Network                *nativev1.NetworkDomain
	AcceptedQuote          *cell.Cell
	Terms                  EscrowTermsV1
	ExecutionSignerEd25519 []byte
	TransportBinding       TransportBindingV1
	AssetMasterAddress     string
	AssetWalletCode        *cell.Cell
}

type EscrowStateV2 struct {
	Status                 uint8
	QuoteCommitment        string
	EscrowTermsDigest      string
	AuthorizationDigest    string
	TransportDigest        string
	DisputePolicyDigest    string
	TransportBinding       TransportBindingV1
	BuyerAddress           string
	ProviderAddress        string
	AssetMasterAddress     string
	AssetWalletCodeHash    string
	AssetWalletCode        *cell.Cell
	FundingDeadline        uint64
	RefundAvailableAt      uint64
	AcceptByUnix           uint64
	ExecutionDeadline      uint64
	ProviderOfferDigest    string
	AcceptedAtUnix         uint64
	FundedAtomicAmount     string
	SettledAtomicAmount    string
	ReceiptCommitment      string
	PendingQueryID         uint64
	AcceptedQuote          *cell.Cell
	ExecutionSignerEd25519 []byte
}

func BuildEscrowStateInitV2(workchain int32, code *cell.Cell, init EscrowInitV2) (EscrowIdentityV2, error) {
	if workchain != 0 || code == nil || init.AcceptedQuote == nil || init.Network == nil {
		return EscrowIdentityV2{}, errors.New("invalid escrow V2 code, quote, network, or workchain")
	}
	if err := RequireEscrowV2Code(code); err != nil {
		return EscrowIdentityV2{}, err
	}
	quote, err := DecodeAcceptedQuoteV2(init.AcceptedQuote, init.Network)
	if err != nil {
		return EscrowIdentityV2{}, err
	}
	terms, err := BuildEscrowTermsCellV1(init.Terms)
	if err != nil {
		return EscrowIdentityV2{}, err
	}
	authorization, err := BuildEscrowAuthorizationCellV1(init.ExecutionSignerEd25519)
	if err != nil {
		return EscrowIdentityV2{}, err
	}
	masterAddress, err := escrowAddress(init.AssetMasterAddress)
	if err != nil || init.AssetWalletCode == nil {
		return EscrowIdentityV2{}, errors.New("invalid escrow V2 asset route")
	}
	transport, _, err := BuildTransportBindingCellV1(init.TransportBinding)
	if err != nil {
		return EscrowIdentityV2{}, err
	}
	dispute, _ := BuildObjectiveDisputePolicyCellV1()
	proposal := quote.Terms.Proposal
	if proposal.EscrowTermsDigest != "sha256:"+hex.EncodeToString(terms.Hash()) ||
		quote.Terms.ExecutionSignerAuthorization != "sha256:"+hex.EncodeToString(authorization.Hash()) ||
		proposal.TransportBindingDigest != "sha256:"+hex.EncodeToString(transport.Hash()) ||
		proposal.DisputePolicyDigest != "sha256:"+hex.EncodeToString(dispute.Hash()) ||
		init.Terms.FundingDeadline > init.Terms.RefundAvailableAt || quote.Extension.ExecutionDeadline >= init.Terms.RefundAvailableAt ||
		init.Terms.FundingDeadline < quote.Extension.AcceptByUnix || init.Terms.FundingDeadline >= quote.Extension.ExecutionDeadline {
		// The escrow contract enforces accept_by <= funding_deadline <
		// execution_deadline < refund_at; build nothing it would reject at accept.
		return EscrowIdentityV2{}, errors.New("escrow V2 terms, authorization, policy, or deadlines differ from Quote")
	}
	quoteMaster, quoteWalletCode, err := acceptedQuoteAssetRouteFromProposal(proposal)
	if err != nil || init.AssetMasterAddress != quoteMaster || !bytes.Equal(init.AssetWalletCode.Hash(), quoteWalletCode) {
		return EscrowIdentityV2{}, errors.New("escrow V2 asset route differs from Quote")
	}
	route := cell.BeginCell().MustStoreUInt(escrowAssetRouteMagic, 32).MustStoreUInt(escrowStateVersion, 16).
		MustStoreAddr(masterAddress).MustStoreSlice(init.AssetWalletCode.Hash(), 256).MustStoreRef(init.AssetWalletCode).EndCell()
	runtime := cell.BeginCell().MustStoreUInt(escrowRuntimeMagic, 32).MustStoreUInt(escrowStateVersion, 16).
		MustStoreBigUInt(new(big.Int), 128).MustStoreBigUInt(new(big.Int), 128).
		MustStoreSlice(make([]byte, 32), 256).MustStoreUInt(0, 64).MustStoreUInt(0, 64).
		MustStoreRef(route).MustStoreRef(transport).MustStoreRef(dispute).EndCell()
	data := cell.BeginCell().MustStoreUInt(escrowDataMagic, 32).MustStoreUInt(escrowStateVersion, 16).
		MustStoreUInt(uint64(EscrowStatusPendingAcceptanceV2), 8).MustStoreSlice(init.AcceptedQuote.Hash(), 256).
		MustStoreSlice(terms.Hash(), 256).MustStoreSlice(authorization.Hash(), 256).
		MustStoreRef(init.AcceptedQuote).MustStoreRef(terms).MustStoreRef(authorization).MustStoreRef(runtime).EndCell()
	stateInit := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(code).MustStoreBoolBit(true).MustStoreRef(data).
		MustStoreBoolBit(false).EndCell()
	return EscrowIdentityV2{Address: fmt.Sprintf("%d:%s", workchain, hex.EncodeToString(stateInit.Hash())),
		CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(code.Hash()), QuoteCommitment: "tvm-cell-sha256:" + hex.EncodeToString(init.AcceptedQuote.Hash()),
		EscrowTermsDigest: "tvm-cell-sha256:" + hex.EncodeToString(terms.Hash()), AuthorizationDigest: "tvm-cell-sha256:" + hex.EncodeToString(authorization.Hash()),
		TransportDigest: "tvm-cell-sha256:" + hex.EncodeToString(transport.Hash()), DisputePolicyDigest: "tvm-cell-sha256:" + hex.EncodeToString(dispute.Hash()),
		StateInitBOC: base64.StdEncoding.EncodeToString(stateInit.ToBOC()), Data: data}, nil
}

func DecodeEscrowDataV2(data *cell.Cell, network *nativev1.NetworkDomain) (*EscrowStateV2, error) {
	if data == nil || network == nil {
		return nil, errors.New("missing escrow V2 data or network")
	}
	s, err := data.BeginParse()
	if err != nil {
		return nil, errors.New("invalid escrow V2 data")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowDataMagic {
		return nil, errors.New("invalid escrow V2 magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowStateVersion {
		return nil, errors.New("unsupported escrow V2 schema")
	}
	status, err := s.LoadUInt(8)
	if err != nil || status > uint64(EscrowStatusRefundPendingV2) {
		return nil, errors.New("invalid escrow V2 status")
	}
	quoteHash, err := s.LoadSlice(256)
	if err != nil {
		return nil, err
	}
	termsHash, err := s.LoadSlice(256)
	if err != nil {
		return nil, err
	}
	authHash, err := s.LoadSlice(256)
	if err != nil {
		return nil, err
	}
	quoteCell, err := s.LoadRefCell()
	if err != nil || !bytes.Equal(quoteHash, quoteCell.Hash()) {
		return nil, errors.New("escrow V2 Quote commitment mismatch")
	}
	termsCell, err := s.LoadRefCell()
	if err != nil || !bytes.Equal(termsHash, termsCell.Hash()) {
		return nil, errors.New("escrow V2 terms commitment mismatch")
	}
	authCell, err := s.LoadRefCell()
	if err != nil || !bytes.Equal(authHash, authCell.Hash()) {
		return nil, errors.New("escrow V2 authorization commitment mismatch")
	}
	runtimeCell, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, errors.New("invalid escrow V2 data shape")
	}
	quote, err := DecodeAcceptedQuoteV2(quoteCell, network)
	if err != nil {
		return nil, err
	}
	terms, err := decodeEscrowTerms(termsCell)
	if err != nil {
		return nil, err
	}
	authorization, err := decodeEscrowAuthorization(authCell)
	if err != nil {
		return nil, err
	}
	runtime, err := decodeEscrowRuntimeV2(runtimeCell)
	if err != nil {
		return nil, err
	}
	route, err := decodeEscrowAssetRouteV2(runtime.route)
	if err != nil {
		return nil, err
	}
	transport, err := DecodeTransportBindingCellV1(runtime.transport)
	if err != nil || ValidateObjectiveDisputePolicyCellV1(runtime.dispute) != nil {
		return nil, errors.New("invalid escrow V2 policy")
	}
	proposal := quote.Terms.Proposal
	quoteMaster, quoteWalletHash, err := acceptedQuoteAssetRouteFromProposal(proposal)
	amount, ok := new(big.Int).SetString(proposal.MaximumPrice.AtomicAmount, 10)
	if err != nil || !ok || amount.Sign() <= 0 || proposal.EscrowTermsDigest != "sha256:"+hex.EncodeToString(termsHash) ||
		quote.Terms.ExecutionSignerAuthorization != "sha256:"+hex.EncodeToString(authHash) ||
		proposal.TransportBindingDigest != "sha256:"+hex.EncodeToString(runtime.transport.Hash()) ||
		proposal.DisputePolicyDigest != "sha256:"+hex.EncodeToString(runtime.dispute.Hash()) ||
		route.master != quoteMaster || !bytes.Equal(route.walletCode.Hash(), quoteWalletHash) ||
		!validEscrowRuntimeV2(uint8(status), amount, runtime, quote.Extension.AcceptByUnix) {
		return nil, errors.New("escrow V2 cross-cell or runtime invariant failed")
	}
	return &EscrowStateV2{Status: uint8(status), QuoteCommitment: "tvm-cell-sha256:" + hex.EncodeToString(quoteHash),
		EscrowTermsDigest: "tvm-cell-sha256:" + hex.EncodeToString(termsHash), AuthorizationDigest: "tvm-cell-sha256:" + hex.EncodeToString(authHash),
		TransportDigest: "tvm-cell-sha256:" + hex.EncodeToString(runtime.transport.Hash()), DisputePolicyDigest: "tvm-cell-sha256:" + hex.EncodeToString(runtime.dispute.Hash()),
		TransportBinding: transport, BuyerAddress: terms.BuyerAddress, ProviderAddress: terms.ProviderAddress,
		AssetMasterAddress: route.master, AssetWalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(route.walletCode.Hash()), AssetWalletCode: route.walletCode,
		FundingDeadline: terms.FundingDeadline, RefundAvailableAt: terms.RefundAvailableAt, AcceptByUnix: quote.Extension.AcceptByUnix,
		ExecutionDeadline: quote.Extension.ExecutionDeadline, ProviderOfferDigest: quote.Extension.ProviderOfferDigest, AcceptedAtUnix: runtime.acceptedAt,
		FundedAtomicAmount: runtime.funded.String(), SettledAtomicAmount: runtime.settled.String(), ReceiptCommitment: func() string {
			if equalBytes(runtime.receipt, make([]byte, 32)) {
				return ""
			}
			return digestString(runtime.receipt)
		}(),
		PendingQueryID: runtime.query, AcceptedQuote: quoteCell, ExecutionSignerEd25519: authorization}, nil
}

func validEscrowRuntimeV2(status uint8, amount *big.Int, runtime escrowRuntimeV2, acceptBy uint64) bool {
	receiptZero := equalBytes(runtime.receipt, make([]byte, 32))
	switch status {
	case EscrowStatusPendingAcceptanceV2:
		return runtime.acceptedAt == 0 && runtime.funded.Sign() == 0 && runtime.settled.Sign() == 0 && receiptZero && runtime.query == 0
	case EscrowStatusAwaitingFundingV2:
		return runtime.acceptedAt > 0 && runtime.acceptedAt < acceptBy && runtime.funded.Sign() == 0 && runtime.settled.Sign() == 0 && receiptZero && runtime.query == 0
	case EscrowStatusFundedV2:
		return runtime.acceptedAt > 0 && runtime.acceptedAt < acceptBy && runtime.funded.Cmp(amount) == 0 && runtime.settled.Sign() == 0 && receiptZero && runtime.query == 0
	case EscrowStatusReleasePendingV2:
		return runtime.acceptedAt > 0 && runtime.acceptedAt < acceptBy && runtime.funded.Cmp(amount) == 0 && runtime.settled.Cmp(amount) == 0 && !receiptZero && runtime.query != 0
	case EscrowStatusRefundPendingV2:
		return runtime.acceptedAt > 0 && runtime.acceptedAt < acceptBy && runtime.funded.Cmp(amount) == 0 && runtime.settled.Sign() == 0 && receiptZero && runtime.query != 0
	default:
		return false
	}
}

type escrowRuntimeV2 struct {
	funded, settled *big.Int
	receipt         []byte
	query           uint64
	acceptedAt      uint64
	route           *cell.Cell
	transport       *cell.Cell
	dispute         *cell.Cell
}

func decodeEscrowRuntimeV2(root *cell.Cell) (escrowRuntimeV2, error) {
	s, err := root.BeginParse()
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowRuntimeMagic {
		return escrowRuntimeV2{}, errors.New("invalid escrow V2 runtime")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowStateVersion {
		return escrowRuntimeV2{}, errors.New("invalid escrow V2 runtime schema")
	}
	funded, err := s.LoadBigUInt(128)
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	settled, err := s.LoadBigUInt(128)
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	receipt, err := s.LoadSlice(256)
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	query, err := s.LoadUInt(64)
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	accepted, err := s.LoadUInt(64)
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	route, err := s.LoadRefCell()
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	transport, err := s.LoadRefCell()
	if err != nil {
		return escrowRuntimeV2{}, err
	}
	dispute, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return escrowRuntimeV2{}, errors.New("invalid escrow V2 runtime shape")
	}
	return escrowRuntimeV2{funded: funded, settled: settled, receipt: receipt, query: query, acceptedAt: accepted,
		route: route, transport: transport, dispute: dispute}, nil
}

type escrowAssetRouteV2 struct {
	master     string
	walletCode *cell.Cell
}

func decodeEscrowAssetRouteV2(root *cell.Cell) (escrowAssetRouteV2, error) {
	s, err := root.BeginParse()
	if err != nil {
		return escrowAssetRouteV2{}, err
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != escrowAssetRouteMagic {
		return escrowAssetRouteV2{}, errors.New("invalid escrow V2 route")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != escrowStateVersion {
		return escrowAssetRouteV2{}, errors.New("invalid escrow V2 route schema")
	}
	masterAddress, err := s.LoadAddr()
	if err != nil || masterAddress == nil {
		return escrowAssetRouteV2{}, errors.New("invalid escrow V2 master")
	}
	walletHash, err := s.LoadSlice(256)
	if err != nil {
		return escrowAssetRouteV2{}, err
	}
	walletCode, err := s.LoadRefCell()
	if err != nil || !bytes.Equal(walletHash, walletCode.Hash()) || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return escrowAssetRouteV2{}, errors.New("invalid escrow V2 wallet route")
	}
	return escrowAssetRouteV2{master: masterAddress.StringRaw(), walletCode: walletCode}, nil
}

func acceptedQuoteAssetRouteFromProposal(proposal *nativev1.QuoteProposalV1) (string, []byte, error) {
	if proposal == nil || proposal.MaximumPrice == nil || proposal.MaximumPrice.Asset == nil || proposal.MaximumPrice.Asset.Master == nil {
		return "", nil, errors.New("missing Quote asset")
	}
	asset := proposal.MaximumPrice.Asset
	master := address.NewAddress(0, byte(asset.Master.Workchain), asset.Master.AccountId)
	walletHash, err := digestBytes(asset.WalletCodeHash, "tvm-cell-sha256:", false)
	if err != nil {
		return "", nil, err
	}
	return master.StringRaw(), walletHash, nil
}

func BuildPaidDemandAcceptBodyV2(queryID uint64, quoteCommitment, providerOfferDigest string) (*cell.Cell, error) {
	quote, err := digestBytes(quoteCommitment, "tvm-cell-sha256:", false)
	if err != nil || queryID == 0 {
		return nil, errors.New("invalid Paid Demand accept identity")
	}
	offer, err := digestBytes(providerOfferDigest, "sha256:", false)
	if err != nil {
		return nil, err
	}
	return cell.BeginCell().MustStoreUInt(PaidDemandAcceptOperationV2, 32).MustStoreUInt(queryID, 64).
		MustStoreSlice(quote, 256).MustStoreSlice(offer, 256).EndCell(), nil
}
