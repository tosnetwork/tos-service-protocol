package nativecore

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math"
	"math/big"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	softwareWorkReceiptMagic  = 0x4e575231 // NWR1
	settlementIntentMagic     = 0x4e534931 // NSI1
	settlementIntentVersion   = 2
	softwareWorkReceiptSchema = 1

	EscrowReleaseOpcode uint64 = 0x4e450001
	EscrowRefundOpcode  uint64 = 0x4e450002
)

type SoftwareWorkReceiptV1 struct {
	QuoteCommitment     string
	ExecutionID         string
	InputDigest         string
	ResultDigest        string
	ArtifactDigest      string
	ReportDigest        string
	SourceDigest        string
	ToolchainDigest     string
	SandboxDigest       string
	ChargedAtomicAmount string
	ProviderAgentID     string
	CompletedAt         uint64
	ExitCode            int32
}

func receiptDigest(value, prefix, name string) ([]byte, error) {
	decoded, err := digestBytes(value, prefix, false)
	if err != nil || equalBytes(decoded, make([]byte, 32)) {
		return nil, errors.New("invalid Receipt " + name)
	}
	return decoded, nil
}

// BuildSoftwareWorkReceiptCellV1 builds the complete canonical evidence cell.
func BuildSoftwareWorkReceiptCellV1(value SoftwareWorkReceiptV1) (*cell.Cell, string, error) {
	quote, err := receiptDigest(value.QuoteCommitment, "tvm-cell-sha256:", "Quote commitment")
	if err != nil {
		return nil, "", err
	}
	execution, err := receiptDigest(value.ExecutionID, "sha256:", "execution ID")
	if err != nil {
		return nil, "", err
	}
	input, err := receiptDigest(value.InputDigest, "sha256:", "input digest")
	if err != nil {
		return nil, "", err
	}
	result, err := receiptDigest(value.ResultDigest, "sha256:", "result digest")
	if err != nil {
		return nil, "", err
	}
	artifact, err := receiptDigest(value.ArtifactDigest, "sha256:", "artifact digest")
	if err != nil {
		return nil, "", err
	}
	report, err := receiptDigest(value.ReportDigest, "sha256:", "report digest")
	if err != nil {
		return nil, "", err
	}
	source, err := receiptDigest(value.SourceDigest, "sha256:", "source digest")
	if err != nil {
		return nil, "", err
	}
	toolchain, err := receiptDigest(value.ToolchainDigest, "sha256:", "toolchain digest")
	if err != nil {
		return nil, "", err
	}
	sandbox, err := receiptDigest(value.SandboxDigest, "sha256:", "sandbox digest")
	if err != nil {
		return nil, "", err
	}
	provider, kind, err := objectID(value.ProviderAgentID)
	if err != nil || kind != 1 {
		return nil, "", errors.New("invalid Receipt provider Agent")
	}
	charged, ok := new(big.Int).SetString(value.ChargedAtomicAmount, 10)
	if !ok || !atomicAmountPattern.MatchString(value.ChargedAtomicAmount) || charged.Sign() <= 0 || charged.BitLen() > 120 {
		return nil, "", errors.New("invalid Receipt charged amount")
	}
	if value.CompletedAt == 0 || value.ExitCode != 0 {
		return nil, "", errors.New("Receipt is not a successful completed execution")
	}
	binding := cell.BeginCell().MustStoreSlice(quote, 256).MustStoreSlice(execution, 256).
		MustStoreSlice(input, 256).EndCell()
	outcome := cell.BeginCell().MustStoreSlice(result, 256).MustStoreSlice(artifact, 256).
		MustStoreSlice(report, 256).EndCell()
	evidence := cell.BeginCell().MustStoreSlice(source, 256).MustStoreSlice(toolchain, 256).
		MustStoreSlice(sandbox, 256).EndCell()
	economic := cell.BeginCell().MustStoreBigUInt(charged, 128).MustStoreSlice(provider, 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(softwareWorkReceiptMagic, 32).
		MustStoreUInt(softwareWorkReceiptSchema, 16).MustStoreUInt(value.CompletedAt, 64).
		MustStoreInt(int64(value.ExitCode), 32).MustStoreRef(binding).MustStoreRef(outcome).
		MustStoreRef(evidence).MustStoreRef(economic).EndCell()
	return root, digestString(root.Hash()), nil
}

// DecodeSoftwareWorkReceiptCellV1 rejects non-canonical shapes and returns the
// values used by settlement validation.
func DecodeSoftwareWorkReceiptCellV1(root *cell.Cell) (SoftwareWorkReceiptV1, error) {
	if root == nil {
		return SoftwareWorkReceiptV1{}, errors.New("missing Receipt")
	}
	s, err := root.BeginParse()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != softwareWorkReceiptMagic {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != softwareWorkReceiptSchema {
		return SoftwareWorkReceiptV1{}, errors.New("unsupported Receipt schema")
	}
	completed, err := s.LoadUInt(64)
	if err != nil || completed == 0 {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt completion time")
	}
	exitCode, err := s.LoadInt(32)
	if err != nil || exitCode != 0 {
		return SoftwareWorkReceiptV1{}, errors.New("Receipt execution did not succeed")
	}
	binding, err := s.LoadRefCell()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("missing Receipt binding")
	}
	outcome, err := s.LoadRefCell()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("missing Receipt outcome")
	}
	evidence, err := s.LoadRefCell()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("missing Receipt evidence")
	}
	economic, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt root shape")
	}
	b, err := binding.BeginParse()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt binding")
	}
	quote, err := b.LoadSlice(256)
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt Quote")
	}
	execution, err := b.LoadSlice(256)
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt execution")
	}
	input, err := b.LoadSlice(256)
	if err != nil || b.BitsLeft() != 0 || b.RefsNum() != 0 {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt binding shape")
	}
	o, err := outcome.BeginParse()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt outcome")
	}
	result, err := o.LoadSlice(256)
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt result")
	}
	artifact, err := o.LoadSlice(256)
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt artifact")
	}
	report, err := o.LoadSlice(256)
	if err != nil || o.BitsLeft() != 0 || o.RefsNum() != 0 {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt outcome shape")
	}
	ev, err := evidence.BeginParse()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt evidence")
	}
	source, err := ev.LoadSlice(256)
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt source")
	}
	toolchain, err := ev.LoadSlice(256)
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt toolchain")
	}
	sandbox, err := ev.LoadSlice(256)
	if err != nil || ev.BitsLeft() != 0 || ev.RefsNum() != 0 {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt evidence shape")
	}
	ec, err := economic.BeginParse()
	if err != nil {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt economics")
	}
	charged, err := ec.LoadBigUInt(128)
	if err != nil || charged.Sign() <= 0 {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt charge")
	}
	provider, err := ec.LoadSlice(256)
	if err != nil || ec.BitsLeft() != 0 || ec.RefsNum() != 0 {
		return SoftwareWorkReceiptV1{}, errors.New("invalid Receipt economic shape")
	}
	values := [][]byte{quote, execution, input, result, artifact, report, source, toolchain, sandbox, provider}
	for _, item := range values {
		if equalBytes(item, make([]byte, 32)) {
			return SoftwareWorkReceiptV1{}, errors.New("Receipt contains a zero digest")
		}
	}
	return SoftwareWorkReceiptV1{
		QuoteCommitment: digestString(quote), ExecutionID: "sha256:" + hex.EncodeToString(execution), InputDigest: "sha256:" + hex.EncodeToString(input),
		ResultDigest: "sha256:" + hex.EncodeToString(result), ArtifactDigest: "sha256:" + hex.EncodeToString(artifact), ReportDigest: "sha256:" + hex.EncodeToString(report),
		SourceDigest: "sha256:" + hex.EncodeToString(source), ToolchainDigest: "sha256:" + hex.EncodeToString(toolchain), SandboxDigest: "sha256:" + hex.EncodeToString(sandbox),
		ChargedAtomicAmount: charged.String(), ProviderAgentID: "agent_" + hex.EncodeToString(provider), CompletedAt: completed, ExitCode: int32(exitCode),
	}, nil
}

// BuildEscrowSettlementIntentV2 builds the statement the execution signer
// signs to release an escrow, exactly as the v2 escrow contract rebuilds it
// before checking the signature:
//
//	magic:uint32 version:uint16=2 global_id:int32 query_id:uint64
//	charged:uint128 escrow:MsgAddressInt ^(quote_hash:uint256 receipt_hash:uint256)
//
// globalID is the network's ConfigParam 19, which the contract reads with
// GLOBALID; a signature made for one network does not settle on another.
func BuildEscrowSettlementIntentV2(globalID int32, escrowAccount string, quote, receipt *cell.Cell, charged *big.Int, queryID uint64) (*cell.Cell, error) {
	escrow, err := escrowAddress(escrowAccount)
	if err != nil || quote == nil || receipt == nil || charged == nil || charged.Sign() <= 0 || charged.BitLen() > 120 || queryID == 0 {
		return nil, errors.New("invalid escrow settlement intent")
	}
	hashes := cell.BeginCell().MustStoreSlice(quote.Hash(), 256).MustStoreSlice(receipt.Hash(), 256).EndCell()
	return cell.BeginCell().MustStoreUInt(settlementIntentMagic, 32).MustStoreUInt(settlementIntentVersion, 16).
		MustStoreInt(int64(globalID), 32).MustStoreUInt(queryID, 64).MustStoreBigUInt(charged, 128).
		MustStoreAddr(escrow).MustStoreRef(hashes).EndCell(), nil
}

// BuildEscrowReleaseBodyV2 builds the v2 escrow release message body.
func BuildEscrowReleaseBodyV2(queryID uint64, receipt *cell.Cell, signature []byte) (*cell.Cell, error) {
	if queryID == 0 || receipt == nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid escrow release message")
	}
	return cell.BeginCell().MustStoreUInt(EscrowReleaseOpcode, 32).MustStoreUInt(queryID, 64).
		MustStoreSlice(signature, 512).MustStoreRef(receipt).EndCell(), nil
}

// BuildEscrowRefundBodyV2 builds the v2 escrow refund message body.
func BuildEscrowRefundBodyV2(queryID uint64) (*cell.Cell, error) {
	if queryID == 0 || queryID == math.MaxUint64 {
		return nil, errors.New("invalid escrow refund query ID")
	}
	return cell.BeginCell().MustStoreUInt(EscrowRefundOpcode, 32).MustStoreUInt(queryID, 64).EndCell(), nil
}
