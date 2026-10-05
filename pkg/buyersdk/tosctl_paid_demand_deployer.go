package buyersdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type PreparedPaidDemandDeployment struct {
	EscrowAddress      string `json:"escrow_address"`
	QuoteCommitment    string `json:"quote_commitment"`
	StateInitBOCBase64 string `json:"state_init_boc_base64"`
	StateInitHash      string `json:"state_init_hash"`
	AttachedNanoTOS    uint64 `json:"attached_nanotos"`
	MessageBOCBase64   string `json:"message_boc_base64"`
	MessageHash        string `json:"message_hash"`
}

type PaidDemandEscrowDeployer interface {
	PreparePaidDemandDeployment(context.Context, *PreparedPaidDemandPurchase) (*PreparedPaidDemandDeployment, error)
	BroadcastPaidDemandDeployment(context.Context, *PreparedPaidDemandDeployment) error
}

type TOSCTLPaidDemandEscrowDeployerConfig struct {
	BinaryPath                         string
	ConfigPath                         string
	WalletName                         string
	RelayerAddress                     string
	AttachedNanoTOS                    uint64
	Timeout                            time.Duration
	VaultURL                           string
	AcknowledgeUnpinnedManualBroadcast bool
}

type TOSCTLPaidDemandEscrowDeployer struct {
	binary, config, wallet, relayer    string
	attached                           uint64
	timeout                            time.Duration
	runner                             commandRunner
	acknowledgeUnpinnedManualBroadcast bool
}

func NewTOSCTLPaidDemandEscrowDeployer(config TOSCTLPaidDemandEscrowDeployerConfig) (*TOSCTLPaidDemandEscrowDeployer, error) {
	if !secureExecutable(config.BinaryPath) || !secureConfigFile(config.ConfigPath) || !isRawAddress(config.RelayerAddress) ||
		config.WalletName == "" || strings.TrimSpace(config.WalletName) != config.WalletName || len(config.WalletName) > 128 {
		return nil, errors.New("invalid Paid Demand deployer configuration")
	}
	if config.AttachedNanoTOS == 0 {
		config.AttachedNanoTOS = 100_000_000
	}
	if config.AttachedNanoTOS > 1_000_000_000 {
		return nil, errors.New("invalid Paid Demand deployment budget")
	}
	if config.Timeout == 0 {
		config.Timeout = 90 * time.Second
	}
	if config.Timeout < time.Second || config.Timeout > 5*time.Minute {
		return nil, errors.New("invalid Paid Demand deployment timeout")
	}
	runner, err := newPinnedExecRunnerWithVault(config.BinaryPath, config.ConfigPath, config.VaultURL)
	if err != nil {
		return nil, err
	}
	return &TOSCTLPaidDemandEscrowDeployer{binary: config.BinaryPath, config: config.ConfigPath,
		wallet: config.WalletName, relayer: config.RelayerAddress, attached: config.AttachedNanoTOS,
		timeout: config.Timeout, runner: runner,
		acknowledgeUnpinnedManualBroadcast: config.AcknowledgeUnpinnedManualBroadcast}, nil
}

func (deployer *TOSCTLPaidDemandEscrowDeployer) PreparePaidDemandDeployment(ctx context.Context,
	purchase *PreparedPaidDemandPurchase) (*PreparedPaidDemandDeployment, error) {
	if deployer == nil || ctx == nil {
		return nil, errors.New("invalid Paid Demand deployment")
	}
	stateInit, stateInitHash, err := validatePaidDemandDeploymentPurchase(purchase)
	if err != nil {
		return nil, err
	}
	raw, err := deployer.run(ctx, "wallet", "send", "--from", deployer.wallet, "--to", purchase.Escrow.Address,
		"--amount-nanotos", fmt.Sprint(deployer.attached), "--state-init-boc", stateInit, "--build-only", "-c", deployer.config)
	if err != nil {
		return nil, errors.New("tosctl could not prepare Paid Demand deployment")
	}
	var output struct {
		Version       string `json:"version"`
		Wallet        string `json:"wallet"`
		Payer         string `json:"payer"`
		Destination   string `json:"destination"`
		AmountNanoTOS uint64 `json:"amount_nanotos"`
		BodyHash      string `json:"body_hash"`
		StateInitHash string `json:"state_init_hash"`
		MessageBOC    string `json:"message_boc_base64"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	emptyBodyHash := cellHash(cell.BeginCell().EndCell())
	if decoder.Decode(&output) != nil || output.Version != "tosctl.wallet-prepared-send.v1" || output.Wallet != deployer.wallet ||
		!sameAddress(output.Payer, deployer.relayer) || !sameAddress(output.Destination, purchase.Escrow.Address) ||
		output.AmountNanoTOS != deployer.attached || output.BodyHash != emptyBodyHash || output.StateInitHash != stateInitHash || output.MessageBOC == "" {
		return nil, errors.New("tosctl prepared a conflicting Paid Demand deployment")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("Paid Demand deployment output has trailing data")
	}
	message, err := decodeSingleCell(output.MessageBOC)
	if err != nil {
		return nil, errors.New("tosctl prepared an invalid Paid Demand deployment")
	}
	return &PreparedPaidDemandDeployment{EscrowAddress: purchase.Escrow.Address, QuoteCommitment: purchase.QuoteCommitment,
		StateInitBOCBase64: stateInit, StateInitHash: stateInitHash, AttachedNanoTOS: deployer.attached,
		MessageBOCBase64: output.MessageBOC, MessageHash: cellHash(message)}, nil
}

func (deployer *TOSCTLPaidDemandEscrowDeployer) BroadcastPaidDemandDeployment(ctx context.Context,
	prepared *PreparedPaidDemandDeployment) error {
	if deployer == nil || ctx == nil || prepared == nil || !isRawAddress(prepared.EscrowAddress) ||
		!validCellDigest(prepared.QuoteCommitment) || prepared.AttachedNanoTOS != deployer.attached || !validCellDigest(prepared.MessageHash) {
		return errors.New("invalid prepared Paid Demand deployment")
	}
	stateInit, hash, err := decodeStateInit(prepared.StateInitBOCBase64)
	if err != nil || hash != prepared.StateInitHash || prepared.EscrowAddress != "0:"+fmt.Sprintf("%x", stateInit.Hash()) {
		return errors.New("Paid Demand StateInit changed before broadcast")
	}
	code, data, err := strictStateInitParts(stateInit)
	if err != nil {
		return err
	}
	if err := nativecore.RequireEscrowV2Code(code); err != nil {
		return err
	}
	// The network is committed inside Quote and checked again by the quorum
	// resolver. Here deployment only proves schema/status/Quote identity.
	root, err := data.BeginParse()
	if err != nil {
		return err
	}
	magic, _ := root.LoadUInt(32)
	schema, _ := root.LoadUInt(16)
	status, _ := root.LoadUInt(8)
	quote, _ := root.LoadSlice(256)
	if magic != 0x4e455331 || schema != 2 || status != uint64(nativecore.EscrowStatusPendingAcceptanceV2) ||
		"tvm-cell-sha256:"+fmt.Sprintf("%x", quote) != prepared.QuoteCommitment {
		return errors.New("Paid Demand deployment data changed")
	}
	message, err := decodeSingleCell(prepared.MessageBOCBase64)
	if err != nil || cellHash(message) != prepared.MessageHash {
		return errors.New("Paid Demand deployment message changed")
	}
	arguments := deployer.broadcastArguments(prepared.MessageBOCBase64)
	raw, err := deployer.run(ctx, arguments...)
	if err != nil {
		return fmt.Errorf("Paid Demand deployment outcome is ambiguous: %w%s", err, boundedCommandDiagnostic(raw))
	}
	var output struct {
		Version     string `json:"version"`
		MessageHash string `json:"message_hash"`
		Status      string `json:"status"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&output) != nil || output.Version != "tosctl.wallet-prepared-broadcast.v1" ||
		output.MessageHash != prepared.MessageHash || output.Status != "submitted" {
		return errors.New("Paid Demand deployment outcome is ambiguous")
	}
	return nil
}

func (deployer *TOSCTLPaidDemandEscrowDeployer) broadcastArguments(messageBOC string) []string {
	arguments := []string{"wallet", "broadcast-prepared", "--message-boc", messageBOC, "--yes"}
	if deployer.acknowledgeUnpinnedManualBroadcast {
		arguments = append(arguments, "--acknowledge-unpinned-manual-broadcast")
	}
	arguments = append(arguments, "-c", deployer.config)
	return arguments
}

func boundedCommandDiagnostic(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	text := strings.Map(func(value rune) rune {
		if value == '\n' || value == '\r' || value == '\t' || value >= 0x20 && value <= 0x7e {
			return value
		}
		return '?'
	}, string(raw))
	return ": tosctl=" + text
}

func validatePaidDemandDeploymentPurchase(purchase *PreparedPaidDemandPurchase) (string, string, error) {
	if purchase == nil || purchase.Escrow.Data == nil || !validCellDigest(purchase.QuoteCommitment) ||
		purchase.Escrow.QuoteCommitment != purchase.QuoteCommitment || !isRawAddress(purchase.Escrow.Address) {
		return "", "", errors.New("invalid Paid Demand deployment identity")
	}
	stateInit, hash, err := decodeStateInit(purchase.Escrow.StateInitBOC)
	if err != nil || purchase.Escrow.Address != "0:"+fmt.Sprintf("%x", stateInit.Hash()) {
		return "", "", errors.New("Paid Demand StateInit identity changed")
	}
	code, data, err := strictStateInitParts(stateInit)
	if err != nil || cellHash(code) != purchase.Escrow.CodeHash || !bytes.Equal(data.Hash(), purchase.Escrow.Data.Hash()) {
		return "", "", errors.New("Paid Demand StateInit contents changed")
	}
	if err := nativecore.RequireEscrowV2Code(code); err != nil {
		return "", "", err
	}
	return purchase.Escrow.StateInitBOC, hash, nil
}

func (deployer *TOSCTLPaidDemandEscrowDeployer) run(ctx context.Context, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, deployer.timeout)
	defer cancel()
	return deployer.runner.run(call, deployer.binary, args...)
}

func decodeStateInit(encoded string) (*cell.Cell, string, error) {
	value, err := decodeSingleCell(encoded)
	if err != nil {
		return nil, "", err
	}
	return value, cellHash(value), nil
}

func strictStateInitParts(value *cell.Cell) (*cell.Cell, *cell.Cell, error) {
	if value == nil {
		return nil, nil, errors.New("missing StateInit")
	}
	s, err := value.BeginParse()
	if err != nil {
		return nil, nil, errors.New("invalid StateInit cell")
	}
	splitDepth, err := s.LoadBoolBit()
	if err != nil || splitDepth {
		return nil, nil, errors.New("unsupported StateInit split depth")
	}
	special, err := s.LoadBoolBit()
	if err != nil || special {
		return nil, nil, errors.New("unsupported StateInit special value")
	}
	codePresent, err := s.LoadBoolBit()
	if err != nil || !codePresent {
		return nil, nil, errors.New("missing StateInit code")
	}
	code, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("invalid StateInit code")
	}
	dataPresent, err := s.LoadBoolBit()
	if err != nil || !dataPresent {
		return nil, nil, errors.New("missing StateInit data")
	}
	data, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("invalid StateInit data")
	}
	libraryPresent, err := s.LoadBoolBit()
	if err != nil || libraryPresent || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, nil, errors.New("unsupported StateInit library or trailing data")
	}
	return code, data, nil
}

func decodeSingleCell(encoded string) (*cell.Cell, error) {
	if encoded == "" || strings.Join(strings.Fields(encoded), "") != encoded {
		return nil, errors.New("invalid cell BOC")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("invalid cell BOC")
	}
	value, err := cell.FromBOC(raw)
	if err != nil {
		return nil, errors.New("invalid cell BOC")
	}
	return value, nil
}

func cellHash(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}
