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
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// ServiceActorCallIntent is the exact call the buyer verified.
type ServiceActorCallIntent struct {
	Actor             string
	BuyerWallet       string
	QueryID           uint64
	RequestHash       [32]byte
	ExpectedTermsHash [32]byte
	Price             *big.Int
	StorageFee        *big.Int
}

// Payment is price + storage fee + the admission allowance.
func (i ServiceActorCallIntent) Payment() (*big.Int, error) {
	return nativecore.MinimumServiceActorCallPayment(i.Price, i.StorageFee)
}

// ServiceActorSender hands a verified call to custody.
type ServiceActorSender interface {
	// Preflight proves, without sending, that custody would sign from the
	// buyer wallet on the verified network and can pay the exact amount.
	Preflight(ctx context.Context, intent ServiceActorCallIntent) error
	// SendCall submits the call. ErrCallNotStarted means custody was never
	// started; any other error leaves the outcome ambiguous.
	SendCall(ctx context.Context, intent ServiceActorCallIntent) error
}

var (
	// ErrCallNotStarted reports that custody was not started at all.
	ErrCallNotStarted = errors.New("the call was not handed to custody")
	// ErrUnsupportedAmount reports an amount this custody path cannot carry.
	ErrUnsupportedAmount = errors.New("the tosctl Service Actor path carries prices, fees and payments only within 64 bits")
)

// EndpointVetter checks the endpoints custody will submit through.
type EndpointVetter interface {
	Endpoints() []string
	CheckEndpointGenesis(ctx context.Context, endpoint string) error
}

// TOSCTLServiceActorSenderConfig pins the custody binary by SHA-256 and its
// configuration bytes at construction.
type TOSCTLServiceActorSenderConfig struct {
	BinaryPath   string
	BinarySHA256 string
	ConfigPath   string
	WalletName   string
	VaultURL     string
	Timeout      time.Duration
	Endpoints    EndpointVetter
}

// TOSCTLServiceActorSender sends calls with `tosctl agent service send
// --operation call`, always with the quoted --expected-terms-hash.
type TOSCTLServiceActorSender struct {
	binary, wallet string
	timeout        time.Duration
	runner         *execRunner
	endpoints      EndpointVetter
	run            func(ctx context.Context, args ...string) ([]byte, error)
	runWithPath    func(ctx context.Context, args ...string) ([]byte, error)
}

// NewTOSCTLServiceActorSender pins the binary and the configuration.
func NewTOSCTLServiceActorSender(config TOSCTLServiceActorSenderConfig) (*TOSCTLServiceActorSender, error) {
	if !secureExecutable(config.BinaryPath) || !secureConfigFile(config.ConfigPath) || config.Endpoints == nil ||
		config.WalletName == "" || strings.TrimSpace(config.WalletName) != config.WalletName || len(config.WalletName) > 128 {
		return nil, errors.New("invalid tosctl Service Actor sender configuration")
	}
	if config.Timeout == 0 {
		config.Timeout = 2 * time.Minute
	}
	if config.Timeout < time.Second || config.Timeout > 10*time.Minute {
		return nil, errors.New("invalid tosctl sender timeout")
	}
	runner, err := newPinnedExecRunnerWithVault(config.BinaryPath, config.ConfigPath, config.VaultURL)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(runner.identity.digest[:]) != config.BinarySHA256 {
		return nil, errors.New("the tosctl binary does not have the pinned SHA-256")
	}
	sender := &TOSCTLServiceActorSender{binary: config.BinaryPath, wallet: config.WalletName, timeout: config.Timeout,
		runner: runner, endpoints: config.Endpoints}
	sender.run = func(ctx context.Context, args ...string) ([]byte, error) {
		call, cancel := context.WithTimeout(ctx, sender.timeout)
		defer cancel()
		return runner.run(call, sender.binary, args...)
	}
	sender.runWithPath = func(ctx context.Context, args ...string) ([]byte, error) {
		call, cancel := context.WithTimeout(ctx, sender.timeout)
		defer cancel()
		return runner.runWithConfigPath(call, sender.binary, args...)
	}
	return sender, nil
}

func u64Amount(value *big.Int) (uint64, error) {
	if value == nil || value.Sign() < 0 || !value.IsUint64() {
		return 0, ErrUnsupportedAmount
	}
	return value.Uint64(), nil
}

// Preflight runs the amount, network and wallet bindings.
func (s *TOSCTLServiceActorSender) Preflight(ctx context.Context, intent ServiceActorCallIntent) error {
	if s == nil || ctx == nil || !isRawAddress(intent.Actor) || !isRawAddress(intent.BuyerWallet) || intent.QueryID == 0 {
		return errors.New("invalid Service Actor call intent")
	}
	if _, err := u64Amount(intent.Price); err != nil {
		return err
	}
	if _, err := u64Amount(intent.StorageFee); err != nil {
		return err
	}
	payment, err := intent.Payment()
	if err != nil {
		return err
	}
	paymentNano, err := u64Amount(payment)
	if err != nil {
		return err
	}
	endpoints, err := effectiveChainEndpoints(s.runner.config)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, endpoint := range s.endpoints.Endpoints() {
		allowed[endpoint] = true
	}
	for _, endpoint := range endpoints {
		if !allowed[endpoint] {
			return fmt.Errorf("tosctl would submit through %s, which is not a verified endpoint", endpoint)
		}
		if err := s.endpoints.CheckEndpointGenesis(ctx, endpoint); err != nil {
			return fmt.Errorf("tosctl endpoint %s is not on the verified network: %w", endpoint, err)
		}
	}
	body := nativecore.BuildServiceActorCallBody(intent.QueryID, intent.RequestHash, intent.ExpectedTermsHash)
	bodyBOC := base64.StdEncoding.EncodeToString(body.ToBOCWithOptions(cell.BOCSerializeOptions{}))
	raw, err := s.run(ctx, "wallet", "send", "--from", s.wallet, "--to", intent.Actor,
		"--amount-nanotos", fmt.Sprint(paymentNano), "--body-boc", bodyBOC, "--build-only")
	if err != nil {
		return errors.New("tosctl could not prepare the wallet binding check")
	}
	var prepared struct {
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
	if decoder.Decode(&prepared) != nil || prepared.Version != "tosctl.wallet-prepared-send.v1" || prepared.Wallet != s.wallet ||
		prepared.StateInitHash != "" || prepared.MessageBOC == "" {
		return errors.New("tosctl returned an unexpected wallet binding result")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("tosctl wallet binding output has trailing data")
	}
	if !sameAddress(prepared.Payer, intent.BuyerWallet) {
		return fmt.Errorf("tosctl wallet %s signs as %s, not the buyer wallet %s", s.wallet, prepared.Payer, intent.BuyerWallet)
	}
	if !sameAddress(prepared.Destination, intent.Actor) || prepared.AmountNanoTOS != paymentNano || prepared.BodyHash != cellHash(body) {
		return errors.New("tosctl prepared a message other than the verified call")
	}
	return nil
}

// SendCall runs `tosctl agent service send --operation call`. tosctl
// defaults the attached value to price + storage fee + the allowance from the
// live terms, and refuses unless those terms hash to --expected-terms-hash.
func (s *TOSCTLServiceActorSender) SendCall(ctx context.Context, intent ServiceActorCallIntent) error {
	if s == nil || ctx == nil || !isRawAddress(intent.Actor) || intent.QueryID == 0 {
		return ErrCallNotStarted
	}
	output, err := s.runWithPath(ctx, "agent", "service", "send", "--operation", "call", "--address", intent.Actor,
		"--from", s.wallet, "--query-id", fmt.Sprint(intent.QueryID), "--request-hash", hex.EncodeToString(intent.RequestHash[:]),
		"--expected-terms-hash", hex.EncodeToString(intent.ExpectedTermsHash[:]), "--yes")
	if errors.Is(err, ErrCallNotStarted) {
		return err
	}
	if err != nil {
		return fmt.Errorf("tosctl call outcome is ambiguous: %w", err)
	}
	if !bytes.Contains(output, []byte("Service Actor call message submitted to")) {
		return errors.New("tosctl call outcome is ambiguous: no submission report")
	}
	return nil
}

// effectiveChainEndpoints mirrors tosctl's resolved_endpoints: the legacy
// url first, then urls entries (string or {url, api_key}), each trimmed,
// empty entries dropped and duplicates removed. An empty list, where tosctl
// would fall back to its built-in endpoint, is refused.
func effectiveChainEndpoints(config []byte) ([]string, error) {
	var parsed struct {
		ChainRPC *struct {
			URLs []json.RawMessage `json:"urls"`
			URL  *string           `json:"url"`
		} `json:"chain_rpc"`
	}
	if err := json.Unmarshal(config, &parsed); err != nil {
		return nil, errors.New("tosctl configuration is not JSON")
	}
	if parsed.ChainRPC == nil {
		return nil, errors.New("tosctl configuration names no chain_rpc endpoints; it would use its built-in default")
	}
	var candidates []string
	if parsed.ChainRPC.URL != nil {
		candidates = append(candidates, *parsed.ChainRPC.URL)
	}
	for _, entry := range parsed.ChainRPC.URLs {
		var text string
		if err := json.Unmarshal(entry, &text); err == nil {
			candidates = append(candidates, text)
			continue
		}
		var object struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(entry, &object); err != nil {
			return nil, errors.New("tosctl chain_rpc entry is neither a URL nor an endpoint object")
		}
		candidates = append(candidates, object.URL)
	}
	seen := map[string]bool{}
	var result []string
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil, errors.New("tosctl configuration names no usable chain_rpc endpoint; it would use its built-in default")
	}
	return result, nil
}

// runWithConfigPath runs the pinned executable with the pinned configuration
// written to a fresh owner-private .json file, for commands that read their
// configuration only from a path. The file is removed afterwards.
func (r *execRunner) runWithConfigPath(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if r == nil {
		return nil, ErrCallNotStarted
	}
	executable, identity, err := openAndIdentifyExecutable(binary)
	if err != nil || identity != r.identity {
		if executable != nil {
			_ = executable.Close()
		}
		return nil, fmt.Errorf("%w: enrolled tosctl executable identity changed", ErrCallNotStarted)
	}
	defer executable.Close()
	directory, err := os.MkdirTemp("", "tosctl-custody-")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallNotStarted, err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallNotStarted, err)
	}
	path := filepath.Join(directory, "tosctl-config.json")
	if err := os.WriteFile(path, r.config, 0o600); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallNotStarted, err)
	}
	command := exec.CommandContext(ctx, "/proc/self/fd/3", append(append([]string(nil), args...), "-c", path)...)
	command.ExtraFiles = []*os.File{executable}
	command.Env = append([]string(nil), r.environment...)
	output := cappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallNotStarted, err)
	}
	err = command.Wait()
	return output.Bytes(), err
}
