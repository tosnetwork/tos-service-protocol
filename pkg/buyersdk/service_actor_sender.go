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
	"strconv"
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
// empty entries dropped and duplicates removed. Keys are matched exactly and
// a duplicated key is refused, as tosctl's parser treats them; an empty
// list, where tosctl would fall back to its built-in endpoint, is refused.
func effectiveChainEndpoints(config []byte) ([]string, error) {
	top, err := strictObject(config)
	if err != nil {
		return nil, fmt.Errorf("tosctl configuration: %w", err)
	}
	chainRaw, ok := top["chain_rpc"]
	if !ok {
		return nil, errors.New("tosctl configuration names no chain_rpc endpoints; it would use its built-in default")
	}
	chainRPC, err := strictObject(chainRaw)
	if err != nil {
		return nil, fmt.Errorf("tosctl chain_rpc: %w", err)
	}
	var candidates []string
	if raw, ok := chainRPC["url"]; ok && string(raw) != "null" {
		var legacy string
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return nil, errors.New("tosctl chain_rpc url is not a string")
		}
		candidates = append(candidates, legacy)
	}
	if raw, ok := chainRPC["urls"]; ok {
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
			return nil, errors.New("tosctl chain_rpc urls is not an array")
		}
		for _, entry := range entries {
			var text string
			if err := json.Unmarshal(entry, &text); err == nil {
				candidates = append(candidates, text)
				continue
			}
			object, err := strictObject(entry)
			if err != nil {
				return nil, errors.New("tosctl chain_rpc entry is neither a URL nor an endpoint object")
			}
			var url, key string
			if json.Unmarshal(object["url"], &url) != nil || json.Unmarshal(object["api_key"], &key) != nil {
				return nil, errors.New("tosctl chain_rpc endpoint object needs string url and api_key")
			}
			candidates = append(candidates, url)
		}
	}
	seen := map[string]bool{}
	var result []string
	for _, candidate := range candidates {
		// tosctl trims entries and drops empty ones before refusing
		// whitespace; any whitespace at all is refused here.
		target, err := submissionURL(candidate)
		if err != nil {
			return nil, err
		}
		if seen[target] {
			continue
		}
		seen[target] = true
		result = append(result, target)
	}
	if len(result) == 0 {
		return nil, errors.New("tosctl configuration names no usable chain_rpc endpoint; it would use its built-in default")
	}
	return result, nil
}

// submissionURL is the URL tosctl posts to for a configured endpoint. It
// does not reproduce tosctl's URL normalization; it accepts only a closed
// canonical form on which Go and tosctl cannot disagree, and refuses
// everything else: a scheme of exactly http or https (http only for a
// loopback host), a lower-case host of [a-z0-9-] labels (a numeric host only
// as a canonical dotted quad, no 0x labels, no IPv6 literal), an optional
// canonical decimal port, and a path of plain segments with no dot segment,
// empty segment, percent encoding or backslash. No whitespace, userinfo,
// query or fragment. The result is the endpoint without a default port and
// without its trailing slash, with /jsonRPC appended, as tosctl joins it.
func submissionURL(endpoint string) (string, error) {
	refuse := func(reason string) (string, error) {
		return "", fmt.Errorf("tosctl chain_rpc endpoint %q is refused: %s", endpoint, reason)
	}
	for _, character := range []byte(endpoint) {
		if character <= 0x20 || character >= 0x7f || strings.IndexByte("\\%?#@", character) >= 0 {
			return refuse("it holds whitespace, a control or non-ASCII byte, or one of \\ % ? # @")
		}
	}
	scheme, rest, ok := strings.Cut(endpoint, "://")
	if !ok || scheme != "http" && scheme != "https" {
		return refuse("the scheme is not exactly http or https")
	}
	authority, path := rest, ""
	if index := strings.IndexByte(rest, '/'); index >= 0 {
		authority, path = rest[:index], rest[index:]
	}
	host, port := authority, ""
	if index := strings.LastIndexByte(authority, ':'); index >= 0 {
		host, port = authority[:index], authority[index+1:]
		if port == "" || port[0] == '0' || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return refuse("the port is not a canonical decimal")
		}
		if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
			return refuse("the port is out of range")
		}
	}
	loopback, err := canonicalHost(host)
	if err != nil {
		return refuse(err.Error())
	}
	if scheme == "http" && !loopback {
		return refuse("plain http is accepted only for a loopback host")
	}
	if path != "" && path != "/" {
		segments := strings.Split(strings.TrimSuffix(path, "/"), "/")
		for _, segment := range segments[1:] {
			if segment == "" || segment == "." || segment == ".." || segment[0] == '.' ||
				strings.Trim(segment, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~-") != "" {
				return refuse("the path has an empty, dot or non-plain segment")
			}
		}
	}
	if scheme == "http" && port == "80" || scheme == "https" && port == "443" {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host + strings.TrimSuffix(path, "/") + "/jsonRPC", nil
}

// canonicalHost accepts a lower-case DNS name of [a-z0-9-] labels or a
// canonical dotted-quad IPv4 address and reports whether it is loopback.
func canonicalHost(host string) (bool, error) {
	if host == "" || len(host) > 253 {
		return false, errors.New("the host is empty or too long")
	}
	labels := strings.Split(host, ".")
	numeric := true
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false, errors.New("the host is not a lower-case name of plain labels")
		}
		if strings.HasPrefix(label, "0x") {
			return false, errors.New("the host has a hexadecimal label")
		}
		if strings.Trim(label, "0123456789") != "" {
			numeric = false
		}
	}
	if !numeric {
		if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
			return false, errors.New("the host ends in a numeric label")
		}
		return host == "localhost", nil
	}
	if len(labels) != 4 {
		return false, errors.New("a numeric host must be a dotted quad")
	}
	for _, label := range labels {
		value, err := strconv.Atoi(label)
		if err != nil || value > 255 || len(label) > 1 && label[0] == '0' {
			return false, errors.New("a numeric host must be a canonical dotted quad")
		}
	}
	return labels[0] == "127", nil
}

// strictObject decodes one JSON object with exact, unique keys.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	result := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid JSON object key")
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON object key")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid JSON object value")
		}
		result[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("unterminated JSON object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON object")
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
