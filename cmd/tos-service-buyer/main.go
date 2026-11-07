// Command tos-service-buyer discovers, verifies and calls Service Actors
// from quorum-finalized TOS state, and queries the derived request index.
// Every command prints JSON. No command trusts a gateway for authority: a
// manifest is used only after it matches the finalized digest, and every
// verification reads one finalized checkpoint.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/buyersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactorindex"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/encoding/protojson"
)

const usage = "usage: tos-service-buyer <discover|prepare|call|status|requests> [flags]"

// usageOutput receives flag errors and usage text.
var usageOutput io.Writer = os.Stderr

// newCallSender builds the tosctl custody sender for call. The vault URL
// carries the vault's master key, so it is read here, and only here, from the
// VAULT_URL environment variable tosctl itself uses, and handed to tosctl only
// in its environment, never on a command line where the process table would
// show it.
func newCallSender(tosctlPath, tosctlSHA, tosctlConfig, wallet string,
	endpoints buyersdk.EndpointVetter) (*buyersdk.TOSCTLServiceActorSender, error) {
	return buyersdk.NewTOSCTLServiceActorSender(buyersdk.TOSCTLServiceActorSenderConfig{BinaryPath: tosctlPath,
		BinarySHA256: tosctlSHA, ConfigPath: tosctlConfig, WalletName: wallet, VaultURL: os.Getenv("VAULT_URL"),
		Endpoints: endpoints})
}

// requestLister is the index surface the requests command pages through.
type requestLister interface {
	Requests(actor string, filter serviceactorindex.RequestFilter, pageSize int, after *uint64) (*serviceactorindex.RequestPage, error)
}

// requestPage reads one page, continuing after the caller's cursor so every
// request is reachable however many an actor holds.
func requestPage(index requestLister, actor string, filter serviceactorindex.RequestFilter, pageSize int,
	after *uint64) (*serviceactorindex.RequestPage, error) {
	return index.Requests(actor, filter, pageSize, after)
}

// parseAfterRequestID reads a page cursor: empty for the first page, else a
// canonical unsigned decimal request ID (no sign, no leading zeros).
func parseAfterRequestID(value string) (*uint64, error) {
	if value == "" {
		return nil, nil
	}
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(id, 10) != value {
		return nil, fmt.Errorf("--after-request-id must be a canonical unsigned decimal request ID, not %q", value)
	}
	return &id, nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tos-service-buyer:", err)
		os.Exit(1)
	}
}

func run(arguments []string, out io.Writer) error {
	if len(arguments) == 0 {
		return errors.New(usage)
	}
	if arguments[0] == "help" || arguments[0] == "-h" || arguments[0] == "--help" {
		fmt.Fprintln(out, usage)
		return nil
	}
	command, rest := arguments[0], arguments[1:]
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	set.SetOutput(usageOutput)
	common := addCommonFlags(set)
	var capabilityID, version, packagePath, executionID, inputDigest, requestHash, actor, caller string
	var tosctlPath, tosctlSHA, tosctlConfig, wallet string
	var pageSize int
	var afterRequestID string
	switch command {
	case "discover":
		set.StringVar(&capabilityID, "capability-id", "", "Capability ID")
		set.StringVar(&version, "version", "", "Capability version")
	case "prepare":
		set.StringVar(&packagePath, "package", "", "QuoteProposalPackageV1 protojson file")
		set.StringVar(&executionID, "execution-id", "", "64 lowercase hex execution ID")
		set.StringVar(&inputDigest, "input-digest", "", "64 lowercase hex input digest")
	case "call":
		set.StringVar(&requestHash, "request-hash", "", "request_hash of a prepared call")
		set.StringVar(&tosctlPath, "tosctl", "", "absolute path of the tosctl custody binary")
		set.StringVar(&tosctlSHA, "tosctl-sha256", "", "lowercase hex SHA-256 of that binary")
		set.StringVar(&tosctlConfig, "tosctl-config", "", "absolute path of the tosctl configuration (JSON)")
		set.StringVar(&wallet, "wallet", "", "tosctl wallet name that signs as the buyer wallet")
	case "status":
		set.StringVar(&requestHash, "request-hash", "", "request_hash of a call")
	case "requests":
		set.StringVar(&actor, "actor", "", "raw Service Actor address")
		set.StringVar(&caller, "caller", "", "optional raw caller address filter")
		set.StringVar(&requestHash, "request-hash", "", "optional request_hash filter")
		set.IntVar(&pageSize, "page-size", 50, "page size, at most 100")
		set.StringVar(&afterRequestID, "after-request-id", "",
			"continue after this request ID: the previous page's next_after_request_id")
	default:
		return errors.New(usage)
	}
	if err := set.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	after, err := parseAfterRequestID(afterRequestID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	environment, err := common.open()
	if err != nil {
		return err
	}
	switch command {
	case "requests":
		index, err := serviceactorindex.New(serviceactorindex.FromChain(environment.reader))
		if err != nil {
			return err
		}
		if _, err := index.Refresh(ctx, actor); err != nil {
			return err
		}
		page, err := requestPage(index, actor, serviceactorindex.RequestFilter{Caller: caller, RequestHash: requestHash}, pageSize, after)
		if err != nil {
			return err
		}
		return printJSON(out, page)
	}
	var sender buyersdk.ServiceActorSender = refusingSender{}
	if command == "call" {
		if tosctlPath == "" || tosctlSHA == "" || tosctlConfig == "" || wallet == "" {
			return errors.New("call needs --tosctl, --tosctl-sha256, --tosctl-config and --wallet")
		}
		sender, err = newCallSender(tosctlPath, tosctlSHA, tosctlConfig, wallet, environment.reader)
		if err != nil {
			return err
		}
	}
	buyer, err := environment.buyer(sender)
	if err != nil {
		return err
	}
	switch command {
	case "discover":
		offer, err := buyer.Discover(ctx, capabilityID, version)
		if err != nil {
			return err
		}
		return printJSON(out, offer)
	case "prepare":
		value, err := readPackage(packagePath)
		if err != nil {
			return err
		}
		execution, err := hex32(executionID)
		if err != nil {
			return fmt.Errorf("--execution-id: %w", err)
		}
		input, err := hex32(inputDigest)
		if err != nil {
			return fmt.Errorf("--input-digest: %w", err)
		}
		request := &nativev1.RequestQuoteProposalRequest{CapabilityId: value.GetProposal().GetCapabilityId(),
			CapabilityVersion: value.GetProposal().GetCapabilityVersion(), BuyerAddress: common.buyerWallet}
		record, err := buyer.Prepare(ctx, request, value, execution, input)
		if err != nil {
			return err
		}
		return printJSON(out, record)
	case "call":
		record, err := buyer.Call(ctx, requestHash)
		if printErr := printJSON(out, record); printErr != nil {
			return printErr
		}
		return err
	case "status":
		report, err := buyer.Resolve(ctx, requestHash)
		if err != nil {
			return err
		}
		return printJSON(out, report)
	}
	return errors.New(usage)
}

type commonFlags struct {
	networkPath, endpoints, registryCodePath, registryCodeHash, actorCodeHash string
	stateDir, manifestDir, buyerWallet                                        string
	quorum, registryWorkchain                                                 int
	timeout                                                                   time.Duration
	maxPerCall, maxWindow                                                     string
	maxCalls                                                                  int
	window                                                                    time.Duration
}

func addCommonFlags(set *flag.FlagSet) *commonFlags {
	flags := &commonFlags{}
	set.StringVar(&flags.networkPath, "network-domain", "", "JSON file {network_id, genesis_root_hash, genesis_file_hash}")
	set.StringVar(&flags.endpoints, "rpc", "", "comma-separated TOS JSON-RPC endpoints (3 to 8)")
	set.IntVar(&flags.quorum, "quorum", 0, "strict-majority quorum; defaults to a majority of --rpc")
	set.StringVar(&flags.registryCodePath, "registry-code-boc", "", "file holding the Native Registry code BOC (base64)")
	set.StringVar(&flags.registryCodeHash, "registry-code-hash", "", "tvm-cell-sha256:<hex> Native Registry code hash")
	set.IntVar(&flags.registryWorkchain, "registry-workchain", 0, "Native Registry workchain")
	set.StringVar(&flags.actorCodeHash, "actor-code-hash", "", "tvm-cell-sha256:<hex> pinned Service Actor release code hash (required)")
	set.StringVar(&flags.stateDir, "state-dir", "", "owner-private directory for checkpoints and the call journal")
	set.StringVar(&flags.manifestDir, "manifest-dir", "", "directory of canonical manifests named <sha256 hex>.cbor")
	set.StringVar(&flags.buyerWallet, "buyer-wallet", "", "raw workchain 0 buyer wallet address")
	set.DurationVar(&flags.timeout, "timeout", 2*time.Minute, "overall command timeout")
	set.StringVar(&flags.maxPerCall, "max-per-call-nanotos", "1000000000", "largest payment of one call")
	set.StringVar(&flags.maxWindow, "max-window-nanotos", "10000000000", "largest total reserved in the window")
	set.IntVar(&flags.maxCalls, "max-calls", 100, "most calls reserved in the window")
	set.DurationVar(&flags.window, "budget-window", 24*time.Hour, "budget window")
	return flags
}

type environment struct {
	flags   *commonFlags
	network *nativev1.NetworkDomain
	reader  *toschain.ServiceActorReader
}

func (c *commonFlags) open() (*environment, error) {
	if c.networkPath == "" || c.endpoints == "" || c.registryCodePath == "" || c.registryCodeHash == "" ||
		c.actorCodeHash == "" || c.stateDir == "" || c.buyerWallet == "" {
		return nil, errors.New("--network-domain, --rpc, --registry-code-boc, --registry-code-hash, --actor-code-hash, --state-dir and --buyer-wallet are required")
	}
	if !filepath.IsAbs(c.stateDir) || filepath.Clean(c.stateDir) != c.stateDir {
		return nil, errors.New("--state-dir must be absolute and clean")
	}
	raw, err := readBounded(c.networkPath, 4096)
	if err != nil {
		return nil, err
	}
	var domain struct {
		NetworkID       string `json:"network_id"`
		GenesisRootHash string `json:"genesis_root_hash"`
		GenesisFileHash string `json:"genesis_file_hash"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&domain); err != nil {
		return nil, fmt.Errorf("--network-domain: %w", err)
	}
	network := &nativev1.NetworkDomain{NetworkId: domain.NetworkID, GenesisRootHash: domain.GenesisRootHash, GenesisFileHash: domain.GenesisFileHash}
	endpoints := strings.Split(c.endpoints, ",")
	quorum := c.quorum
	if quorum == 0 {
		quorum = len(endpoints)/2 + 1
	}
	chain, err := toschain.New(toschain.Config{Network: network.NetworkId, Endpoints: endpoints, Quorum: quorum})
	if err != nil {
		return nil, err
	}
	code, err := readBounded(c.registryCodePath, 1<<20)
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(network, int32(c.registryWorkchain), strings.Join(strings.Fields(string(code)), ""), c.registryCodeHash)
	if err != nil {
		return nil, err
	}
	registry, err := toschain.NewSimplifiedNativeResolver(chain, locator, filepath.Join(c.stateDir, "registry.checkpoint"))
	if err != nil {
		return nil, err
	}
	reader, err := toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{Chain: chain, Network: network,
		ActorCodeHash: c.actorCodeHash, Registry: registry, CheckpointPath: filepath.Join(c.stateDir, "service-actor.checkpoint")})
	if err != nil {
		return nil, err
	}
	return &environment{flags: c, network: network, reader: reader}, nil
}

func (e *environment) buyer(sender buyersdk.ServiceActorSender) (*buyersdk.ServiceActorBuyer, error) {
	journalDir := filepath.Join(e.flags.stateDir, "journal")
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		return nil, err
	}
	journal, err := buyersdk.OpenServiceActorJournal(journalDir, time.Now())
	if err != nil {
		return nil, err
	}
	perCall, ok := new(big.Int).SetString(e.flags.maxPerCall, 10)
	if !ok {
		return nil, errors.New("--max-per-call-nanotos is not a decimal")
	}
	window, ok := new(big.Int).SetString(e.flags.maxWindow, 10)
	if !ok {
		return nil, errors.New("--max-window-nanotos is not a decimal")
	}
	if e.flags.manifestDir == "" {
		return nil, errors.New("--manifest-dir is required")
	}
	return buyersdk.NewServiceActorBuyer(buyersdk.ServiceActorBuyerConfig{Reader: buyersdk.BuyerReaderFromChain(e.reader),
		Manifests: manifestDirectory(e.flags.manifestDir), Network: e.network, ActorCodeHash: e.flags.actorCodeHash,
		BuyerWallet: e.flags.buyerWallet, Sender: sender, Journal: journal,
		Limits: buyersdk.ServiceActorLimits{Window: e.flags.window, MaxCalls: e.flags.maxCalls, MaxPerCallNanoTOS: perCall, MaxWindowNanoTOS: window}})
}

// manifestDirectory serves untrusted manifest bytes by digest; the buyer
// checks them against the finalized digest before use.
type manifestDirectory string

func (m manifestDirectory) Manifest(_ context.Context, digest string) ([]byte, error) {
	name := strings.TrimPrefix(digest, "sha256:")
	if _, err := hex32(name); err != nil || "sha256:"+name != digest {
		return nil, errors.New("invalid manifest digest")
	}
	return readBounded(filepath.Join(string(m), name+".cbor"), 1<<20)
}

// refusingSender is used by every command but call: nothing else may send.
type refusingSender struct{}

func (refusingSender) Preflight(context.Context, buyersdk.ServiceActorCallIntent) error {
	return errors.New("this command does not send calls")
}

func (refusingSender) SendCall(context.Context, buyersdk.ServiceActorCallIntent) error {
	return buyersdk.ErrCallNotStarted
}

func readPackage(path string) (*nativev1.QuoteProposalPackageV1, error) {
	raw, err := readBounded(path, 4<<20)
	if err != nil {
		return nil, err
	}
	value := &nativev1.QuoteProposalPackageV1{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, value); err != nil {
		return nil, fmt.Errorf("--package: %w", err)
	}
	return value, nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%q must be an absolute path", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, fmt.Errorf("%s is not a regular file within %d bytes", path, maximum)
	}
	return io.ReadAll(io.LimitReader(file, maximum))
}

func hex32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value {
		return out, errors.New("expected 64 lowercase hex characters")
	}
	copy(out[:], raw)
	return out, nil
}

func printJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
