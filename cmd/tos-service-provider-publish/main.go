// Command tos-service-provider-publish turns a reviewed provider Capability
// action into finalized Native state and then publishes its immutable manifest
// to the derived Gateway catalog. Private controller keys remain in
// tos-service-wallet/tosctl custody; this command accepts only the signed action.
//
// Every publication is journaled in an owner-private state directory before
// its action is printed for signing, so `apply` resumes the same action after
// a crash at any phase instead of rebuilding it.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/providersdk"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/encoding/protojson"
)

const maxPublicationFile = 1 << 20

const usage = "usage: tos-service-provider-publish <prepare|preview|apply|status> [flags]"

type options struct {
	stateDir                                               string
	gateway, tokenPath, caller, caFile, serverName         string
	network, genesisRoot, genesisFile, registryHash, owner string
	manifestPath, objectNonce, actionNonce, signedAction   string
	capabilityRetry, manifestRetry, actionHash             string
	tosctl, tosctlSHA256                                   string
	rpc, registryCodeBOC, actorCodeHash                    string
	quorum, registryWorkchain                              int
	insecure                                               bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tos-service-provider-publish:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return errors.New(usage)
	}
	mode := arguments[0]
	switch mode {
	case "prepare", "preview", "apply", "status":
	default:
		return errors.New(usage)
	}
	value, err := parse(mode, arguments[1:])
	if err != nil {
		return err
	}
	journal, err := openJournal(value.stateDir)
	if err != nil {
		return err
	}
	if mode == "status" {
		return status(journal, value.actionHash, stdout)
	}
	var record providersdk.PublicationRecord
	var network *nativev1.NetworkDomain
	registryHash := value.registryHash
	if mode == "prepare" {
		network = &nativev1.NetworkDomain{NetworkId: value.network, GenesisRootHash: value.genesisRoot, GenesisFileHash: value.genesisFile}
	} else {
		if record, err = journal.Read(value.actionHash); err != nil {
			return fmt.Errorf("read journaled publication: %w", err)
		}
		network, registryHash = record.Network(), record.RegistryCodeHash
		value.registryHash = registryHash
	}
	provider, closeClient, err := newProvider(value, network, registryHash)
	if err != nil {
		return err
	}
	defer closeClient()
	switch mode {
	case "prepare":
		return prepare(value, provider, journal, network, stdout, stderr)
	case "preview":
		return writePreview(value, provider, record, network, stdout, stderr, true)
	default:
		return apply(value, provider, journal, record, stdout)
	}
}

func parse(mode string, arguments []string) (options, error) {
	set := flag.NewFlagSet(mode, flag.ContinueOnError)
	var value options
	set.StringVar(&value.stateDir, "state-dir", "", "owner-private directory holding the publication journal")
	if mode != "status" {
		set.StringVar(&value.gateway, "gateway", "", "Native Gateway base URL")
		set.StringVar(&value.tokenPath, "token-file", "", "owner-private Gateway bearer token")
		set.StringVar(&value.caller, "caller-id", "", "bounded provider caller identity")
		set.StringVar(&value.caFile, "ca-file", "", "optional private Gateway CA")
		set.StringVar(&value.serverName, "server-name", "", "optional Gateway TLS server name")
		set.BoolVar(&value.insecure, "insecure", false, "allow loopback plaintext Gateway")
		set.StringVar(&value.tosctl, "tosctl", "", "absolute path of the tosctl binary that verifies ML-DSA-44 signatures")
		set.StringVar(&value.tosctlSHA256, "tosctl-sha256", "", "lowercase hex SHA-256 of that tosctl binary")
	}
	if mode == "prepare" {
		set.StringVar(&value.network, "network-id", "", "TOS network ID")
		set.StringVar(&value.genesisRoot, "genesis-root", "", "network genesis root hash")
		set.StringVar(&value.genesisFile, "genesis-file", "", "network genesis file hash")
		set.StringVar(&value.registryHash, "registry-code-hash", "", "frozen Registry TVM digest")
		set.StringVar(&value.owner, "owner-agent-id", "", "finalized provider AgentID")
		set.StringVar(&value.manifestPath, "manifest-json", "", "reviewed software-work manifest JSON")
		set.StringVar(&value.objectNonce, "object-nonce", "", "optional nonzero 32-byte hex Capability nonce (generated and journaled when omitted)")
		set.StringVar(&value.actionNonce, "action-nonce", "", "optional nonzero 32-byte hex action nonce (given with --object-nonce)")
		set.StringVar(&value.capabilityRetry, "capability-idempotency-key", "", "optional Capability relay retry key (generated when omitted)")
		set.StringVar(&value.manifestRetry, "manifest-idempotency-key", "", "optional manifest catalog retry key (generated when omitted)")
	} else {
		set.StringVar(&value.actionHash, "action-hash", "", "sha256:<hex> action hash naming the journaled publication")
	}
	if mode == "prepare" || mode == "preview" {
		set.StringVar(&value.rpc, "rpc", "", "optional comma-separated TOS JSON-RPC endpoints (3 to 8) for reading the Service Actor")
		set.IntVar(&value.quorum, "quorum", 0, "strict-majority quorum; defaults to a majority of --rpc")
		set.StringVar(&value.registryCodeBOC, "registry-code-boc", "", "file holding the Native Registry code BOC (base64); required with --rpc")
		set.IntVar(&value.registryWorkchain, "registry-workchain", 0, "Native Registry workchain")
		set.StringVar(&value.actorCodeHash, "actor-code-hash", "", "tvm-cell-sha256:<hex> pinned Service Actor release, checked against manifest key 21; required with --rpc")
	}
	if mode == "apply" {
		set.StringVar(&value.signedAction, "signed-action", "", "tos-service-wallet SignedNativeActionV1 JSON (required while the publication is prepared)")
	}
	if err := set.Parse(arguments); err != nil {
		return value, err
	}
	if set.NArg() != 0 || value.stateDir == "" {
		return value, errors.New("--state-dir is required and positional arguments are not accepted")
	}
	if mode != "status" && (value.gateway == "" || value.caller == "") {
		return value, errors.New("--gateway and --caller-id are required")
	}
	if mode == "prepare" && (value.network == "" || value.genesisRoot == "" || value.genesisFile == "" ||
		value.registryHash == "" || !canonicalAgent(value.owner) || value.manifestPath == "") {
		return value, errors.New("prepare requires --network-id, --genesis-root, --genesis-file, --registry-code-hash, a canonical --owner-agent-id and --manifest-json")
	}
	if (mode == "preview" || mode == "apply") && value.actionHash == "" {
		return value, errors.New("--action-hash is required")
	}
	if value.rpc != "" && (value.registryCodeBOC == "" || value.actorCodeHash == "") {
		return value, errors.New("--rpc requires --registry-code-boc and --actor-code-hash")
	}
	// --actor-code-hash alone is a local pin check against manifest key 21;
	// the registry code and quorum are only meaningful for chain reads.
	if value.rpc == "" && (value.registryCodeBOC != "" || value.quorum != 0) {
		return value, errors.New("--registry-code-boc and --quorum are only used with --rpc")
	}
	return value, nil
}

// openJournal opens <state-dir>/journal, creating both owner-private
// directories when missing and refusing symlinks or broader permissions.
func openJournal(stateDir string) (*providersdk.PublicationJournal, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("--state-dir must be absolute and clean")
	}
	for _, directory := range []string{stateDir, filepath.Join(stateDir, "journal")} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
			return nil, fmt.Errorf("%s must be an owner-private directory (mode 0700), not a symlink", directory)
		}
	}
	return providersdk.OpenPublicationJournal(filepath.Join(stateDir, "journal"), time.Now())
}

func newProvider(value options, network *nativev1.NetworkDomain, registryHash string) (*providersdk.Provider, func(), error) {
	token, err := readToken(value.tokenPath)
	if err != nil {
		return nil, nil, err
	}
	client, err := nativeclient.New(nativeclient.Config{BaseURL: value.gateway, BearerToken: token,
		Insecure: value.insecure, CAFile: value.caFile, ServerName: value.serverName, Timeout: 45 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	// Controller signatures are verified against the finalized owner policy
	// before anything is relayed; the helper only verifies here, it holds no
	// keys for this command.
	verifier, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: value.tosctl, SHA256: value.tosctlSHA256})
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	provider, err := providersdk.New(providersdk.Config{Client: client, Verifier: verifier, Network: network,
		RegistryCodeHash: registryHash, CallerID: value.caller, PollInterval: time.Second, FinalityTimeout: 10 * time.Minute})
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return provider, func() { client.Close() }, nil
}

func prepare(value options, provider *providersdk.Provider, journal *providersdk.PublicationJournal, network *nativev1.NetworkDomain,
	stdout, stderr io.Writer) error {
	// The pin is checked before anything is journaled, so a manifest that
	// names another Service Actor release never leaves an applicable record.
	publication := providersdk.PublicationOptions{CapabilityIdempotencyKey: value.capabilityRetry, ManifestIdempotencyKey: value.manifestRetry,
		PinnedActorCodeHash: value.actorCodeHash}
	if (value.objectNonce == "") != (value.actionNonce == "") {
		return errors.New("give both --object-nonce and --action-nonce, or neither")
	}
	if value.objectNonce != "" {
		var err error
		if publication.ObjectNonce, err = nonce(value.objectNonce); err != nil {
			return err
		}
		if publication.ActionNonce, err = nonce(value.actionNonce); err != nil {
			return err
		}
	}
	manifest, err := readBoundedRegular(value.manifestPath, false)
	if err != nil {
		return err
	}
	// The record is durable before the action is printed for signing.
	record, created, err := provider.PrepareJournaledPublication(journal, manifest, value.owner, publication)
	if err != nil {
		return err
	}
	if !created {
		fmt.Fprintf(stderr, "resuming journaled publication %s in phase %s\n", record.ActionHash, record.Phase)
	}
	if err := writePreview(value, provider, record, network, nil, stderr, false); err != nil {
		return err
	}
	prepared, err := record.Prepared()
	if err != nil {
		return err
	}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}).Marshal(prepared.Action)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	actionPath := filepath.Join(value.stateDir, "action-"+strings.TrimPrefix(record.ActionHash, "sha256:")+".json")
	if err := writePrivateFile(actionPath, raw); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "unsigned action for tos-service-wallet: %s\nresume with: apply --state-dir %s --action-hash %s\n",
		actionPath, value.stateDir, record.ActionHash)
	_, err = stdout.Write(raw)
	return err
}

// writePreview builds the preview, writes its JSON beside the journal and
// renders it. With toStdout the JSON is also printed for machine use.
// Manifest mistakes that no later chain change can fix stop the command.
func writePreview(value options, provider *providersdk.Provider, record providersdk.PublicationRecord,
	network *nativev1.NetworkDomain, stdout, stderr io.Writer, toStdout bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	actors, err := actorReader(value, network)
	if err != nil {
		return err
	}
	preview, err := provider.PreviewPublication(ctx, record, providersdk.PreviewSources{PinnedActorCodeHash: value.actorCodeHash, Actors: actors})
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	previewPath := filepath.Join(value.stateDir, "preview-"+strings.TrimPrefix(record.ActionHash, "sha256:")+".json")
	if err := writePrivateFile(previewPath, raw); err != nil {
		return err
	}
	if err := preview.WriteText(stderr); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "machine-readable preview: %s\n", previewPath)
	if toStdout {
		if _, err := stdout.Write(raw); err != nil {
			return err
		}
	}
	for _, blocking := range []providersdk.PreviewField{preview.ServiceActorCodeHash, preview.AttestorAuthorized} {
		if blocking.Status == providersdk.PreviewMismatch {
			return errors.New("the manifest's Service Actor binding is wrong (see the preview); do not sign this action")
		}
	}
	return nil
}

// actorReader wires the repository's quorum Service Actor reader when
// --rpc is given; without it the preview marks actor fields unknown.
func actorReader(value options, network *nativev1.NetworkDomain) (providersdk.ServiceActorStateReader, error) {
	if value.rpc == "" {
		return nil, nil
	}
	endpoints := strings.Split(value.rpc, ",")
	quorum := value.quorum
	if quorum == 0 {
		quorum = len(endpoints)/2 + 1
	}
	chain, err := toschain.New(toschain.Config{Network: network.NetworkId, Endpoints: endpoints, Quorum: quorum})
	if err != nil {
		return nil, err
	}
	code, err := readBoundedRegular(value.registryCodeBOC, false)
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(network, int32(value.registryWorkchain), strings.Join(strings.Fields(string(code)), ""), value.registryHash)
	if err != nil {
		return nil, err
	}
	registry, err := toschain.NewSimplifiedNativeResolver(chain, locator, filepath.Join(value.stateDir, "registry.checkpoint"))
	if err != nil {
		return nil, err
	}
	reader, err := toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{Chain: chain, Network: network,
		ActorCodeHash: value.actorCodeHash, Registry: registry, CheckpointPath: filepath.Join(value.stateDir, "service-actor.checkpoint")})
	if err != nil {
		return nil, err
	}
	return providersdk.ServiceActorSessionReader{Reader: reader}, nil
}

func apply(value options, provider *providersdk.Provider, journal *providersdk.PublicationJournal, record providersdk.PublicationRecord, stdout io.Writer) error {
	var signed *nativev1.SignedNativeActionV1
	if value.signedAction != "" {
		var err error
		if signed, err = readSignedAction(value.signedAction); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	result, applyErr := provider.ApplyPublication(ctx, journal, record.ActionHash, signed)
	if applyErr != nil {
		// Report the phase the journal holds now, never the one read before
		// apply started.
		if current, err := journal.Read(record.ActionHash); err == nil {
			result = current
		} else if result.ActionHash == "" {
			result = record
		}
	}
	if err := writeStatus(stdout, result); err != nil {
		return err
	}
	return applyErr
}

// publicationStatus reports chain publication and catalog admission as
// separate facts; a relay acknowledgement is only the submitted phase.
type publicationStatus struct {
	ActionHash          string `json:"action_hash"`
	CapabilityID        string `json:"capability_id"`
	ManifestDigest      string `json:"manifest_digest"`
	Phase               string `json:"phase"`
	SubmitAttempts      uint32 `json:"submit_attempts"`
	ChainPublished      bool   `json:"chain_published"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
	CatalogAdmitted     bool   `json:"catalog_admitted"`
	CatalogCheckpoint   uint64 `json:"catalog_checkpoint"`
}

func toStatus(record providersdk.PublicationRecord) publicationStatus {
	return publicationStatus{ActionHash: record.ActionHash, CapabilityID: record.CapabilityID, ManifestDigest: record.ManifestDigest,
		Phase: string(record.Phase), SubmitAttempts: record.SubmitAttempts,
		ChainPublished:      record.Phase == providersdk.PublicationFinalized || record.Phase == providersdk.PublicationCataloged,
		FinalizedCheckpoint: record.FinalizedCheckpoint, CatalogAdmitted: record.Phase == providersdk.PublicationCataloged,
		CatalogCheckpoint: record.CatalogCheckpoint}
}

func writeStatus(out io.Writer, record providersdk.PublicationRecord) error {
	raw, err := json.Marshal(toStatus(record))
	if err != nil {
		return err
	}
	_, err = out.Write(append(raw, '\n'))
	return err
}

func status(journal *providersdk.PublicationJournal, actionHash string, stdout io.Writer) error {
	if actionHash != "" {
		record, err := journal.Read(actionHash)
		if err != nil {
			return err
		}
		return writeStatus(stdout, record)
	}
	records, err := journal.Records()
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := writeStatus(stdout, record); err != nil {
			return err
		}
	}
	return nil
}

// writePrivateFile atomically replaces path with an owner-private file.
func writePrivateFile(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".out-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func readSignedAction(path string) (*nativev1.SignedNativeActionV1, error) {
	raw, err := readBoundedRegular(path, false)
	if err != nil {
		return nil, err
	}
	var result nativev1.SignedNativeActionV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &result); err != nil ||
		result.Action == nil || len(result.AuthoritySignatures) == 0 || len(result.AuthoritySignatures) > nativecore.MaxSignatures {
		return nil, errors.New("invalid signed Capability action")
	}
	return &result, nil
}

func readToken(path string) (string, error) {
	raw, err := readBoundedRegular(path, true)
	value := strings.TrimSpace(string(raw))
	if err != nil || value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid private Gateway bearer token")
	}
	return value, nil
}

func readBoundedRegular(path string, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("publication input path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxPublicationFile ||
		(private && (info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info))) {
		return nil, errors.New("publication input must be a bounded regular file")
	}
	return os.ReadFile(path)
}

func nonce(value string) ([]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || value != strings.ToLower(value) || bytes.Equal(raw, make([]byte, 32)) {
		return nil, errors.New("publication nonces must be nonzero canonical 32-byte hex")
	}
	return raw, nil
}

func canonicalAgent(value string) bool {
	if len(value) != len("agent_")+64 || !strings.HasPrefix(value, "agent_") || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "agent_"))
	return err == nil
}
