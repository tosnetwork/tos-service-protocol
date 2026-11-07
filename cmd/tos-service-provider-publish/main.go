// Command tos-service-provider-publish turns a reviewed provider Capability
// action into finalized Native state and then publishes its immutable manifest
// to the derived Gateway catalog. Private controller keys remain in
// tos-service-wallet/tosctl custody; this command accepts only the signed action.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
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
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const maxPublicationFile = 1 << 20

type options struct {
	gateway, tokenPath, caller, caFile, serverName         string
	network, genesisRoot, genesisFile, registryHash, owner string
	manifestPath, objectNonce, actionNonce, signedAction   string
	capabilityRetry, manifestRetry                         string
	tosctl, tosctlSHA256                                   string
	insecure                                               bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tos-service-provider-publish:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 || (arguments[0] != "prepare" && arguments[0] != "apply") {
		return errors.New("usage: tos-service-provider-publish <prepare|apply> [flags]")
	}
	mode := arguments[0]
	set := flag.NewFlagSet(mode, flag.ContinueOnError)
	var value options
	set.StringVar(&value.gateway, "gateway", "", "Native Gateway base URL")
	set.StringVar(&value.tokenPath, "token-file", "", "owner-private Gateway bearer token")
	set.StringVar(&value.caller, "caller-id", "", "bounded provider caller identity")
	set.StringVar(&value.caFile, "ca-file", "", "optional private Gateway CA")
	set.StringVar(&value.serverName, "server-name", "", "optional Gateway TLS server name")
	set.BoolVar(&value.insecure, "insecure", false, "allow loopback plaintext Gateway")
	set.StringVar(&value.network, "network-id", "", "TOS network ID")
	set.StringVar(&value.genesisRoot, "genesis-root", "", "network genesis root hash")
	set.StringVar(&value.genesisFile, "genesis-file", "", "network genesis file hash")
	set.StringVar(&value.registryHash, "registry-code-hash", "", "frozen Registry TVM digest")
	set.StringVar(&value.owner, "owner-agent-id", "", "finalized provider AgentID")
	set.StringVar(&value.manifestPath, "manifest-json", "", "reviewed software-work manifest JSON")
	set.StringVar(&value.objectNonce, "object-nonce", "", "retained nonzero 32-byte hex Capability nonce")
	set.StringVar(&value.actionNonce, "action-nonce", "", "retained nonzero 32-byte hex action nonce")
	set.StringVar(&value.signedAction, "signed-action", "", "tos-service-wallet SignedNativeActionV1 JSON")
	set.StringVar(&value.capabilityRetry, "capability-idempotency-key", "", "durable Capability publication retry key")
	set.StringVar(&value.manifestRetry, "manifest-idempotency-key", "", "durable manifest publication retry key")
	set.StringVar(&value.tosctl, "tosctl", "", "absolute path of the tosctl binary that verifies ML-DSA-44 signatures")
	set.StringVar(&value.tosctlSHA256, "tosctl-sha256", "", "lowercase hex SHA-256 of that tosctl binary")
	if err := set.Parse(arguments[1:]); err != nil {
		return err
	}
	if set.NArg() != 0 || value.gateway == "" || value.caller == "" || value.network == "" ||
		value.genesisRoot == "" || value.genesisFile == "" || value.registryHash == "" ||
		!canonicalAgent(value.owner) || value.manifestPath == "" {
		return errors.New("provider publication configuration is incomplete")
	}
	objectNonce, err := nonce(value.objectNonce)
	if err != nil {
		return err
	}
	actionNonce, err := nonce(value.actionNonce)
	if err != nil {
		return err
	}
	manifest, err := readBoundedRegular(value.manifestPath, false)
	if err != nil {
		return err
	}
	token, err := readToken(value.tokenPath)
	if err != nil {
		return err
	}
	client, err := nativeclient.New(nativeclient.Config{BaseURL: value.gateway, BearerToken: token,
		Insecure: value.insecure, CAFile: value.caFile, ServerName: value.serverName, Timeout: 45 * time.Second})
	if err != nil {
		return err
	}
	defer client.Close()
	// Controller signatures are verified against the finalized owner policy
	// before anything is relayed; the helper only verifies here, it holds no
	// keys for this command.
	verifier, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: value.tosctl, SHA256: value.tosctlSHA256})
	if err != nil {
		return err
	}
	network := &nativev1.NetworkDomain{NetworkId: value.network, GenesisRootHash: value.genesisRoot, GenesisFileHash: value.genesisFile}
	provider, err := providersdk.New(providersdk.Config{Client: client, Verifier: verifier, Network: network,
		RegistryCodeHash: value.registryHash, CallerID: value.caller, PollInterval: time.Second, FinalityTimeout: 10 * time.Minute})
	if err != nil {
		return err
	}
	prepared, err := provider.PrepareCapabilityPublication(manifest, value.owner, objectNonce, actionNonce)
	if err != nil {
		return err
	}
	if mode == "prepare" {
		raw, err := (protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}).Marshal(prepared.Action)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "capability_id=%s manifest_digest=%s action_hash=%s\n", prepared.CapabilityID, prepared.ManifestDigest, prepared.ActionHash)
		_, err = os.Stdout.Write(append(raw, '\n'))
		return err
	}
	if value.signedAction == "" || !boundedKey(value.capabilityRetry) || !boundedKey(value.manifestRetry) ||
		value.capabilityRetry == value.manifestRetry {
		return errors.New("apply requires a signed action and two distinct bounded retry keys")
	}
	signed, err := readSignedAction(value.signedAction)
	if err != nil {
		return err
	}
	if !proto.Equal(signed.Action, prepared.Action) || len(signed.CounterpartySignatures) != 0 {
		return errors.New("signed Capability action differs from deterministic reviewed publication")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	state, err := provider.PublishCapability(ctx, prepared, signed.AuthoritySignatures, value.capabilityRetry)
	if err != nil {
		return err
	}
	catalogState, err := provider.PublishManifest(ctx, prepared, value.manifestRetry)
	if err != nil {
		return err
	}
	if !proto.Equal(state, catalogState) {
		return errors.New("Gateway catalog admission returned different finalized Capability state")
	}
	fmt.Printf("PASS capability_id=%s manifest_digest=%s finalized_checkpoint=%d\n",
		prepared.CapabilityID, prepared.ManifestDigest, state.GetReference().GetFinalizedCheckpoint())
	return nil
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

func boundedKey(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
