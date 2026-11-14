// Command service-actor-e2e-fixture prepares the provider-side inputs of the
// local Service Actor buyer acceptance run: the canonical software-work
// manifest naming the actor in key 21, the NSM1 metadata hash the actor must
// carry, a code hash of a code BOC, a Quote Proposal package built by
// pkg/quoteprovider from finalized chain state, and the attestor's check of a
// software-work Receipt before it signs the response. It is a local stand-in
// for a provider's manifest store, quote endpoint and attestor policy; it
// holds no authority and sends nothing.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/tosnetwork/tos-service-protocol/internal/servicefixture"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteprovider"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "service-actor-e2e-fixture:", err)
		os.Exit(1)
	}
}

func run(arguments []string, out io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: service-actor-e2e-fixture <code-hash|manifest|metadata|quote|receipt-check> [flags]")
	}
	set := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	var bocPath, actor, codeHash, attestor, version, outDir, networkPath, capabilityID, providerID, digest string
	var rpc, registryBOC, registryHash, stateDir, manifestPath, buyer, outPath string
	var toolchain, invocationArgs string
	var receipt ReceiptExpectation
	set.StringVar(&bocPath, "boc-file", "", "file holding a base64 cell BOC")
	set.StringVar(&actor, "actor", "", "raw workchain 0 Service Actor address")
	set.StringVar(&codeHash, "code-hash", "", "tvm-cell-sha256:<hex> actor code hash")
	set.StringVar(&attestor, "attestor", "", "mldsa44:<key id> attestor")
	set.StringVar(&version, "version", "1.0.0", "Capability version")
	set.StringVar(&outDir, "out-dir", "", "manifest directory (<sha256 hex>.cbor)")
	set.StringVar(&networkPath, "network-domain", "", "network domain JSON file")
	set.StringVar(&capabilityID, "capability-id", "", "Capability ID")
	set.StringVar(&providerID, "provider-agent-id", "", "provider Agent ID")
	set.StringVar(&digest, "manifest-digest", "", "sha256:<hex> manifest digest")
	set.StringVar(&rpc, "rpc", "", "comma-separated JSON-RPC endpoints")
	set.StringVar(&registryBOC, "registry-code-boc", "", "Native Registry code BOC file")
	set.StringVar(&registryHash, "registry-code-hash", "", "Native Registry code hash")
	set.StringVar(&stateDir, "state-dir", "", "owner-private checkpoint directory")
	set.StringVar(&manifestPath, "manifest", "", "canonical manifest CBOR file")
	set.StringVar(&buyer, "buyer-wallet", "", "raw buyer wallet address")
	set.StringVar(&outPath, "out", "", "output file for the Quote package (protojson)")
	set.StringVar(&toolchain, "toolchain-digest", "", "manifest, receipt-check: sha256:<hex> toolchain image digest the executor pins (manifest default: a placeholder)")
	set.StringVar(&invocationArgs, "invocation-args", "", "manifest: space-separated invocation arguments the executor runs (default: the fixture's)")
	receipt.addFlags(set)
	if err := set.Parse(arguments[1:]); err != nil {
		return err
	}
	switch arguments[0] {
	case "code-hash":
		raw, err := os.ReadFile(bocPath)
		if err != nil {
			return err
		}
		boc, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
		if err != nil {
			return err
		}
		root, err := cell.FromBOC(boc)
		if err != nil {
			return err
		}
		return emit(out, map[string]string{"code_hash": "tvm-cell-sha256:" + hex.EncodeToString(root.Hash())})
	case "manifest":
		account, err := hex.DecodeString(strings.TrimPrefix(actor, "0:"))
		if err != nil || len(account) != 32 || !strings.HasPrefix(actor, "0:") {
			return errors.New("--actor must be 0:<hex>")
		}
		code, err := hex.DecodeString(strings.TrimPrefix(codeHash, "tvm-cell-sha256:"))
		if err != nil || len(code) != 32 {
			return errors.New("--code-hash must be tvm-cell-sha256:<hex>")
		}
		manifest := servicefixture.Manifest(version, servicefixture.Settlement{ActorAccount: account, ActorCodeHash: code, AttestorKey: attestor})
		if toolchain != "" {
			manifest.ToolchainDigest = toolchain
		}
		if invocationArgs != "" {
			manifest.Invocation.Arguments = strings.Fields(invocationArgs)
		}
		encoded, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
		if err != nil {
			return err
		}
		path := filepath.Join(outDir, strings.TrimPrefix(manifestDigest, "sha256:")+".cbor")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			return err
		}
		return emit(out, map[string]string{"manifest_digest": manifestDigest, "path": path})
	case "metadata":
		network, err := readNetwork(networkPath)
		if err != nil {
			return err
		}
		hash, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
			CapabilityID: capabilityID, ProviderAgentID: providerID, CapabilityVersion: version, ManifestDigest: digest})
		if err != nil {
			return err
		}
		return emit(out, map[string]string{"metadata_hash": hex.EncodeToString(hash[:]),
			"proof_scheme_hash": hex.EncodeToString(nativecore.ServiceActorSoftwareWorkProofScheme[:])})
	case "quote":
		network, err := readNetwork(networkPath)
		if err != nil {
			return err
		}
		reader, err := openReader(network, rpc, registryBOC, registryHash, codeHash, stateDir)
		if err != nil {
			return err
		}
		manifest, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		provider, err := quoteprovider.New(quoteprovider.Config{Sessions: quoteprovider.FromChain(reader), Network: network,
			RegistryCodeHash: registryHash, ProviderAgentID: providerID, ManifestCBOR: manifest,
			Transport: nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20,
				BaseURL: "https://provider.local.invalid"}, CallerID: "service-actor-e2e"})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		value, err := provider.RequestQuoteProposal(ctx, &nativev1.RequestQuoteProposalRequest{
			Context:      &nativev1.RequestContext{RequestId: fmt.Sprintf("e2e-%d", time.Now().UnixNano()), CallerId: "service-actor-e2e"},
			CapabilityId: capabilityID, CapabilityVersion: version, BuyerAddress: buyer})
		if err != nil {
			return err
		}
		encoded, err := protojson.Marshal(value)
		if err != nil {
			return err
		}
		if err := os.WriteFile(outPath, encoded, 0o600); err != nil {
			return err
		}
		return emit(out, map[string]any{"package": outPath, "terms_hash": value.Proposal.TermsHash,
			"price_nanotos": value.Proposal.PriceNanotos, "expires_at": value.Proposal.ExpiresAtUnixSeconds})
	case "receipt-check":
		receipt.providerAgentID, receipt.toolchainDigest, receipt.manifestDigest = providerID, toolchain, digest
		checked, err := receipt.check()
		if err != nil {
			return err
		}
		return emit(out, checked)
	default:
		return errors.New("unknown fixture command")
	}
}

func openReader(network *nativev1.NetworkDomain, rpc, registryBOC, registryHash, actorCodeHash, stateDir string) (*toschain.ServiceActorReader, error) {
	endpoints := strings.Split(rpc, ",")
	chain, err := toschain.New(toschain.Config{Network: network.NetworkId, Endpoints: endpoints, Quorum: len(endpoints)/2 + 1})
	if err != nil {
		return nil, err
	}
	code, err := os.ReadFile(registryBOC)
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(network, 0, strings.Join(strings.Fields(string(code)), ""), registryHash)
	if err != nil {
		return nil, err
	}
	registry, err := toschain.NewSimplifiedNativeResolver(chain, locator, filepath.Join(stateDir, "registry.checkpoint"))
	if err != nil {
		return nil, err
	}
	return toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{Chain: chain, Network: network, ActorCodeHash: actorCodeHash,
		Registry: registry, CheckpointPath: filepath.Join(stateDir, "service-actor.checkpoint")})
}

func readNetwork(path string) (*nativev1.NetworkDomain, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var domain struct {
		NetworkID       string `json:"network_id"`
		GenesisRootHash string `json:"genesis_root_hash"`
		GenesisFileHash string `json:"genesis_file_hash"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&domain); err != nil {
		return nil, err
	}
	return &nativev1.NetworkDomain{NetworkId: domain.NetworkID, GenesisRootHash: domain.GenesisRootHash, GenesisFileHash: domain.GenesisFileHash}, nil
}

func emit(out io.Writer, value any) error {
	return json.NewEncoder(out).Encode(value)
}
