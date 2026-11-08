// Command agent-commerce-carrier-campaign drives the released HTTP Carrier
// contract without importing either Carrier implementation.  It is used by
// source-loss acceptance tests to prove that exact signed bytes remain
// discoverable after one independent store is removed.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// authorityCustody names the ML-DSA-44 Action Authority controller that the
// pinned tosctl helper holds in its vault. The campaign never sees its key.
type authorityCustody struct {
	binary, sha256, configPath, vaultURLPath, controller string
}

func (custody authorityCustody) signer() (*mldsa44.Tosctl, error) {
	if custody.controller == "" {
		return nil, errors.New("the Action Authority controller is not configured")
	}
	vaultURL, err := readText(custody.vaultURLPath, 4096)
	if err != nil {
		return nil, fmt.Errorf("Action Authority vault URL: %w", err)
	}
	signer, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: custody.binary, SHA256: custody.sha256,
		ConfigPath: custody.configPath, VaultURL: strings.TrimSpace(vaultURL)})
	if err != nil {
		return nil, err
	}
	return signer, nil
}

type carriersFlag []carrierConfig
type carrierConfig struct{ id, endpoint, readTokenPath, writeTokenPath string }

func (values *carriersFlag) String() string { return fmt.Sprintf("%d configured", len(*values)) }
func (values *carriersFlag) Set(value string) error {
	parts := strings.Split(value, ",")
	if len(parts) != 4 || parts[0] == "" {
		return errors.New("carrier must be ID,ENDPOINT,READ_TOKEN_FILE,WRITE_TOKEN_FILE")
	}
	*values = append(*values, carrierConfig{parts[0], strings.TrimRight(parts[1], "/"), parts[2], parts[3]})
	return nil
}

func main() {
	initDir := flag.String("init-dir", "", "create campaign keys in an absolute private directory and exit")
	custody := authorityCustody{}
	flag.StringVar(&custody.binary, "tosctl", "", "absolute path of the pinned tosctl helper that holds the Action Authority key")
	flag.StringVar(&custody.sha256, "tosctl-sha256", "", "lowercase hex SHA-256 of the tosctl helper")
	flag.StringVar(&custody.configPath, "tosctl-config", "", "absolute tosctl configuration path")
	flag.StringVar(&custody.vaultURLPath, "vault-url-file", "", "absolute path of a file holding the tosctl vault URL")
	flag.StringVar(&custody.controller, "authority-controller", "", "the vault controller name of the Action Authority")
	issuerPath := flag.String("issuer-key", "", "absolute campaign issuer key path")
	digestPath := flag.String("digest-file", "", "absolute expected Intent digest file")
	verifyOnly := flag.Bool("verify-only", false, "only verify the retained digest on configured Carriers")
	carriers := carriersFlag{}
	flag.Var(&carriers, "carrier", "ID,ENDPOINT,READ_TOKEN_FILE,WRITE_TOKEN_FILE (repeat)")
	flag.Parse()
	if *initDir != "" {
		if err := initialize(*initDir); err != nil {
			fatal(err)
		}
		return
	}
	if err := run(custody, *issuerPath, *digestPath, carriers, *verifyOnly); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "agent-commerce-carrier-campaign:", err)
	os.Exit(1)
}

func initialize(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("init directory must be canonical and absolute")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	_, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeExclusiveKey(filepath.Join(directory, "issuer.key"), issuer); err != nil {
		return err
	}
	readToken := make([]byte, 32)
	writeToken := make([]byte, 32)
	if _, err := rand.Read(readToken); err != nil {
		return err
	}
	if _, err := rand.Read(writeToken); err != nil {
		return err
	}
	if err := writeExclusiveText(filepath.Join(directory, "read.token"), hex.EncodeToString(readToken)); err != nil {
		return err
	}
	if err := writeExclusiveText(filepath.Join(directory, "write.token"), hex.EncodeToString(writeToken)); err != nil {
		return err
	}
	// The Action Authority is an ML-DSA-44 controller in tosctl custody,
	// created with `tosctl agent native-registry new-controller`; its key ID
	// and key are published from there, never from this directory.
	fmt.Printf("authority_id=authority:carrier-campaign issuer_key=%s read_token=%s write_token=%s\n",
		filepath.Join(directory, "issuer.key"), filepath.Join(directory, "read.token"), filepath.Join(directory, "write.token"))
	return nil
}

func writeExclusiveKey(path string, key ed25519.PrivateKey) error {
	return writeExclusiveText(path, hex.EncodeToString(key))
}

func writeExclusiveText(path, value string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(value)
	return err
}

func run(custody authorityCustody, issuerPath, digestPath string, carriers []carrierConfig, verifyOnly bool) error {
	if len(carriers) == 0 || len(carriers) > 16 || !filepath.IsAbs(digestPath) {
		return errors.New("campaign configuration is incomplete or unbounded")
	}
	seen := map[string]bool{}
	for _, carrier := range carriers {
		if seen[carrier.id] {
			return errors.New("duplicate Carrier ID")
		}
		seen[carrier.id] = true
	}
	if verifyOnly {
		digest, err := readText(digestPath, 256)
		if err != nil || !strings.HasPrefix(digest, "sha256:") {
			return errors.New("expected digest is unavailable")
		}
		return verifyCarriers(carriers, digest)
	}
	authority, err := custody.signer()
	if err != nil {
		return err
	}
	issuer, err := readPrivateKey(issuerPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	intent, err := campaignIntent(now, issuer)
	if err != nil {
		return err
	}
	digest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil {
		return err
	}
	fence, err := commerce.SignWriterFence(context.Background(), commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:carrier-campaign",
		AgentID: intent.Body.IssuerAgentID, InstanceID: "instance:carrier-campaign", LeaseID: "lease:carrier-campaign",
		WriterGeneration: 1, IssuedAtUnix: uint64(now.Add(-time.Second).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		AuthorityID: "authority:carrier-campaign", Scope: []string{"publication.publish"}}, authority, custody.controller)
	if err != nil {
		return err
	}
	for _, carrier := range carriers {
		if err := publish(carrier, intent, fence, authority, custody.controller, now); err != nil {
			return fmt.Errorf("%s: %w", carrier.id, err)
		}
	}
	if err := writeAtomicText(digestPath, digest); err != nil {
		return err
	}
	if err := verifyCarriers(carriers, digest); err != nil {
		return err
	}
	fmt.Printf("published=true intent_digest=%s independent_carriers=%d\n", digest, len(carriers))
	return nil
}

func publish(carrier carrierConfig, intent commerce.SignedAgentIntent, fence commerce.WriterFence,
	authority mldsa44.Signer, controller string, now time.Time) error {
	exact, err := codec.Marshal(intent)
	if err != nil {
		return err
	}
	writeToken, err := readText(carrier.writeTokenPath, 8192)
	if err != nil {
		return err
	}
	challengeURL := fmt.Sprintf("%s/v1/intents/admission-challenge?actor_id=%s&audience=%s&declared_bytes=%d&operation_kind=publication.publish",
		carrier.endpoint, url.QueryEscape(intent.Body.IssuerAgentID), url.QueryEscape(intent.Body.Audience), len(exact))
	var challenge commerce.SignedOperationAdmissionChallenge
	if err := requestJSON(http.MethodPost, challengeURL, writeToken, nil, &challenge); err != nil {
		return err
	}
	if challenge.Body.CarrierID != carrier.id {
		return errors.New("admission challenge came from a different Carrier")
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		return err
	}
	operationDigest, err := codec.Digest("tos.agent-intent-publication-operation.v1", intent)
	if err != nil {
		return err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:carrier-campaign"),
		"agent_id": commerce.ID(intent.Body.IssuerAgentID), "carrier_id": commerce.ID(carrier.id),
		"intent_object_id": commerce.ID(intent.Body.ObjectID), "revision": commerce.U64(intent.Body.Revision),
		"operation_digest": commerce.Digest32(operationDigest)}
	action, err := commerce.BuildAuthorizedAction("owner:carrier-campaign", intent.Body.IssuerAgentID, "publication.publish",
		fields, exact, fence, 1, "sha256:"+strings.Repeat("1", 64), "", "not-published", uint64(now.Add(time.Hour).Unix()))
	if err == nil {
		action, err = commerce.SignAuthorizedAction(context.Background(), action, fence.KeyID, authority, controller)
	}
	if err != nil {
		return err
	}
	body := struct {
		Intent    commerce.SignedAgentIntent       `json:"intent"`
		Admission commerce.OperationAdmissionProof `json:"admission"`
		Action    commerce.AuthorizedAction        `json:"authorized_action"`
		Fence     commerce.WriterFence             `json:"writer_fence"`
	}{intent, proof, action, fence}
	var response struct {
		Result     json.RawMessage           `json:"result"`
		Resolution commerce.ActionResolution `json:"action_resolution"`
	}
	if err := requestJSON(http.MethodPost, carrier.endpoint+"/v1/intents", writeToken, body, &response); err != nil {
		return err
	}
	if response.Resolution.State != commerce.ActionTerminal && response.Resolution.State != commerce.ActionAccepted {
		return fmt.Errorf("publication did not become durably accepted: %s", response.Resolution.State)
	}
	return nil
}

func verifyCarriers(carriers []carrierConfig, digest string) error {
	for _, carrier := range carriers {
		readToken, err := readText(carrier.readTokenPath, 8192)
		if err != nil {
			return err
		}
		var page struct {
			CarrierID string `json:"carrier_id"`
			Results   []struct {
				IntentDigest       string                     `json:"intent_digest"`
				Intent             commerce.SignedAgentIntent `json:"intent"`
				AuthorizationLevel string                     `json:"authorization_level"`
				StoredAtUnix       uint64                     `json:"stored_at_unix"`
				CarrierSequence    uint64                     `json:"carrier_sequence"`
			} `json:"results"`
			Operations []json.RawMessage `json:"operations"`
			Next       string            `json:"next_cursor"`
		}
		if err := requestJSON(http.MethodGet, carrier.endpoint+"/v1/intents?limit=10&keyword=review", readToken, nil, &page); err != nil {
			return fmt.Errorf("%s search: %w", carrier.id, err)
		}
		found := false
		for _, result := range page.Results {
			computed, digestErr := commerce.IntentBodyDigest(result.Intent.Body)
			found = found || digestErr == nil && computed == digest && result.IntentDigest == digest
		}
		if page.CarrierID != carrier.id || !found {
			return fmt.Errorf("%s did not independently return exact signed bytes", carrier.id)
		}
	}
	fmt.Printf("verified=true intent_digest=%s carriers=%d\n", digest, len(carriers))
	return nil
}

func campaignIntent(now time.Time, issuer ed25519.PrivateKey) (commerce.SignedAgentIntent, error) {
	detail := []byte("review one bounded source tree")
	detailDigest := sha256.Sum256(detail)
	issuerPublic := issuer.Public().(ed25519.PublicKey)
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:local-three-validator", IssuerAgentID: "agent:" + hex.EncodeToString(issuerPublic),
		Audience: "public:indexable", ObjectID: "intent:" + hex.EncodeToString(detailDigest[:]), Revision: 1,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{
			Summary: "Review source", IntentModes: []commerce.IntentMode{commerce.IntentRequest}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
			TaxonomyPaths: []string{"tos.taxonomy.v1/service/security/review"}, Keywords: []commerce.IntentKeyword{{Text: "review", Language: "en"}},
			ValueState: commerce.ValueSpecified, ValueHints: []commerce.ValueHint{{Role: "budget", AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountKind: "exact", MinimumDecimal: "50", MaximumDecimal: "50", Unit: "total"}},
			Schedule: commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(detailDigest[:]), ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes:      []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: "agent:" + hex.EncodeToString(issuerPublic)}}}}
	return commerce.SignIntent(body, issuer)
}

func requestJSON(method, endpoint, token string, input, output any) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("Carrier endpoint is invalid")
	}
	if parsed.Scheme == "http" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		return errors.New("plaintext Carrier endpoint is not loopback")
	}
	var body io.Reader
	if input != nil {
		raw, marshalErr := json.Marshal(input)
		if marshalErr != nil || len(raw) > 3<<20 {
			return errors.New("Carrier request is invalid")
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, endpoint, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, DisableCompression: true}}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 4<<20)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(limited, 4096))
		return fmt.Errorf("Carrier HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(raw)))
	}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	text, err := readText(path, 256)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("private key is invalid")
	}
	return ed25519.PrivateKey(raw), nil
}

func readText(path string, maximum int64) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("input path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximum {
		return "", errors.New("input must be a bounded mode-0600 regular file")
	}
	raw, err := os.ReadFile(path)
	return strings.TrimSpace(string(raw)), err
}

func writeAtomicText(path, value string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".campaign-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err = temporary.WriteString(value + "\n"); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
