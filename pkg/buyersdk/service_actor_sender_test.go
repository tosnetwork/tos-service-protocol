package buyersdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

type vetter struct {
	endpoints []string
	bad       map[string]bool
}

func (v vetter) Endpoints() []string { return v.endpoints }
func (v vetter) CheckEndpointGenesis(_ context.Context, endpoint string) error {
	if v.bad[endpoint] {
		return errors.New("genesis differs")
	}
	return nil
}

func testIntent() ServiceActorCallIntent {
	return ServiceActorCallIntent{Actor: saActor, BuyerWallet: saBuyer, QueryID: 7, RequestHash: digest32(4),
		ExpectedTermsHash: digest32(5), Price: big.NewInt(300_000_000), StorageFee: big.NewInt(200_000_000)}
}

func preparedOutput(t *testing.T, payer, destination string, amount uint64, intent ServiceActorCallIntent) []byte {
	t.Helper()
	body := nativecore.BuildServiceActorCallBody(intent.QueryID, intent.RequestHash, intent.ExpectedTermsHash)
	raw, err := json.Marshal(map[string]any{"version": "tosctl.wallet-prepared-send.v1", "wallet": "buyer", "payer": payer,
		"destination": destination, "amount_nanotos": amount, "body_hash": cellHash(body), "state_init_hash": "", "message_boc_base64": "te6c"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testSender(t *testing.T, config string, endpoints vetter, output []byte) (*TOSCTLServiceActorSender, *[][]string) {
	t.Helper()
	calls := &[][]string{}
	sender := &TOSCTLServiceActorSender{wallet: "buyer", runner: &execRunner{config: []byte(config)}, endpoints: endpoints}
	sender.run = func(_ context.Context, args ...string) ([]byte, error) {
		*calls = append(*calls, args)
		return output, nil
	}
	sender.runWithPath = func(_ context.Context, args ...string) ([]byte, error) {
		*calls = append(*calls, args)
		return []byte("Terms committed to: ...\nOK Service Actor call message submitted to " + saActor + "\n"), nil
	}
	return sender, calls
}

const validConfig = `{"chain_rpc":{"urls":["https://a.example", {"url":" https://B.example:443/ ","api_key":"k"}],"url":"https://c.example"}}`

func TestSenderPreflightBindsWalletNetworkAndAmount(t *testing.T) {
	intent := testIntent()
	good := vetter{endpoints: []string{"https://a.example/jsonRPC", "https://b.example/jsonRPC", "https://c.example/jsonRPC"}}
	output := preparedOutput(t, saBuyer, saActor, 700_000_000, intent)
	sender, calls := testSender(t, validConfig, good, output)
	if err := sender.Preflight(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	args := strings.Join((*calls)[0], " ")
	if !strings.HasPrefix(args, "wallet send --from buyer --to "+saActor+" --amount-nanotos 700000000 --body-boc ") ||
		!strings.HasSuffix(args, " --build-only") {
		t.Fatalf("binding check argv = %s", args)
	}
	for name, test := range map[string]struct {
		config  string
		vetter  vetter
		output  []byte
		intent  ServiceActorCallIntent
		wantErr error
	}{
		"other payer":           {validConfig, good, preparedOutput(t, saOwner, saActor, 700_000_000, intent), intent, nil},
		"other destination":     {validConfig, good, preparedOutput(t, saBuyer, saOwner, 700_000_000, intent), intent, nil},
		"other amount":          {validConfig, good, preparedOutput(t, saBuyer, saActor, 700_000_001, intent), intent, nil},
		"other body":            {validConfig, good, preparedOutput(t, saBuyer, saActor, 700_000_000, func() ServiceActorCallIntent { i := intent; i.QueryID = 8; return i }()), intent, nil},
		"foreign endpoint":      {validConfig, vetter{endpoints: []string{"https://a.example/jsonRPC", "https://b.example/jsonRPC"}}, output, intent, nil},
		"wrong genesis":         {validConfig, vetter{endpoints: good.endpoints, bad: map[string]bool{"https://b.example/jsonRPC": true}}, output, intent, nil},
		"no chain_rpc":          {`{"wallets":{}}`, good, output, intent, nil},
		"key case differential": {`{"chain_rpc":{"urls":["https://foreign.example"],"URLS":["https://a.example"]}}`, good, output, intent, nil},
		"empty endpoints":       {`{"chain_rpc":{"urls":["  "],"url":""}}`, good, output, intent, nil},
		"price beyond 64 bits":  {validConfig, good, output, func() ServiceActorCallIntent { i := intent; i.Price = new(big.Int).Lsh(big.NewInt(1), 64); return i }(), ErrUnsupportedAmount},
		"payment beyond 64 bit": {validConfig, good, output, func() ServiceActorCallIntent { i := intent; i.Price = new(big.Int).SetUint64(^uint64(0) - 1); return i }(), ErrUnsupportedAmount},
	} {
		sender, _ := testSender(t, test.config, test.vetter, test.output)
		err := sender.Preflight(context.Background(), test.intent)
		if err == nil || test.wantErr != nil && !errors.Is(err, test.wantErr) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEffectiveEndpointsMirrorTheCustodyResolution(t *testing.T) {
	endpoints, err := effectiveChainEndpoints([]byte(validConfig))
	if err != nil || strings.Join(endpoints, ",") != "https://c.example/jsonRPC,https://a.example/jsonRPC,https://b.example/jsonRPC" {
		t.Fatalf("endpoints = %v %v", endpoints, err)
	}
	duplicate, err := effectiveChainEndpoints([]byte(`{"chain_rpc":{"urls":["https://a.example","https://a.example "]}}`))
	if err != nil || len(duplicate) != 1 {
		t.Fatalf("duplicates = %v %v", duplicate, err)
	}
	for name, config := range map[string]string{
		"malformed entry":       `{"chain_rpc":{"urls":[7]}}`,
		"key case differential": `{"chain_rpc":{"urls":["https://foreign.example"],"URLS":["https://a.example"]}}`,
		"duplicate urls":        `{"chain_rpc":{"urls":["https://a.example"],"urls":["https://foreign.example"]}}`,
		"duplicate chain_rpc":   `{"chain_rpc":{"urls":["https://a.example"]},"chain_rpc":{"urls":["https://foreign.example"]}}`,
		"object without key":    `{"chain_rpc":{"urls":[{"url":"https://a.example"}]}}`,
		"null urls":             `{"chain_rpc":{"urls":null}}`,
		"upper-case only":       `{"chain_rpc":{"URLS":["https://a.example"]}}`,
	} {
		endpoints, err := effectiveChainEndpoints([]byte(config))
		if name == "key case differential" {
			// tosctl ignores URLS and submits through the foreign endpoint;
			// the preflight must see exactly that.
			if err != nil || len(endpoints) != 1 || endpoints[0] != "https://foreign.example/jsonRPC" {
				t.Errorf("%s: %v %v", name, endpoints, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s was accepted: %v", name, endpoints)
		}
	}
}

func TestSendCallPassesTheQuotedTermsHash(t *testing.T) {
	sender, calls := testSender(t, validConfig, vetter{}, nil)
	intent := testIntent()
	if err := sender.SendCall(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("agent service send --operation call --address %s --from buyer --query-id 7 --request-hash %s --expected-terms-hash %s --yes",
		saActor, strings.Repeat("04", 32), strings.Repeat("05", 32))
	if got := strings.Join((*calls)[0], " "); got != want {
		t.Fatalf("argv\n got %s\nwant %s", got, want)
	}
	silent, _ := testSender(t, validConfig, vetter{}, nil)
	silent.runWithPath = func(context.Context, ...string) ([]byte, error) { return []byte("nothing"), nil }
	if err := silent.SendCall(context.Background(), intent); err == nil || errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("an unreported submission was not ambiguous: %v", err)
	}
	failed, _ := testSender(t, validConfig, vetter{}, nil)
	failed.runWithPath = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("exit status 1") }
	if err := failed.SendCall(context.Background(), intent); err == nil || errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("a failed tosctl run was not ambiguous: %v", err)
	}
}

// The runner writes the pinned configuration to a private .json path,
// passes it with -c, and removes it afterwards.
func TestConfigPathRunnerUsesAPrivateCopy(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "tosctl")
	config := filepath.Join(directory, "config.json")
	script := "#!/bin/sh\nfor last; do :; done\nstat -c '%a' \"$last\"\ncat \"$last\"\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"chain_rpc":{"urls":["https://a.example"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := newPinnedExecRunner(binary, config)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runner.runWithConfigPath(context.Background(), binary, "agent", "service")
	if err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	if !strings.HasPrefix(string(output), "600\n") || !strings.Contains(string(output), "https://a.example") {
		t.Fatalf("output = %q", output)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.runWithConfigPath(context.Background(), binary, "agent"); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("a substituted executable was started: %v", err)
	}
}
