package buyersdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestPaidDemandDeployerManualBroadcastAcknowledgementIsExplicit(t *testing.T) {
	deployer := &TOSCTLPaidDemandEscrowDeployer{config: "/private/config.json"}
	arguments := deployer.broadcastArguments("message-boc")
	if slices.Contains(arguments, "--acknowledge-unpinned-manual-broadcast") {
		t.Fatal("default Paid Demand deployment acknowledged an unpinned manual broadcast")
	}

	deployer.acknowledgeUnpinnedManualBroadcast = true
	arguments = deployer.broadcastArguments("message-boc")
	if !slices.Contains(arguments, "--acknowledge-unpinned-manual-broadcast") {
		t.Fatal("explicit test/operator acknowledgement was not forwarded to tosctl")
	}
}

type paidDeployRunnerFake struct {
	purchase *PreparedPaidDemandPurchase
	deployer *TOSCTLPaidDemandEscrowDeployer
	conflict bool
	calls    [][]string
}

func (f *paidDeployRunnerFake) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	message := cell.BeginCell().EndCell()
	if len(f.calls) == 1 {
		_, stateHash, _ := decodeStateInit(f.purchase.Escrow.StateInitBOC)
		if f.conflict {
			stateHash = "tvm-cell-sha256:" + strings.Repeat("a", 64)
		}
		return json.Marshal(map[string]any{
			"version": "tosctl.wallet-prepared-send.v1", "message_boc_base64": base64BOC(message),
			"wallet": f.deployer.wallet, "payer": f.deployer.relayer,
			"destination": f.purchase.Escrow.Address, "amount_nanotos": f.deployer.attached,
			"body_hash": cellHash(cell.BeginCell().EndCell()), "state_init_hash": stateHash,
		})
	}
	return json.Marshal(map[string]any{"version": "tosctl.wallet-prepared-broadcast.v1",
		"message_hash": cellHash(message), "status": "submitted"})
}

func testPaidDemandDeployment(t *testing.T) (*TOSCTLPaidDemandEscrowDeployer, *PreparedPaidDemandPurchase) {
	t.Helper()
	fixture := newPaidDemandBuyerFixture(t)
	purchase, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	sender := testTOSCTLSender(t)
	deployer, err := NewTOSCTLPaidDemandEscrowDeployer(TOSCTLPaidDemandEscrowDeployerConfig{
		BinaryPath: sender.binary, ConfigPath: sender.config, WalletName: sender.wallet,
		RelayerAddress: "0:" + strings.Repeat("ab", 32), Timeout: time.Second,
		AcknowledgeNonProductionTestDeployment: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return deployer, purchase
}

func TestPaidDemandDeployerPreparesThenBroadcastsExactMessage(t *testing.T) {
	deployer, purchase := testPaidDemandDeployment(t)
	if purchase.Escrow.CodeHash != nativecore.EscrowV2CodeHash {
		t.Fatalf("purchase escrow runs code %s", purchase.Escrow.CodeHash)
	}
	fake := &paidDeployRunnerFake{purchase: purchase, deployer: deployer}
	deployer.runner = fake
	prepared, err := deployer.PreparePaidDemandDeployment(context.Background(), purchase)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.EscrowAddress != purchase.Escrow.Address || prepared.QuoteCommitment != purchase.QuoteCommitment ||
		prepared.StateInitBOCBase64 != purchase.Escrow.StateInitBOC {
		t.Fatalf("prepared deployment = %+v", prepared)
	}
	if !prepared.NonProduction {
		t.Fatal("the prepared deployment does not record the non-production acknowledgment")
	}
	evidence, err := json.Marshal(prepared)
	if err != nil || !strings.Contains(string(evidence), `"non_production":true`) {
		t.Fatalf("deployment evidence omits the acknowledgment: %s %v", evidence, err)
	}
	if err := deployer.BroadcastPaidDemandDeployment(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || fake.calls[0][len(fake.calls[0])-3] != "--build-only" ||
		fake.calls[1][1] != "broadcast-prepared" {
		t.Fatalf("calls = %v", fake.calls)
	}
}

func TestPaidDemandDeployerRejectsCustodyAndArtifactSubstitution(t *testing.T) {
	deployer, purchase := testPaidDemandDeployment(t)
	fake := &paidDeployRunnerFake{purchase: purchase, deployer: deployer, conflict: true}
	deployer.runner = fake
	if _, err := deployer.PreparePaidDemandDeployment(context.Background(), purchase); err == nil {
		t.Fatal("deployer accepted a substituted StateInit hash from custody")
	}
	fake.conflict = false
	fake.calls = nil
	prepared, err := deployer.PreparePaidDemandDeployment(context.Background(), purchase)
	if err != nil {
		t.Fatal(err)
	}
	prepared.EscrowAddress = "0:" + strings.Repeat("f", 64)
	if err := deployer.BroadcastPaidDemandDeployment(context.Background(), prepared); err == nil {
		t.Fatal("deployer broadcast a substituted deployment artifact")
	}
}

// Escrow v2 is an accepted risk only on test networks: without the operator's
// non-production acknowledgment nothing is prepared or broadcast, and a
// deployment prepared without it cannot be broadcast.
func TestPaidDemandDeployerRequiresTheNonProductionAcknowledgment(t *testing.T) {
	deployer, purchase := testPaidDemandDeployment(t)
	fake := &paidDeployRunnerFake{purchase: purchase, deployer: deployer}
	deployer.runner = fake
	prepared, err := deployer.PreparePaidDemandDeployment(context.Background(), purchase)
	if err != nil {
		t.Fatalf("positive control: acknowledged deployment refused: %v", err)
	}
	fake.calls = nil

	deployer.nonProduction = false
	if _, err := deployer.PreparePaidDemandDeployment(context.Background(), purchase); !errors.Is(err, errProductionEscrowDeployment) {
		t.Fatalf("prepared a deployment without the acknowledgment: %v", err)
	}
	if err := deployer.BroadcastPaidDemandDeployment(context.Background(), prepared); !errors.Is(err, errProductionEscrowDeployment) {
		t.Fatalf("broadcast a deployment without the acknowledgment: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("custody was reached without the acknowledgment: %v", fake.calls)
	}

	deployer.nonProduction = true
	unacknowledged := *prepared
	unacknowledged.NonProduction = false
	if err := deployer.BroadcastPaidDemandDeployment(context.Background(), &unacknowledged); !errors.Is(err, errProductionEscrowDeployment) {
		t.Fatalf("broadcast a deployment whose evidence lacks the acknowledgment: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("custody was reached for an unacknowledged deployment: %v", fake.calls)
	}
}

func TestPaidDemandDeployerAcknowledgmentDefaultsOff(t *testing.T) {
	sender := testTOSCTLSender(t)
	deployer, err := NewTOSCTLPaidDemandEscrowDeployer(TOSCTLPaidDemandEscrowDeployerConfig{
		BinaryPath: sender.binary, ConfigPath: sender.config, WalletName: sender.wallet,
		RelayerAddress: "0:" + strings.Repeat("ab", 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if deployer.nonProduction {
		t.Fatal("the non-production acknowledgment is on by default")
	}
	if _, err := deployer.PreparePaidDemandDeployment(context.Background(), nil); !errors.Is(err, errProductionEscrowDeployment) {
		t.Fatalf("a default deployer did not refuse: %v", err)
	}
}

// withCode returns the StateInit with its code replaced and the purchase
// identity rewritten to match, as a purchase built for other code would be.
func withCode(t *testing.T, purchase *PreparedPaidDemandPurchase, code *cell.Cell) *PreparedPaidDemandPurchase {
	t.Helper()
	stateInit, _, err := decodeStateInit(purchase.Escrow.StateInitBOC)
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := strictStateInitParts(stateInit)
	if err != nil {
		t.Fatal(err)
	}
	replaced := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).MustStoreBoolBit(true).
		MustStoreRef(code).MustStoreBoolBit(true).MustStoreRef(data).MustStoreBoolBit(false).EndCell()
	changed := *purchase
	changed.Escrow.StateInitBOC = base64BOC(replaced)
	changed.Escrow.Address = "0:" + fmt.Sprintf("%x", replaced.Hash())
	changed.Escrow.CodeHash = cellHash(code)
	return &changed
}

func TestPaidDemandDeployerRefusesAnyOtherEscrowCode(t *testing.T) {
	deployer, purchase := testPaidDemandDeployment(t)
	other := withCode(t, purchase, cell.BeginCell().MustStoreUInt(0xabcdef02, 32).EndCell())
	fake := &paidDeployRunnerFake{purchase: other, deployer: deployer}
	deployer.runner = fake
	if _, err := deployer.PreparePaidDemandDeployment(context.Background(), other); err == nil {
		t.Fatal("deployer prepared an escrow running other code")
	}
	if len(fake.calls) != 0 {
		t.Fatal("custody was asked to sign a deployment of other code")
	}
	fake.purchase = purchase
	prepared, err := deployer.PreparePaidDemandDeployment(context.Background(), purchase)
	if err != nil {
		t.Fatal(err)
	}
	prepared.StateInitBOCBase64 = other.Escrow.StateInitBOC
	prepared.EscrowAddress = other.Escrow.Address
	_, prepared.StateInitHash, _ = decodeStateInit(other.Escrow.StateInitBOC)
	if err := deployer.BroadcastPaidDemandDeployment(context.Background(), prepared); err == nil ||
		!strings.Contains(err.Error(), "escrow v2") {
		t.Fatalf("deployer broadcast an escrow running other code: %v", err)
	}
}

func base64BOC(value *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(value.ToBOC())
}
