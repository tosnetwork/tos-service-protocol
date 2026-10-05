# TOS Service Protocol — Finalized TOS Boundary

This repository implements the `tos_service_v1` protocol boundary between the
TOS Service Gateway and finalized TOS Network state. It has one protocol and one
authority model: typed TVM state in finalized TOS accounts.

The normative product and protocol design lives in
[`tosnetwork/tos-service-spec`](https://github.com/tosnetwork/tos-service-spec).

## What remains here

- `api/tos/service/v1/native.proto` — the single Native Connect contract.
- `pkg/nativecore` — deterministic Agent and Capability action/state machines,
  contract addressing, signatures, portable off-chain projection, and Accepted
  Quote commitment construction.
- `pkg/toschain` — strict-majority finalized chain reads and typed Native state
  decoding.
- `pkg/nativeclient`, `pkg/providersdk`, and `pkg/buyersdk` — public Gate E
  building blocks for canonical publication and bounded stablecoin purchases.
- `pkg/capabilitycatalog` — bounded, incomplete discovery IDs plus immutable
  digest-addressed manifests; all listed state is freshly resolved from TOS.
- `pkg/chainactionpublisher` — hardened `tosctl` transport for exact signed TVM
  message cells. It pays relay fees but has no semantic authority.
- `pkg/agentrelay` — canonical gas-sponsorship and exact-transaction relay
  profiles, signed quotes, Agreement bindings, recovery state, and the
  provider service boundary. It preserves the underlying economic action ID
  across provider failover and never exposes a transaction signing key. The
  service mode is independent from the signed assurance level
  (`trusted-local`, `authorized-single-provider`, or
  `autonomous-decentralized`); a deployment certification is not a wire-level
  prerequisite, while network binding, idempotency, spend caps, and ambiguous
  write handling remain mandatory at every level.
- `pkg/servicerpc` and `cmd/tos-service-rpc` — private authenticated Connect service
  used by the public TOS Service Gateway.

There is no Managed or Verified mode, gateway-owned registry, per-action
contract, legacy execution RPC, payment observer, or hosted settlement path in
this module. Portable CBOR is a derived export and never a consensus input.

## Build and test

The module uses Go 1.26.5.

```bash
go test ./...
go build ./cmd/tos-service-rpc
```

## Provider SDK

Gate E provider onboarding starts with the public `pkg/nativeclient` and
`pkg/providersdk` packages. They prepare a canonical software-work Capability,
accept externally generated controller signatures, relay the exact reviewed
action, and wait for matching finalized typed TOS state. They contain no
private-key or gateway-database authority. See
[`docs/provider-sdk.md`](docs/provider-sdk.md).

## Buyer SDK

`pkg/buyersdk` prepares an exact Accepted Quote and deterministic stablecoin
escrow v2 only after checking the Agreement, signed Provider Offer, manifest,
finalized Capability, TOS-network stablecoin, and buyer balance. It deploys,
accepts and funds the escrow as separate custody-authorized steps, each
confirmed from finalized chain state; an ambiguous submission is resolved from
finalized state and never paid again automatically. Only the released escrow v2
code (`nativecore.EscrowV2CodeHash`) is built, deployed or resolved. See
[`docs/buyer-sdk.md`](docs/buyer-sdk.md).

The separate derived discovery boundary is documented in
[`docs/capability-catalog.md`](docs/capability-catalog.md). Catalog inclusion is
not registration, and manifest retrieval is always checked against a fresh
Capability or Accepted Quote digest.

Frozen registry vectors are checked twice: `pkg/nativecore` is the production
encoder, while `internal/referencecodec` is an independent conformance encoder
that does not import generated Native messages or `nativecore`. Reproduce its
results with:

```bash
go run ./cmd/native-vector-reference
```

## Review and sign an action

`tos-service-wallet` signs the canonical TVM action hash using an owner-private
Ed25519 seed file. It prints the complete action semantics and, by default,
requires the operator to type the exact hash before signing:

```bash
go run ./cmd/tos-service-wallet \
  --action /absolute/path/action.json \
  --authority-key /absolute/private/controller.json \
  --output /absolute/private/signed-action.json
```

The key file is mode `0600` and contains
`{"schema":"tos.service.wallet-key.v1","private_seed_hex":"<64 lowercase hex>"}`.
Use `--counterparty-key` for Capability transfer acceptance or new-policy proof
of possession. The tool produces a signed action only; finality is confirmed
separately through `ResolveNativeState`.

## Run the private Native service

```bash
export TOS_SERVICE_RPC_TOKEN='<private-token>'
export TOS_SERVICE_V1_CONFIG='/absolute/private/native-v1.json'

go run ./cmd/tos-service-rpc
```

Plain HTTP is restricted to loopback. Configure `TOS_SERVICE_RPC_TLS_CERT` and
`TOS_SERVICE_RPC_TLS_KEY` for a remote listener, and optionally
`TOS_SERVICE_RPC_CLIENT_CA` for mTLS.

The Native configuration is strict JSON and contains:

- `protocol: "tos_service_v1"`;
- the exact network ID and genesis root/file digests;
- three to eight independently operated JSON-RPC endpoints and a strict
  majority quorum;
- Registry workchain, reviewed contract code BOC and exact code hash;
- bounded relay funding in nanoTOS;
- a mandatory relay budget window plus per-target and relay-wallet action and
  nanoTOS ceilings;
- a mandatory `recovery_relay_safety_seconds` value between 300 and 86400
  seconds, applied on top of the live policy timelock and quorum-finalized
  chain time before a recovery initiation may be relayed;
- an absolute owner-private `state_directory` for the durable relay journal and
  finalized-checkpoint fence;
- a pinned, owner-private `tosctl` sender configuration.

Startup fails closed unless both the finalized-state resolver and sender are
ready. The state directory is mandatory: a process never falls back to
in-memory idempotency or finality state. `/livez` reports process liveness;
`/readyz` and `/healthz` verify both Native dependencies.

Every process or host spending from the same relay wallet must use one shared,
process-independent journal. Request idempotency keys are aliases. The journal
first claims the canonical network/code/object/generation/sequence/predecessor
state slot and its exact action identity, complete outbound intent, claimed
time, and `prepared` phase in one atomic record. A separate atomic broadcast
lease advances `prepared` to `broadcasting` before entering the sender; only
the lease winner may pay. `prepared` survives a pre-send crash and is safely
recoverable, while `broadcasting` is resolved read-only after any ambiguous
crash. Changing either a request key or action nonce cannot purchase a second
broadcast for the same mutually exclusive transition. The same journal
atomically enforces `relay_window_seconds`, `max_actions_per_target`,
`max_funding_per_target_nanotos`, `max_actions_per_wallet`, and
`max_funding_per_wallet_nanotos`.

Recovery authorization never substitutes gateway wall-clock time for contract
time. The resolver returns the chain-authored unix time from the same quorum
observation used for the finalized target-state read. Initiation requires that
time plus the live timelock and configured relay safety margin; completion is
not relayed until finalized chain time reaches the stored execution time.

## Security boundary

The RPC server and gateways authenticate transport access only. A relayer can
submit bytes and pay gas, but only a correctly signed action accepted by the
Native contract can change state. Resolution validates network genesis,
strict-majority finality, exact contract code hash, account data, and the last
transaction tuple before returning typed state.

Capability transfer authorization is encoded and validated atomically by the
Native action/state machine. Gateway Quote Proposals remain non-canonical; an
Accepted Quote becomes canonical only when its commitment is recorded by the
relevant TOS contract flow.

Licensed under the [GNU General Public License v3.0](LICENSE).
