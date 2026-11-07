# Service Actor buyer SDK

`pkg/buyersdk` buys one call from a Service Actor: discover the offer, verify
it against quorum-finalized state, call with the quoted terms, and read the
result back from the finalized call transaction. Settlement is native TOS on
the Service Actor rail; there is no escrow, stablecoin or Paid Demand path.

The SDK holds no private key and trusts no gateway for authority. A manifest
is used only after its bytes reproduce the digest the finalized Capability
version commits to, and every verification reads one finalized checkpoint
(`toschain.ServiceActorSession`), so no result is composed from reads at
different checkpoints.

## Pins

- the network domain (genesis root and file hashes, network ID);
- the Native Registry code BOC and hash;
- the Service Actor release code hash (`tvm-cell-sha256:<hex>`). No release
  is published yet, so there is no default: the buyer refuses to start
  without one;
- three to eight RPC endpoints and a strict-majority quorum;
- the buyer wallet address and the tosctl custody binary by SHA-256.

## Flow

1. `Discover(capability, version)` returns an `Offer` that passed the
   binding steps (Capability, version, owner Agent, manifest digest; one actor
   address in manifest key 21; one code hash, equal to the pinned release;
   one attestor in key 21, committed by key 18) and the admission steps that
   need no Quote (active, attestor equal to key 21, NSM1 metadata and the
   software-work proof scheme, policy bounds, the buyer admitted).
2. `Prepare(request, package, execution_id, input_digest)` validates the
   Quote Proposal package (`pkg/quoteexchange`), refuses an expired Quote,
   runs admission including the Quote's terms hash, policy version, price and
   storage fee against one fresh checkpoint, builds the rail Accepted Quote
   and the NSR1 `request_hash`, and records the call in the journal with a
   budget reservation of `price + storage_fee + 0.2 TOS`. A `request_hash` or
   `query_id` is never reused.
3. `Call(request_hash)` re-derives every commitment from the record, refuses
   an expired Quote, re-runs admission at a fresh checkpoint, runs the custody
   preflight, durably enters `sending`, and runs

   ```text
   tosctl agent service send --operation call --address <actor> --from <wallet>
     --query-id <q> --request-hash <hex> --expected-terms-hash <quoted hex> --yes
   ```

   tosctl attaches the exact minimum payment and refuses the call unless the
   actor's live terms hash to the quoted value; the contract refuses it again
   (exit 1926) if the terms change before the call lands. A call that left
   `prepared` is never sent again: a send that may have reached the chain is
   `ambiguous`, and a record found in `sending` after a crash is recovered as
   `ambiguous`.
4. `Resolve(request_hash)` finds the exactly one finalized transaction from
   the buyer wallet whose call body carries the record's `query_id`,
   `request_hash` and terms hash. An aborted one marks the call `refused` and
   releases its reservation. A successful one is verified from the
   transaction and its `SAR1` request snapshot alone (caller, request hash,
   the attestor admission verified, the terms preimage hashing to the quoted
   terms hash, NSM1, proof scheme and deadlines); then the actor's complete
   history is replayed through the request state machine and reconciled with
   the actor state at the same checkpoint, and `get_request` / `get_refund`
   must agree with the decoded entries. The report gives the state
   (`pending`, `expired`, `responded`, `refunded`, `swept`), the buyer status
   (`pending`, `overdue`, `refundable`, `lapsed`, ...) and the required action.

The SDK does not send `expire` or `claim_refund`; it reports when they are
due. The storage fee is never refunded.

## Custody preflight

Before a call is sent, `TOSCTLServiceActorSender.Preflight` proves without
broadcasting that:

- the tosctl wallet signs as the buyer wallet: a `wallet send --build-only`
  of the exact call body must report the buyer as payer, the actor as
  destination and the exact payment;
- tosctl submits only to verified endpoints: its effective `chain_rpc` list,
  resolved as tosctl resolves it, must be non-empty, every entry must be one
  of the reader's endpoints, and each must report the pinned genesis;
- the amounts fit this tosctl path, which carries prices and payments in 64
  bits; larger values are refused with `ErrUnsupportedAmount` before
  anything is recorded as sent.

## Journal

`ServiceActorJournal` is an owner-private directory. Every change holds one
exclusive file lock across processes and is written by an atomic, synced
replacement. Reservations are kept by `prepared` (until the Quote expires),
`sending`, `submitted`, `ambiguous` and `admitted` records and released only
by `refused`.

## Command

`cmd/tos-service-buyer` exposes `discover`, `prepare`, `call`, `status` and
`requests` (the derived request index of `pkg/serviceactorindex`), printing
JSON. `call` reads the tosctl vault URL, which carries the vault master key,
from the `VAULT_URL` environment variable and hands it to tosctl only as its
sole environment variable; there is no command-line flag for it, so it never
appears in the process table.
