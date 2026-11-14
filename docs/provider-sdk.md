# Native provider SDK

`pkg/providersdk` is the first Gate E developer surface. It publishes one
software-work Capability through the existing Native Submit/Resolve service;
it does not add an authority API, store provider state, or sign with provider
keys.

The SDK strictly decodes the frozen V1 manifest, produces canonical CBOR,
derives the Capability ID, and builds the canonical registration action for
offline review. Before relay it resolves the finalized owner Agent and checks
Capability-purpose signatures. A relay acknowledgement is never treated as
success: the SDK polls finalized typed state and returns only an exact matching
Capability version, owner, action hash, code hash, network, and checkpoint.

## Go flow

Create the authority-neutral gateway client and provider SDK:

```go
gateway, err := nativeclient.New(nativeclient.Config{
    BaseURL: "https://gateway.example",
    BearerToken: os.Getenv("TOS_SERVICE_RELAY_TOKEN"),
})
if err != nil { /* fail closed */ }
defer gateway.Close()

provider, err := providersdk.New(providersdk.Config{
    Client: gateway,
    Network: networkDomain,
    RegistryCodeHash: registryCodeHash,
    CallerID: providerAgentID,
})
```

Prepare a fresh Capability publication. Both nonces must be independently
generated nonzero 32-byte values and retained with the publication record:

```go
prepared, err := provider.PrepareCapabilityPublication(
    manifestJSON, providerAgentID, objectNonce, actionNonce,
)
if err != nil { /* reject the manifest */ }
```

Persist `prepared.ManifestCBOR` under `prepared.ManifestDigest`. Serialize
`prepared.Action` with protobuf JSON and inspect `prepared.ActionHash`. Sign
that exact action through the reviewed `tos-service-wallet`/`tosctl` custody
flow. The SDK deliberately has no private-key option.

After loading the resulting `authority_signatures`, publish with a durable,
unique request retry key:

```go
state, err := provider.PublishCapability(
    ctx, prepared, signed.AuthoritySignatures, idempotencyKey,
)
if err != nil { /* absence, conflict, timeout, or quorum failure */ }
```

Success means `state` is finalized canonical TOS state containing the exact
publication action. It never means only `relay_accepted=true`.

After finalization, publish the immutable manifest to the gateway's derived
catalog with a separate durable request key:

```go
catalogState, err := provider.PublishManifest(ctx, prepared, manifestRetryKey)
```

The SDK sends the exact reviewed canonical CBOR. The gateway re-resolves the
Capability and admits the bytes only when its active version commits to their
digest. `catalogState` is the finalized admission observation; catalog
inclusion itself is not canonical publication.

The client requires HTTPS by default. Plain HTTP must be explicitly enabled
and is intended only for loopback development. Mutual TLS and a private CA can
be configured through `nativeclient.Config`; bearer credentials grant
transport access only and cannot authorize a Native transition.

Capability publication does not start an executor or grant it signing
authority. Deploy the provider-local runtime using the reviewed template under
`tos-ai/deploy/provider`, keep raw containerd inaccessible to the gateway, and
keep all signing keys in the separate `tosctl` custody boundary.

## Journaled, restartable publication

`PublishCapability` keeps no state: if the process stops, only an operator who
retained the prepared action, both nonces and both retry keys can resume it.
`PublicationJournal` removes that burden. It is an owner-private directory
(mode `0700`, files `0600`, symlinks and broader permissions refused) holding
one versioned record (`tos.service.provider-publication.v1`) per publication,
named by its action hash. Each write is a temporary file, `fsync`, rename and
directory `fsync` under an exclusive lock. A record carries the exact action,
canonical manifest bytes, nonces, network and Registry identity, both retry
keys, the signed action once verified, and a phase:

| Phase | Meaning | What `ApplyPublication` does next |
| --- | --- | --- |
| `prepared` | Durable before the action is handed to the signer | Requires the signed action, verifies it against the finalized owner policy, stores it |
| `signed` | Verified signatures stored | Takes the record's relay lock, journals `submitting`, relays once |
| `submitting` | Written before the relay starts, under the relay lock | While the relaying process lives: nothing (`ErrRelayInProgress`). Once it has died (its relay lock is free): becomes `ambiguous` |
| `submitted` | Gateway acknowledged the exact action hash (transport only) | Waits for exact finalized state; a finality timeout makes it `ambiguous` |
| `ambiguous` | The relay may or may not have landed | Settles from finalized state first; only a finalized absence re-relays the **stored** signed action under the **same** retry key |
| `finalized` | Finalized Capability state matches the action | Publishes the stored manifest to the derived catalog |
| `cataloged` | Catalog admitted the manifest | Nothing; re-runs are no-ops |

A record with an unknown schema, unknown phase, unknown field, trailing data,
or any field that does not re-derive from its action is refused whole. A
stored action or signature set is never replaced; a different signed action
is refused. Finalized state that names another action is an error, never a
reason to re-relay.

Each record has a relay lock file (`publication-<hex>.relay`). The process
that relays holds it from journaling `submitting` until the outcome is
journaled, and the operating system releases it if that process dies. Opening
the journal, or applying a `submitting` record, recovers it as `ambiguous`
only when that lock is free, so a live relay is never treated as abandoned
and never relayed twice.

```go
journal, err := providersdk.OpenPublicationJournal("/var/lib/provider/journal", time.Now())
record, created, err := provider.PrepareJournaledPublication(journal, manifestJSON, providerAgentID,
    providersdk.PublicationOptions{PinnedActorCodeHash: actorCodeHash}) // nonces and retry keys generated and journaled
preview, err := provider.PreviewPublication(ctx, record, providersdk.PreviewSources{
    PinnedActorCodeHash: actorCodeHash, Actors: actorReader, // both optional
})
// ... sign record's action externally ...
record, err = provider.ApplyPublication(ctx, journal, record.ActionHash, signed)
// After a crash at any phase, call ApplyPublication again with signed == nil.
```

With no nonces given, `PrepareJournaledPublication` resumes the journaled
publication of the same manifest by the same owner on the same network
instead of deriving a second Capability; pass explicit nonces to publish a
deliberate second Capability of the same manifest. The lookup and the write
hold one journal lock, so concurrent nonce-less prepares of one manifest
journal one Capability. With `PinnedActorCodeHash` set, a manifest whose key
21 names another Service Actor release is refused before anything is
journaled.

## Pre-signing preview

`PreviewPublication` returns `PublicationPreview`
(`tos.service.provider-publication-preview.v1`). Every field is always present
with a `status` (`known`, `verified`, `unknown`, `absent`, `mismatch`), a
`value`, a `source` (`prepared_action`, `manifest`, `configuration`,
`journal`, `finalized_state`, `none`) and a `detail`; `attention` lists every
field that is unknown, absent or mismatched. It covers the signing purpose,
network and genesis hashes, Registry code hash, owner Agent and its finalized
liveness, Capability ID and version, manifest digest, operation, endpoint
commitment, Service Actor address, code hash, account state and owner wallet,
the manifest attestor and its key 18 authorization, the actor's current
attestor, NSM1 metadata binding, proof scheme, `terms_hash`, policy version,
price, storage fee, cleanup bounty, response SLA, refund window, caller
access, policy bounds, publication fee and both retry keys.

The owner Agent is resolved through the Gateway. The Service Actor is read
through the repository's quorum Service Actor reader only when one is
configured; otherwise every actor-derived field is `unknown` with that
reason. A configured pin is compared with manifest key 21 locally, before
and independently of any chain read, so a failed or absent read never hides
a manifest that names another release; without a pin the code hash is shown
as `known` and marked as not compared. The key 18/21 attestor authorization
is a consistency check inside the manifest and is reported as `known`, not
`verified`. Read errors are shown with URL credentials, queries and fragments
redacted. Two values have no resolver in this repository and are always
`unknown`: the transport bound to `endpoint_commitment` (the manifest commits
to it by digest only), and the publication fee (the Gateway's action
publisher pays the relay fee; the signed action carries no fee). The actor
owner wallet is shown but its relationship to the owner Agent cannot be
verified from finalized state; confirm it yourself.

## Operator command

`cmd/tos-service-provider-publish` wires the journal and preview into four
modes. Private controller keys never enter it: signing stays with
`tos-service-wallet`/`tosctl`, and `--tosctl` here only verifies signatures.
The Gateway bearer token is read from an owner-private regular file; HTTPS is
the default and plaintext needs `--insecure` for loopback development.

Common flags for `prepare`, `preview` and `apply`:

```sh
COMMON="--state-dir /var/lib/provider/publish \
  --gateway https://gateway.example --token-file /etc/provider/gateway-token \
  --caller-id $AGENT_ID \
  --tosctl /usr/local/bin/tosctl --tosctl-sha256 $TOSCTL_SHA256"
```

`--state-dir` is created with mode `0700` when missing and must otherwise be
owner-private; the journal lives in its `journal/` subdirectory.

1. Prepare. The record is durable before anything is printed. Nonces and
   retry keys are generated and journaled unless given
   (`--object-nonce`/`--action-nonce` together, `--capability-idempotency-key`,
   `--manifest-idempotency-key`). `--actor-code-hash` on its own pins the
   Service Actor release and checks manifest key 21 against it locally, with
   no chain read. Add `--rpc` and `--registry-code-boc` as well to verify the
   actor binding against finalized state:

   ```sh
   tos-service-provider-publish prepare $COMMON \
     --network-id $NETWORK_ID --genesis-root $GENESIS_ROOT --genesis-file $GENESIS_FILE \
     --registry-code-hash $REGISTRY_CODE_HASH --owner-agent-id $AGENT_ID \
     --manifest-json /etc/provider/manifest.json \
     --rpc https://rpc1.example,https://rpc2.example,https://rpc3.example \
     --registry-code-boc /etc/provider/registry-code.boc \
     --actor-code-hash $SERVICE_ACTOR_CODE_HASH \
     > /var/lib/provider/publish/unsigned-action.json
   ```

   stdout is the unsigned `NativeActionV1` (also written to
   `<state-dir>/action-<hex>.json`); stderr shows the human-readable preview,
   the machine-readable preview path `<state-dir>/preview-<hex>.json`, and the
   `--action-hash` to resume with. When the manifest's Service Actor code hash
   differs from `--actor-code-hash`, `prepare` refuses before journaling
   anything, so no record that `apply` would accept is left behind; an
   immutable manifest cannot be fixed after publication. Without
   `--actor-code-hash` that check is skipped and the preview marks the code
   hash as not compared. Re-running `prepare` with the same manifest resumes
   the same record.

2. Review the preview again at any time (JSON on stdout, text on stderr):

   ```sh
   tos-service-provider-publish preview $COMMON --action-hash $ACTION_HASH \
     [--rpc ... --registry-code-boc ... --actor-code-hash ...]
   ```

3. Sign the exact action in custody:

   ```sh
   tos-service-wallet --action /var/lib/provider/publish/unsigned-action.json \
     --output /var/lib/provider/publish/signed-action.json \
     --tosctl /usr/local/bin/tosctl --tosctl-sha256 $TOSCTL_SHA256 \
     --tosctl-config /etc/provider/tosctl.json --authority-controller provider
   ```

4. Apply. The first run needs the signed action; every later run resumes from
   the journal and may omit it:

   ```sh
   tos-service-provider-publish apply $COMMON --action-hash $ACTION_HASH \
     --signed-action /var/lib/provider/publish/signed-action.json
   tos-service-provider-publish apply $COMMON --action-hash $ACTION_HASH
   ```

   stdout is one JSON status line reporting chain publication and catalog
   admission separately, for example:

   ```json
   {"action_hash":"sha256:…","capability_id":"…","manifest_digest":"sha256:…","phase":"cataloged","submit_attempts":1,"chain_published":true,"finalized_checkpoint":42,"catalog_admitted":true,"catalog_checkpoint":42}
   ```

   The status line is printed even when `apply` fails. It shows the phase
   the journal holds at that moment, and the exit code is non-zero until the
   phase is `cataloged`.

5. Inspect the journal without a Gateway:

   ```sh
   tos-service-provider-publish status --state-dir /var/lib/provider/publish [--action-hash $ACTION_HASH]
   ```

### Recovery

Re-run `apply` with the same `--state-dir` and `--action-hash` after any
crash, timeout or Gateway error. A `prepared` record still needs the signed
action. An `ambiguous` record is settled from finalized state before any
re-relay, so re-running is safe even when the previous relay reached the
chain. Two concurrent `apply` processes are serialized by the journal lock
and the record's relay lock. While one process is relaying, the other stops
with "another process is relaying this publication" and leaves the record in
`submitting`. Re-run it after the first finishes or dies. Back up the state
directory: it holds the only copy of generated nonces and retry keys.

**Owner policy changed after signing.** Every re-relay first verifies the
stored signatures against the owner Agent's current finalized policy. If the
controllers were rotated after signing and finalized state shows no
Capability, an `ambiguous` record cannot be re-relayed: the stored signatures
no longer satisfy the policy, and the journal never replaces them. `apply`
reports this explicitly. Abandon that record and publish again with explicit
fresh nonces, which derive a new Capability ID, then sign the new action
under the new policy:

```sh
tos-service-provider-publish prepare $COMMON ... \
  --object-nonce $(openssl rand -hex 32) --action-nonce $(openssl rand -hex 32)
```

A nonce-less `prepare` would resume the stuck record instead, because it
publishes the same manifest. The old signed action cannot land later: the
Registry rejects signatures outside the current policy.
