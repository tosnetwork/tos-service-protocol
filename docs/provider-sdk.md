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

## Restartable operator command

`cmd/tos-service-provider-publish` wires the SDK into an operator workflow
without moving controller keys into the provider runtime. `prepare` takes the
reviewed manifest and two retained nonzero 32-byte nonces, prints the canonical
`NativeActionV1` for `tos-service-wallet`, and reports its Capability ID,
manifest digest and action hash on stderr. `apply` recomputes that publication,
requires the returned `SignedNativeActionV1` to match byte-for-byte at the
protobuf semantic layer, submits it with a durable retry key, waits for exact
finalized Capability state, and then publishes the same immutable manifest
under a separate retry key. Both modes take `--tosctl` and `--tosctl-sha256`,
the pinned helper that verifies the ML-DSA-44 controller signatures against the
finalized owner policy before anything is relayed; it holds no keys for this
command.

The Gateway bearer token is read from an owner-private regular file. HTTPS is
the default; plaintext requires the client's explicit loopback/development
override. Unknown signed-action fields, counterparty signatures, action or
manifest substitution, missing finality, and catalog/finalized-state mismatch
all fail closed. Re-running `apply` with the same retained nonces and retry keys
resumes the same publication instead of deriving a second Capability.
