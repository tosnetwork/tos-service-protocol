# Native buyer SDK

`pkg/buyersdk` is the buyer-side safety boundary for one Paid Demand purchase
settled through the stablecoin escrow v2 contract. It reviews a non-canonical
Quote Proposal together with the Agent Agreement and signed Provider Offer,
verifies the manifest and finalized Capability, derives the exact Accepted
Quote and escrow, and then deploys, accepts and funds only that escrow, each as
a separate custody-authorized step confirmed from finalized chain state.

The SDK builds, deploys and settles against exactly one escrow code: the
released `tos-service-stablecoin-escrow-v2` contract, whose cell hash is
`nativecore.EscrowV2CodeHash` and whose frozen code `nativecore.EscrowV2Code()`
returns. Any other escrow code is refused when the buyer is configured, when a
StateInit is built, when a deployment is prepared or broadcast, and when an
escrow is resolved from the chain.

The SDK does not trust a gateway response as commercial authority and does not
hold a private key. Applications supply narrow adapters: finalized Native
resolution, finalized TOS stablecoin observation, finalized escrow resolution,
an escrow deployer, a wallet action sender and a custody effect authorizer.

## Construct the readers

chain, err := toschain.New(toschain.Config{
    Network: networkDomain.NetworkId,
    Endpoints: []string{nodeA, nodeB, nodeC},
    Quorum: 2,
})
if err != nil { /* fail closed */ }
locator, err := nativecore.NewLocator(
    networkDomain,
    0,
    reviewedRegistryCodeBOCBase64,
    registryCodeHash,
)
if err != nil { /* fail closed */ }
nativeResolver, err := toschain.NewSimplifiedNativeResolver(
    chain,
    locator,
    "/var/lib/tos-service-buyer/native.checkpoint",
)
if err != nil { /* fail closed */ }
nativeClient, err := toschain.NewDirectNativeClient(nativeResolver)
if err != nil { /* fail closed */ }
assetResolver, err := toschain.NewStablecoinResolver(
    chain,
    networkDomain,
    "/var/lib/tos-service-buyer/stablecoin.checkpoint",
)
if err != nil { /* fail closed */ }

escrowResolver, err := toschain.NewEscrowResolver(
    chain,
    networkDomain,
    nativecore.EscrowV2CodeHash,
    "/var/lib/tos-service-buyer/escrow.checkpoint",
)
if err != nil { /* fail closed */ }
escrowCode, err := nativecore.EscrowV2Code()
if err != nil { /* fail closed */ }

buyer, err := buyersdk.NewPaidDemandBuyer(buyersdk.PaidDemandBuyerConfig{
    NativeClient: nativeClient,
    AssetResolver: assetResolver,
    Network: networkDomain,
    RegistryCodeHash: registryCodeHash,
    BuyerAddress: buyerAddress,
    AssetWalletCode: reviewedStablecoinWalletCode,
    BudgetLimits: buyersdk.BudgetLimits{
        Window: 24 * time.Hour,
        MaxPurchases: 20,
        MaxPerPurchaseAtomic: "50000000",
        MaxTotalAtomic: "250000000",
    },
    EscrowResolver: escrowResolver,
    ProviderOfferResolver: providerOfferKeys,
    EscrowCode: escrowCode,
    Deployer: deployer,
    ActionSender: actionSender,
    EffectAuthorizer: custodyAuthorizer,
    OwnerID: ownerID,
    AgentID: buyerAgentID,
    CallerID: buyerAgentID,
    NetworkGlobalID: networkGlobalID,
})
```

`NewEscrowResolver` refuses any code hash other than `nativecore.EscrowV2CodeHash`.

`DirectNativeClient` is an in-process interface adapter, not another resolver.
The authoritative result still comes from `SimplifiedNativeResolver` reading
typed Registry state at a strict-majority finalized TOS checkpoint. Deployments
may instead supply the authenticated Connect client when process separation is
required; both paths apply the same SDK verification and neither makes the
gateway authoritative.

The stablecoin resolver reads the authenticated master and the buyer's
deterministically derived wallet at one quorum-finalized checkpoint. It obtains
the wallet-code preimage from the reviewed master contract, checks both code
hashes, owner, master, unlocked status, exact balance, network genesis, and a
durable monotonic checkpoint. It does not resolve assets by ticker or trust a
gateway-projected balance.

## Prepare, deploy, accept and fund

Prepare the purchase from the Agreement, the signed Provider Offer, the
received Quote Proposal and the independently retrieved manifest:

```go
prepared, err := buyer.PreparePurchase(ctx, buyersdk.PaidDemandPurchaseInput{
    Agreement: agreement,
    ProviderOffer: providerOffer,
    Proposal: proposal,
    ManifestCanonical: manifest,
    EscrowTerms: reviewedTerms,
    ExecutionSignerEd25519: executionSigner,
    TransportBinding: reviewedTransport,
    ExecutionDeadlineUnix: executionDeadline,
})
if err != nil { /* reject the proposal */ }
```

Show the operator at least `ManifestDigest`, `AgreementDigest`,
`QuoteCommitment`, escrow address, stablecoin master, buyer wallet, and
`AmountAtomic`. Then run the three transitions; each returns only after the
finalized escrow reaches the expected state:

```go
deployed, err := buyer.Deploy(ctx, prepared) // pending_acceptance
accepted, err := buyer.Accept(ctx, prepared) // awaiting_funding
funded, err := buyer.Fund(ctx, prepared)     // funded
```

Deployment creates only the deterministic pending-acceptance account. The
escrow cannot receive stablecoin until the buyer's separately authorized
acceptance has finalized. Acceptance and funding are custody effects: the
authorizer approves each exact message body before the wallet action sender
signs it, and an ambiguous result is resolved from finalized chain state and
never resubmitted as a new action.

For local `tosctl` custody, `TOSCTLPaidDemandEscrowDeployer` implements the
deployment boundary without receiving a key. It first asks custody to build and
sign the exact message without broadcasting it, then a separate step submits
only those exact signed bytes. It independently parses the StateInit and
requires the frozen shape (no split depth or special value, exactly one code
and data reference, no library or trailing data), the released escrow v2 code,
version 2 pending-acceptance data, the Quote commitment, the deterministic
address, an empty deploy body, the attached TOS amount, and the
custody-produced signed-message hash. An uncertain broadcast result is reported
as ambiguous and is never rebuilt or re-signed automatically.

Escrow v2 is experimental: a payout refused by the recipient's wallet can
strand funds in the escrow, an accepted risk only for local and test networks
with test assets. The deployer therefore prepares and broadcasts nothing
unless it is configured with `AcknowledgeNonProductionTestDeployment`, which is
off by default. The acknowledgment is checked before preparation and again
before broadcast, and is recorded in the prepared deployment as
`"non_production": true`; a prepared deployment without it is not broadcast.
This is separate from `AcknowledgeUnpinnedManualBroadcast`.
