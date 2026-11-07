# Non-canonical Quote Proposal exchange

`RequestQuoteProposal` asks a provider-facing Gateway for terms covering one
exact Capability version and buyer address. Its response is a transport object,
not an acceptance record.

`pkg/quoteexchange` requires the response package to carry the complete
canonical manifest CBOR and the canonical single-root transport binding BOC.
It hashes and decodes both preimages, checks the requested Capability and
version, bounds expiry and package size, parses the Service Actor rail
(workchain 0 actor, code hash, policy version, terms hash, positive native
TOS price and storage fee below 2^120, ML-DSA-44 attestor key id), requires
the rail to name exactly the actor, code hash and attestor of manifest key 21,
and proves the proposal can be encoded by the canonical Accepted Quote
builder.

The `terms_hash` preimage is the actor's finalized policy, not package data:
a Gateway cannot make a proposal canonical. The buyer verifies every rail
field against finalized state before calling, and only the finalized Service
Actor `call` transaction accepts the Quote.

`pkg/quoteprovider` builds such packages from finalized Capability state and
the finalized policy of the actor that manifest key 21 names.
