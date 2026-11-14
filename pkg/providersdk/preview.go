package providersdk

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/serviceactor"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// PreviewStatus says how far a preview value is established.
type PreviewStatus string

const (
	// PreviewKnown: taken from the reviewed action, manifest or
	// configuration; not checked against chain state.
	PreviewKnown PreviewStatus = "known"
	// PreviewVerified: checked against finalized chain state.
	PreviewVerified PreviewStatus = "verified"
	// PreviewUnknown: could not be established; Detail says why.
	PreviewUnknown PreviewStatus = "unknown"
	// PreviewAbsent: finalized state shows the object does not exist.
	PreviewAbsent PreviewStatus = "absent"
	// PreviewMismatch: finalized state contradicts the publication.
	PreviewMismatch PreviewStatus = "mismatch"
)

// Preview value sources.
const (
	SourcePreparedAction = "prepared_action"
	SourceManifest       = "manifest"
	SourceConfiguration  = "configuration"
	SourceJournal        = "journal"
	SourceFinalizedState = "finalized_state"
	SourceNone           = "none"
)

// PreviewField is one previewed value. Every field is always present; a
// value that cannot be established says so in Status and Detail instead of
// being left out.
type PreviewField struct {
	Status PreviewStatus `json:"status"`
	Value  string        `json:"value"`
	Source string        `json:"source"`
	Detail string        `json:"detail"`
}

const publicationPreviewSchema = "tos.service.provider-publication-preview.v1"

// PublicationPreview is what an operator reviews before signing. It covers
// the identity, network, endpoint, settlement, attestor, commercial terms
// and costs of one journaled publication.
type PublicationPreview struct {
	Schema     string           `json:"schema"`
	ActionHash string           `json:"action_hash"`
	Phase      PublicationPhase `json:"phase"`

	SigningPurpose     PreviewField `json:"signing_purpose"`
	NetworkID          PreviewField `json:"network_id"`
	GenesisRootHash    PreviewField `json:"genesis_root_hash"`
	GenesisFileHash    PreviewField `json:"genesis_file_hash"`
	RegistryCodeHash   PreviewField `json:"registry_code_hash"`
	OwnerAgentID       PreviewField `json:"owner_agent_id"`
	OwnerAgentState    PreviewField `json:"owner_agent_state"`
	CapabilityID       PreviewField `json:"capability_id"`
	CapabilityVersion  PreviewField `json:"capability_version"`
	ManifestDigest     PreviewField `json:"manifest_digest"`
	Operation          PreviewField `json:"operation"`
	EndpointCommitment PreviewField `json:"endpoint_commitment"`
	TransportBinding   PreviewField `json:"transport_binding"`

	ServiceActorAddress  PreviewField `json:"service_actor_address"`
	ServiceActorCodeHash PreviewField `json:"service_actor_code_hash"`
	ServiceActorAccount  PreviewField `json:"service_actor_account"`
	ServiceActorOwner    PreviewField `json:"service_actor_owner"`
	AttestorKey          PreviewField `json:"attestor_key"`
	AttestorAuthorized   PreviewField `json:"attestor_authorization"`
	ActorAttestor        PreviewField `json:"actor_attestor"`
	ActorMetadataBinding PreviewField `json:"actor_metadata_binding"`
	ActorProofScheme     PreviewField `json:"actor_proof_scheme"`

	TermsHash         PreviewField `json:"terms_hash"`
	PolicyVersion     PreviewField `json:"policy_version"`
	PricePerCall      PreviewField `json:"price_per_call_nanotos"`
	StorageFee        PreviewField `json:"storage_fee_nanotos"`
	CleanupBounty     PreviewField `json:"cleanup_bounty_nanotos"`
	ResponseSLA       PreviewField `json:"response_sla_seconds"`
	RefundClaimWindow PreviewField `json:"refund_claim_window_seconds"`
	CallerAccess      PreviewField `json:"caller_access"`
	PolicyBounds      PreviewField `json:"policy_bounds"`
	PublicationFee    PreviewField `json:"publication_fee"`

	CapabilityRetryKey PreviewField `json:"capability_idempotency_key"`
	ManifestRetryKey   PreviewField `json:"manifest_idempotency_key"`

	// Attention names every field that is unknown, absent or mismatched.
	Attention []string `json:"attention"`
}

// ServiceActorObservation is one finalized read of a Service Actor account.
// Account is nil when the account is not active at Checkpoint.
type ServiceActorObservation struct {
	Checkpoint     uint64
	PinnedCodeHash string
	Account        *toschain.ActorAccount
}

// ServiceActorStateReader reads a Service Actor account at one finalized
// checkpoint, through the repository's quorum Service Actor reader.
type ServiceActorStateReader interface {
	ObserveServiceActor(ctx context.Context, actor string) (ServiceActorObservation, error)
}

// ServiceActorSessionReader adapts a toschain Service Actor reader: each
// observation opens one session at a fresh finalized checkpoint.
type ServiceActorSessionReader struct{ Reader *toschain.ServiceActorReader }

// ObserveServiceActor implements ServiceActorStateReader.
func (r ServiceActorSessionReader) ObserveServiceActor(ctx context.Context, actor string) (ServiceActorObservation, error) {
	if r.Reader == nil {
		return ServiceActorObservation{}, errors.New("Service Actor reader is not configured")
	}
	session, err := r.Reader.Begin(ctx)
	if err != nil {
		return ServiceActorObservation{}, err
	}
	account, found, err := session.ReadActor(ctx, actor)
	if err != nil {
		return ServiceActorObservation{}, err
	}
	observation := ServiceActorObservation{Checkpoint: session.Checkpoint(), PinnedCodeHash: r.Reader.ActorCodeHash()}
	if found {
		observation.Account = account
	}
	return observation, nil
}

// PreviewSources are the optional inputs of a preview beyond the Gateway.
type PreviewSources struct {
	// PinnedActorCodeHash is the tvm-cell-sha256 Service Actor release the
	// operator deploys. It is compared with manifest key 21 locally, so the
	// comparison holds even when Actors is nil or its read fails.
	PinnedActorCodeHash string
	// Actors reads the Service Actor at a finalized checkpoint; nil leaves
	// every actor-derived field unknown.
	Actors ServiceActorStateReader
}

// PreviewPublication builds the pre-signing preview of a journaled
// publication. The owner Agent is resolved through the Gateway; the Service
// Actor is read only when sources.Actors is non-nil. Read failures become
// unknown fields with their reason, with any URL credentials and queries
// redacted; they never drop a field.
func (p *Provider) PreviewPublication(ctx context.Context, record PublicationRecord, sources PreviewSources) (*PublicationPreview, error) {
	if p == nil || ctx == nil {
		return nil, errors.New("invalid publication preview request")
	}
	if err := record.validate(); err != nil {
		return nil, err
	}
	input := previewInput{record: record, provider: p, pinned: sources.PinnedActorCodeHash}
	input.owner, input.ownerFound, input.ownerErr = p.resolveFound(ctx, record.OwnerAgentID)
	if actors := sources.Actors; actors != nil {
		manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(record.ManifestCBOR)
		if err != nil {
			return nil, err
		}
		observation, err := actors.ObserveServiceActor(ctx, "0:"+hex.EncodeToString(manifest.Settlement.ActorAccountID))
		input.actorConfigured, input.actor, input.actorErr = true, &observation, err
	}
	return buildPreview(input)
}

type previewInput struct {
	record          PublicationRecord
	provider        *Provider
	pinned          string
	owner           *nativev1.NativeStateV1
	ownerFound      bool
	ownerErr        error
	actorConfigured bool
	actor           *ServiceActorObservation
	actorErr        error
}

func known(value, source, detail string) PreviewField {
	return PreviewField{Status: PreviewKnown, Value: value, Source: source, Detail: detail}
}

func field(status PreviewStatus, value, source, detail string) PreviewField {
	return PreviewField{Status: status, Value: value, Source: source, Detail: detail}
}

func buildPreview(input previewInput) (*PublicationPreview, error) {
	record := input.record
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(record.ManifestCBOR)
	if err != nil {
		return nil, err
	}
	settlement := manifest.Settlement
	actorAddress := "0:" + hex.EncodeToString(settlement.ActorAccountID)
	manifestCodeHash := "tvm-cell-sha256:" + hex.EncodeToString(settlement.ActorCodeHash)
	preview := &PublicationPreview{Schema: publicationPreviewSchema, ActionHash: record.ActionHash, Phase: record.Phase,
		SigningPurpose: known("capability-control", SourcePreparedAction,
			"controller signatures over action_hash under the owner Agent's Capability-control purpose"),
		NetworkID:         known(record.NetworkID, SourcePreparedAction, ""),
		GenesisRootHash:   known(record.GenesisRootHash, SourcePreparedAction, ""),
		GenesisFileHash:   known(record.GenesisFileHash, SourcePreparedAction, ""),
		RegistryCodeHash:  known(record.RegistryCodeHash, SourcePreparedAction, ""),
		OwnerAgentID:      known(record.OwnerAgentID, SourcePreparedAction, ""),
		CapabilityID:      known(record.CapabilityID, SourcePreparedAction, "derived from the network, object nonce, owner and initial version"),
		CapabilityVersion: known(record.CapabilityVersion, SourceManifest, ""),
		ManifestDigest:    known(record.ManifestDigest, SourceManifest, "SHA-256 of the canonical manifest CBOR the action commits to"),
		Operation:         known(manifest.Operation, SourceManifest, ""),
		EndpointCommitment: known(manifest.EndpointCommitment, SourceManifest,
			"manifest key 17 commits to the endpoint by digest only"),
		TransportBinding: field(PreviewUnknown, "", SourceNone,
			"no finalized-state resolver maps endpoint_commitment to a transport; confirm it against the endpoint you operate"),
		ServiceActorAddress: known(actorAddress, SourceManifest, "manifest key 21 settlement actor"),
		AttestorKey:         known(settlement.AttestorKey, SourceManifest, "manifest key 21 attestor"),
		AttestorAuthorized: known(manifest.ExecutionSignerAuthorization, SourceManifest,
			"manifest key 18 commits to the key 21 attestor text; a consistency check within the manifest, not a chain check"),
		PublicationFee: field(PreviewUnknown, "", SourceNone,
			"the Gateway's action publisher pays the relay fee of a Native action; this SDK has no fee estimator and the signed action carries no fee"),
		CapabilityRetryKey: known(record.CapabilityIdempotencyKey, SourceJournal, ""),
		ManifestRetryKey:   known(record.ManifestIdempotencyKey, SourceJournal, ""),
	}
	if manifest.ExecutionSignerAuthorization != nativecore.SettlementAttestorAuthorization(settlement.AttestorKey) {
		preview.AttestorAuthorized.Status = PreviewMismatch
	}
	preview.OwnerAgentState = ownerField(input)
	actorFields(preview, input, manifest, actorAddress, manifestCodeHash)
	for _, named := range preview.fields() {
		switch named.field.Status {
		case PreviewKnown, PreviewVerified:
		case PreviewUnknown, PreviewAbsent, PreviewMismatch:
			preview.Attention = append(preview.Attention, named.name)
		default:
			return nil, fmt.Errorf("preview field %s has no status", named.name)
		}
	}
	if preview.Attention == nil {
		preview.Attention = []string{}
	}
	return preview, nil
}

func ownerField(input previewInput) PreviewField {
	switch {
	case input.ownerErr != nil:
		return field(PreviewUnknown, "", SourceFinalizedState, "owner Agent resolution failed: "+redactURLs(input.ownerErr.Error()))
	case !input.ownerFound:
		return field(PreviewAbsent, "", SourceFinalizedState, "the owner Agent is not in finalized state; publication will be refused")
	}
	agent := input.owner.GetAgent()
	checkpoint := input.owner.GetReference().GetFinalizedCheckpoint()
	if agent == nil || agent.AgentId != input.record.OwnerAgentID || agent.Policy == nil || !input.provider.validStateEnvelope(input.owner) {
		return field(PreviewMismatch, "", SourceFinalizedState, "the resolved object is not this owner Agent on this network and Registry")
	}
	if agent.Tombstoned {
		return field(PreviewMismatch, "tombstoned", SourceFinalizedState, fmt.Sprintf("the owner Agent is tombstoned at checkpoint %d", checkpoint))
	}
	controllers := 0
	for _, controller := range agent.Policy.Controllers {
		if controller != nil && controller.PurposeMask&nativecore.PurposeCapabilityControl != 0 {
			controllers++
		}
	}
	return field(PreviewVerified, "live", SourceFinalizedState, fmt.Sprintf("live at checkpoint %d; threshold %d with %d Capability-control controllers",
		checkpoint, agent.Policy.Threshold, controllers))
}

// actorFields fills every field that only the finalized Service Actor
// account can establish.
func actorFields(preview *PublicationPreview, input previewInput, manifest nativecore.SoftwareWorkManifestV1, actorAddress, manifestCodeHash string) {
	// The pin comparison is local and runs before, and independently of,
	// any chain read, so a failed or absent read cannot hide it.
	pinMismatch := input.pinned != "" && input.pinned != manifestCodeHash
	switch {
	case input.pinned == "":
		preview.ServiceActorCodeHash = known(manifestCodeHash, SourceManifest,
			"manifest key 21 code hash; no pinned Service Actor release is configured, so it was not compared")
	case pinMismatch:
		preview.ServiceActorCodeHash = field(PreviewMismatch, manifestCodeHash, SourceConfiguration,
			"manifest key 21 code hash is not the pinned Service Actor release "+input.pinned)
	default:
		preview.ServiceActorCodeHash = known(manifestCodeHash, SourceConfiguration,
			"manifest key 21 code hash equals the pinned Service Actor release; the account was not checked")
	}
	dependent := []*PreviewField{&preview.ServiceActorAccount, &preview.ServiceActorOwner, &preview.ActorAttestor,
		&preview.ActorMetadataBinding, &preview.ActorProofScheme, &preview.TermsHash, &preview.PolicyVersion,
		&preview.PricePerCall, &preview.StorageFee, &preview.CleanupBounty, &preview.ResponseSLA,
		&preview.RefundClaimWindow, &preview.CallerAccess, &preview.PolicyBounds}
	fill := func(status PreviewStatus, detail string) {
		for _, target := range dependent {
			*target = field(status, "", SourceFinalizedState, detail)
		}
	}
	switch {
	case !input.actorConfigured:
		fill(PreviewUnknown, "no Service Actor reader is configured; the actor's state, terms and fees were not read")
		return
	case input.actorErr != nil:
		fill(PreviewUnknown, "Service Actor read failed: "+redactURLs(input.actorErr.Error()))
		return
	}
	observation := input.actor
	if observation.PinnedCodeHash != "" && observation.PinnedCodeHash != input.pinned {
		fill(PreviewUnknown, "the Service Actor reader pins release "+observation.PinnedCodeHash+", not the configured pin; its read was not used")
		return
	}
	if observation.Account == nil {
		fill(PreviewAbsent, fmt.Sprintf("the Service Actor is not active at checkpoint %d; buyers refuse admission until it is deployed", observation.Checkpoint))
		return
	}
	account := observation.Account
	if account.Address != actorAddress || account.Data == nil {
		fill(PreviewMismatch, "the reader returned another account or undecoded data")
		return
	}
	switch {
	case account.CodeHash != manifestCodeHash:
		preview.ServiceActorCodeHash = field(PreviewMismatch, account.CodeHash, SourceFinalizedState,
			"the account code hash differs from manifest key 21 "+manifestCodeHash)
	case pinMismatch:
		preview.ServiceActorCodeHash = field(PreviewMismatch, manifestCodeHash, SourceFinalizedState,
			fmt.Sprintf("account code at checkpoint %d equals manifest key 21, but both differ from the pinned release %s", observation.Checkpoint, input.pinned))
	case input.pinned == "":
		preview.ServiceActorCodeHash = field(PreviewVerified, manifestCodeHash, SourceFinalizedState,
			fmt.Sprintf("account code at checkpoint %d equals manifest key 21; no pinned release is configured", observation.Checkpoint))
	default:
		preview.ServiceActorCodeHash = field(PreviewVerified, manifestCodeHash, SourceFinalizedState,
			fmt.Sprintf("account code at checkpoint %d equals manifest key 21 and the pinned release", observation.Checkpoint))
	}
	data := account.Data
	policy := data.Policy
	state := fmt.Sprintf("checkpoint %d, balance %d nanoTOS, %d pending, last transaction %d:%s",
		observation.Checkpoint, account.BalanceNano, data.PendingCount, account.LastTransaction.LT, account.LastTransaction.Hash)
	if data.Active {
		preview.ServiceActorAccount = field(PreviewVerified, "active", SourceFinalizedState, state)
	} else {
		preview.ServiceActorAccount = field(PreviewMismatch, "inactive", SourceFinalizedState, state+"; the actor admits no calls")
	}
	preview.ServiceActorOwner = known(data.Owner.Text(), SourceFinalizedState,
		"the actor owner wallet is read from finalized state; its relationship to the owner Agent is not verifiable on chain, confirm it is yours")
	attestorID, err := mldsa44.ParseKeyIDText(manifest.Settlement.AttestorKey)
	switch {
	case err != nil:
		preview.ActorAttestor = field(PreviewMismatch, "", SourceFinalizedState, "manifest key 21 attestor does not parse")
	case !policy.HasAttestor:
		preview.ActorAttestor = field(PreviewMismatch, "", SourceFinalizedState, "the actor has no attestor; buyers refuse admission")
	default:
		derived, deriveErr := mldsa44.KeyID(policy.AttestorKey)
		current := mldsa44.KeyIDText(policy.AttestorKeyID)
		if deriveErr != nil || derived != policy.AttestorKeyID {
			preview.ActorAttestor = field(PreviewMismatch, current, SourceFinalizedState, "the stored attestor key does not derive its key id")
		} else if policy.AttestorKeyID != attestorID {
			preview.ActorAttestor = field(PreviewMismatch, current, SourceFinalizedState, "the actor's attestor is not manifest key 21; buyers refuse admission")
		} else {
			preview.ActorAttestor = field(PreviewVerified, current, SourceFinalizedState, "the actor's current attestor is manifest key 21")
		}
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: input.record.Network(),
		CapabilityID: input.record.CapabilityID, ProviderAgentID: input.record.OwnerAgentID,
		CapabilityVersion: input.record.CapabilityVersion, ManifestDigest: input.record.ManifestDigest})
	switch {
	case err != nil:
		preview.ActorMetadataBinding = field(PreviewUnknown, hex.EncodeToString(policy.MetadataHash[:]), SourceFinalizedState, "NSM1 metadata cannot be built: "+err.Error())
	case metadata != policy.MetadataHash:
		preview.ActorMetadataBinding = field(PreviewMismatch, hex.EncodeToString(policy.MetadataHash[:]), SourceFinalizedState,
			"the actor's metadata_hash does not commit to this Capability version (expected "+hex.EncodeToString(metadata[:])+"); buyers refuse admission until it does")
	default:
		preview.ActorMetadataBinding = field(PreviewVerified, hex.EncodeToString(metadata[:]), SourceFinalizedState,
			"the actor's metadata_hash commits to this network, Capability, owner, version and manifest")
	}
	if policy.ProofSchemeHash == nativecore.ServiceActorSoftwareWorkProofScheme {
		preview.ActorProofScheme = field(PreviewVerified, hex.EncodeToString(policy.ProofSchemeHash[:]), SourceFinalizedState, "software-work Receipt scheme")
	} else {
		preview.ActorProofScheme = field(PreviewMismatch, hex.EncodeToString(policy.ProofSchemeHash[:]), SourceFinalizedState, "not the software-work Receipt scheme")
	}
	if terms, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(policy)); err != nil {
		preview.TermsHash = field(PreviewUnknown, "", SourceFinalizedState, "the current terms cannot be encoded: "+err.Error())
	} else {
		preview.TermsHash = known(hex.EncodeToString(terms[:]), SourceFinalizedState, "terms_hash of the actor's current policy; a Quote must carry it")
	}
	preview.PolicyVersion = known(fmt.Sprint(policy.PolicyVersion), SourceFinalizedState, "")
	preview.PricePerCall = known(bigText(policy.PricePerCall), SourceFinalizedState, "paid by the buyer per call")
	preview.StorageFee = known(bigText(policy.StorageFee), SourceFinalizedState, "paid by the buyer per call and locked until cleanup")
	preview.CleanupBounty = known(bigText(policy.CleanupBounty), SourceFinalizedState, "")
	preview.ResponseSLA = known(fmt.Sprint(policy.ResponseSLA), SourceFinalizedState, "")
	preview.RefundClaimWindow = known(fmt.Sprint(policy.RefundClaimWindow), SourceFinalizedState, "")
	switch {
	case policy.OpenAccess:
		preview.CallerAccess = known("open", SourceFinalizedState, "")
	case policy.HasAuthorizedCaller:
		preview.CallerAccess = known("authorized:"+policy.AuthorizedCaller.Text(), SourceFinalizedState, "only this caller is admitted")
	default:
		preview.CallerAccess = field(PreviewMismatch, "closed", SourceFinalizedState, "the actor admits no caller")
	}
	if err := serviceactor.CheckPolicyBounds(policy); err != nil {
		preview.PolicyBounds = field(PreviewMismatch, "", SourceFinalizedState, err.Error())
	} else {
		preview.PolicyBounds = field(PreviewVerified, "within contract bounds", SourceFinalizedState, "")
	}
}

var urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

// redactURLs removes user information, query strings and fragments from
// every URL in an error text before it reaches a preview file or a
// terminal; an RPC endpoint may carry credentials in either.
func redactURLs(text string) string {
	return urlPattern.ReplaceAllStringFunc(text, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			scheme, _, _ := strings.Cut(raw, "://")
			return scheme + "://[redacted]"
		}
		if parsed.User != nil {
			parsed.User = url.User("redacted")
		}
		if parsed.RawQuery != "" {
			parsed.RawQuery = "redacted"
		}
		if parsed.Fragment != "" {
			parsed.Fragment = "redacted"
		}
		return parsed.String()
	})
}

func bigText(value interface{ String() string }) string {
	if value == nil || reflect.ValueOf(value).IsNil() {
		return ""
	}
	return value.String()
}

type namedField struct {
	name  string
	field PreviewField
}

// fields lists every preview field by its JSON name, in display order.
func (p *PublicationPreview) fields() []namedField {
	value := reflect.ValueOf(p).Elem()
	kind := reflect.TypeOf(PreviewField{})
	var result []namedField
	for index := 0; index < value.NumField(); index++ {
		member := value.Type().Field(index)
		if member.Type != kind {
			continue
		}
		name, _, _ := strings.Cut(member.Tag.Get("json"), ",")
		result = append(result, namedField{name: name, field: value.Field(index).Interface().(PreviewField)})
	}
	return result
}

// WriteText renders the preview for a human reviewer. Every field is shown,
// including unknown and absent ones.
func (p *PublicationPreview) WriteText(out io.Writer) error {
	if _, err := fmt.Fprintf(out, "Capability publication preview (%s)\naction_hash: %s\nphase: %s\n", p.Schema, p.ActionHash, p.Phase); err != nil {
		return err
	}
	for _, named := range p.fields() {
		value := named.field.Value
		if value == "" {
			value = "-"
		}
		line := fmt.Sprintf("  %-28s [%-8s] %s (source: %s)", named.name, named.field.Status, value, named.field.Source)
		if named.field.Detail != "" {
			line += "\n      " + named.field.Detail
		}
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	if len(p.Attention) == 0 {
		_, err := fmt.Fprintln(out, "attention: none")
		return err
	}
	_, err := fmt.Fprintf(out, "attention (%d): %s\n", len(p.Attention), strings.Join(p.Attention, ", "))
	return err
}
