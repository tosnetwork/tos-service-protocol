package agentguarantor

type ClaimTerminalResolutionRefSetV1 struct {
	SchemaVersion               uint16                         `json:"schema_version"`
	CoverageAgreementBodyDigest string                         `json:"coverage_agreement_body_digest"`
	CoverageObligationID        string                         `json:"coverage_obligation_id"`
	AdmissionHighWater          uint64                         `json:"admission_high_water"`
	Refs                        []ClaimTerminalResolutionRefV1 `json:"refs"`
}

type CoverageClosureEvidenceContextV1 struct {
	SchemaVersion                     uint16         `json:"schema_version"`
	CoverageAgreementBodyDigest       string         `json:"coverage_agreement_body_digest"`
	CoverageObligationID              string         `json:"coverage_obligation_id"`
	ClaimFilingCloseReceiptDigest     string         `json:"claim_filing_close_receipt_digest"`
	CoverageCancellationReceiptDigest string         `json:"coverage_cancellation_receipt_digest,omitempty"`
	CoverageEndCommitmentDigest       string         `json:"coverage_end_commitment_digest"`
	FilingCloseReason                 string         `json:"filing_close_reason"`
	CoverageEndReason                 string         `json:"coverage_end_reason"`
	IncidentEligibilityEndsAtUnix     uint64         `json:"incident_eligibility_ends_at_unix,omitempty"`
	CoverageEndEvidenceDigest         string         `json:"coverage_end_evidence_digest,omitempty"`
	ActivationEvidenceDigest          string         `json:"activation_evidence_digest,omitempty"`
	CoverageClosureReason             string         `json:"coverage_closure_reason"`
	ResolutionTargetTerminalState     string         `json:"resolution_target_terminal_state"`
	AdmissionHighWater                uint64         `json:"admission_high_water"`
	ClaimAdmissionLogRoot             string         `json:"claim_admission_log_root"`
	ClaimResolutionSetDigest          string         `json:"claim_resolution_set_digest"`
	CumulativeApprovedAmount          AtomicAmountV1 `json:"cumulative_approved_amount"`
	CumulativePaidAmount              AtomicAmountV1 `json:"cumulative_paid_amount"`
	CumulativeDefaultedAmount         AtomicAmountV1 `json:"cumulative_defaulted_amount"`
	OutstandingApprovedAmount         AtomicAmountV1 `json:"outstanding_approved_amount"`
	ReleaseNotBeforeUnix              uint64         `json:"release_not_before_unix"`
}

func ClaimTerminalResolutionRefSetDigestV1(value ClaimTerminalResolutionRefSetV1) (string, error) {
	return guarantorCodec.Digest("tos.service.agent-guarantor-claim-resolution-set.v1", value)
}

func CoverageClosureEvidenceContextDigestV1(value CoverageClosureEvidenceContextV1) (string, error) {
	return guarantorCodec.Digest("tos.service.agent-guarantor-coverage-closure-context.v1", value)
}

type ExposureDispositionComputationV1 struct {
	SchemaVersion                  uint16         `json:"schema_version"`
	CoverageAgreementBodyDigest    string         `json:"coverage_agreement_body_digest"`
	CoverageObligationID           string         `json:"coverage_obligation_id"`
	ReservationID                  string         `json:"reservation_id"`
	ExposureAdmissionReceiptDigest string         `json:"exposure_admission_receipt_digest"`
	ReservationScopeDigest         string         `json:"reservation_scope_digest"`
	ReleasedExposure               AtomicAmountV1 `json:"released_exposure"`
	CumulativeApprovedAmount       AtomicAmountV1 `json:"cumulative_approved_amount"`
	CumulativePaidAmount           AtomicAmountV1 `json:"cumulative_paid_amount"`
	CumulativeDefaultedAmount      AtomicAmountV1 `json:"cumulative_defaulted_amount"`
	OutstandingApprovedAmount      AtomicAmountV1 `json:"outstanding_approved_amount"`
	DefaultLiabilityDisposition    string         `json:"default_liability_disposition"`
	ReturnedToAvailableExposure    AtomicAmountV1 `json:"returned_to_available_exposure"`
	RealizedLoss                   AtomicAmountV1 `json:"realized_loss"`
	RetainedDefaultedLiability     AtomicAmountV1 `json:"retained_defaulted_liability"`
	PortfolioDisposition           string         `json:"portfolio_disposition"`
}

type ExposureReleaseEvidenceProjectionV1 struct {
	SchemaVersion                          uint16 `json:"schema_version"`
	CoverageAgreementBodyDigest            string `json:"coverage_agreement_body_digest"`
	CoverageObligationID                   string `json:"coverage_obligation_id"`
	ReservationID                          string `json:"reservation_id"`
	ExposureAdmissionReceiptDigest         string `json:"exposure_admission_receipt_digest"`
	TerminalClaimSetEvidenceDigest         string `json:"terminal_claim_set_evidence_digest"`
	TerminalPaymentEvidenceSetDigest       string `json:"terminal_payment_evidence_set_digest"`
	CollateralDispositionEvidenceSetDigest string `json:"collateral_disposition_evidence_set_digest,omitempty"`
}
