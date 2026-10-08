use super::*;

pub(super) fn render_finding(finding: positron_kernel::IntegrityQuarantineFinding) -> String {
    let scope = finding.scope();
    let signal = match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => "logs",
        positron_domain::routing::SignalKind::Traces => "traces",
    };
    let (event_provenance, event_earliest, event_latest) = event_range(finding.event_range());
    let (ingest_provenance, ingest_earliest, ingest_latest) = ingest_range(finding.ingest_range());
    format!(
        "quarantine_tenant={} quarantine_signal={signal} quarantine_shard={} quarantine_segment={} quarantine_base_position={} quarantine_event_provenance={event_provenance} quarantine_event_earliest_unix_nanos={event_earliest} quarantine_event_latest_unix_nanos={event_latest} quarantine_ingest_provenance={ingest_provenance} quarantine_ingest_earliest_unix_nanos={ingest_earliest} quarantine_ingest_latest_unix_nanos={ingest_latest}\n",
        scope.tenant_id(),
        scope.shard_id().value(),
        hex(&finding.segment().to_bytes()),
        finding.base_position(),
    )
}

fn event_range(range: positron_kernel::AuthenticatedEventRange) -> (&'static str, String, String) {
    match range {
        positron_kernel::AuthenticatedEventRange::Known { earliest, latest } => (
            "known",
            earliest.value().to_string(),
            latest.value().to_string(),
        ),
        positron_kernel::AuthenticatedEventRange::Unavailable(reason) => (
            match reason {
                positron_kernel::EventRangeUnavailable::MissingSourceTime => "missing_source_time",
                positron_kernel::EventRangeUnavailable::InvalidSourceTime => "invalid_source_time",
                positron_kernel::EventRangeUnavailable::LegacyFormat => "legacy_format",
            },
            "none".to_owned(),
            "none".to_owned(),
        ),
    }
}

fn ingest_range(
    range: positron_kernel::AuthenticatedIngestRange,
) -> (&'static str, String, String) {
    match range {
        positron_kernel::AuthenticatedIngestRange::Known { earliest, latest } => (
            "known",
            earliest.value().to_string(),
            latest.value().to_string(),
        ),
        positron_kernel::AuthenticatedIngestRange::Unavailable => {
            ("unavailable", "none".to_owned(), "none".to_owned())
        },
    }
}

pub(super) fn render_report(report: positron_kernel::IntegrityVerificationReport) -> String {
    let scope = report.scope();
    let signal = match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => "logs",
        positron_domain::routing::SignalKind::Traces => "traces",
    };
    let outcome = match report.outcome() {
        positron_kernel::IntegrityVerificationOutcome::Verified => "verified",
        positron_kernel::IntegrityVerificationOutcome::Incomplete => "incomplete",
        positron_kernel::IntegrityVerificationOutcome::Stale => "stale",
        positron_kernel::IntegrityVerificationOutcome::Quarantined => "quarantined",
        positron_kernel::IntegrityVerificationOutcome::Fenced => "fenced",
    };
    let quarantined = report
        .quarantined_segment()
        .map(|segment| hex(&segment.to_bytes()))
        .unwrap_or_else(|| "none".to_owned());
    let continuation = report
        .continuation()
        .map(|cursor| hex(&cursor.encode()))
        .unwrap_or_else(|| "none".to_owned());
    let localized = render_localized_observation(report.localized_finding());
    format!(
        "report_scope_tenant={} report_scope_signal={signal} report_scope_shard={} catalog_generation={} examined_segments={} examined_bytes={} omitted_segments={} outcome={outcome} continuation={continuation} quarantined_segment={quarantined} {localized} report_checksum={}\n",
        scope.tenant_id(),
        scope.shard_id().value(),
        report.catalog_generation(),
        report.examined_segments(),
        report.examined_bytes(),
        report.omitted_segments(),
        hex(&report.checksum()),
    )
}

fn render_localized_observation(
    finding: Option<positron_kernel::IntegrityQuarantineFinding>,
) -> String {
    let Some(finding) = finding else {
        return "localized_observation=none localized_publication=none".to_owned();
    };
    let scope = finding.scope();
    let signal = match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => "logs",
        positron_domain::routing::SignalKind::Traces => "traces",
    };
    let (event_provenance, event_earliest, event_latest) = event_range(finding.event_range());
    let (ingest_provenance, ingest_earliest, ingest_latest) = ingest_range(finding.ingest_range());
    format!(
        "localized_observation=observed localized_publication=not_published localized_tenant={} localized_signal={signal} localized_shard={} localized_segment={} localized_base_position={} localized_sealed_frontier={} localized_event_provenance={event_provenance} localized_event_earliest_unix_nanos={event_earliest} localized_event_latest_unix_nanos={event_latest} localized_ingest_provenance={ingest_provenance} localized_ingest_earliest_unix_nanos={ingest_earliest} localized_ingest_latest_unix_nanos={ingest_latest}",
        scope.tenant_id(),
        scope.shard_id().value(),
        hex(&finding.segment().to_bytes()),
        finding.base_position(),
        finding.sealed_frontier().value(),
    )
}

pub(super) fn render_aggregate_evidence(
    evidence: positron_runtime::OfflineIntegrityEvidence,
) -> String {
    let scope = evidence.scope();
    let signal = match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => "logs",
        positron_domain::routing::SignalKind::Traces => "traces",
    };
    let outcome = match evidence.outcome() {
        positron_kernel::IntegrityVerificationOutcome::Verified => "verified",
        positron_kernel::IntegrityVerificationOutcome::Incomplete => "incomplete",
        positron_kernel::IntegrityVerificationOutcome::Stale => "stale",
        positron_kernel::IntegrityVerificationOutcome::Quarantined => "quarantined",
        positron_kernel::IntegrityVerificationOutcome::Fenced => "fenced",
    };
    format!(
        "aggregate_evidence_tenant={} aggregate_evidence_signal={signal} aggregate_evidence_shard={} aggregate_evidence_generation={} aggregate_evidence_outcome={outcome} aggregate_evidence_checksum={}\n",
        scope.tenant_id(),
        scope.shard_id().value(),
        evidence.catalog_generation(),
        hex(&evidence.checksum()),
    )
}

pub(super) fn render_online_report(report: &OnlineVerificationReport) -> String {
    let continuation = report.continuation.as_deref().unwrap_or("none");
    let mut output = format!(
        "report_version={}\nmode=online\nstatus={}\nverification_complete={}\nreport_checksum={}\nreport_scope_tenant={} report_scope_signal={} report_scope_shard={} catalog_generation={} examined_segments={} examined_bytes={} omitted_segments={} continuation={}\n",
        report.report_version,
        report.outcome,
        report.verification_complete,
        report.report_checksum,
        report.tenant,
        report.signal,
        report.shard,
        report.catalog_generation,
        report.examined_segments,
        report.examined_bytes,
        report.omitted_segments,
        continuation,
    );
    for finding in &report.findings {
        output.push_str(&format!(
            "quarantine_tenant={} quarantine_signal={} quarantine_shard={} quarantine_segment={} quarantine_base_position={} quarantine_event_provenance={} quarantine_event_earliest_unix_nanos={} quarantine_event_latest_unix_nanos={} quarantine_ingest_provenance={} quarantine_ingest_earliest_unix_nanos={} quarantine_ingest_latest_unix_nanos={}\n",
            finding.tenant,
            finding.signal,
            finding.shard,
            finding.segment,
            finding.base_position,
            finding.event_range.provenance,
            finding.event_range.earliest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            finding.event_range.latest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            finding.ingest_range.provenance,
            finding.ingest_range.earliest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            finding.ingest_range.latest_unix_nanos.map_or_else(|| "none".to_owned(), |value| value.to_string()),
        ));
    }
    output
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}
