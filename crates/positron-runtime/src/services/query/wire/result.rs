use super::{ServiceFailure, api, value};
use positron_domain::time::{QueryTimeProvenance, SourceTimeQuality};
use positron_query::{QueryHeader, QueryRecord, QueryStats, ResultValueType};

pub(super) fn budget(value: positron_query::QueryBudget) -> api::LogQueryBudget {
    api::LogQueryBudget {
        scanned_bytes: value.scanned_bytes(),
        decoded_records: value.decoded_records(),
        output_rows: value.output_rows(),
        output_bytes: value.output_bytes(),
        memory_bytes: value.memory_bytes(),
        cpu_work_units: value.cpu_work_units(),
        wall_seconds: value.wall_seconds(),
        maximum_time_range_nanoseconds: value.maximum_time_range_nanoseconds(),
    }
}
pub(super) fn header(header: &QueryHeader) -> Result<api::LogQueryHeader, ServiceFailure> {
    if header.tail_phase().is_some() || header.correlation_snapshot().is_some() {
        return Err(ServiceFailure::InvalidRequest);
    }
    let names = header.schema().columns();
    let types = header.schema().types();
    let nullable = header.schema().nullable();
    if names.len() != types.len() || names.len() != nullable.len() || names.len() > 128 {
        return Err(ServiceFailure::Internal);
    }
    let mut columns = Vec::new();
    columns
        .try_reserve_exact(names.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for ((name, kind), nullable) in names.into_iter().zip(types).zip(nullable) {
        columns.push(api::LogQueryColumn {
            name: value::text(name)?,
            value_type: type_name(*kind).into(),
            nullable: *nullable,
        });
    }
    let order = header.ordering();
    let names = order.columns();
    if names.len() != order.types().len() || names.len() != order.directions().len() {
        return Err(ServiceFailure::Internal);
    }
    let mut ordering = Vec::new();
    ordering
        .try_reserve_exact(names.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for ((name, kind), direction) in names.into_iter().zip(order.types()).zip(order.directions()) {
        ordering.push(api::LogQueryOrdering {
            column: value::text(name)?,
            value_type: type_name(*kind).into(),
            direction: match direction {
                positron_query::OrderDirection::Ascending => "ascending",
                positron_query::OrderDirection::Descending => "descending",
            }
            .into(),
        });
    }
    let snapshot = header.snapshot();
    let lease = header.lease();
    Ok(api::LogQueryHeader {
        columns,
        snapshot: Some(api::LogQuerySnapshot {
            identity: snapshot.identity().to_vec(),
            generation: snapshot.generation(),
            frontier: snapshot.frontier(),
        }),
        ordering,
        effective_budget: Some(budget(header.budget())),
        lease: Some(api::LogQueryLease {
            identity: lease.identity().to_vec(),
            expiry_unix_seconds: lease.expiry(),
        }),
        initial_cursor: header
            .initial_cursor()
            .map(|cursor| cursor.as_bytes().to_vec()),
    })
}
pub(super) fn row(
    row: &QueryRecord,
    types: &[ResultValueType],
) -> Result<api::LogQueryRow, ServiceFailure> {
    use api::log_query_cell::Value;
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(types.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for (index, kind) in types.iter().enumerate() {
        let item = match kind {
            ResultValueType::NativeValue => row
                .body_value()
                .map(|value| value::native(value, 0))
                .transpose()?
                .map(Value::NativeValue),
            ResultValueType::AttributeOccurrenceSet => row
                .attribute_occurrence_set(index)
                .map(|set| {
                    let mut values = Vec::new();
                    values
                        .try_reserve_exact(set.len())
                        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                    for index in 0..set.len() {
                        values.push(value::native(
                            set.occurrence(index).ok_or(ServiceFailure::Internal)?,
                            0,
                        )?);
                    }
                    Ok::<_, ServiceFailure>(Value::Occurrences(api::LogQueryOccurrences { values }))
                })
                .transpose()?,
            ResultValueType::QueryTime => row.query_time_value().map(|time| {
                Value::Timestamp(api::LogQueryTimestamp {
                    unix_nanoseconds: Some(time.instant().value()),
                    provenance: match time.provenance() {
                        QueryTimeProvenance::Event => "event",
                        QueryTimeProvenance::Observed => "observed",
                        QueryTimeProvenance::Ingest => "ingest",
                    }
                    .into(),
                    quality: String::new(),
                    source_value: None,
                })
            }),
            ResultValueType::EventTime => row.event_time_value().map(|time| {
                Value::Timestamp(api::LogQueryTimestamp {
                    unix_nanoseconds: time.instant().map(|time| time.value()),
                    provenance: String::new(),
                    quality: match time.quality() {
                        SourceTimeQuality::Usable => "usable",
                        SourceTimeQuality::Missing => "missing",
                        SourceTimeQuality::Zero => "zero",
                        SourceTimeQuality::Outlier => "outlier",
                        SourceTimeQuality::Contradictory => "contradictory",
                    }
                    .into(),
                    source_value: time.source_value(),
                })
            }),
            ResultValueType::IngestTime => row.ingest_time_value().map(|time| {
                Value::Timestamp(api::LogQueryTimestamp {
                    unix_nanoseconds: Some(time.instant().value()),
                    provenance: "kernel".into(),
                    quality: String::new(),
                    source_value: None,
                })
            }),
            ResultValueType::CommitPosition => {
                Some(Value::UnsignedInteger(row.commit_position().value()))
            },
            ResultValueType::RecordOrdinal => Some(Value::UnsignedInteger(u64::from(
                row.record_ordinal().value(),
            ))),
            ResultValueType::UnsignedInteger => row.count().map(Value::UnsignedInteger),
            // These legacy schema tags are not emitted by current Log planning.
            ResultValueType::UnixNanoseconds | ResultValueType::OptionalUnixNanoseconds => {
                return Err(ServiceFailure::Internal);
            },
        };
        cells.push(api::LogQueryCell {
            value: Some(item.unwrap_or(Value::Missing(api::LogQueryMissing {}))),
        });
    }
    Ok(api::LogQueryRow {
        cells,
        replayed: row.replayed(),
    })
}
pub(super) fn stats(value: QueryStats) -> api::LogQueryStats {
    api::LogQueryStats {
        records: value.records(),
        scanned_bytes: value.scanned_bytes(),
        decoded_records: value.decoded_records(),
        output_bytes: value.output_bytes(),
        memory_peak_bytes: value.memory_peak_bytes(),
        cpu_work_units: value.cpu_work_units(),
        wall_seconds: value.wall_seconds(),
        last_sequence: value.last_sequence(),
        result_digest: value.result_digest().to_vec(),
        cumulative_budget: Some(budget(value.cumulative_budget())),
        resume_count: value.resume_count(),
        repeated_batch_count: value.repeated_batch_count(),
        limiting_budget: value
            .limiting_budget()
            .map(|value| budget_name(value).into()),
        reduced_pruning: value.reduced_pruning(),
    }
}
pub(super) const fn type_name(kind: ResultValueType) -> &'static str {
    match kind {
        ResultValueType::NativeValue => "native_value",
        ResultValueType::UnixNanoseconds => "unix_nanoseconds",
        ResultValueType::OptionalUnixNanoseconds => "optional_unix_nanoseconds",
        ResultValueType::QueryTime => "query_time",
        ResultValueType::EventTime => "event_time",
        ResultValueType::IngestTime => "ingest_time",
        ResultValueType::CommitPosition => "commit_position",
        ResultValueType::RecordOrdinal => "record_ordinal",
        ResultValueType::UnsignedInteger => "unsigned_integer",
        ResultValueType::AttributeOccurrenceSet => "attribute_occurrence_set",
    }
}
pub(super) const fn budget_name(value: positron_query::QueryBudgetDimension) -> &'static str {
    use positron_query::QueryBudgetDimension::*;
    match value {
        ScannedBytes => "scanned_bytes",
        DecodedRecords => "decoded_records",
        OutputRows => "output_rows",
        OutputBytes => "output_bytes",
        MemoryBytes => "memory_bytes",
        CpuWorkUnits => "cpu_work_units",
        WallSeconds => "wall_seconds",
        MaximumTimeRangeNanoseconds => "maximum_time_range_nanoseconds",
    }
}
