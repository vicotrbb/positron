use super::*;

pub(in crate::services) fn execute(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<(Vec<u8>, TransferredResourceReservation), ServiceFailure> {
    services.require_data_or_mutation_admission()?;
    let context = super::super::authorize(services, bearer)?;
    let request =
        api::LogQuerySessionRequest::decode(body).map_err(|_| ServiceFailure::InvalidRequest)?;
    let tenant = crate::services::context_tenant(context)?;
    let claim = WorkClaim::authenticated(
        tenant,
        context.principal_id(),
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, RESPONSE_WORKSPACE_BYTES)
            .map_err(|_| ServiceFailure::Internal)?,
    )
    .map_err(|_| ServiceFailure::Internal)?;
    let reservation = services
        .instance
        .resource_governor()
        .reserve(claim)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let batch_limit =
        u16::try_from(request.batch_limit).map_err(|_| ServiceFailure::InvalidRequest)?;
    use api::log_query_session_request::Operation;
    if let Some(api::log_query_session_request::Operation::Tail(tail)) = request.operation.as_ref()
    {
        let bytes = super::tail::execute(services, bearer, tail)?;
        return Ok((bytes, reservation.transfer()));
    }
    let cursor;
    let mode = match request.operation.as_ref() {
        Some(Operation::Execute(query)) => {
            let value = query
                .budget
                .as_ref()
                .ok_or(ServiceFailure::InvalidRequest)?;
            let budget = native_budget(value)?;
            super::super::QueryMode::Page {
                source: &query.pipeline,
                budget,
                batch_limit,
            }
        },
        Some(Operation::Resume(bytes)) => {
            cursor = positron_query::QueryCursor::from_bytes(bytes)
                .map_err(|_| ServiceFailure::InvalidRequest)?;
            super::super::QueryMode::Resume {
                cursor: &cursor,
                batch_limit,
            }
        },
        Some(Operation::Tail(_)) | None => return Err(ServiceFailure::InvalidRequest),
    };
    let bytes = super::super::with_log_query_events_mode(
        services,
        bearer,
        services.instance.logs_shard,
        mode,
        |events| render(events, true),
    )?;
    Ok((bytes, reservation.transfer()))
}

pub(in crate::services) fn cancel(
    services: &ServiceHandle,
    bearer: &str,
    body: &[u8],
) -> Result<(Vec<u8>, TransferredResourceReservation), ServiceFailure> {
    services.require_data_or_mutation_admission()?;
    if body.len() > api::MAX_CANCEL_REQUEST_BYTES {
        return Err(ServiceFailure::InvalidRequest);
    }
    let context = super::super::authorize(services, bearer)?;
    let tenant = crate::services::context_tenant(context)?;
    let claim = WorkClaim::authenticated(
        tenant,
        context.principal_id(),
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, CANCELLATION_WORKSPACE_BYTES)
            .map_err(|_| ServiceFailure::Internal)?,
    )
    .map_err(|_| ServiceFailure::Internal)?;
    let reservation = services
        .instance
        .resource_governor()
        .reserve(claim)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let request =
        api::LogQueryCancelRequest::decode(body).map_err(|_| ServiceFailure::InvalidRequest)?;
    super::super::with_native_query_service(
        services,
        bearer,
        services.instance.logs_shard,
        1,
        |service, context| match request.cursor.as_ref() {
            Some(api::log_query_cancel_request::Cursor::Query(bytes)) => {
                let cursor = positron_query::QueryCursor::from_bytes(bytes)
                    .map_err(|_| ServiceFailure::InvalidRequest)?;
                service
                    .cancel_cursor(context, &cursor)
                    .map_err(ServiceFailure::QueryCancellationFailed)
            },
            Some(api::log_query_cancel_request::Cursor::Tail(bytes)) => {
                let cursor = positron_query::TailCursor::from_bytes(bytes)
                    .map_err(|_| ServiceFailure::InvalidRequest)?;
                service
                    .cancel_tail_cursor(context, &cursor)
                    .map_err(ServiceFailure::QueryCancellationFailed)
            },
            None => Err(ServiceFailure::InvalidRequest),
        },
    )?;
    let bytes = serde_json::to_vec(&api::LogQueryCancelResponse { cancelled: true })
        .map_err(|_| ServiceFailure::Internal)?;
    Ok((bytes, reservation.transfer()))
}
