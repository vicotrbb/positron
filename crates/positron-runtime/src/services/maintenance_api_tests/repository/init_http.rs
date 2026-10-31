//! Resolve init capacity ambiguity by same-key lookup and at most one exact replay.
use positron_api::repository::{
    RepositoryRequest, RepositoryResponse, RepositoryServiceClient,
    RepositoryServiceClientFailure as WireFailure,
};
use std::time::Instant;

#[derive(Debug)]
pub(super) enum Failure {
    Refused(WireFailure),
    Unresolved(&'static str),
}
impl Failure {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Unresolved(label) => label,
            Self::Refused(failure) => match failure {
                WireFailure::InvalidRequest => "invalid_request",
                WireFailure::AuthenticationRejected => "authentication_rejected",
                WireFailure::SourceUnavailable => "source_unavailable",
                WireFailure::TaskUnavailable => "task_unavailable",
                WireFailure::StaleGeneration => "stale_generation",
                WireFailure::PreconditionFailed => "precondition_failed",
                WireFailure::IdempotencyConflict => "idempotency_conflict",
                WireFailure::AdministrationUnavailable => "administration_unavailable",
                WireFailure::CapacityUnavailable => "capacity_unavailable",
                WireFailure::Transport => "transport",
            },
        }
    }
}
pub(super) fn admit_once(
    client: &RepositoryServiceClient,
    credential: &str,
    request: &RepositoryRequest,
    deadline: Instant,
    physical_init_requests: &mut u64,
    replay_requests: &mut u64,
) -> Result<RepositoryResponse, Failure> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Failure::Unresolved("init_deadline"));
    }
    if request.action != "init" || request.idempotency_key.is_none() {
        return Err(Failure::Refused(WireFailure::InvalidRequest));
    }
    *physical_init_requests += 1;
    match client.manage_with_timeout(credential, request, remaining) {
        Err(WireFailure::CapacityUnavailable) => {},
        result => return result.map_err(Failure::Refused),
    }
    // Capacity may be projected after durable acceptance: freeze the same key
    // and request. Only an authenticated stale-basis refusal can return control
    // to the existing outer refresh; lookup absence alone cannot do so.
    let mut replayed = false;
    let lookup = RepositoryRequest {
        action: "lookup".into(),
        idempotency_key: request.idempotency_key.clone(),
        expected_catalog_generation: None,
        locator: None,
        repository_id: None,
        operation_id: None,
        aws_s3: None,
        google_cloud_storage: None,
        azure_blob: None,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Failure::Unresolved("lookup_deadline"));
        }
        let result = client.manage_with_timeout(credential, &lookup, remaining);
        if Instant::now() >= deadline {
            return Err(Failure::Unresolved("lookup_deadline"));
        }
        match result {
            Ok(response) => {
                if response.operation.is_none() {
                    return Err(Failure::Unresolved("lookup_operation_missing"));
                }
                if response.identity.as_ref().is_some_and(|identity| {
                    Some(&identity.repository_id) != request.repository_id.as_ref()
                }) {
                    return Err(Failure::Unresolved("lookup_repository_mismatch"));
                }
                return Ok(response);
            },
            Err(WireFailure::SourceUnavailable) if !replayed => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Failure::Unresolved("replay_deadline"));
                }
                // SourceUnavailable does not prove absence. Governance permits one
                // exact original replay; no field, principal, or basis is refreshed.
                replayed = true;
                *physical_init_requests += 1;
                *replay_requests += 1;
                let replay = client.manage_with_timeout(credential, request, remaining);
                if Instant::now() >= deadline {
                    return Err(Failure::Unresolved("replay_deadline"));
                }
                match replay {
                    Ok(response) => {
                        if response.operation.is_none() {
                            return Err(Failure::Unresolved("replay_operation_missing"));
                        }
                        if response.identity.as_ref().is_some_and(|identity| {
                            Some(&identity.repository_id) != request.repository_id.as_ref()
                        }) {
                            return Err(Failure::Unresolved("replay_repository_mismatch"));
                        }
                        return Ok(response);
                    },
                    Err(WireFailure::CapacityUnavailable) => {},
                    // This authenticated response is produced only after Governance
                    // checked committed bindings and recovered prepared acceptance.
                    Err(WireFailure::StaleGeneration) => {
                        return Err(Failure::Refused(WireFailure::StaleGeneration));
                    },
                    Err(failure) => {
                        return Err(Failure::Unresolved(match failure {
                            WireFailure::SourceUnavailable => "replay_binding_unavailable",
                            WireFailure::IdempotencyConflict => "replay_conflict",
                            WireFailure::AuthenticationRejected => "replay_authentication_rejected",
                            WireFailure::StaleGeneration => "replay_stale_generation",
                            WireFailure::InvalidRequest => "replay_invalid_request",
                            WireFailure::TaskUnavailable => "replay_task_unavailable",
                            WireFailure::PreconditionFailed => "replay_precondition_failed",
                            WireFailure::AdministrationUnavailable => {
                                "replay_administration_unavailable"
                            },
                            WireFailure::Transport => "replay_transport",
                            WireFailure::CapacityUnavailable => "replay_capacity_unavailable",
                        }));
                    },
                }
            },
            Err(WireFailure::CapacityUnavailable) => std::thread::sleep(
                std::time::Duration::from_millis(25)
                    .min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(failure) => {
                return Err(Failure::Unresolved(match failure {
                    WireFailure::SourceUnavailable => "binding_unavailable",
                    WireFailure::IdempotencyConflict => "lookup_conflict",
                    WireFailure::AuthenticationRejected => "lookup_authentication_rejected",
                    WireFailure::StaleGeneration => "lookup_stale_generation",
                    WireFailure::InvalidRequest => "lookup_invalid_request",
                    WireFailure::TaskUnavailable => "lookup_task_unavailable",
                    WireFailure::PreconditionFailed => "lookup_precondition_failed",
                    WireFailure::AdministrationUnavailable => "lookup_administration_unavailable",
                    WireFailure::Transport => "lookup_transport",
                    WireFailure::CapacityUnavailable => "lookup_capacity_unavailable",
                }));
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::status_http::Inspection;
    use super::*;
    use std::time::Duration;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    const CAPACITY: &str = r#"{"code":"capacity_unavailable"}"#;
    const ACCEPTED: &str = r#"{"catalog_generation":7,"operation":{"id":"22222222222222222222222222222222","status":"running","phase":"preflight","progress_percent":0,"retry":"never","cancellation":"not_allowed_after_drain","irreversible_boundary":"not_crossed"}}"#;
    fn scripted(
        responses: &[(u16, &str)],
        budget: Duration,
    ) -> TestResult<(Inspection, Vec<Vec<u8>>, Duration)> {
        let request = RepositoryRequest::decode(br#"{"action":"init","expected_catalog_generation":6,"idempotency_key":"61616161-6161-4161-8161-616161616161","repository_id":"62626262-6262-4262-8262-626262626262","locator":"/owned/fixture"}"#)?;
        super::super::status_http::tests::scripted_with(
            responses,
            &request,
            budget,
            |client, credential, request, deadline| {
                let mut physical = 0;
                let mut replays = 0;
                let result = admit_once(
                    client,
                    credential,
                    request,
                    deadline,
                    &mut physical,
                    &mut replays,
                );
                assert!(physical <= 2 && replays <= 1);
                result.map_err(|failure| failure.label().to_owned())
            },
        )
    }
    fn assert_one_init_same_key_lookups(requests: &[Vec<u8>]) -> TestResult {
        let mut bodies = requests.iter().map(|bytes| {
            let start = bytes
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .ok_or("request headers")?
                + 4;
            RepositoryRequest::decode(bytes.get(start..).ok_or("request body")?)
                .map_err(|_| "request decode")
        });
        let first = bodies.next().ok_or("init missing")??;
        assert_eq!(first.action, "init");
        for lookup in bodies {
            let lookup = lookup?;
            assert_eq!(lookup.action, "lookup");
            assert_eq!(lookup.idempotency_key, first.idempotency_key);
            assert!(lookup.expected_catalog_generation.is_none());
            assert!(
                lookup.locator.is_none()
                    && lookup.repository_id.is_none()
                    && lookup.operation_id.is_none()
            );
            assert!(
                lookup.aws_s3.is_none()
                    && lookup.google_cloud_storage.is_none()
                    && lookup.azure_blob.is_none()
            );
        }
        Ok(())
    }
    #[test]
    fn init_capacity_ambiguity_resolves_one_operation_without_another_init() -> TestResult {
        for responses in [
            vec![(503, CAPACITY), (200, ACCEPTED)],
            vec![(503, CAPACITY), (503, CAPACITY), (200, ACCEPTED)],
        ] {
            let (result, requests, _) = scripted(&responses, Duration::from_secs(10))?;
            let accepted =
                result.map_err(|error| format!("capacity ambiguity was not resolved: {error}"))?;
            assert_eq!(
                accepted.operation.ok_or("accepted operation")?.id,
                "22222222222222222222222222222222"
            );
            assert_eq!(requests.len(), responses.len());
            assert_one_init_same_key_lookups(&requests)?;
        }
        Ok(())
    }
    #[test]
    fn unresolved_lookup_cannot_refresh_or_repeat_init() -> TestResult {
        for (status, body, expected) in [
            (409, r#"{"code":"idempotency_conflict"}"#, "lookup_conflict"),
            (
                401,
                r#"{"code":"authentication_rejected"}"#,
                "lookup_authentication_rejected",
            ),
            (
                409,
                r#"{"code":"stale_generation"}"#,
                "lookup_stale_generation",
            ),
            (
                200,
                r#"{"catalog_generation":7}"#,
                "lookup_operation_missing",
            ),
        ] {
            let (result, requests, _) =
                scripted(&[(503, CAPACITY), (status, body)], Duration::from_secs(10))?;
            assert_eq!(
                result.expect_err("unresolved binding must fail closed"),
                expected
            );
            assert_eq!(requests.len(), 2);
            assert_one_init_same_key_lookups(&requests)?;
        }
        Ok(())
    }
    #[test]
    fn capacity_lookup_exhausts_the_original_deadline_without_more_init() -> TestResult {
        let (result, requests, _) = scripted(
            &[(503, CAPACITY), (503, CAPACITY), (503, CAPACITY)],
            Duration::from_millis(40),
        )?;
        assert_eq!(
            result.expect_err("capacity remains unavailable"),
            "lookup_deadline"
        );
        assert_one_init_same_key_lookups(&requests)?;
        assert!(requests.len() >= 2 && requests.len() <= 3);
        let (result, requests, _) = scripted(&[], Duration::ZERO)?;
        assert_eq!(result.expect_err("expired deadline"), "init_deadline");
        assert!(requests.is_empty());
        Ok(())
    }
    #[test]
    fn initial_stale_basis_and_other_refusals_remain_with_the_existing_owner() -> TestResult {
        for (status, body, expected) in [
            (409, r#"{"code":"stale_generation"}"#, "stale_generation"),
            (
                401,
                r#"{"code":"authentication_rejected"}"#,
                "authentication_rejected",
            ),
            (
                409,
                r#"{"code":"idempotency_conflict"}"#,
                "idempotency_conflict",
            ),
        ] {
            let (result, requests, _) = scripted(&[(status, body)], Duration::from_secs(10))?;
            assert_eq!(result.expect_err("direct refusal remains typed"), expected);
            assert_eq!(requests.len(), 1);
            assert_one_init_same_key_lookups(&requests)?;
        }
        Ok(())
    }

    #[test]
    fn lookup_repository_mismatch_cannot_be_accepted_or_restart_init() -> TestResult {
        let mut response: serde_json::Value = serde_json::from_str(ACCEPTED)?;
        response["identity"] = serde_json::json!({
            "repository_id": "73737373-7373-4373-8373-737373737373",
            "instance_id": "74747474-7474-4474-8474-747474747474",
            "provider_kind": "local_filesystem", "format_epoch": 1,
            "integrity_fingerprint": "11".repeat(32), "prefix_commitment": "22".repeat(32)
        });
        let body = serde_json::to_string(&response)?;
        let (result, requests, _) =
            scripted(&[(503, CAPACITY), (200, &body)], Duration::from_secs(10))?;
        assert_eq!(
            result.expect_err("wrong repository must fail closed"),
            "lookup_repository_mismatch"
        );
        assert_eq!(requests.len(), 2);
        assert_one_init_same_key_lookups(&requests)?;
        Ok(())
    }
    #[test]
    fn unavailable_binding_allows_only_one_identical_original_init_replay() -> TestResult {
        let unavailable = r#"{"code":"source_unavailable"}"#;
        for responses in [
            vec![(503, CAPACITY), (404, unavailable), (200, ACCEPTED)],
            vec![
                (503, CAPACITY),
                (404, unavailable),
                (503, CAPACITY),
                (200, ACCEPTED),
            ],
        ] {
            let (result, requests, _) = scripted(&responses, Duration::from_secs(10))?;
            assert_eq!(
                result
                    .map_err(|error| format!("exact replay did not resolve acceptance: {error}"))?
                    .operation
                    .ok_or("operation")?
                    .id,
                "22222222222222222222222222222222"
            );
            assert_eq!(requests.len(), responses.len());
            assert_eq!(
                requests.first(),
                requests.get(2),
                "replay must preserve every original request byte"
            );
            let mut lookups = vec![requests.first().ok_or("init")?.clone()];
            lookups.extend(
                requests
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index == 1 || *index == 3)
                    .map(|(_, request)| request.clone()),
            );
            assert_one_init_same_key_lookups(&lookups)?;
        }
        Ok(())
    }

    #[test]
    fn exact_replay_stale_generation_returns_to_existing_basis_refresh() -> TestResult {
        let request = RepositoryRequest::decode(br#"{"action":"init","expected_catalog_generation":6,"idempotency_key":"61616161-6161-4161-8161-616161616161","repository_id":"62626262-6262-4262-8262-626262626262","locator":"/owned/fixture"}"#)?;
        let (result, requests, _) = super::super::status_http::tests::scripted_with(
            &[
                (503, CAPACITY),
                (404, r#"{"code":"source_unavailable"}"#),
                (409, r#"{"code":"stale_generation"}"#),
            ],
            &request,
            Duration::from_secs(10),
            |client, credential, request, deadline| match admit_once(
                client, credential, request, deadline, &mut 0, &mut 0,
            ) {
                Err(Failure::Refused(WireFailure::StaleGeneration)) => {
                    Err("refreshable_stale_generation".into())
                },
                Err(other) => Err(other.label().into()),
                Ok(response) => Ok(response),
            },
        )?;
        assert_eq!(
            result.expect_err("stale basis"),
            "refreshable_stale_generation"
        );
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests.first(),
            requests.get(2),
            "only exact original replay may establish stale basis"
        );
        Ok(())
    }

    #[test]
    fn replay_refusal_or_second_unavailable_binding_cannot_send_another_init() -> TestResult {
        let unavailable = r#"{"code":"source_unavailable"}"#;
        for (status, body, expected) in [
            (409, r#"{"code":"stale_generation"}"#, "stale_generation"),
            (409, r#"{"code":"idempotency_conflict"}"#, "replay_conflict"),
            (
                401,
                r#"{"code":"authentication_rejected"}"#,
                "replay_authentication_rejected",
            ),
        ] {
            let (result, requests, _) = scripted(
                &[(503, CAPACITY), (404, unavailable), (status, body)],
                Duration::from_secs(10),
            )?;
            assert_eq!(
                result.expect_err("ambiguous replay refusal must stop"),
                expected
            );
            assert_eq!(requests.len(), 3);
            assert_eq!(requests.first(), requests.get(2));
        }
        let (result, requests, _) = scripted(
            &[
                (503, CAPACITY),
                (404, unavailable),
                (503, CAPACITY),
                (404, unavailable),
            ],
            Duration::from_secs(10),
        )?;
        assert_eq!(
            result.expect_err("second unresolved binding"),
            "binding_unavailable"
        );
        assert_eq!(requests.len(), 4);
        assert_eq!(requests.first(), requests.get(2));
        Ok(())
    }
}
