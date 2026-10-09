use std::io::{Read, Write};

use http::{HeaderMap, Method, Uri};
use positron_api::generated::{ApiError, CapabilityResponse};
use positron_governance::CompatibilityHints;
use zeroize::{Zeroize, Zeroizing};

use super::super::TrustedProxy;
use crate::health::MaintenanceHealth;
use crate::{
    ConfigurationObservation, DoctorRuntimeFacts, HealthWarning, ListenerRole, ProcessPhase,
};
use positron_kernel::TransferredResourceReservation;

const MAX_HEADER_BYTES: usize = 8 * 1024;

pub(in crate::native_host) struct RequestHead {
    pub(in crate::native_host) method: String,
    pub(in crate::native_host) path: String,
    pub(in crate::native_host) content_length: usize,
    pub(in crate::native_host) bearer: Option<String>,
    pub(in crate::native_host) content_type: Option<String>,
    pub(in crate::native_host) content_encoding: Option<String>,
    pub(in crate::native_host) tenant_hint: Option<String>,
    pub(in crate::native_host) forwarded_for: Option<String>,
    pub(in crate::native_host) forwarded_actor: Option<String>,
}

impl RequestHead {
    pub(in crate::native_host) fn compatibility_hints(
        &self,
        peer: std::net::SocketAddr,
        trusted_proxy: Option<TrustedProxy>,
    ) -> Result<CompatibilityHints, ()> {
        let forwarded = self.forwarded_for.is_some() || self.forwarded_actor.is_some();
        match trusted_proxy {
            Some(policy) if forwarded => {
                if !policy.validates(peer, self.forwarded_for.as_deref()) {
                    return Err(());
                }
                CompatibilityHints::trusted_proxy(
                    self.tenant_hint.as_deref(),
                    self.forwarded_actor.as_deref(),
                )
                .map_err(|_| ())
            },
            Some(_) | None => self
                .tenant_hint
                .as_deref()
                .map(CompatibilityHints::external_tenant_alias)
                .transpose()
                .map_err(|_| ())
                .map(|hints| hints.unwrap_or_else(CompatibilityHints::none)),
        }
    }
}

pub(in crate::native_host) fn read_head<S: Read>(stream: &mut S) -> Result<RequestHead, Response> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(512));
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER_BYTES {
            return Err(Response::empty(431));
        }
        stream
            .read_exact(&mut byte)
            .map_err(|_| Response::empty(400))?;
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Response::empty(400))?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next().ok_or_else(|| Response::empty(400))?.split(' ');
    let method = request.next().ok_or_else(|| Response::empty(400))?;
    let path = request.next().ok_or_else(|| Response::empty(400))?;
    if request.next() != Some("HTTP/1.1") || request.next().is_some() {
        return Err(Response::empty(400));
    }
    let mut content_length: Option<usize> = None;
    let mut bearer = None;
    let mut authorization_seen = false;
    let mut content_type = None;
    let mut content_encoding = None;
    let mut tenant_hint = None;
    let mut forwarded_for = None;
    let mut forwarded_actor = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| Response::empty(400))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Response::empty(400));
            }
            content_length = Some(value.parse().map_err(|_| Response::empty(400))?);
        } else if name.eq_ignore_ascii_case("authorization") {
            if authorization_seen {
                return Err(Response::empty(400));
            }
            authorization_seen = true;
            bearer = value.strip_prefix("Bearer ").map(ToOwned::to_owned);
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return Err(Response::empty(400));
            }
            content_type = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.is_some() {
                return Err(Response::empty(400));
            }
            content_encoding = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-scope-orgid") {
            if tenant_hint.is_some() {
                return Err(Response::empty(400));
            }
            tenant_hint = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-forwarded-for") {
            if forwarded_for.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_for = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-forwarded-user")
            || name.eq_ignore_ascii_case("x-forwarded-service")
        {
            if forwarded_actor.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_actor = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Response::empty(400));
        }
    }
    Ok(RequestHead {
        method: method.to_owned(),
        path: path.to_owned(),
        content_length: content_length.unwrap_or(0),
        bearer,
        content_type,
        content_encoding,
        tenant_hint,
        forwarded_for,
        forwarded_actor,
    })
}

pub(in crate::native_host) fn head_from_http_parts(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body_length: usize,
) -> Result<RequestHead, Response> {
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let mut content_length: Option<usize> = None;
    let mut bearer = None;
    let mut authorization_seen = false;
    let mut content_type = None;
    let mut content_encoding = None;
    let mut tenant_hint = None;
    let mut forwarded_for = None;
    let mut forwarded_actor = None;
    for (name, value) in headers {
        let value = value.to_str().map_err(|_| Response::empty(400))?.trim();
        if name == http::header::CONTENT_LENGTH {
            if content_length.is_some() {
                return Err(Response::empty(400));
            }
            content_length = Some(value.parse().map_err(|_| Response::empty(400))?);
        } else if name == http::header::AUTHORIZATION {
            if authorization_seen {
                return Err(Response::empty(400));
            }
            authorization_seen = true;
            bearer = value.strip_prefix("Bearer ").map(ToOwned::to_owned);
        } else if name == http::header::CONTENT_TYPE {
            if content_type.is_some() {
                return Err(Response::empty(400));
            }
            content_type = Some(value.to_owned());
        } else if name == http::header::CONTENT_ENCODING {
            if content_encoding.is_some() {
                return Err(Response::empty(400));
            }
            content_encoding = Some(value.to_owned());
        } else if name.as_str().eq_ignore_ascii_case("x-scope-orgid") {
            if tenant_hint.is_some() {
                return Err(Response::empty(400));
            }
            tenant_hint = Some(value.to_owned());
        } else if name.as_str().eq_ignore_ascii_case("x-forwarded-for") {
            if forwarded_for.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_for = Some(value.to_owned());
        } else if name.as_str().eq_ignore_ascii_case("x-forwarded-user")
            || name.as_str().eq_ignore_ascii_case("x-forwarded-service")
        {
            if forwarded_actor.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_actor = Some(value.to_owned());
        } else if name == http::header::TRANSFER_ENCODING {
            return Err(Response::empty(400));
        }
    }
    if content_length.is_some_and(|length| length != body_length) {
        return Err(Response::empty(400));
    }
    Ok(RequestHead {
        method: method.as_str().to_owned(),
        path: path.to_owned(),
        content_length: body_length,
        bearer,
        content_type,
        content_encoding,
        tenant_hint,
        forwarded_for,
        forwarded_actor,
    })
}

pub(in crate::native_host) fn read_body<S: Read>(
    stream: &mut S,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, Response> {
    if length > maximum {
        return Err(Response::empty(413));
    }
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|_| Response::empty(400))?;
    Ok(body)
}

pub(in crate::native_host) fn health_response(
    healthy: bool,
    label: &'static str,
    warnings: &[HealthWarning],
) -> Response {
    let warnings =
        warnings
            .iter()
            .enumerate()
            .fold(String::from("["), |mut rendered, (index, warning)| {
                if index > 0 {
                    rendered.push(',');
                }
                rendered.push('\"');
                rendered.push_str(warning.label());
                rendered.push('\"');
                rendered
            })
            + "]";
    if healthy {
        Response::json(
            200,
            format!("{{\"status\":\"{label}\",\"warnings\":{warnings}}}"),
        )
    } else {
        Response::json(
            503,
            format!("{{\"status\":\"not_{label}\",\"warnings\":{warnings}}}"),
        )
    }
}

pub(in crate::native_host) fn configuration_status_response(
    phase: ProcessPhase,
    integrity_degraded: bool,
    status: &ConfigurationObservation,
    maintenance: MaintenanceHealth,
    doctor: DoctorRuntimeFacts,
    bound_listener_roles: u8,
) -> Response {
    let required_families = required_families_json(
        phase,
        integrity_degraded,
        status,
        maintenance,
        doctor,
        bound_listener_roles,
    );
    Response::json(
        200,
        format!(
            "{{\"phase\":\"{}\",\"integrity_degraded\":{},\"observed_generation\":{},\"effective_digest\":\"{}\",\"desired_digest\":\"{}\",\"drift_disposition\":\"{}\",\"pending_restart\":{},\"doctor\":{{\"key_custody\":\"{}\",\"catalog_bootstrap\":\"{}\",\"catalog_generation\":{},\"backup_repository\":\"{}\",\"durable_operations\":{},\"active_durable_operations\":{},\"snapshot_leases\":{},\"listener_topology\":{{\"control\":{},\"operations\":{},\"api\":{},\"otlp_grpc\":{},\"otlp_http\":{},\"loki_push\":{}}},\"required_families\":{required_families}}},\"maintenance\":{{\"queued\":{},\"running\":{},\"deferred\":{},\"terminal\":{},\"failed\":{},\"clock_uncertain\":{},\"oldest_queued_age_seconds\":{},\"lower_class_queue_delay_breaches\":{},\"running_no_durable_progress_slo_breaches\":{},\"running_no_durable_progress_slo_unknown\":{},\"checkpointed_tasks\":{},\"paused_tasks\":{},\"conflicted_tasks\":{},\"completed_inputs\":{},\"input_objects\":{},\"outstanding_reservations\":{},\"maximum_outstanding_reservations\":{},\"outstanding_maintenance_reservations\":{},\"global_reservation_classes\":{{\"durability_recovery\":{},\"security_lifecycle\":{},\"ingest\":{},\"interactive_query_tail\":{},\"ordinary_maintenance_backup\":{}}},\"failure_classes\":{{\"identity_mismatch\":{},\"stale_generation\":{},\"unclassified\":{}}}}}}}",
            process_phase_name(phase),
            integrity_degraded,
            status.generation(),
            hexadecimal_digest(crate::configuration_catalog::configuration_digest(
                status.effective()
            )),
            hexadecimal_digest(crate::configuration_catalog::configuration_digest(
                status.desired()
            )),
            drift_disposition_name(status.drift_disposition()),
            status.pending_restart().is_some(),
            if doctor.key_custody_verified() {
                "verified"
            } else {
                "unavailable"
            },
            if doctor.catalog_bootstrap_verified() {
                "verified"
            } else {
                "unavailable"
            },
            doctor.catalog_generation(),
            doctor.backup_repository().label(),
            doctor.durable_operations(),
            doctor.active_durable_operations(),
            doctor.snapshot_leases(),
            listener_bound(bound_listener_roles, ListenerRole::Control),
            listener_bound(bound_listener_roles, ListenerRole::Operations),
            listener_bound(bound_listener_roles, ListenerRole::Api),
            listener_bound(bound_listener_roles, ListenerRole::OtlpGrpc),
            listener_bound(bound_listener_roles, ListenerRole::OtlpHttp),
            listener_bound(bound_listener_roles, ListenerRole::LokiPush),
            maintenance.queued(),
            maintenance.running(),
            maintenance.deferred(),
            maintenance.terminal(),
            maintenance.failed(),
            maintenance.clock_uncertain(),
            maintenance
                .oldest_queued_age_seconds()
                .map_or_else(|| "null".to_owned(), |age| age.to_string()),
            maintenance.lower_class_queue_delay_breaches(),
            maintenance.running_no_durable_progress_slo_breaches(),
            maintenance.running_no_durable_progress_slo_unknown(),
            maintenance.checkpointed_tasks(),
            maintenance.paused_tasks(),
            maintenance.conflicted_tasks(),
            maintenance.completed_inputs(),
            maintenance.input_objects(),
            maintenance.outstanding_reservations(),
            maintenance.maximum_outstanding_reservations(),
            maintenance.outstanding_maintenance_reservations(),
            maintenance.durability_recovery_reservations(),
            maintenance.security_lifecycle_reservations(),
            maintenance.ingest_reservations(),
            maintenance.interactive_query_tail_reservations(),
            maintenance.ordinary_maintenance_backup_reservations(),
            maintenance.failed_identity_mismatch(),
            maintenance.failed_stale_generation(),
            maintenance.failed_unclassified(),
        ),
    )
}

pub(in crate::native_host) fn fenced_doctor_response(
    doctor: DoctorRuntimeFacts,
    bound_listener_roles: u8,
    reason: Option<crate::IntegrityFenceReason>,
) -> Response {
    let reason = reason.map_or("none", crate::IntegrityFenceReason::redacted_label);
    Response::json(
        200,
        format!(
            "{{\"phase\":\"fenced\",\"liveness\":\"live\",\"readiness\":\"not_ready\",\"reason\":\"{reason}\",\"doctor\":{{\"key_custody\":\"{}\",\"catalog_bootstrap\":\"{}\",\"catalog_generation\":{},\"backup_repository\":\"{}\",\"listener_topology\":{{\"control\":{},\"operations\":{},\"api\":{},\"otlp_grpc\":{},\"otlp_http\":{},\"loki_push\":{}}}}}}}",
            if doctor.key_custody_verified() {
                "verified"
            } else {
                "unavailable"
            },
            if doctor.catalog_bootstrap_verified() {
                "verified"
            } else {
                "unavailable"
            },
            doctor.catalog_generation(),
            doctor.backup_repository().label(),
            listener_bound(bound_listener_roles, ListenerRole::Control),
            listener_bound(bound_listener_roles, ListenerRole::Operations),
            listener_bound(bound_listener_roles, ListenerRole::Api),
            listener_bound(bound_listener_roles, ListenerRole::OtlpGrpc),
            listener_bound(bound_listener_roles, ListenerRole::OtlpHttp),
            listener_bound(bound_listener_roles, ListenerRole::LokiPush),
        ),
    )
}

fn listener_bound(roles: u8, role: ListenerRole) -> bool {
    roles & crate::health::listener_role_bit(role) != 0
}

fn required_families_json(
    phase: ProcessPhase,
    integrity_degraded: bool,
    status: &ConfigurationObservation,
    maintenance: MaintenanceHealth,
    doctor: DoctorRuntimeFacts,
    bound_listener_roles: u8,
) -> String {
    use positron_config::NetworkListenerRole;

    let network_roles = [
        (ListenerRole::Operations, NetworkListenerRole::Operations),
        (ListenerRole::Api, NetworkListenerRole::Api),
        (ListenerRole::OtlpGrpc, NetworkListenerRole::OtlpGrpc),
        (ListenerRole::OtlpHttp, NetworkListenerRole::OtlpHttp),
        (ListenerRole::LokiPush, NetworkListenerRole::LokiPush),
    ];
    let effective = status.effective();
    let all_network_bound = network_roles
        .iter()
        .all(|(runtime_role, _)| listener_bound(bound_listener_roles, *runtime_role));
    let all_tls_certificates_loaded = network_roles.iter().all(|(runtime_role, config_role)| {
        effective
            .network_listener_profile(*config_role)
            .is_some_and(|profile| {
                profile.transport() == positron_config::NetworkTransport::PlaintextOptOut
                    || listener_bound(bound_listener_roles, *runtime_role)
            })
    });
    let proxy_trust_configured = network_roles.iter().any(|(_, config_role)| {
        effective
            .network_listener_profile(*config_role)
            .is_some_and(|profile| !profile.trusted_proxy_cidrs().is_empty())
    });
    let fairness = if maintenance.lower_class_queue_delay_breaches() == 0 {
        "within_bound"
    } else {
        "breached"
    };
    let listener_profiles = if all_network_bound {
        "active"
    } else {
        "incomplete"
    };
    let listener_certificates = if all_tls_certificates_loaded {
        "loaded_or_not_required"
    } else {
        "not_loaded"
    };
    let proxy_trust = if proxy_trust_configured {
        "configured"
    } else {
        "not_configured"
    };
    let drain = match phase {
        ProcessPhase::Serving => "accepting",
        ProcessPhase::Draining => "draining",
        _ => "not_serving",
    };
    let health_derivation = match (phase, integrity_degraded) {
        (ProcessPhase::Serving, false) => "serving_ready_live",
        (ProcessPhase::Serving, true) => "serving_integrity_degraded",
        (ProcessPhase::Fenced, _) => "fenced_not_ready_live",
        _ => "not_ready_live",
    };
    let configuration_sources = if effective
        .source_for("runtime.max_registered_tenants")
        .is_some()
    {
        "redacted"
    } else {
        "unavailable"
    };
    format!(
        "{{\"catalog_integrity\":{{\"disposition\":\"observed\",\"audit_chain\":\"verified\",\"frontier\":{},\"manifest_objects\":{},\"reachable_ledger_scopes\":{},\"quarantine_findings\":{},\"scrub\":\"observed\",\"scrub_tasks\":{},\"scrub_checkpoints\":{}}},\"resource_governor\":{{\"disposition\":\"observed\",\"queues\":\"observed\",\"fairness\":\"{fairness}\",\"recovery_reserve\":\"configured\",\"recovery_reserve_memory_bytes\":{}}},\"listener_security\":{{\"disposition\":\"observed\",\"profiles\":\"{listener_profiles}\",\"certificates\":\"{listener_certificates}\",\"proxy_trust\":\"{proxy_trust}\",\"drain\":\"{drain}\"}},\"backup_verification\":{{\"disposition\":\"not_shipped\",\"manifest_verification\":\"not_shipped\",\"purge_compatibility\":\"not_shipped\"}},\"health_state\":{{\"disposition\":\"observed\",\"derivation\":\"{health_derivation}\"}},\"configuration\":{{\"disposition\":\"observed\",\"contract\":\"valid\",\"effective_sources\":\"{configuration_sources}\",\"key_custody\":\"{}\"}}}}",
        doctor.catalog_audit_frontier(),
        doctor.catalog_manifest_objects(),
        doctor.catalog_reachable_ledger_scopes(),
        doctor.catalog_quarantine_findings(),
        doctor.integrity_scrub_tasks(),
        doctor.integrity_scrub_checkpoints(),
        maintenance.recovery_reserve_memory_bytes(),
        if doctor.key_custody_verified() {
            "verified"
        } else {
            "unavailable"
        },
    )
}

fn process_phase_name(phase: ProcessPhase) -> &'static str {
    match phase {
        ProcessPhase::Starting => "starting",
        ProcessPhase::Recovering => "recovering",
        ProcessPhase::Serving => "serving",
        ProcessPhase::Draining => "draining",
        ProcessPhase::Fenced => "fenced",
        ProcessPhase::Stopping => "stopping",
        ProcessPhase::Stopped => "stopped",
    }
}

fn drift_disposition_name(
    disposition: positron_config::ConfigurationDriftDisposition,
) -> &'static str {
    match disposition {
        positron_config::ConfigurationDriftDisposition::None => "none",
        positron_config::ConfigurationDriftDisposition::Reconcile => "reconcile",
        positron_config::ConfigurationDriftDisposition::Fence => "fence",
    }
}

fn hexadecimal_digest(digest: [u8; 32]) -> String {
    let mut rendered = String::with_capacity(64);
    for byte in digest {
        const HEXADECIMAL: &[u8; 16] = b"0123456789abcdef";
        rendered.push(char::from(HEXADECIMAL[usize::from(byte >> 4)]));
        rendered.push(char::from(HEXADECIMAL[usize::from(byte & 0x0f)]));
    }
    rendered
}

pub(in crate::native_host) fn capability_response(
    result: Result<CapabilityResponse, ApiError>,
) -> Response {
    match result {
        Ok(response) => {
            let refusal = response.refusal().map_or_else(
                || "null".to_owned(),
                |error| {
                    format!(
                        "{{\"code\":{},\"retry_class\":{},\"completion_state\":{},\"source\":{},\"safe_detail\":{}}}",
                        error.code() as u32,
                        error.retry_class() as u32,
                        error.completion_state() as u32,
                        error.source() as u32,
                        error.safe_detail() as u32
                    )
                },
            );
            Response::json(
                200,
                format!(
                    "{{\"api_major\":{},\"schema_digest\":\"{}\",\"availability\":{},\"refusal\":{},\"deprecation\":{},\"capability\":{}}}",
                    response.api_major().major(),
                    response.schema_digest().as_str(),
                    response.availability() as u32,
                    refusal,
                    response.deprecation() as u32,
                    response.capability() as u32
                ),
            )
        },
        Err(error) => Response::json(400, format!("{{\"code\":{}}}", error.code() as u32)),
    }
}

pub(in crate::native_host) struct Response {
    pub(in crate::native_host) status: u16,
    pub(in crate::native_host) content_type: &'static str,
    pub(in crate::native_host) body: Vec<u8>,
    pub(in crate::native_host) retry_after_seconds: Option<u32>,
    pub(in crate::native_host) diagnostics_reservation: Option<Box<TransferredResourceReservation>>,
}

impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl Response {
    pub(in crate::native_host) fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: Vec::new(),
            retry_after_seconds: None,
            diagnostics_reservation: None,
        }
    }

    pub(in crate::native_host) fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into_bytes(),
            retry_after_seconds: None,
            diagnostics_reservation: None,
        }
    }

    pub(in crate::native_host) fn protobuf(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/x-protobuf",
            body,
            retry_after_seconds: None,
            diagnostics_reservation: None,
        }
    }

    pub(in crate::native_host) const fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    #[cfg(test)]
    pub(in crate::native_host) const fn status(&self) -> u16 {
        self.status
    }

    #[cfg(test)]
    pub(in crate::native_host) const fn content_type(&self) -> &'static str {
        self.content_type
    }

    #[cfg(test)]
    pub(in crate::native_host) fn body(&self) -> &[u8] {
        &self.body
    }

    #[cfg(test)]
    pub(in crate::native_host) const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }
}

pub(in crate::native_host) fn write_response<S: Write>(
    stream: &mut S,
    mut response: Response,
) -> Result<(), std::io::Error> {
    let reason = match response.status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let retry_after = response
        .retry_after_seconds
        .map_or_else(String::new, |seconds| format!("Retry-After: {seconds}\r\n"));
    let content_length = if response.status == 204 {
        String::new()
    } else {
        format!("Content-Length: {}\r\n", response.body.len())
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}{}Connection: close\r\n\r\n",
        response.status, reason, response.content_type, content_length, retry_after
    );
    stream.write_all(header.as_bytes())?;
    let outcome = if response.status == 204 {
        Ok(())
    } else {
        stream.write_all(&response.body)
    };
    drop(response.diagnostics_reservation.take());
    outcome
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::super::{TimeoutStream, serve_tls_connection};

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryStream {
        fn request(path: &str) -> Self {
            Self {
                input: Cursor::new(
                    format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n")
                        .into_bytes(),
                ),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
            self.input.read(buffer)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    impl TimeoutStream for MemoryStream {
        fn set_timeouts(&mut self, _timeout: std::time::Duration) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    #[test]
    fn native_http_success_and_timeout_status_lines_are_truthful() -> Result<(), std::io::Error> {
        for (status, reason) in [(204, "No Content"), (408, "Request Timeout")] {
            let mut output = Vec::new();
            super::write_response(&mut output, super::Response::empty(status))?;
            let response = std::str::from_utf8(&output).expect("HTTP response");
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status} {reason}\r\n")),
                "{response}"
            );
            assert!(response.ends_with("\r\n\r\n"));
            if status == 204 {
                assert!(!response.contains("Content-Length:"), "{response}");
            }
        }
        Ok(())
    }

    #[test]
    fn tls_api_dispatch_reaches_each_existing_authenticated_route() {
        let health = crate::health::ProcessState::starting().health();
        for path in [
            positron_api::tenant_aliases::HTTP_PATH,
            positron_api::policy::HTTP_EXPLAIN_PATH,
            positron_api::policy::HTTP_ACTIVATE_PATH,
        ] {
            let mut stream = MemoryStream::request(path);
            assert!(
                serve_tls_connection(
                    &mut stream,
                    crate::ListenerRole::Api,
                    "127.0.0.1:1".parse().expect("loopback peer"),
                    None,
                    &health,
                    super::super::RouteDependencies::new(None, None),
                    crate::ConnectionProtection::new(
                        std::num::NonZeroU16::MIN,
                        std::time::Duration::from_secs(1),
                        std::time::Duration::from_secs(1),
                        std::time::Duration::from_secs(1),
                        std::time::Duration::from_secs(1),
                        std::time::Duration::from_secs(1),
                    ),
                )
                .is_ok()
            );
            let response = std::str::from_utf8(&stream.output).expect("HTTP response");
            assert!(
                response.starts_with("HTTP/1.1 503 Service Unavailable"),
                "TLS dispatcher did not reach {path}: {response}"
            );
        }
    }
}
