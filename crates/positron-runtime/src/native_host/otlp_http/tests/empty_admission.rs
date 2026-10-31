//! Empty exports still cross authenticated, nonblocking resource admission.
use super::*;
use std::io::{Cursor, Read};

#[test]
fn empty_exports_observe_capacity_before_payload() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let bearer = claim.ingest_secret().ok_or("ingest secret missing")?;
    let instance = std::sync::Arc::new(InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(std::sync::Arc::clone(&instance))?;
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let generation = instance.catalog_generation();
        let before = instance.resource_governor().inspect()?;
        let payload = match encoding {
            ResponseEncoding::Protobuf => Vec::new(),
            ResponseEncoding::Json => serde_json::to_vec(
                &opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest::default(
                ),
            )?,
        };
        let receive = || {
            let mut body = ObservedBody {
                inner: Cursor::new(payload.clone()),
                reads: 0,
            };
            let head = RequestHead {
                openmetrics: false,
                method: "POST".to_owned(),
                path: "/v1/logs".to_owned(),
                content_length: payload.len(),
                bearer: Some(bearer.to_owned()),
                content_type: Some(encoding.content_type().to_owned()),
                content_encoding: None,
                tenant_hint: None,
                forwarded_for: None,
                forwarded_actor: None,
            };
            let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
            let response =
                super::super::super::receive_from(&mut body, head, peer, None, &services)
                    .unwrap_or_else(std::convert::identity);
            (response, body.reads)
        };
        let (refused, reads) = instance
            ._authority
            .with_control_contention_for_test(receive)?;
        assert_eq!(
            reads, 0,
            "admission refusal must precede even empty payload reads"
        );
        assert_eq!(refused.status(), 429);
        assert_eq!(refused.retry_after_seconds(), Some(1));
        let status = super::super::decode_status(&refused, encoding);
        assert_eq!(status.code, 14);
        assert_eq!(status.message, "OTLP Logs ingest capacity is unavailable");
        drop(refused);
        assert_eq!(instance.catalog_generation(), generation);
        let after_refusal = instance.resource_governor().inspect()?;
        assert_eq!(
            after_refusal.outstanding_reservations(),
            before.outstanding_reservations(),
            "refused {} export after consuming its response",
            encoding.content_type(),
        );
        for dimension in positron_kernel::ResourceDimension::ALL {
            assert_eq!(after_refusal.usage(dimension), before.usage(dimension));
        }
        let (accepted, _) = receive();
        assert_eq!(accepted.status(), 200);
        assert_eq!(
            super::super::decode_success(&accepted, encoding),
            Default::default()
        );
    }
    assert!(
        services
            .query_log_bodies(
                claim.query_secret().ok_or("query secret missing")?,
                "logs | range query_time 0 100 | limit 16",
                positron_query::QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                    .with_cpu_work_units(15)?,
            )?
            .is_empty()
    );
    Ok(())
}

struct ObservedBody {
    inner: Cursor<Vec<u8>>,
    reads: usize,
}

impl Read for ObservedBody {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        self.inner.read(bytes)
    }
}

impl std::io::Write for ObservedBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
