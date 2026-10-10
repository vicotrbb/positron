use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, GovernanceAuditEntry, PresentedCredential,
    RequestedIntent, ResourceGeneration,
};
use positron_ingest::load_schema_checkpoint;
use positron_kernel::{
    ActiveSegmentLedger, AuditIntent, Catalog, CatalogObject, CatalogProposal,
    CatalogPublicationFault, FormatEpoch, MaintenancePreconditions, MaintenanceScope,
    MaintenanceTask, MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase,
    MaintenanceTrigger, MountQualification, ResourceAmounts, ResourceDimension,
    RetentionTimeAuthority, SegmentScope, StoreBlockIdentity, TransactionId, WorkClaim, WorkClass,
    WorkKind, with_catalog_publication_fault_after,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
};
use positron_query::QueryBudget;
use positron_signals::{LogRecord as StoredLogRecord, LogStore};
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle, schema_maintenance};
use crate::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};

pub(crate) type InitializedCredentials = (Arc<crate::InitializedInstance>, String, String, String);

static LIVE_NATIVE_MAINTENANCE_TEST: Mutex<()> = Mutex::new(());

pub(crate) fn live_native_maintenance_test_guard() -> MutexGuard<'static, ()> {
    match LIVE_NATIVE_MAINTENANCE_TEST.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

mod audit_recovery;
mod integrity;
mod recovery;
mod retention;
mod schema_corruption;
pub(crate) fn publish_unrelated(
    initialized: &crate::InitializedInstance,
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            basis
                .object(identity)?
                .ok_or_else(|| "missing object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let unrelated = CatalogObject::new(b"unrelated-runtime-state".to_vec())?;
    let identity = unrelated.identity();
    objects.push(unrelated);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x91; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        Some(AuditIntent::new(b"test-unrelated-state".to_vec())?),
    )?;
    Ok(identity)
}

fn publish_unrelated_bytes(
    initialized: &crate::InitializedInstance,
    bytes: Vec<u8>,
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    publish_unrelated_bytes_with_transaction(initialized, bytes, [0x75; 16])
}

fn publish_unrelated_bytes_with_transaction(
    initialized: &crate::InitializedInstance,
    bytes: Vec<u8>,
    transaction: [u8; 16],
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let before = catalog.pin()?;
    let object = CatalogObject::new(bytes)?;
    let identity = object.identity();
    let mut objects = before
        .object_identities()
        .map(|known| {
            before
                .object(known)?
                .ok_or_else(|| "missing object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(object);
    catalog.commit(
        before.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(identity)
}

fn schema_audit_count(initialized: &crate::InitializedInstance) -> Result<usize, Box<dyn Error>> {
    Ok(open_catalog(initialized)?
        .governance_audit_records()?
        .iter()
        .filter(|record| {
            GovernanceAuditEntry::decode(record)
                .ok()
                .and_then(|entry| entry.as_schema_checkpoint().cloned())
                .is_some()
        })
        .count())
}

pub(crate) fn open_catalog(
    initialized: &crate::InitializedInstance,
) -> Result<Catalog<'_>, Box<dyn Error>> {
    Ok(Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?)
}

pub(crate) fn request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn reserve_native_addresses() -> Result<[SocketAddr; 5], Box<dyn Error>> {
    let mut listeners = Vec::with_capacity(5);
    let mut addresses = Vec::with_capacity(5);
    for _ in 0..5 {
        let listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        addresses.push(listener.local_addr()?);
        listeners.push(listener);
    }
    drop(listeners);
    addresses
        .try_into()
        .map_err(|_| "five native listener addresses".into())
}

pub(crate) struct Fixture {
    root: PathBuf,
}

impl Fixture {
    pub(crate) fn control_socket_path(&self) -> PathBuf {
        self.root.join("control.sock")
    }
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-schema-maintenance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("data"))?;
        fs::create_dir_all(root.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root })
    }

    pub(crate) fn sealed_segments_directory(&self) -> PathBuf {
        self.root.join("data/segments/sealed")
    }

    pub(crate) fn recovery_export_directory(&self) -> Result<PathBuf, Box<dyn Error>> {
        let export = self.root.join("recovery");
        fs::create_dir(&export)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&export, fs::Permissions::from_mode(0o700))?;
        }
        Ok(fs::canonicalize(export)?)
    }

    pub(crate) fn paths(&self) -> Result<BootstrapPaths, Box<dyn Error>> {
        Ok(BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?)
    }

    pub(super) fn initialized(
        &self,
    ) -> Result<(Arc<crate::InitializedInstance>, String, String), Box<dyn Error>> {
        let (initialized, ingest, query, _) = self.initialized_with_admin()?;
        Ok((initialized, ingest, query))
    }

    pub(crate) fn initialized_with_admin(&self) -> Result<InitializedCredentials, Box<dyn Error>> {
        self.initialized_with_admin_max_registered_tenants(2)
    }

    fn initialized_with_admin_max_registered_tenants(
        &self,
        max_registered_tenants: u16,
    ) -> Result<InitializedCredentials, Box<dyn Error>> {
        let paths = BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        drop(InstanceBootstrap::initialize_with_max_registered_tenants(
            &paths,
            InitializationPlan::non_interactive(),
            max_registered_tenants,
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let ingest = claim.ingest_secret().ok_or("ingest secret")?.to_owned();
        let query = claim.query_secret().ok_or("query secret")?.to_owned();
        let administrator = claim.secret().to_owned();
        Ok((
            Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
                &paths,
                max_registered_tenants,
            )?),
            ingest,
            query,
            administrator,
        ))
    }

    pub(crate) fn reopen(&self) -> Result<Arc<crate::InitializedInstance>, Box<dyn Error>> {
        let paths = BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        Ok(Arc::new(InstanceBootstrap::reopen(&paths)?))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
