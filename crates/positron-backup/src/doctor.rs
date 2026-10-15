use crate::{
    CasOutcome, DeleteOutcome, HeadSlot, ImmutableObject, ObjectRange, ObjectVersion, PutOutcome,
    RegistryHeadChange, Repository, RepositoryFailure, RepositoryIdentity, UploadOutcome,
    UploadPart, UploadPlan,
};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// A stable accepted operation owns its probe selector. Credentials and paths
/// never appear in the plan or report. Runtime admission owns reservations.
pub struct DoctorPlan {
    probe: [u8; 32],
    identity: RepositoryIdentity,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl DoctorPlan {
    pub fn new(
        probe: [u8; 32],
        identity: RepositoryIdentity,
        budget: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, RepositoryFailure> {
        if probe == [0; 32] || budget.is_zero() || budget > Duration::from_secs(60) {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            probe,
            identity,
            deadline: Instant::now()
                .checked_add(budget)
                .ok_or(RepositoryFailure::InvalidInput)?,
            cancelled,
        })
    }
    async fn step<T>(
        &self,
        work: impl Future<Output = Result<T, RepositoryFailure>>,
    ) -> Result<T, RepositoryFailure> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(RepositoryFailure::Interrupted);
        }
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(RepositoryFailure::OutcomeUnknown)?;
        tokio::time::timeout(remaining, work)
            .await
            .map_err(|_| RepositoryFailure::OutcomeUnknown)?
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoctorReport {
    verified: bool,
    probes_deleted: bool,
    policy: crate::RepositoryPolicy,
}
impl DoctorReport {
    pub const fn policy(self) -> crate::RepositoryPolicy {
        self.policy
    }
    pub const fn verified(self) -> bool {
        self.verified
    }
    pub const fn probes_deleted(self) -> bool {
        self.probes_deleted
    }
    /// Successful probe deletion proves visibility through this adapter. It
    /// does not prove deletion from external snapshots or hidden retention.
    pub const fn external_retention_observable(self) -> bool {
        false
    }
}
fn require(condition: bool) -> Result<(), RepositoryFailure> {
    if condition {
        Ok(())
    } else {
        Err(RepositoryFailure::PreconditionFailed)
    }
}
fn payload(probe: &[u8; 32], label: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(probe);
    bytes.extend_from_slice(label);
    bytes
}
/// Probe provider behavior, never registry correctness or backup authenticity.
/// Every object is derived from the caller's stable, private operation selector;
/// listing and foreign objects play no part in publication or cleanup.
pub async fn doctor(
    repository: &dyn Repository,
    plan: DoctorPlan,
) -> Result<DoctorReport, RepositoryFailure> {
    require(plan.step(repository.identify()).await? == plan.identity)?;
    let mut policy = plan.step(repository.storage_policy()).await?;
    let object = ImmutableObject::new(payload(&plan.probe, b"repository doctor immutable v1"))?;
    match plan.step(repository.put_if_absent(object.clone())).await? {
        PutOutcome::Created | PutOutcome::AlreadyPresent => {},
    }
    require(
        plan.step(repository.put_if_absent(object.clone())).await? == PutOutcome::AlreadyPresent,
    )?;
    let metadata = plan.step(repository.head(object.id())).await?;
    policy.doctor_probe = Some(metadata.protection());
    require(
        metadata.size() == object.bytes().len() as u64
            && metadata.checksum() == object.id().checksum(),
    )?;
    let range = plan
        .step(repository.read_range(ObjectRange::new(object.id(), 8, 16)?))
        .await?;
    require(Some(range.bytes()) == object.bytes().get(8..24))?;
    require(range.checksum() == <[u8; 32]>::from(Sha256::digest(range.bytes())))?;
    let multipart = ImmutableObject::new(payload(&plan.probe, b"repository doctor multipart v1"))?;
    let upload = UploadPlan::new(multipart.id(), multipart.bytes().len() as u64)?;
    let mut state = plan.step(repository.begin_upload(upload)).await?;
    // At most four bounded parts for the fixed diagnostic payload. A retry
    // starts at the durable byte offset, never repeats an already accepted part.
    for _ in 0..4 {
        if state.complete() {
            break;
        }
        let start = usize::try_from(state.uploaded_bytes())
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        let end = start
            .checked_add(16)
            .ok_or(RepositoryFailure::LimitExceeded)?
            .min(multipart.bytes().len());
        let part = multipart
            .bytes()
            .get(start..end)
            .ok_or(RepositoryFailure::InvalidInput)?
            .to_vec();
        match plan
            .step(repository.resume_upload(UploadPart::new(state, part)?))
            .await?
        {
            UploadOutcome::Pending(next) => {
                require(next.uploaded_bytes() > state.uploaded_bytes())?;
                require(plan.step(repository.inspect_upload(next.id())).await? == Some(next))?;
                state = next;
            },
            UploadOutcome::Complete(_) => {
                state = plan.step(repository.begin_upload(upload)).await?;
            },
        }
    }
    require(state.complete())?;
    require(
        plan.step(repository.head(multipart.id())).await?.checksum() == multipart.id().checksum(),
    )?;
    let slot = HeadSlot::from_checksum(
        Sha256::digest(payload(&plan.probe, b"repository doctor head v1")).into(),
    );
    let bytes = payload(&plan.probe, b"repository doctor CAS v1");
    let version = ObjectVersion::from_checksum(Sha256::digest(&bytes).into());
    match plan
        .step(
            repository
                .compare_and_swap_head_at(slot, RegistryHeadChange::new(None, bytes.clone())?),
        )
        .await?
    {
        CasOutcome::Published(found) => require(found == version)?,
        CasOutcome::Conflict(Some(found)) => require(found == version)?,
        CasOutcome::Conflict(None) => return Err(RepositoryFailure::PreconditionFailed),
    }
    let head = plan
        .step(repository.registry_head_at(slot))
        .await?
        .ok_or(RepositoryFailure::NotFound)?;
    require(head.version() == version && head.bytes() == bytes)?;
    require(
        plan.step(repository.compare_and_swap_head_at(slot, RegistryHeadChange::new(None, bytes)?))
            .await?
            == CasOutcome::Conflict(Some(version)),
    )?;
    require(matches!(
        plan.step(repository.delete_head_if_version(slot, version))
            .await?,
        DeleteOutcome::Deleted | DeleteOutcome::AlreadyAbsent
    ))?;
    require(
        plan.step(repository.registry_head_at(slot))
            .await?
            .is_none(),
    )?;
    for object in [object.id(), multipart.id()] {
        require(matches!(
            plan.step(repository.delete(object)).await?,
            DeleteOutcome::Deleted | DeleteOutcome::AlreadyAbsent
        ))?;
        require(plan.step(repository.head(object)).await == Err(RepositoryFailure::NotFound))?;
        require(plan.step(repository.delete(object)).await? == DeleteOutcome::AlreadyAbsent)?;
    }
    require(
        plan.step(repository.inspect_upload(upload.id()))
            .await?
            .is_none(),
    )?;
    Ok(DoctorReport {
        verified: true,
        probes_deleted: true,
        policy,
    })
}
