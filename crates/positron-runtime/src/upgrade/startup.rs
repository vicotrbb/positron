use super::UpgradeFailure;
use positron_kernel::release_manifest::VerifiedReleaseManifest;
use zeroize::Zeroizing;
pub(crate) fn upgrade_query_source(
    instance: &crate::InitializedInstance,
) -> Result<String, UpgradeFailure> {
    let seconds = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    let end = i128::from(seconds)
        .checked_mul(1_000_000_000)
        .ok_or(UpgradeFailure::UnsafeState)?;
    let start = end
        .checked_sub(3_600_000_000_000)
        .ok_or(UpgradeFailure::UnsafeState)?;
    Ok(format!("logs | range query_time {start} {end} | limit 1"))
}

/// Independently authenticated installed release and optional live Query key.
/// The key is retained only for the startup verification call and zeroized.
pub struct UpgradeStartupVerification {
    pub(crate) release: VerifiedReleaseManifest,
    query_credential: Option<Zeroizing<String>>,
    #[cfg(test)]
    pub(crate) fixture_executable: Option<std::path::PathBuf>,
    #[cfg(test)]
    pub(crate) fixture_version: Option<positron_kernel::release_manifest::ProductVersion>,
}
impl UpgradeStartupVerification {
    pub fn new(
        release: VerifiedReleaseManifest,
        query_credential: Option<String>,
    ) -> Result<Self, UpgradeFailure> {
        if let Some(credential) = query_credential.as_deref() {
            positron_governance::PresentedCredential::parse(credential)
                .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
        }
        Ok(Self {
            release,
            query_credential: query_credential.map(Zeroizing::new),
            #[cfg(test)]
            fixture_executable: None,
            #[cfg(test)]
            fixture_version: None,
        })
    }
}
impl UpgradeStartupVerification {
    /// Uses ordinary lifecycle and credential attribution for both installed
    /// admission and target verification. This never grants tenant authority.
    pub(crate) fn query_context(
        &self,
        instance: &crate::InitializedInstance,
    ) -> Result<Option<positron_governance::AuthorizedContext>, UpgradeFailure> {
        let required = {
            let catalog = open(instance)?;
            let snapshot = catalog
                .pin()
                .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
            let identity = positron_governance::Identity::open(&snapshot)
                .map_err(|_| UpgradeFailure::UnsafeState)?;
            identity.query_readable_tenant_ids().next().is_some()
        };
        if !required {
            return Ok(None);
        }
        let credential = self
            .query_credential
            .as_ref()
            .ok_or(UpgradeFailure::AuthenticationFailed)?;
        instance
            .attribute(
                positron_governance::PresentedCredential::parse(credential.as_str())
                    .map_err(|_| UpgradeFailure::AuthenticationFailed)?,
                positron_governance::RequestedIntent::Query,
                positron_governance::CompatibilityHints::none(),
            )
            .map(Some)
            .map_err(|_| UpgradeFailure::AuthenticationFailed)
    }
}
impl std::fmt::Debug for UpgradeStartupVerification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpgradeStartupVerification")
            .field("release", &self.release.digest())
            .field("query_credential", &self.query_credential.is_some())
            .finish()
    }
}

pub(crate) struct UpgradeVerificationToken {
    id: positron_governance::OperationId,
}

/// Runs before recovery can publish metadata or ordinary listeners can bind.
pub(crate) fn authorize(
    instance: &crate::InitializedInstance,
    configuration: Option<&positron_config::EffectiveConfiguration>,
    verification: Option<&UpgradeStartupVerification>,
) -> Result<Option<UpgradeVerificationToken>, UpgradeFailure> {
    use positron_governance::{
        DurableOperationAdministration as Administration, DurableOperationStatus,
        UpgradePublicationOutcome, UpgradeStage,
    };
    let catalog = open(instance)?;
    let active = Administration::next_upgrade_operation(&catalog, None).map_err(persistence)?;
    if active.is_some_and(|operation| {
        !matches!(
            operation.upgrade_stage(),
            Some(UpgradeStage::AwaitingRestart | UpgradeStage::Verifying)
        )
    }) {
        return Err(UpgradeFailure::UnsafeState);
    }
    let Some(publication) =
        Administration::current_upgrade_publication(&catalog).map_err(persistence)?
    else {
        return if active.is_none() {
            Ok(None)
        } else {
            Err(UpgradeFailure::UnsafeState)
        };
    };
    let verification = verification.ok_or(UpgradeFailure::AuthenticationFailed)?;
    let configuration = configuration.ok_or(UpgradeFailure::InvalidRequest)?;
    let parameters = publication.parameters();
    if configuration.audit_binding_digest() != parameters.configuration_digest()
        || instance
            .catalog_format_epoch()
            .map_err(|_| UpgradeFailure::UnsafeState)?
            .map(positron_kernel::FormatEpoch::value)
            != Some(parameters.format_epoch())
    {
        return Err(UpgradeFailure::UnsupportedTransition);
    }
    verification.attest(instance, publication.release())?;
    if publication.is_rollback() {
        return if active.is_none() {
            Ok(None)
        } else {
            Err(UpgradeFailure::UnsafeState)
        };
    }
    match publication.outcome() {
        UpgradePublicationOutcome::Verified { .. } if active.is_none() => return Ok(None),
        UpgradePublicationOutcome::AwaitingVerification => {},
        _ => return Err(UpgradeFailure::UnsafeState),
    }
    let operation = active.ok_or(UpgradeFailure::UnsafeState)?;
    if operation.operation_id() != publication.operation_id()
        || operation.status() != DurableOperationStatus::Running
    {
        return Err(UpgradeFailure::UnsafeState);
    }
    let actor = Administration::resume_upgrade_actor(
        &catalog,
        operation.operation_id(),
        instance
            .retention_time
            .security_time_seconds()
            .map_err(|_| UpgradeFailure::UnsafeState)?,
    )
    .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
    // An authenticated first report owns its original immutable proposal. Do
    // not run Query or schema recovery before resolving that exact predecessor.
    if Administration::resume_upgrade_verification(&catalog, actor, operation.operation_id())
        .map_err(persistence)?
        .is_some()
    {
        return Ok(None);
    }
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    if now < operation.updated_at_unix_seconds() {
        return Err(UpgradeFailure::CapacityUnavailable);
    }
    if operation.upgrade_stage() == Some(UpgradeStage::AwaitingRestart) {
        Administration::advance_upgrade(
            &catalog,
            actor,
            operation.operation_id(),
            UpgradeStage::Verifying,
            now,
        )
        .map_err(persistence)?;
    }
    Ok(Some(UpgradeVerificationToken {
        id: operation.operation_id(),
    }))
}

impl UpgradeStartupVerification {
    pub(crate) fn attest(
        &self,
        instance: &crate::InitializedInstance,
        expected: positron_governance::UpgradeReleaseIdentity,
    ) -> Result<(), UpgradeFailure> {
        use positron_kernel::release_manifest::ProductVersion;
        let manifest = self.release.manifest();
        let artifact = super::UpgradeReleasePlan::native_artifact(&self.release)?;
        let expected_version = expected.version();
        if self.release.digest() != expected.manifest_digest()
            || artifact.sha256 != expected.artifact_digest()
            || [
                manifest.version.major,
                manifest.version.minor,
                manifest.version.patch,
            ] != expected_version
        {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        let version = ProductVersion::parse_exact(env!("CARGO_PKG_VERSION"))
            .map_err(|_| UpgradeFailure::UnsafeState)?;
        #[cfg(test)]
        let version = self.fixture_version.unwrap_or(version);
        if manifest.version != version {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        let executable =
            std::env::current_exe().map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        #[cfg(test)]
        let executable = self.fixture_executable.as_ref().unwrap_or(&executable);
        super::UpgradeArtifactIdentity::measure(
            instance,
            executable.as_ref(),
            artifact.sha256,
            artifact.size,
        )?;
        Ok(())
    }
}

/// Only this startup composition owns the integrity-complete candidate. A live
/// Query credential is used through the ordinary Query owner; no system actor
/// is converted into a tenant principal and no sentinel is written.
pub(crate) fn complete(
    services: &crate::ServiceHandle,
    instance: &crate::InitializedInstance,
    verification: Option<&UpgradeStartupVerification>,
    token: Option<UpgradeVerificationToken>,
) -> Result<(), UpgradeFailure> {
    use positron_governance::DurableOperationAdministration as Administration;
    use positron_kernel::upgrade_verification::{
        UpgradeQueryVerification, UpgradeVerificationInput, UpgradeVerificationReport,
    };
    let Some(token) = token else {
        return Ok(());
    };
    let verification = verification.ok_or(UpgradeFailure::AuthenticationFailed)?;
    let context = verification.query_context(instance)?;
    let query = if let Some(context) = context {
        let credential = verification
            .query_credential
            .as_ref()
            .ok_or(UpgradeFailure::AuthenticationFailed)?;
        let tenant = context
            .tenant_attribution()
            .ok_or(UpgradeFailure::AuthenticationFailed)?
            .tenant_id();
        let budget =
            positron_query::QueryBudget::new(4_194_304, 1_024, 1_024, 4_194_304, 1_048_576, 5)
                .map_err(|_| UpgradeFailure::InvalidRequest)?;
        let source = upgrade_query_source(instance)?;
        let _bodies = services
            .query_log_bodies(credential.as_str(), &source, budget)
            .map_err(|failure| match failure {
                crate::ServiceFailure::Unauthorized => UpgradeFailure::AuthenticationFailed,
                crate::ServiceFailure::CapacityUnavailable
                | crate::ServiceFailure::StorageUnavailable => UpgradeFailure::CapacityUnavailable,
                _ => UpgradeFailure::VerificationFailed,
            })?;
        UpgradeQueryVerification::Executed {
            tenant: tenant.to_bytes(),
        }
    } else {
        UpgradeQueryVerification::NotApplicableNoQueryableTenant
    };
    let _gate = services
        .catalog_operation()
        .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
    let catalog = open(instance)?;
    let snapshot = catalog
        .pin()
        .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
    let publication = Administration::current_upgrade_publication(&catalog)
        .map_err(persistence)?
        .ok_or(UpgradeFailure::UnsafeState)?;
    let (_, governance) = snapshot
        .governance_object()
        .map_err(|_| UpgradeFailure::UnsafeState)?;
    let signer = instance
        .key
        .upgrade_verification_signer(instance.instance, governance.protected_integrity_key())
        .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
    let input = UpgradeVerificationInput::new(
        instance.instance.to_bytes(),
        token.id.to_bytes(),
        publication.object_identity().map_err(persistence)?,
        snapshot.identity().to_bytes(),
        snapshot.number(),
        query,
    )
    .map_err(|_| UpgradeFailure::VerificationFailed)?;
    let report = UpgradeVerificationReport::sign(input, &signer)
        .map_err(|_| UpgradeFailure::VerificationFailed)?;
    let actor = Administration::resume_upgrade_actor(
        &catalog,
        token.id,
        instance
            .retention_time
            .security_time_seconds()
            .map_err(|_| UpgradeFailure::UnsafeState)?,
    )
    .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    Administration::succeed_upgrade(&catalog, actor, token.id, &report, now)
        .map_err(persistence)?;
    Ok(())
}

fn open(
    instance: &crate::InitializedInstance,
) -> Result<positron_kernel::Catalog<'_>, UpgradeFailure> {
    positron_kernel::Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| UpgradeFailure::UnsafeState)?,
    )
    .map_err(|_| UpgradeFailure::PersistenceUnavailable)
}
fn persistence(_: positron_governance::DurableOperationFailure) -> UpgradeFailure {
    UpgradeFailure::PersistenceUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use positron_kernel::release_manifest::ProductVersion;
    #[test]
    fn startup_verification_keeps_query_secret_only_in_redacted_memory()
    -> Result<(), Box<dyn std::error::Error>> {
        let release = crate::upgrade::signed_fixture_release(
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 1,
            },
            [0x51; 32],
            15,
        )?;
        let secret = format!("pos_{}", "a5".repeat(32));
        let verification = UpgradeStartupVerification::new(release, Some(secret.clone()))?;
        assert!(!format!("{verification:?}").contains(&secret));
        assert!(!format!("{verification:?}").contains("a5a5a5"));
        Ok(())
    }
}
