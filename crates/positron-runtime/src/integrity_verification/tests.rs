use std::fs;
use std::path::{Path, PathBuf};

use super::{
    OfflineIntegrityFailure, resume_offline_integrity, verify_offline_integrity,
    verify_offline_integrity_scope,
};
use crate::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_kernel::{IntegrityCancellation, MountQualification, ResourceAmounts, WorkClaim};

#[test]
fn offline_verification_aggregates_healthy_reachable_scopes_without_changing_any_file()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let before = file_tree(&root)?;
    let report = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
    let after = file_tree(&root)?;

    assert!(report.is_complete());
    assert!(report.is_verified());
    let facts = report.facts();
    assert!(facts.catalog_generation() > 0);
    assert_eq!(facts.registered_tenant_count(), 1);
    assert_eq!(facts.verified_envelope_count(), 1);
    assert_eq!(facts.reachable_scope_count(), 2);
    assert_eq!(report.reports().len(), 2);
    assert_eq!(facts.verified_scope_count(), report.reports().len());
    assert_eq!(facts.fenced_scope_count(), 0);
    assert_eq!(facts.incomplete_scope_count(), 0);
    let retained = paths.retain_volume_for_test()?;
    drop(retained);
    assert_eq!(
        after, before,
        "offline verification must not create, repair, or publish"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn selected_terminal_scope_does_not_claim_whole_instance_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;

    let first = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("first offline pass failed: {failure:?}"))?;
    let selected_scope = first.reports()[0].scope();
    let selected = verify_offline_integrity_scope(&paths, 2, selected_scope)
        .map_err(|failure| format!("selected scope failed: {failure:?}"))?;

    assert_eq!(
        selected.reports()[0].outcome(),
        positron_kernel::IntegrityVerificationOutcome::Verified
    );
    assert!(
        !selected.is_complete(),
        "a selected terminal scope must not claim other reachable scopes were verified"
    );
    assert!(!selected.is_verified());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_sealed_corruption_is_localized_without_publishing_a_quarantine()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::{routing::SignalKind, value::ValueLimitProfile};
    use positron_kernel::{
        ActiveSegmentLedger, Catalog, ResourceDimension, SegmentScope, StoreBlockIdentity, WorkKind,
    };
    use positron_policy::{
        IngestPolicy, LogMetadata, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
    };
    use positron_signals::{LogRecord as StoredLogRecord, LogStore};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let key = crate::services::tenant_segment_key(&instance, &identity, scope)
        .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        scope,
        key,
    )?;
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(Some(10), None, None, Vec::new(), LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("fixture policy rejected an immutable log".into());
    };
    let capacity = instance._authority.governor().reserve(WorkClaim::tenant(
        instance.tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    ledger.append(
        LogStore::new()
            .prepare(
                ledger.begin_store_block(capacity, StoreBlockIdentity::new([0x82; 16])?)?,
                vec![StoredLogRecord::checked_evaluated(
                    ValueLimitProfile::release_1_system_maximum(),
                    *evaluated,
                )?],
            )?
            .into_store_block(),
    )?;
    let sealed_receipt = ledger.seal()?;
    drop(catalog);
    drop(instance);

    let sealed_name = sealed_receipt
        .segment_id()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let sealed = root
        .join("data/segments/sealed")
        .join(format!("{sealed_name}.segment"));
    let mut damaged = fs::read(&sealed)?;
    let byte = damaged.last_mut().ok_or("sealed segment bytes")?;
    *byte ^= 0xa5;
    fs::write(sealed, damaged)?;
    let before = file_tree(&root)?;
    let report = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
    assert!(!report.is_verified());
    assert_eq!(
        report.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Quarantined,
        "isolated sealed corruption is localized even though offline inspection cannot publish it: {:?}",
        report.reports()
    );
    assert!(report.reports().iter().any(|item| {
        item.outcome() == positron_kernel::IntegrityVerificationOutcome::Quarantined
            && item.quarantined_segment() == Some(sealed_receipt.segment_id())
    }));
    let finding = report
        .reports()
        .iter()
        .copied()
        .find_map(positron_kernel::IntegrityVerificationReport::localized_finding)
        .ok_or("missing read-only localized offline finding")?;
    assert_eq!(finding.scope(), scope);
    assert_eq!(finding.segment(), sealed_receipt.segment_id());
    assert!(matches!(
        finding.event_range(),
        positron_kernel::AuthenticatedEventRange::Known { .. }
    ));
    assert!(matches!(
        finding.ingest_range(),
        positron_kernel::AuthenticatedIngestRange::Known { .. }
    ));
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_verification_fences_corruption_at_an_active_durability_frontier()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let active = fs::read_dir(root.join("data/segments/active"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .next()
        .ok_or("active segment")?;
    fs::write(&active, b"corrupt at acknowledged frontier")?;
    let before = file_tree(&root)?;

    let report = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("offline verification failed: {failure:?}"))?;

    assert!(
        report.is_complete(),
        "a fenced terminal result still covers every reachable scope"
    );
    assert!(!report.is_verified());
    assert_eq!(
        report.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Fenced,
        "an active durability-frontier failure remains an instance-wide fence"
    );
    assert!(
        report
            .reports()
            .iter()
            .any(|item| item.outcome() == positron_kernel::IntegrityVerificationOutcome::Fenced),
        "offline inspection must authenticate a reachable active durability frontier"
    );
    assert_eq!(
        file_tree(&root)?,
        before,
        "offline inspection never repairs source bytes"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_verification_leaves_an_active_nondurable_tail_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let active = fs::read_dir(root.join("data/segments/active"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .next()
        .ok_or("active segment")?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&active)?
        .write_all(b"uncommitted active tail")?;
    let before = file_tree(&root)?;

    let report = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("offline verification failed: {failure:?}"))?;

    assert!(report.is_complete());
    assert!(report.is_verified());
    assert_eq!(
        file_tree(&root)?,
        before,
        "offline inspection must not truncate an active tail"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn selected_scope_verification_returns_a_bound_cursor_and_resumes_without_global_claim()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::routing::SignalKind;
    use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    // Initialization already leaves one reachable immutable segment in
    // this scope. Add 128 more so the production 128-segment budget
    // must return one authenticated omission.
    for _ in 0..128 {
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
    }
    drop(catalog);
    drop(instance);

    let before = file_tree(&root)?;
    let first = verify_offline_integrity_scope(&paths, 2, scope)
        .map_err(|failure| format!("first offline pass failed: {failure:?}"))?;
    assert!(!first.is_complete());
    assert!(!first.is_verified());
    assert_eq!(first.reports().len(), 1);
    let partial = first
        .reports()
        .iter()
        .copied()
        .find(|report| report.scope() == scope)
        .ok_or("missing requested scope report")?;
    assert_eq!(
        partial.outcome(),
        positron_kernel::IntegrityVerificationOutcome::Incomplete
    );
    assert_eq!(partial.examined_segments(), 128);
    assert_eq!(partial.omitted_segments(), 1);
    assert!(partial.continuation().is_some());
    let continuation = first
        .continuation()
        .cloned()
        .ok_or("missing aggregate continuation")?;
    let mut tampered = continuation.clone();
    tampered.0[0] ^= 0x80;
    assert_eq!(
        resume_offline_integrity(&paths, 2, tampered),
        Err(OfflineIntegrityFailure::CorruptState)
    );
    assert_eq!(file_tree(&root)?, before);

    let resumed = resume_offline_integrity(&paths, 2, continuation)
        .map_err(|failure| format!("resumed offline pass failed: {failure:?}"))?;
    assert!(!resumed.is_complete());
    assert!(!resumed.is_verified());
    assert!(resumed.continuation().is_none());
    assert_eq!(resumed.reports().len(), 1);
    assert_eq!(resumed.reports()[0].scope(), scope);
    assert_eq!(resumed.reports()[0].examined_segments(), 1);
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn aggregate_verification_bounds_valid_multi_scope_bytes_and_resumes_with_a_fresh_claim()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::routing::{SignalKind, VirtualShardId};
    use positron_kernel::{
        ActiveSegmentLedger, Catalog, IntegrityScrubBudget, PreparedStoreBlock, SegmentScope,
        StoreBlockIdentity,
    };

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    drop(catalog);

    // Seventeen non-default Trace scopes each contain one normally sealed
    // segment with two valid 512 KiB Store Blocks. Every scope fits under
    // the claim independently, while their cumulative authenticated bytes
    // exceed it. Reopening the Catalog after each seal is the normal
    // next-segment path, so this is not an oversized or invalid fixture.
    for shard in 2_u16..=18 {
        let scope = SegmentScope::new(
            instance.tenant,
            SignalKind::Traces,
            VirtualShardId::new(shard.into())?,
        );
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("trace segment key unavailable: {failure:?}"))?;
        let ledger = ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?;
        let identity_byte = u8::try_from(shard * 2)?;
        for block in 0_u8..2 {
            ledger.append(PreparedStoreBlock::new(
                scope,
                StoreBlockIdentity::new([identity_byte.saturating_add(block); 16])?,
                vec![identity_byte.saturating_add(block); 524_288],
            )?)?;
        }
        ledger
            .seal()
            .map_err(|failure| format!("trace seal {shard} failed: {failure:?}"))?;
    }
    drop(instance);

    let before = file_tree(&root)?;
    let first = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("aggregate offline pass failed: {failure:?}"))?;
    let examined_bytes = first
        .reports()
        .iter()
        .map(|report| report.examined_bytes())
        .sum::<u64>();
    assert!(
        examined_bytes <= IntegrityScrubBudget::MAX_BYTES,
        "the actual bytes examined by one aggregate invocation must fit its single 16 MiB resource claim"
    );
    let partial = first
        .reports()
        .iter()
        .copied()
        .find(|report| {
            report.outcome() == positron_kernel::IntegrityVerificationOutcome::Incomplete
        })
        .ok_or("missing truthful aggregate byte-bound partial report")?;
    assert!(partial.omitted_segments() > 0);
    assert!(!first.is_complete());
    assert!(!first.is_verified());
    let continuation = first
        .continuation()
        .cloned()
        .ok_or("missing aggregate byte-bound continuation")?;
    assert!(
        continuation.encoded().len().saturating_mul(2) > 2_048,
        "the real bounded aggregate token must exceed the obsolete CLI hex limit"
    );
    assert_eq!(file_tree(&root)?, before);

    let resumed = resume_offline_integrity(&paths, 2, continuation)
        .map_err(|failure| format!("fresh aggregate continuation failed: {failure:?}"))?;
    let resumed_bytes = resumed
        .reports()
        .iter()
        .map(|report| report.examined_bytes())
        .sum::<u64>();
    assert!(resumed_bytes <= IntegrityScrubBudget::MAX_BYTES);
    assert!(resumed.reports().iter().all(|report| {
        report.outcome() == positron_kernel::IntegrityVerificationOutcome::Verified
    }));
    assert!(resumed.is_complete());
    assert!(resumed.is_verified());
    assert!(resumed.continuation().is_none());
    assert_eq!(
        resumed.aggregate_evidence().len(),
        resumed.facts().reachable_scope_count(),
        "the final aggregate must retain authenticated terminal evidence from the first pass as well as the final pass"
    );
    assert!(resumed.aggregate_evidence().iter().all(|evidence| {
        evidence.catalog_generation() == resumed.facts().catalog_generation()
            && evidence.outcome() == positron_kernel::IntegrityVerificationOutcome::Verified
    }));
    assert_eq!(
        resumed.examined_bytes(),
        examined_bytes + resumed_bytes,
        "aggregate byte accounting must cover both bounded passes"
    );
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn selected_nonfirst_scope_resumes_its_own_bound_cursor_without_claiming_instance_completion()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::routing::{SignalKind, VirtualShardId};
    use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    // Traces sorts after the initialized Logs scope, so this proves that
    // an authenticated selected-scope continuation retains its target.
    let scope = SegmentScope::new(instance.tenant, SignalKind::Traces, VirtualShardId::new(2)?);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    for _ in 0..129 {
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
    }
    drop(catalog);
    drop(instance);

    let before = file_tree(&root)?;
    let first = verify_offline_integrity_scope(&paths, 2, scope)
        .map_err(|failure| format!("selected offline pass failed: {failure:?}"))?;
    assert_eq!(first.reports().len(), 1);
    assert_eq!(
        first.reports()[0].outcome(),
        positron_kernel::IntegrityVerificationOutcome::Incomplete
    );
    assert_eq!(first.reports()[0].examined_segments(), 128);
    let continuation = first
        .continuation()
        .cloned()
        .ok_or("missing selected continuation")?;

    let resumed = resume_offline_integrity(&paths, 2, continuation)
        .map_err(|failure| format!("selected resume failed: {failure:?}"))?;
    assert_eq!(resumed.reports().len(), 1);
    assert_eq!(resumed.reports()[0].scope(), scope);
    assert_eq!(
        resumed.reports()[0].outcome(),
        positron_kernel::IntegrityVerificationOutcome::Verified
    );
    assert!(
        resumed.continuation().is_none(),
        "the selected terminal scope must not continue into aggregate scopes"
    );
    assert!(
        !resumed.is_complete(),
        "selected completion must not claim the whole instance was covered"
    );
    assert!(!resumed.is_verified());
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn protected_malformed_v2_continuation_fails_closed_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::BootstrapObjectPurpose;

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let malformed = crate::OfflineIntegrityContinuation(instance.key.protect(
        instance.instance,
        BootstrapObjectPurpose::Initialized,
        b"\x02malformed-v2",
    )?);
    drop(instance);
    let before = file_tree(&root)?;

    assert_eq!(
        resume_offline_integrity(&paths, 2, malformed),
        Err(OfflineIntegrityFailure::CorruptState)
    );
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn stale_authenticated_continuation_fails_closed_without_mutating_after_catalog_advance()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::{identity::Scope, routing::SignalKind};
    use positron_governance::{
        AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
        ResourceGeneration,
    };
    use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    for _ in 0..128 {
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
    }
    drop(catalog);
    drop(instance);
    let continuation = verify_offline_integrity_scope(&paths, 2, scope)
        .map_err(|failure| format!("selected pass failed: {failure:?}"))?
        .continuation()
        .cloned()
        .ok_or("missing continuation")?;

    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let administrator = instance.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    instance.create_api_key(
        administrator,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x91; 16])?,
    )?;
    drop(instance);
    let before = file_tree(&root)?;

    assert_eq!(
        resume_offline_integrity(&paths, 2, continuation),
        Err(OfflineIntegrityFailure::CorruptState)
    );
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_missing_key_reports_typed_failure_without_bootstrap_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    fs::remove_file(root.join("secrets/local-root-key.v1"))?;
    let before = file_tree(&root)?;
    assert_eq!(
        verify_offline_integrity(&paths, 2),
        Err(OfflineIntegrityFailure::KeyUnavailable)
    );
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn key_unavailable_diagnostics_reserve_before_collection_and_release_after_output()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    fs::remove_file(root.join("secrets/local-root-key.v1"))?;
    let before = file_tree(&root)?;
    let claim = WorkClaim::system_diagnostics(ResourceAmounts::new([
        24_576, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0,
    ]))?;

    let collected =
        InstanceBootstrap::with_offline_key_unavailable_diagnostics(&paths, 2, claim, |_| {
            assert!(
                paths.retain_volume_for_test().is_err(),
                "the diagnostics reservation must hold exclusive ownership through collection"
            );
            file_tree(&root)
        })
        .map_err(|failure| format!("offline diagnostics failed: {failure:?}"))?;
    assert_eq!(collected?, before);
    let retained = paths.retain_volume_for_test()?;
    drop(retained);
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn key_unavailable_diagnostics_refuse_before_collection_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    fs::remove_file(root.join("secrets/local-root-key.v1"))?;
    let before = file_tree(&root)?;
    let entered = std::cell::Cell::new(false);
    let refusal = InstanceBootstrap::with_offline_key_unavailable_diagnostics(
        &paths,
        2,
        WorkClaim::system_diagnostics(ResourceAmounts::new([
            u64::MAX,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            0,
        ]))?,
        |_| entered.set(true),
    );
    assert_eq!(refusal, Err(OfflineIntegrityFailure::CapacityUnavailable));
    assert!(!entered.get(), "refused admission must precede collection");
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_verification_refuses_the_aggregate_reservation_before_collection_and_releases()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let before = file_tree(&root)?;
    let refusal = InstanceBootstrap::verify_offline_integrity_with_claim_for_test(
        &paths,
        2,
        WorkClaim::system_diagnostics(ResourceAmounts::new([
            u64::MAX,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            0,
        ]))?,
    );

    assert_eq!(refusal, Err(OfflineIntegrityFailure::CapacityUnavailable));
    let retained = paths.retain_volume_for_test()?;
    drop(retained);
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_verification_releases_its_reservation_after_a_cancelled_scrub()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::routing::SignalKind;
    use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let key = crate::services::tenant_segment_key(&instance, &identity, scope)
        .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
    ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
    drop(catalog);
    drop(instance);
    let before = file_tree(&root)?;
    let cancellation = IntegrityCancellation::new();
    cancellation.cancel();
    let cancelled =
        InstanceBootstrap::verify_offline_integrity_with_claim_and_cancellation_for_test(
            &paths,
            2,
            WorkClaim::system_diagnostics(ResourceAmounts::new([
                16_000_000, 0, 1, 4_000_000, 128, 0, 0, 1, 1, 1, 0,
            ]))?,
            &cancellation,
        );

    let cancelled =
        cancelled.map_err(|failure| format!("cancelled scrub failed unexpectedly: {failure:?}"))?;
    assert!(!cancelled.is_complete());
    assert_eq!(
        cancelled.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Incomplete,
        "a resumable bounded pass remains incomplete rather than degraded or fenced"
    );
    assert_eq!(
        cancelled.reports()[0].outcome(),
        positron_kernel::IntegrityVerificationOutcome::Incomplete
    );
    let retained = paths.retain_volume_for_test()?;
    drop(retained);
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_verification_of_missing_root_never_creates_bootstrap_artifacts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    let before = file_tree(&root)?;
    assert_eq!(
        verify_offline_integrity(&paths, 2),
        Err(OfflineIntegrityFailure::BootstrapUnavailable)
    );
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn temporary_root() -> Result<PathBuf, std::io::Error> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "positron-offline-integrity-{}-{}",
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
    Ok(root)
}

fn file_tree(root: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>, std::io::Error> {
    let mut entries = Vec::new();
    collect_files(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn collect_files(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, entries)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_owned();
            // The volume acquisition lease is the only intentional
            // filesystem side effect of offline exclusivity.
            if relative != Path::new("data/.positron-volume.lock") {
                entries.push((relative, fs::read(&path)?));
            }
        }
    }
    Ok(())
}

#[test]
fn offline_localized_corruption_continues_to_later_ambiguous_sealed_target()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::{routing::SignalKind, value::ValueLimitProfile};
    use positron_kernel::{
        ActiveSegmentLedger, Catalog, ResourceDimension, SegmentScope, StoreBlockIdentity, WorkKind,
    };
    use positron_policy::{
        IngestPolicy, LogMetadata, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
    };
    use positron_signals::{LogRecord as StoredLogRecord, LogStore};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let mut receipts = Vec::new();
    for identity_byte in [0x91, 0x92] {
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )?;
        let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
            NativeLogCandidate::new(Some(10), None, None, Vec::new(), LogMetadata::empty()),
            PolicyReceiver::OtlpGrpc,
        )?
        else {
            return Err("fixture policy rejected an immutable log".into());
        };
        let capacity = instance._authority.governor().reserve(WorkClaim::tenant(
            instance.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
        ledger.append(
            LogStore::new()
                .prepare(
                    ledger.begin_store_block(
                        capacity,
                        StoreBlockIdentity::new([identity_byte; 16])?,
                    )?,
                    vec![StoredLogRecord::checked_evaluated(
                        ValueLimitProfile::release_1_system_maximum(),
                        *evaluated,
                    )?],
                )?
                .into_store_block(),
        )?;
        receipts.push(ledger.seal()?);
    }
    drop(catalog);
    drop(instance);

    let sealed_path = |id: positron_kernel::SegmentId| {
        let name = id
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        root.join("data/segments/sealed")
            .join(format!("{name}.segment"))
    };
    let first_path = sealed_path(receipts[0].segment_id());
    let mut damaged = fs::read(&first_path)?;
    let byte = damaged.last_mut().ok_or("sealed segment bytes")?;
    *byte ^= 0xa5;
    fs::write(&first_path, damaged)?;
    fs::remove_file(sealed_path(receipts[1].segment_id()))?;
    let before = file_tree(&root)?;

    let first = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
    assert_eq!(
        first.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Incomplete,
        "a localized first target cannot conceal an omitted later target: {:?}",
        first.reports()
    );
    assert!(!first.is_complete());
    assert!(first.continuation().is_some());
    let localized = first
        .reports()
        .iter()
        .copied()
        .find(|report| {
            report.outcome() == positron_kernel::IntegrityVerificationOutcome::Quarantined
        })
        .ok_or("missing localized first target report")?;
    assert_eq!(
        localized.quarantined_segment(),
        Some(receipts[0].segment_id())
    );
    assert!(localized.localized_finding().is_some());
    assert!(localized.omitted_segments() > 0);
    assert_eq!(file_tree(&root)?, before);

    let resumed = resume_offline_integrity(
        &paths,
        2,
        first
            .continuation()
            .cloned()
            .ok_or("missing continuation")?,
    )
    .map_err(|failure| format!("resumed offline verification failed: {failure:?}"))?;
    assert!(resumed.is_complete());
    let retained = resumed
        .localized_observations()
        .first()
        .copied()
        .ok_or("missing retained localized observation")?;
    assert_eq!(retained.segment(), receipts[0].segment_id());
    assert!(matches!(
        retained.event_range(),
        crate::OfflineEventRange::Known { .. }
    ));
    assert!(matches!(
        retained.ingest_range(),
        crate::OfflineIngestRange::Known { .. }
    ));
    assert_eq!(
        resumed.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Fenced,
        "the later sealed-source ambiguity must fence the aggregate"
    );
    assert!(resumed.reports().iter().any(|report| {
        report.outcome() == positron_kernel::IntegrityVerificationOutcome::Fenced
    }));
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_localized_corruption_continues_to_later_healthy_sealed_target()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::{routing::SignalKind, value::ValueLimitProfile};
    use positron_kernel::{
        ActiveSegmentLedger, Catalog, ResourceDimension, SegmentScope, StoreBlockIdentity, WorkKind,
    };
    use positron_policy::{
        IngestPolicy, LogMetadata, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
    };
    use positron_signals::{LogRecord as StoredLogRecord, LogStore};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let mut receipts = Vec::new();
    for identity_byte in [0x91, 0x92] {
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )?;
        let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
            NativeLogCandidate::new(Some(10), None, None, Vec::new(), LogMetadata::empty()),
            PolicyReceiver::OtlpGrpc,
        )?
        else {
            return Err("fixture policy rejected an immutable log".into());
        };
        let capacity = instance._authority.governor().reserve(WorkClaim::tenant(
            instance.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
        ledger.append(
            LogStore::new()
                .prepare(
                    ledger.begin_store_block(
                        capacity,
                        StoreBlockIdentity::new([identity_byte; 16])?,
                    )?,
                    vec![StoredLogRecord::checked_evaluated(
                        ValueLimitProfile::release_1_system_maximum(),
                        *evaluated,
                    )?],
                )?
                .into_store_block(),
        )?;
        receipts.push(ledger.seal()?);
    }
    drop(catalog);
    drop(instance);

    let sealed_path = |id: positron_kernel::SegmentId| {
        let name = id
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        root.join("data/segments/sealed")
            .join(format!("{name}.segment"))
    };
    let first_path = sealed_path(receipts[0].segment_id());
    let mut damaged = fs::read(&first_path)?;
    let byte = damaged.last_mut().ok_or("sealed segment bytes")?;
    *byte ^= 0xa5;
    fs::write(&first_path, damaged)?;
    let before = file_tree(&root)?;

    let first = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
    assert_eq!(
        first.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Incomplete,
        "a localized first target cannot conceal an omitted later target: {:?}",
        first.reports()
    );
    assert!(!first.is_complete());
    assert!(first.continuation().is_some());
    let localized = first
        .reports()
        .iter()
        .copied()
        .find(|report| {
            report.outcome() == positron_kernel::IntegrityVerificationOutcome::Quarantined
        })
        .ok_or("missing localized first target report")?;
    assert_eq!(
        localized.quarantined_segment(),
        Some(receipts[0].segment_id())
    );
    assert!(localized.localized_finding().is_some());
    assert!(localized.omitted_segments() > 0);
    assert_eq!(file_tree(&root)?, before);

    let resumed = resume_offline_integrity(
        &paths,
        2,
        first
            .continuation()
            .cloned()
            .ok_or("missing continuation")?,
    )
    .map_err(|failure| format!("resumed offline verification failed: {failure:?}"))?;
    assert!(resumed.is_complete());
    let retained = resumed
        .localized_observations()
        .first()
        .copied()
        .ok_or("missing retained localized observation")?;
    assert_eq!(retained.segment(), receipts[0].segment_id());
    assert!(matches!(
        retained.event_range(),
        crate::OfflineEventRange::Known { .. }
    ));
    assert!(matches!(
        retained.ingest_range(),
        crate::OfflineIngestRange::Known { .. }
    ));
    assert_eq!(
        resumed.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Quarantined,
        "the later healthy sealed target must complete coverage without erasing the observation"
    );
    assert!(resumed.reports().iter().any(|report| {
        report.outcome() == positron_kernel::IntegrityVerificationOutcome::Verified
    }));
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn offline_multiple_localized_corruptions_resume_through_healthy_remainder()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::{routing::SignalKind, value::ValueLimitProfile};
    use positron_kernel::{
        ActiveSegmentLedger, Catalog, ResourceDimension, SegmentScope, StoreBlockIdentity, WorkKind,
    };
    use positron_policy::{
        IngestPolicy, LogMetadata, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
    };
    use positron_signals::{LogRecord as StoredLogRecord, LogStore};

    let root = temporary_root()?;
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let mut receipts = Vec::new();
    for identity_byte in [0x91, 0x92, 0x93] {
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )?;
        let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
            NativeLogCandidate::new(Some(10), None, None, Vec::new(), LogMetadata::empty()),
            PolicyReceiver::OtlpGrpc,
        )?
        else {
            return Err("fixture policy rejected an immutable log".into());
        };
        let capacity = instance._authority.governor().reserve(WorkClaim::tenant(
            instance.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
        ledger.append(
            LogStore::new()
                .prepare(
                    ledger.begin_store_block(
                        capacity,
                        StoreBlockIdentity::new([identity_byte; 16])?,
                    )?,
                    vec![StoredLogRecord::checked_evaluated(
                        ValueLimitProfile::release_1_system_maximum(),
                        *evaluated,
                    )?],
                )?
                .into_store_block(),
        )?;
        receipts.push(ledger.seal()?);
    }
    drop(catalog);
    drop(instance);

    let sealed_path = |id: positron_kernel::SegmentId| {
        let name = id
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        root.join("data/segments/sealed")
            .join(format!("{name}.segment"))
    };
    let first_path = sealed_path(receipts[0].segment_id());
    let mut damaged = fs::read(&first_path)?;
    let byte = damaged.last_mut().ok_or("sealed segment bytes")?;
    *byte ^= 0xa5;
    fs::write(&first_path, damaged)?;
    let second_path = sealed_path(receipts[1].segment_id());
    let mut second_damaged = fs::read(&second_path)?;
    let second_byte = second_damaged
        .last_mut()
        .ok_or("second sealed segment bytes")?;
    *second_byte ^= 0x5a;
    fs::write(&second_path, second_damaged)?;
    let before = file_tree(&root)?;

    let first = verify_offline_integrity(&paths, 2)
        .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
    assert_eq!(
        first.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Incomplete,
        "a localized first target cannot conceal an omitted later target: {:?}",
        first.reports()
    );
    assert!(!first.is_complete());
    assert!(first.continuation().is_some());
    let localized = first
        .reports()
        .iter()
        .copied()
        .find(|report| {
            report.outcome() == positron_kernel::IntegrityVerificationOutcome::Quarantined
        })
        .ok_or("missing localized first target report")?;
    assert_eq!(
        localized.quarantined_segment(),
        Some(receipts[0].segment_id())
    );
    assert!(localized.localized_finding().is_some());
    assert!(localized.omitted_segments() > 0);
    assert_eq!(file_tree(&root)?, before);

    let second = resume_offline_integrity(
        &paths,
        2,
        first
            .continuation()
            .cloned()
            .ok_or("missing first continuation")?,
    )
    .map_err(|failure| format!("second offline verification failed: {failure:?}"))?;
    assert!(!second.is_complete());
    assert_eq!(
        second.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Incomplete
    );
    assert!(second.continuation().is_some());
    assert_eq!(second.localized_observations().len(), 2);
    assert_eq!(
        second.localized_observations()[1].segment(),
        receipts[1].segment_id()
    );
    assert!(matches!(
        second.localized_observations()[1].event_range(),
        crate::OfflineEventRange::Known { .. }
    ));
    assert!(matches!(
        second.localized_observations()[1].ingest_range(),
        crate::OfflineIngestRange::Known { .. }
    ));
    assert_eq!(file_tree(&root)?, before);

    let resumed = resume_offline_integrity(
        &paths,
        2,
        second
            .continuation()
            .cloned()
            .ok_or("missing second continuation")?,
    )
    .map_err(|failure| format!("final offline verification failed: {failure:?}"))?;
    assert!(resumed.is_complete());
    assert_eq!(resumed.localized_observations().len(), 2);
    assert_eq!(
        resumed.localized_observations()[0].segment(),
        receipts[0].segment_id()
    );
    assert_eq!(
        resumed.localized_observations()[1].segment(),
        receipts[1].segment_id()
    );
    assert_eq!(
        resumed.aggregate_outcome(),
        crate::OfflineIntegrityAggregateOutcome::Quarantined,
        "the healthy remainder completes coverage without losing either observation"
    );
    assert!(resumed.reports().iter().any(|report| {
        report.outcome() == positron_kernel::IntegrityVerificationOutcome::Verified
    }));
    assert_eq!(file_tree(&root)?, before);
    fs::remove_dir_all(root)?;
    Ok(())
}
