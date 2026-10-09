//! Exercise destructive confirmation independently of the retained-block oracle.
use super::*;
use crate::{
    AuditIntent, CatalogIntegrityVerificationRequest, CommittedLedgerReader, IntegrityCancellation,
    IntegrityScrubBudget, IntegrityVerificationMode, IntegrityVerificationRequest,
    SegmentAbandonmentPlan,
};

pub(super) fn exercise(selector: u8) {
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    let volume =
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost).expect("fuzz volume");
    let Some(authority) = fuzz_authority(volume) else {
        return;
    };
    let instance = InstanceId::new([0x81; 16]).expect("instance");
    let catalog = Catalog::open(&authority, instance, catalog_secret()).expect("catalog");
    let scope = scope();
    install_retention_policy(&catalog, instance, scope.tenant_id());
    let (time, _) = RetentionTimeAuthority::establish_with_manual_elapsed(
        positron_domain::time::UnixNanoseconds::new(1_000_000_000),
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0x91; 32]));
    let ledger = open(&authority, &time, &catalog, scope).expect("ledger");
    ledger.seal().expect("empty marker");
    let ledger = open(&authority, &time, &catalog, scope).expect("reopen");
    let capacity = authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                scope.tenant_id(),
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)
                    .expect("bounded capacity"),
            )
            .expect("claim"),
        )
        .expect("reservation");
    let prepared = ledger
        .begin_store_block(capacity, identity(1))
        .expect("preparation")
        .finish_with_event_range(
            vec![selector],
            super::super::AuthenticatedEventRange::known(
                positron_domain::time::UnixNanoseconds::new(1),
                positron_domain::time::UnixNanoseconds::new(2),
            )
            .expect("range"),
        )
        .expect("block");
    ledger.append(prepared).expect("append");
    let sealed = ledger.seal().expect("seal");
    let path = root
        .0
        .join("segments/sealed")
        .join(super::super::recovery::segment_name(sealed.segment_id()));
    fs::write(&path, [selector]).expect("corrupt evidence");
    ActiveSegmentLedger::verify_catalog_integrity(
        &authority,
        &catalog,
        CatalogIntegrityVerificationRequest::new(
            IntegrityVerificationRequest::new(
                scope,
                key(),
                IntegrityScrubBudget::new(8).expect("budget"),
                &IntegrityCancellation::new(),
                TransactionId::new([0xd1; 16]).expect("transaction"),
                None,
            ),
            IntegrityVerificationMode::Online,
        ),
    )
    .expect("quarantine");
    let basis = catalog.pin().expect("basis");
    let mut plan = SegmentAbandonmentPlan::preflight(&catalog, &basis, scope, sealed.segment_id())
        .expect("preview");
    let mut wrong = plan.confirmation_digest();
    wrong[usize::from(selector) % 32] ^= 1;
    assert!(
        SegmentAbandonmentPlan::preflight(&catalog, &basis, scope, sealed.segment_id())
            .expect("preview")
            .confirm(wrong)
            .is_err()
    );
    let confirmation = plan.confirmation_digest();
    let objects = plan.confirm(confirmation).expect("confirm");
    catalog
        .commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([0xd2; 16]).expect("transaction"),
                basis.format_epoch().expect("epoch"),
                objects,
            )
            .expect("proposal"),
            Some(AuditIntent::new(b"fuzz explicit loss".to_vec()).expect("audit")),
        )
        .expect("publication");
    let snapshot = CommittedLedgerReader::open(&authority, &catalog, scope, key())
        .expect("reader")
        .snapshot()
        .expect("snapshot");
    assert_eq!(snapshot.frontier(), sealed.frontier());
    assert!(snapshot.blocks().is_empty());
    assert_eq!(snapshot.quarantined_holes().len(), 1);
    assert_eq!(fs::read(path).expect("evidence"), [selector]);
    let reopened = open(&authority, &time, &catalog, scope).expect("reopen after loss");
    assert_eq!(
        reopened
            .snapshot()
            .expect("snapshot")
            .quarantined_holes()
            .len(),
        1
    );
}
