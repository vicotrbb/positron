//! Hostile persisted Upgrade bytes use the existing record decoder/fuzz seam.
use super::upgrade_parameters::UpgradeProgress;
use super::*;

#[test]
fn upgrade_record_rejects_truncation_unknown_stage_and_missing_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/backup",
        [1; 16],
        [2; 32],
        [3; 32],
    )?;
    let backup = BackupSnapshotParameters::new(repository, 3600, [4; 32])?;
    let parameters = UpgradeParameters::new(
        UpgradeReleaseIdentity::new([5; 32], [6; 32], [0, 1, 0])?,
        UpgradeReleaseIdentity::new([7; 32], [8; 32], [0, 1, 1])?,
        2,
        [9; 32],
        backup,
    )?;
    let request = DurableOperationRequest::upgrade(
        positron_domain::identity::PrincipalId::from_bytes([10; 16])?,
        AdministrativeIdempotencyKey::new([11; 16])?,
        [12; 16],
        1,
        1,
        parameters.intent_digest(),
    )?;
    let mut operation = DurableOperation::accepted(request);
    operation.backup_parameters = Some(BackupOperationParameters::Upgrade(parameters));
    operation.upgrade_progress = Some(UpgradeProgress {
        report: None,
        rollback: None,
        stage: UpgradeStage::Preflight,
        drain: None,
        snapshot: None,
    });
    let encoded = codec::encode_operation(operation);
    assert_eq!(codec::decode_operation(&encoded)?, Some(operation));
    for length in 8..encoded.len() {
        assert!(
            codec::decode_operation(encoded.get(..length).ok_or("prefix")?).is_err(),
            "accepted truncated prefix {length}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(codec::decode_operation(&trailing).is_err());
    for stage in [0, 3, 4, 7, 255] {
        let mut invalid = encoded.clone();
        let offset = invalid.len().checked_sub(5).ok_or("stage")?;
        *invalid.get_mut(offset).ok_or("stage")? = stage;
        assert!(
            codec::decode_operation(&invalid).is_err(),
            "accepted stage {stage} without its evidence"
        );
    }
    let mut hidden = encoded;
    let last = hidden.last_mut().ok_or("snapshot tag")?;
    *last = 2;
    assert!(codec::decode_operation(&hidden).is_err());
    Ok(())
}
