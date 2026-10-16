use super::*;
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};

#[test]
fn restore_report_refuses_malformed_signed_claims_and_wrong_authorities()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let custody = BootstrapKeyCustody::initialize(directory.path())?;
    let instance = InstanceId::new([2; 16])?;
    let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
    let signer = custody.backup_control_signer(instance, &protected)?;
    let repository = RepositoryIdentity::local(
        [1; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        directory.path(),
    )?;
    let mut payload = b"POSBRR02".to_vec();
    payload.extend_from_slice(&[3; 16]);
    payload.extend_from_slice(&[4; 32]);
    payload.extend_from_slice(&repository.encode());
    for value in 5..9 {
        payload.extend_from_slice(&[value; 32]);
    }
    payload.extend_from_slice(&1u64.to_be_bytes());
    payload.extend_from_slice(&2u64.to_be_bytes());
    payload.extend_from_slice(&1u32.to_be_bytes());
    payload.extend_from_slice(&0u64.to_be_bytes());
    payload.extend_from_slice(&[9; 32]);
    payload.extend_from_slice(&1u32.to_be_bytes());
    payload.extend_from_slice(&2u32.to_be_bytes());
    payload.extend_from_slice(&[10; 16]);
    payload.extend_from_slice(&[11; 16]);
    payload.extend_from_slice(&[1, 1, 1]);
    let signed = |payload| super::super::super::super::codec::sign(payload, &signer);
    let bytes = signed(payload.clone())?;
    let report = BackupRestoreReport::verify(&bytes, &repository, signer.identity())?;
    assert_eq!(report.recovered_keys(), 1);
    assert_eq!(report.excluded_tenants(), &[[10; 16], [11; 16]]);
    let wrong = RepositoryIdentity::local(
        [99; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        directory.path(),
    )?;
    assert!(BackupRestoreReport::verify(&bytes, &wrong, signer.identity()).is_err());
    let other = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[8; 32])?;
    let other = custody.backup_control_signer(instance, &other)?;
    assert!(BackupRestoreReport::verify(&bytes, &repository, other.identity()).is_err());
    for offset in [
        0, 8, 24, 164, 196, 228, 260, 292, 300, 308, 320, 352, 356, 360, 376, 392,
    ] {
        let mut malformed = payload.clone();
        // Zero identities, impossible counts, invalid epoch, unordered tenant,
        // and incomplete verification flags are all signed by the real owner.
        let width = match offset {
            8 => 16,
            24 | 164 | 196 | 228 | 260 | 320 => 32,
            292 | 300 => 8,
            308 | 352 | 356 => 4,
            360 | 376 => 16,
            _ => 1,
        };
        malformed
            .get_mut(offset..offset + width)
            .ok_or("field")?
            .fill(0);
        if offset == 300 {
            malformed.get_mut(300..308).ok_or("target")?.fill(0);
        }
        if offset == 352 {
            malformed.get_mut(352..356).ok_or("count")?.fill(255);
        }
        if offset == 356 {
            malformed.get_mut(356..360).ok_or("count")?.fill(255);
        }
        assert!(
            BackupRestoreReport::verify(&signed(malformed)?, &repository, signer.identity())
                .is_err(),
            "field {offset}"
        );
    }
    let mut duplicate = payload.clone();
    duplicate
        .get_mut(376..392)
        .ok_or("second tenant")?
        .copy_from_slice(&[10; 16]);
    assert!(
        BackupRestoreReport::verify(&signed(duplicate)?, &repository, signer.identity()).is_err()
    );
    let mut trailing = payload;
    trailing.push(0);
    assert!(
        BackupRestoreReport::verify(&signed(trailing)?, &repository, signer.identity()).is_err()
    );
    for length in 0..bytes.len() {
        assert!(
            BackupRestoreReport::verify(
                bytes.get(..length).ok_or("prefix")?,
                &repository,
                signer.identity()
            )
            .is_err()
        );
    }
    let mut tampered = bytes;
    *tampered.last_mut().ok_or("signature")? ^= 1;
    assert!(BackupRestoreReport::verify(&tampered, &repository, signer.identity()).is_err());
    assert_eq!(
        BackupRestoreReport::verify(&vec![0; MAX_BYTES + 1], &repository, signer.identity()),
        Err(RepositoryFailure::LimitExceeded)
    );
    Ok(())
}
