use super::*;
#[test]
fn signed_report_roundtrips_exact_upgrade_bindings() {
    let signer = crate::UpgradeVerificationSigner::from_seed(Box::new([29; 32])).expect("signer");
    let input = UpgradeVerificationInput::new(
        [1; 16],
        [2; 16],
        [3; 32],
        [4; 32],
        5,
        UpgradeQueryVerification::Executed { tenant: [6; 16] },
    )
    .expect("input");
    let report = UpgradeVerificationReport::sign(input, &signer).expect("signed report");
    let decoded = UpgradeVerificationReport::from_bytes(report.bytes()).expect("canonical report");
    assert_eq!(decoded.input(), input);
    assert_eq!(decoded.verify(signer.identity()), Ok(()));
}
#[test]
fn refuses_report_without_all_scope_integrity_verification() {
    let signer = crate::UpgradeVerificationSigner::from_seed(Box::new([29; 32])).expect("signer");
    let input = UpgradeVerificationInput::new(
        [1; 16],
        [2; 16],
        [3; 32],
        [4; 32],
        5,
        UpgradeQueryVerification::NotApplicableNoQueryableTenant,
    )
    .expect("input");
    let mut bytes = UpgradeVerificationReport::sign(input, &signer)
        .expect("report")
        .bytes()
        .to_vec();
    bytes[112] = 0;
    assert!(UpgradeVerificationReport::from_bytes(&bytes).is_err());
}

#[test]
fn authentication_refuses_wrong_root_cross_domain_and_mutated_claims() {
    let signer = crate::UpgradeVerificationSigner::from_seed(Box::new([29; 32])).expect("signer");
    let input = UpgradeVerificationInput::new(
        [1; 16],
        [2; 16],
        [3; 32],
        [4; 32],
        5,
        UpgradeQueryVerification::Executed { tenant: [6; 16] },
    )
    .expect("input");
    let report = UpgradeVerificationReport::sign(input, &signer).expect("report");
    let other =
        crate::UpgradeVerificationSigner::from_seed(Box::new([30; 32])).expect("other signer");
    assert_eq!(
        report.verify(other.identity()),
        Err(Failure::AuthenticationFailed)
    );
    let mut changed = report.bytes().to_vec();
    changed[40] ^= 1;
    assert_eq!(
        UpgradeVerificationReport::from_bytes(&changed)
            .expect("structural record")
            .verify(signer.identity()),
        Err(Failure::AuthenticationFailed)
    );
    for signature in [
        crate::ExportManifestSigner::from_seed(Box::new([29; 32]))
            .expect("query signer")
            .sign(&input.encode())
            .expect("query signature")
            .bytes(),
        crate::BackupControlSigner::from_seed(Box::new([29; 32]))
            .expect("backup signer")
            .sign(&input.encode())
            .expect("backup signature")
            .bytes(),
    ] {
        let mut foreign = report.bytes().to_vec();
        foreign[194..].copy_from_slice(&signature);
        assert_eq!(
            UpgradeVerificationReport::from_bytes(&foreign)
                .expect("foreign record")
                .verify(signer.identity()),
            Err(Failure::AuthenticationFailed)
        );
    }
}
#[test]
fn decoding_refuses_missing_bindings_ambiguous_query_and_wire_lengths() {
    let signer = crate::UpgradeVerificationSigner::from_seed(Box::new([29; 32])).expect("signer");
    let input = UpgradeVerificationInput::new(
        [1; 16],
        [2; 16],
        [3; 32],
        [4; 32],
        5,
        UpgradeQueryVerification::Executed { tenant: [6; 16] },
    )
    .expect("input");
    let report = UpgradeVerificationReport::sign(input, &signer).expect("report");
    for mutate in [
        |b: &mut Vec<u8>| b[0] = 0,
        |b: &mut Vec<u8>| b[8..24].fill(0),
        |b: &mut Vec<u8>| b[24..40].fill(0),
        |b: &mut Vec<u8>| b[40..72].fill(0),
        |b: &mut Vec<u8>| b[72..104].fill(0),
        |b: &mut Vec<u8>| b[104..112].fill(0),
        |b: &mut Vec<u8>| b[113] = 2,
        |b: &mut Vec<u8>| b[113] = 0,
        |b: &mut Vec<u8>| b[114..130].fill(0),
        |b: &mut Vec<u8>| b[130..162].fill(0),
        |b: &mut Vec<u8>| b[162..194].fill(0),
        |b: &mut Vec<u8>| b[194..].fill(0),
    ] {
        let mut bytes = report.bytes().to_vec();
        mutate(&mut bytes);
        assert!(UpgradeVerificationReport::from_bytes(&bytes).is_err());
    }
    for len in [0, WIRE - 1, WIRE + 1, 65_536] {
        assert!(UpgradeVerificationReport::from_bytes(&vec![0; len]).is_err());
    }
    let input = UpgradeVerificationInput::new(
        [1; 16],
        [2; 16],
        [3; 32],
        [4; 32],
        5,
        UpgradeQueryVerification::NotApplicableNoQueryableTenant,
    )
    .expect("no-query input");
    let report = UpgradeVerificationReport::sign(input, &signer).expect("no-query report");
    assert_eq!(
        UpgradeVerificationReport::from_bytes(report.bytes())
            .expect("no-query record")
            .input()
            .query(),
        UpgradeQueryVerification::NotApplicableNoQueryableTenant
    );
}
