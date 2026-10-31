//! Bounded post-authentication continuation parsing on a valid native basis.
use super::*;
use crate::ResourceDimension;

pub(in crate::catalog::backup_capture) fn exercise(catalog: &Catalog<'_>, data: &[u8]) {
    if data.len() > 128 {
        return;
    }
    run(catalog, data).expect("fixed native continuation fuzz fixture is valid");
}

fn run(catalog: &Catalog<'_>, data: &[u8]) -> Result<(), CatalogFailure> {
    let operation = [0xa1; 16];
    let request = [0xa2; 32];
    let epoch = FormatEpoch::CATALOG_V2;
    let secret = catalog
        .secret
        .lock()
        .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
    let mut files = Vec::new();
    for plaintext in [
        b"continuation first object".as_slice(),
        b"continuation second object".as_slice(),
    ] {
        let object = CatalogObject::new(plaintext.to_vec())?;
        let ciphertext = storage::artifact::protect_backup_capture(
            &secret,
            catalog.instance,
            object.identity().to_bytes(),
            epoch,
            plaintext,
        )?;
        let mut file = BackupCaptureFile::new(
            BackupCaptureFileKind::CatalogObject,
            object.identity().to_bytes(),
            ciphertext.len() as u64,
        )?;
        file.checksum = Sha256::digest(&ciphertext).into();
        files.push((file, ciphertext));
    }
    files.sort_by_key(|(file, _)| file.identity);
    let capture = BackupCapture {
        directory: catalog.export_output_root()?,
        operation,
        request,
        generation: 1,
        catalog: [0xa3; 32],
        epoch,
        audit: 0,
        files: files.iter().map(|(file, _)| *file).collect(),
    };
    let protected = storage::artifact::protect_backup_capture(
        &secret,
        catalog.instance,
        codec::index_identity(operation, request),
        epoch,
        &capture.encode()?,
    )?;
    drop(secret);
    let mut index = b"POSBCI01".to_vec();
    index.extend_from_slice(&epoch.value().to_be_bytes());
    index.extend_from_slice(&protected);
    let base = || catalog.begin_backup_capture_verification(operation, request, &index);
    let admission = BackupVerificationProgress {
        native: BackupVerificationNativeState::Metadata(Box::new(base()?)),
        semantic: Vec::new(),
    }
    .prospective_continuation_resources(&index)?;
    let (first, ciphertext) = files.first().expect("two fixed native files");
    let mut native = base()?;
    native.verify_file(catalog, first.identity, ciphertext)?;
    let partial = BackupVerificationProgress {
        native: BackupVerificationNativeState::Metadata(Box::new(native)),
        semantic: Vec::new(),
    };
    let partial_bytes = partial.encode()?;
    let decoded = BackupVerificationProgress::decode(&partial_bytes, base()?)?;
    let BackupVerificationNativeState::Metadata(mut native) = decoded.native else {
        panic!("partial continuation retains its native phase");
    };
    for (file, ciphertext) in files.iter().skip(1) {
        native.verify_file(catalog, file.identity, ciphertext)?;
    }
    let snapshot = native.finish()?;
    assert_eq!(snapshot.object_count(), 2);
    let finished = BackupVerificationProgress {
        native: BackupVerificationNativeState::Catalog(snapshot),
        semantic: Vec::new(),
    };
    let finished_bytes = finished.encode()?;
    let restored = BackupVerificationProgress::decode(&finished_bytes, base()?)?;
    let BackupVerificationNativeState::Catalog(snapshot) = restored.native else {
        panic!("finished continuation retains its native phase");
    };
    assert_eq!(snapshot.object_count(), 2);
    assert_eq!(snapshot.identity().to_bytes(), [0xa3; 32]);

    // A later accepted file cannot stand in for the missing first metadata file.
    let mut hole = partial_bytes.clone();
    let position = hole
        .windows(32)
        .position(|value| value == first.identity)
        .expect("partial encoding contains the accepted file identity");
    let second = files.get(1).expect("second fixed native file").0.identity;
    hole.get_mut(position..position + 32)
        .expect("accepted identity range")
        .copy_from_slice(&second);
    assert!(BackupVerificationProgress::decode(&hole, base()?).is_err());

    let mut mutated = if data.first().is_some_and(|value| value & 1 != 0) {
        finished_bytes
    } else {
        partial_bytes
    };
    match data.get(1).copied().unwrap_or_default() % 5 {
        0 => {},
        1 => {
            let offset = usize::from(data.get(2).copied().unwrap_or_default()) % mutated.len();
            if let Some(value) = mutated.get_mut(offset) {
                *value ^= data.get(3).copied().unwrap_or(1).max(1);
            }
        },
        2 => {
            mutated.truncate(usize::from(data.get(2).copied().unwrap_or_default()) % mutated.len())
        },
        3 => mutated.extend_from_slice(data.get(2..).unwrap_or(b"trailing")),
        _ => {
            let offset = usize::from(data.get(2).copied().unwrap_or(60)) % (mutated.len() - 3);
            if let Some(value) = mutated.get_mut(offset..offset + 4) {
                value.copy_from_slice(&u32::MAX.to_be_bytes());
            }
        },
    }
    if let Ok(decoded) = BackupVerificationProgress::decode(&mutated, base()?) {
        let exact = decoded.continuation_resources(&index)?;
        let prospective = decoded.prospective_continuation_resources(&index)?;
        for dimension in ResourceDimension::ALL {
            assert!(admission.get(dimension) >= exact.get(dimension));
            assert!(prospective.get(dimension) >= exact.get(dimension));
        }
    }
    let _raw = BackupVerificationProgress::decode(data, base()?);
    Ok(())
}
