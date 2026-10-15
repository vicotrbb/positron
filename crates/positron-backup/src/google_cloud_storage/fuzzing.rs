use super::{protocol, upload::Record};
use crate::*;
use sha2::{Digest, Sha256};
/// Native response and persisted recovery boundaries; no credentials or I/O.
pub fn fuzz_google_cloud_storage_repository(data: &[u8]) {
    let target =
        GoogleCloudStorageTarget::new("positron-backup", "123456789012", "US-CENTRAL1", "owned/")
            .expect("published target");
    let _ = protocol::bucket(data, &target);
    let _ = protocol::metadata(data, "owned/o-test");
    if let Ok(value) = protocol::json(data) {
        let _ = protocol::policy(&value);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = protocol::session(text, target.bucket());
        let _ = protocol::uploaded(Some(text), 64 * 1024 * 1024);
        let _ = GoogleCloudStorageTarget::decode_locator(text);
    }
    let object = ImmutableObject::new(b"encrypted backup".to_vec()).expect("bounded fixture");
    let plan = UploadPlan::new(object.id(), 16).expect("fixture plan");
    let _ = Record::decode(data.to_vec(), target.commitment(), plan.id());
    let mut record = Record::new(plan, [9; 16]);
    record.bytes = object.bytes().to_vec();
    let mut frame = record.encode(target.commitment());
    for (slot, value) in frame.iter_mut().zip(data) {
        *slot = *value;
    }
    if let Some(end) = frame.len().checked_sub(32) {
        let digest: [u8; 32] = Sha256::digest(frame.get(..end).unwrap_or(&[])).into();
        if let Some(checksum) = frame.get_mut(end..) {
            checksum.copy_from_slice(&digest);
        }
    }
    let _ = Record::decode(frame, target.commitment(), plan.id());
    let custody = positron_kernel::RepositoryUploadAuthenticator::new(
        positron_kernel::CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
        positron_kernel::InstanceId::new([2; 16]).expect("fixture instance"),
    );
    let _ = custody.open_session(data);
}
