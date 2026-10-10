//! One Catalog-owned verified recovery path and optional rotation predecessor.
use positron_kernel::{
    BootstrapIntegrityIdentity, BootstrapKeyIdentity, CatalogSnapshot, InstanceId, RecoveryFailure,
    RecoveryIdentity,
};
use std::path::PathBuf;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryReadiness {
    IndependentRecoveryRequired,
    Verified,
}
#[derive(Clone)]
pub(super) struct BundleReference {
    pub(super) path: PathBuf,
    pub(super) digest: [u8; 32],
}
pub(super) struct VerifiedBundle {
    pub(super) pin: RecoveryIdentity,
    pub(super) current: BundleReference,
    pub(super) predecessor: Option<BundleReference>,
    pub(super) retiring: bool,
}
impl VerifiedBundle {
    pub(super) fn find(snapshot: &CatalogSnapshot) -> Result<Option<Self>, RecoveryFailure> {
        let mut found = None;
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(|_| RecoveryFailure::Storage)?
                .ok_or(RecoveryFailure::Storage)?;
            if bytes.starts_with(b"POSREC01") {
                if found.is_some() {
                    return Err(RecoveryFailure::Authentication);
                }
                found = Some(Self::decode(bytes)?);
            }
        }
        Ok(found)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, RecoveryFailure> {
        let mut bytes = Vec::with_capacity(8192 + 256);
        bytes.extend_from_slice(b"POSREC01");
        bytes.extend_from_slice(&self.pin.instance().to_bytes());
        bytes.extend_from_slice(&self.pin.root().key_id());
        bytes.extend_from_slice(&self.pin.root().created_at_unix_seconds().to_be_bytes());
        bytes.extend_from_slice(&self.pin.root().fingerprint());
        bytes.extend_from_slice(&self.pin.integrity().public_key());
        bytes.extend_from_slice(&self.pin.integrity().fingerprint());
        reference(&self.current, &mut bytes)?;
        bytes.push(u8::from(self.predecessor.is_some()));
        if let Some(predecessor) = &self.predecessor {
            reference(predecessor, &mut bytes)?;
        }
        bytes.push(u8::from(self.retiring));
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, RecoveryFailure> {
        let mut cursor = Cursor(
            bytes
                .strip_prefix(b"POSREC01")
                .ok_or(RecoveryFailure::Authentication)?,
        );
        let instance =
            InstanceId::new(cursor.array()?).map_err(|_| RecoveryFailure::Authentication)?;
        let key_id = cursor.array()?;
        let created = u64::from_be_bytes(cursor.array()?);
        let fingerprint = cursor.array()?;
        let root = BootstrapKeyIdentity::from_parts(key_id, fingerprint, created)
            .map_err(|_| RecoveryFailure::Authentication)?;
        let integrity = BootstrapIntegrityIdentity::from_pinned(cursor.array()?, cursor.array()?)
            .map_err(|_| RecoveryFailure::Authentication)?;
        let pin = RecoveryIdentity::new(instance, root, integrity)?;
        let current = cursor.reference()?;
        let predecessor = match cursor.array::<1>()? {
            [0] => None,
            [1] => Some(cursor.reference()?),
            _ => return Err(RecoveryFailure::Authentication),
        };
        let retiring = match cursor.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err(RecoveryFailure::Authentication),
        };
        if !cursor.0.is_empty() || (retiring && predecessor.is_none()) {
            return Err(RecoveryFailure::Authentication);
        }
        Ok(Self {
            pin,
            current,
            predecessor,
            retiring,
        })
    }
}
fn reference(value: &BundleReference, bytes: &mut Vec<u8>) -> Result<(), RecoveryFailure> {
    let path = value.path.to_str().ok_or(RecoveryFailure::InvalidInput)?;
    if path.is_empty() || path.len() > 4096 || !value.path.is_absolute() {
        return Err(RecoveryFailure::InvalidInput);
    }
    bytes.extend_from_slice(&(path.len() as u16).to_be_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(&value.digest);
    Ok(())
}
struct Cursor<'a>(&'a [u8]);
impl Cursor<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecoveryFailure> {
        let (bytes, tail) = self
            .0
            .split_at_checked(N)
            .ok_or(RecoveryFailure::Authentication)?;
        self.0 = tail;
        bytes
            .try_into()
            .map_err(|_| RecoveryFailure::Authentication)
    }
    fn reference(&mut self) -> Result<BundleReference, RecoveryFailure> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length == 0 || length > 4096 {
            return Err(RecoveryFailure::Authentication);
        }
        let (bytes, tail) = self
            .0
            .split_at_checked(length)
            .ok_or(RecoveryFailure::Authentication)?;
        self.0 = tail;
        let path =
            PathBuf::from(std::str::from_utf8(bytes).map_err(|_| RecoveryFailure::Authentication)?);
        if !path.is_absolute() {
            return Err(RecoveryFailure::Authentication);
        }
        Ok(BundleReference {
            path,
            digest: self.array()?,
        })
    }
}

#[cfg(any(test, fuzzing))]
pub(super) fn fuzz_state(data: &[u8]) -> Result<(), RecoveryFailure> {
    use sha2::{Digest, Sha256};
    if data.len() > 8192 + 256 {
        return Ok(());
    }
    drop(VerifiedBundle::decode(data));
    let public = [0x61; 32];
    let mut fingerprint = Sha256::new();
    fingerprint.update(b"positron-instance-integrity-key-fingerprint-v1\0");
    fingerprint.update(public);
    let integrity = BootstrapIntegrityIdentity::from_pinned(public, fingerprint.finalize().into())
        .map_err(|_| RecoveryFailure::InvalidInput)?;
    let pin = RecoveryIdentity::new(
        InstanceId::new([0x62; 16]).map_err(|_| RecoveryFailure::InvalidInput)?,
        BootstrapKeyIdentity::from_parts([0x63; 16], [0x64; 32], 42)
            .map_err(|_| RecoveryFailure::InvalidInput)?,
        integrity,
    )?;
    let value = VerifiedBundle {
        pin,
        current: BundleReference {
            path: PathBuf::from("/fuzz/recovery.age"),
            digest: [0x65; 32],
        },
        predecessor: Some(BundleReference {
            path: PathBuf::from("/fuzz/predecessor.age"),
            digest: [0x66; 32],
        }),
        retiring: false,
    };
    let mut candidate = value.encode()?;
    for command in data.chunks_exact(3) {
        let [high, low, value]: [u8; 3] = command
            .try_into()
            .map_err(|_| RecoveryFailure::InvalidInput)?;
        if let Some(byte) = candidate.get_mut(usize::from(u16::from_be_bytes([high, low]))) {
            *byte ^= value;
        }
    }
    if let Ok(decoded) = VerifiedBundle::decode(&candidate) {
        assert_eq!(
            decoded.encode()?,
            candidate,
            "accepted Catalog recovery state must roundtrip canonically"
        );
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn catalog_recovery_state_oracle_bounds_raw_and_mutated_references() -> Result<(), RecoveryFailure>
{
    for program in [
        &[][..],
        &[0, 0, 0xff][..],
        &[0, 30, 1][..],
        &[0, 144, 0xff][..],
        &[0, 145, 0xff][..],
        &[0xff; 9][..],
    ] {
        fuzz_state(program)?;
    }
    Ok(())
}
