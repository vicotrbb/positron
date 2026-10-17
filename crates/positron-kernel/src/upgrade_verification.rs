//! Native evidence for one authenticated target startup and Query verification.
use crate::{
    BootstrapIntegrityIdentity, ExportManifestSignatureFailure as Failure,
    UpgradeVerificationSignature, UpgradeVerificationSigner,
};
const MAGIC: &[u8; 8] = b"POSUPVR1";
const PAYLOAD: usize = 130;
const WIRE: usize = 258;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeQueryVerification {
    Executed { tenant: [u8; 16] },
    NotApplicableNoQueryableTenant,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeVerificationInput {
    instance: [u8; 16],
    operation: [u8; 16],
    publication: [u8; 32],
    catalog_identity: [u8; 32],
    catalog_generation: u64,
    query: UpgradeQueryVerification,
}
impl UpgradeVerificationInput {
    pub fn new(
        instance: [u8; 16],
        operation: [u8; 16],
        publication: [u8; 32],
        catalog_identity: [u8; 32],
        catalog_generation: u64,
        query: UpgradeQueryVerification,
    ) -> Result<Self, Failure> {
        if instance == [0; 16]
            || operation == [0; 16]
            || publication == [0; 32]
            || catalog_identity == [0; 32]
            || catalog_generation == 0
            || matches!(query,UpgradeQueryVerification::Executed {tenant} if tenant==[0;16])
        {
            return Err(Failure::AuthenticationFailed);
        }
        Ok(Self {
            instance,
            operation,
            publication,
            catalog_identity,
            catalog_generation,
            query,
        })
    }
    pub const fn instance(self) -> [u8; 16] {
        self.instance
    }
    pub const fn operation(self) -> [u8; 16] {
        self.operation
    }
    pub const fn publication(self) -> [u8; 32] {
        self.publication
    }
    pub const fn catalog_identity(self) -> [u8; 32] {
        self.catalog_identity
    }
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }
    pub const fn query(self) -> UpgradeQueryVerification {
        self.query
    }
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PAYLOAD);
        bytes.extend(MAGIC);
        bytes.extend(self.instance);
        bytes.extend(self.operation);
        bytes.extend(self.publication);
        bytes.extend(self.catalog_identity);
        bytes.extend(self.catalog_generation.to_be_bytes());
        bytes.push(1);
        match self.query {
            UpgradeQueryVerification::Executed { tenant } => {
                bytes.push(1);
                bytes.extend(tenant);
            },
            UpgradeQueryVerification::NotApplicableNoQueryableTenant => {
                bytes.push(0);
                bytes.extend([0; 16]);
            },
        }
        bytes
    }
}
#[derive(Clone, Debug)]
pub struct UpgradeVerificationReport {
    input: UpgradeVerificationInput,
    signature: UpgradeVerificationSignature,
    bytes: Vec<u8>,
}
impl UpgradeVerificationReport {
    pub fn sign(
        input: UpgradeVerificationInput,
        signer: &UpgradeVerificationSigner,
    ) -> Result<Self, Failure> {
        let mut bytes = input.encode();
        let signature = signer.sign(&bytes)?;
        bytes.extend(signer.identity().public_key());
        bytes.extend(signer.identity().fingerprint());
        bytes.extend(signature.bytes());
        Ok(Self {
            input,
            signature,
            bytes,
        })
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() != WIRE {
            return Err(Failure::AuthenticationFailed);
        }
        let mut offset = 0;
        if read::<8>(bytes, &mut offset)? != *MAGIC {
            return Err(Failure::AuthenticationFailed);
        }
        let instance = read(bytes, &mut offset)?;
        let operation = read(bytes, &mut offset)?;
        let publication = read(bytes, &mut offset)?;
        let catalog_identity = read(bytes, &mut offset)?;
        let generation = u64::from_be_bytes(read(bytes, &mut offset)?);
        if read::<1>(bytes, &mut offset)? != [1] {
            return Err(Failure::AuthenticationFailed);
        }
        let query_code = read::<1>(bytes, &mut offset)?;
        let tenant = read(bytes, &mut offset)?;
        let query = match query_code {
            [1] => UpgradeQueryVerification::Executed { tenant },
            [0] if tenant == [0; 16] => UpgradeQueryVerification::NotApplicableNoQueryableTenant,
            _ => return Err(Failure::AuthenticationFailed),
        };
        let input = UpgradeVerificationInput::new(
            instance,
            operation,
            publication,
            catalog_identity,
            generation,
            query,
        )?;
        let public_key = read(bytes, &mut offset)?;
        let fingerprint = read(bytes, &mut offset)?;
        let identity = BootstrapIntegrityIdentity::from_pinned(public_key, fingerprint)
            .map_err(|_| Failure::AuthenticationFailed)?;
        let signature = UpgradeVerificationSignature::new(identity, read(bytes, &mut offset)?)?;
        Ok(Self {
            input,
            signature,
            bytes: bytes.to_vec(),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn input(&self) -> UpgradeVerificationInput {
        self.input
    }
    pub fn verify(&self, expected: BootstrapIntegrityIdentity) -> Result<(), Failure> {
        self.signature.verify(
            expected,
            self.bytes
                .get(..PAYLOAD)
                .ok_or(Failure::AuthenticationFailed)?,
        )
    }
}
fn read<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], Failure> {
    let end = offset.checked_add(N).ok_or(Failure::AuthenticationFailed)?;
    let result = bytes
        .get(*offset..end)
        .ok_or(Failure::AuthenticationFailed)?
        .try_into()
        .map_err(|_| Failure::AuthenticationFailed)?;
    *offset = end;
    Ok(result)
}

#[cfg(test)]
#[path = "upgrade_verification_tests.rs"]
mod tests;
