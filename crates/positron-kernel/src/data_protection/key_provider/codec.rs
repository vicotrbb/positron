//! Key Envelope v1: bounded routing, authoritative child identity, opaque ciphertext.
use super::*;
use positron_domain::identity::TenantId;

impl KeyEnvelope {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1024 + self.ciphertext.len());
        output.extend_from_slice(b"PKEY1");
        output.push(self.provider.family as u8);
        output.push(match self.algorithm {
            WrappingAlgorithm::Aes256Kwp => 1,
            WrappingAlgorithm::Aes256Gcm => 2,
            WrappingAlgorithm::RsaOaepSha256 => 3,
            WrappingAlgorithm::AwsKmsSymmetricDefault => 4,
            WrappingAlgorithm::GoogleSymmetricEncryption => 5,
        });
        for value in [&self.provider.locator, &self.provider.version] {
            output.extend_from_slice(&(value.len() as u16).to_be_bytes());
            output.extend_from_slice(value.as_bytes());
        }
        output.extend_from_slice(&self.context.instance);
        match self.context.scope {
            KeyScope::System => output.extend_from_slice(&[0; 17]),
            KeyScope::Tenant(tenant) => {
                output.push(1);
                output.extend_from_slice(&tenant.to_bytes());
            },
        }
        output.extend_from_slice(&self.context.key_id);
        output.extend_from_slice(&self.context.epoch.to_be_bytes());
        output.extend_from_slice(&self.context.format.to_be_bytes());
        output.extend_from_slice(&self.digest);
        output.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        output.extend_from_slice(&self.ciphertext);
        output
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KeyProviderFailure> {
        if encoded.len() > 9000 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let mut input = Input(encoded);
        if input.take(5)? != b"PKEY1" {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        let family = match input.array::<1>()? {
            [1] => ProviderFamily::LocalFile,
            [2] => ProviderFamily::AwsKms,
            [3] => ProviderFamily::GoogleCloudKms,
            [4] => ProviderFamily::AzureKeyVault,
            [5] => ProviderFamily::AzureManagedHsm,
            [6] => ProviderFamily::VaultTransit,
            [7] => ProviderFamily::OpenBaoTransit,
            [8] => ProviderFamily::Kmip21,
            _ => return Err(KeyProviderFailure::InvalidConfiguration),
        };
        let algorithm = match input.array::<1>()? {
            [1] => WrappingAlgorithm::Aes256Kwp,
            [2] => WrappingAlgorithm::Aes256Gcm,
            [3] => WrappingAlgorithm::RsaOaepSha256,
            [4] => WrappingAlgorithm::AwsKmsSymmetricDefault,
            [5] => WrappingAlgorithm::GoogleSymmetricEncryption,
            _ => return Err(KeyProviderFailure::InvalidConfiguration),
        };
        let locator = input.string()?;
        let version = input.string()?;
        let provider = ProviderKeyUri::new(family, locator, version)?;
        let instance = input.array()?;
        let scope_tag = input.array::<1>()?;
        let tenant = input.array::<16>()?;
        let scope = match scope_tag {
            [0] if tenant == [0; 16] => KeyScope::System,
            [1] => KeyScope::Tenant(
                TenantId::from_bytes(tenant).map_err(|_| KeyProviderFailure::ContextMismatch)?,
            ),
            _ => return Err(KeyProviderFailure::ContextMismatch),
        };
        let context = EnvelopeContext::new(
            instance,
            scope,
            input.array()?,
            u64::from_be_bytes(input.array()?),
            u32::from_be_bytes(input.array()?),
        )?;
        let digest = input.array::<32>()?;
        let length = u32::from_be_bytes(input.array()?) as usize;
        let ciphertext = input.take(length)?;
        if !input.0.is_empty() || digest != context.digest(&provider)? {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        Self::from_provider_response(provider, context, algorithm, ciphertext.to_vec())
    }
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], KeyProviderFailure> {
        let value = self
            .0
            .get(..size)
            .ok_or(KeyProviderFailure::ContextMismatch)?;
        self.0 = self
            .0
            .get(size..)
            .ok_or(KeyProviderFailure::ContextMismatch)?;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], KeyProviderFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| KeyProviderFailure::ContextMismatch)
    }
    fn string(&mut self) -> Result<&'a str, KeyProviderFailure> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        std::str::from_utf8(self.take(length)?)
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)
    }
}
