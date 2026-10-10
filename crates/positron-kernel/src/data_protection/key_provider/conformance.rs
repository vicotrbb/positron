//! Shared executable conformance phases for pre-provisioned real providers.
//! The caller induces and restores outages externally; this harness has no
//! executable/webhook mechanism, emulator, or root-key lifecycle authority.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConformanceTarget {
    family: ProviderFamily,
    service: String,
    api_version: String,
    deployment: String,
}
impl ProviderConformanceTarget {
    pub fn new(
        family: ProviderFamily,
        service: &str,
        api_version: &str,
        deployment: &str,
    ) -> Result<Self, KeyProviderFailure> {
        if [service, api_version, deployment].iter().any(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        }) {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(Self {
            family,
            service: service.to_owned(),
            api_version: api_version.to_owned(),
            deployment: deployment.to_owned(),
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceStep {
    Target,
    LiveProbe,
    Wrap,
    Unwrap,
    WrongContext,
    Substitution,
    Corruption,
    Truncation,
    Outage,
    Recovery,
    RotationMigration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceFailure {
    pub step: ConformanceStep,
    pub failure: KeyProviderFailure,
}
impl std::fmt::Display for ConformanceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("key provider conformance failed")
    }
}
impl std::error::Error for ConformanceFailure {}
fn at<T>(
    step: ConformanceStep,
    result: Result<T, KeyProviderFailure>,
) -> Result<T, ConformanceFailure> {
    result.map_err(|failure| ConformanceFailure { step, failure })
}
fn rejected(
    step: ConformanceStep,
    result: Result<(), KeyProviderFailure>,
) -> Result<(), ConformanceFailure> {
    match result {
        Err(KeyProviderFailure::WrongKey | KeyProviderFailure::ContextMismatch) => Ok(()),
        Err(failure) => Err(ConformanceFailure { step, failure }),
        Ok(()) => Err(ConformanceFailure {
            step,
            failure: KeyProviderFailure::ContextMismatch,
        }),
    }
}

/// Contains only non-secret target metadata and opaque envelopes between phases.
pub struct KeyProviderConformance {
    target: ProviderConformanceTarget,
    context: EnvelopeContext,
    envelope: KeyEnvelope,
}
impl KeyProviderConformance {
    pub async fn healthy<P: KeyProvider>(
        provider: &P,
        target: ProviderConformanceTarget,
        context: EnvelopeContext,
    ) -> Result<Self, ConformanceFailure> {
        if provider.identity().family() != target.family {
            return Err(ConformanceFailure {
                step: ConformanceStep::Target,
                failure: KeyProviderFailure::WrongKey,
            });
        }
        let session = KeyProviderSession::new(provider);
        at(
            ConformanceStep::LiveProbe,
            session.verify_live(context).await,
        )?;
        let key = at(ConformanceStep::Wrap, SecretKek::generate())?;
        let envelope = at(ConformanceStep::Wrap, session.wrap(key, context).await)?;
        at(
            ConformanceStep::Unwrap,
            session.verify(&envelope, context).await,
        )?;
        let epoch = context.epoch.checked_add(1).ok_or(ConformanceFailure {
            step: ConformanceStep::WrongContext,
            failure: KeyProviderFailure::InvalidConfiguration,
        })?;
        let wrong = EnvelopeContext { epoch, ..context };
        rejected(
            ConformanceStep::WrongContext,
            session.verify(&envelope, wrong).await,
        )?;
        // Matching forged routing still has to agree with the embedded payload.
        let mut substituted = envelope.clone();
        substituted.context = wrong;
        substituted.digest = at(
            ConformanceStep::Substitution,
            wrong.digest(provider.identity()),
        )?;
        rejected(
            ConformanceStep::Substitution,
            session.verify(&substituted, wrong).await,
        )?;
        let mut corrupted = envelope.clone();
        let first = corrupted.ciphertext.first_mut().ok_or(ConformanceFailure {
            step: ConformanceStep::Corruption,
            failure: KeyProviderFailure::LimitExceeded,
        })?;
        *first ^= 1;
        rejected(
            ConformanceStep::Corruption,
            session.verify(&corrupted, context).await,
        )?;
        let encoded = envelope.encode();
        for length in 0..encoded.len() {
            if KeyEnvelope::decode(&encoded[..length]).is_ok() {
                return Err(ConformanceFailure {
                    step: ConformanceStep::Truncation,
                    failure: KeyProviderFailure::ContextMismatch,
                });
            }
        }
        Ok(Self {
            target,
            context,
            envelope,
        })
    }
    /// Run with the actual target disconnected or its credentials temporarily
    /// unavailable, then restore connectivity before the recovery phase.
    pub async fn outage<P: KeyProvider>(&self, provider: &P) -> Result<(), ConformanceFailure> {
        match KeyProviderSession::new(provider)
            .verify(&self.envelope, self.context)
            .await
        {
            Err(KeyProviderFailure::Unavailable) => Ok(()),
            Err(failure) => Err(ConformanceFailure {
                step: ConformanceStep::Outage,
                failure,
            }),
            Ok(()) => Err(ConformanceFailure {
                step: ConformanceStep::Outage,
                failure: KeyProviderFailure::Unavailable,
            }),
        }
    }
    pub async fn recovery<P: KeyProvider>(&self, provider: &P) -> Result<(), ConformanceFailure> {
        let session = KeyProviderSession::new(provider);
        at(
            ConformanceStep::Recovery,
            session.verify_live(self.context).await,
        )?;
        at(
            ConformanceStep::Recovery,
            session.verify(&self.envelope, self.context).await,
        )
    }
    /// Same workflow for root rotation and migration; the destination must be
    /// another pre-provisioned, exact pinned key. Neither provider is mutated.
    pub async fn rotation_and_migration<P: KeyProvider, Q: KeyProvider>(
        &self,
        source: &P,
        destination: &Q,
        target: ProviderConformanceTarget,
    ) -> Result<Self, ConformanceFailure> {
        if destination.identity() == self.envelope.identity()
            || destination.identity().family() != target.family
        {
            return Err(ConformanceFailure {
                step: ConformanceStep::RotationMigration,
                failure: KeyProviderFailure::WrongKey,
            });
        }
        let source = KeyProviderSession::new(source);
        let destination = KeyProviderSession::new(destination);
        at(
            ConformanceStep::RotationMigration,
            destination.verify_live(self.context).await,
        )?;
        let envelope = at(
            ConformanceStep::RotationMigration,
            source
                .rewrap(&self.envelope, self.context, &destination)
                .await,
        )?;
        at(
            ConformanceStep::RotationMigration,
            destination.verify(&envelope, self.context).await,
        )?;
        Ok(Self {
            target,
            context: self.context,
            envelope,
        })
    }
    #[must_use]
    pub fn target(&self) -> &ProviderConformanceTarget {
        &self.target
    }
}
