use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

/// The closed set of non-secret deployment identifiers that a current System
/// Administrator may explicitly retain in one support bundle. Secret paths,
/// credentials, keys, and telemetry are deliberately not identifier classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentifierRetention {
    Ephemeral,
    DataDirectory,
}

/// Records both the authenticated operator's requested policy and the policy
/// that the available authority could actually apply. This prevents a fenced
/// process from representing a retired runtime configuration as a live source.
#[derive(Clone, Copy)]
pub(crate) struct IdentifierRetentionPolicy {
    requested: IdentifierRetention,
    applied: IdentifierRetention,
    outcome: &'static str,
}

impl IdentifierRetentionPolicy {
    pub(super) const fn from_requested(retention: IdentifierRetention) -> Self {
        Self {
            requested: retention,
            applied: retention,
            outcome: "applied",
        }
    }

    pub(super) const fn unavailable_after_runtime_retirement(
        requested: IdentifierRetention,
    ) -> Self {
        Self {
            requested,
            applied: IdentifierRetention::Ephemeral,
            outcome: "unavailable_retired_runtime_configuration",
        }
    }

    pub(super) const fn requested(self) -> IdentifierRetention {
        self.requested
    }

    pub(super) const fn applied_retention(self) -> IdentifierRetention {
        self.applied
    }

    pub(super) const fn outcome(self) -> &'static str {
        self.outcome
    }
}

impl IdentifierRetention {
    pub(super) const fn request_value(self) -> Option<&'static str> {
        match self {
            Self::Ephemeral => None,
            Self::DataDirectory => Some("data_directory"),
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, ()> {
        match value {
            "data_directory" => Ok(Self::DataDirectory),
            _ => Err(()),
        }
    }

    pub(super) const fn report_value(self) -> &'static str {
        match self {
            Self::Ephemeral => "none",
            Self::DataDirectory => "data_directory",
        }
    }

    pub(super) const fn pseudonymization_value(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral_per_bundle",
            Self::DataDirectory => "data_directory_retained",
        }
    }
}

/// Ephemeral keyed mapping. It deliberately exposes only the pseudonym, never
/// the key or reverse map, so values correlate inside one export only.
pub(super) struct Pseudonymizer([u8; 32]);

impl Pseudonymizer {
    pub(super) fn new() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub(super) fn pseudonymize(&self, value: &str) -> Result<String, ()> {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.0) else {
            return Err(());
        };
        mac.update(value.as_bytes());
        let mut output = String::with_capacity(67);
        output.push_str("id-");
        for byte in mac.finalize().into_bytes() {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").map_err(|_| ())?;
        }
        Ok(output)
    }
}
