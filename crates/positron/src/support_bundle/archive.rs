use sha2::{Digest, Sha256};
use std::io;

use super::privacy::{IdentifierRetention, IdentifierRetentionPolicy};
use super::{BLOCK, FOOTER, POLICY, output};

mod build;
mod encoding;
mod model;

pub(crate) use build::SupportBundle;
#[cfg(test)]
use encoding::decode_64;
use encoding::{append, blocks, once};
pub(crate) use encoding::{encode_bytes, hex};
pub(crate) use model::{
    AgeRecipients, BundleLimits, BundleMember, Class, ManifestAuthentication, RedactionReport,
};
