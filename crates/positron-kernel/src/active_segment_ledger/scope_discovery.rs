use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use sha2::{Digest, Sha256};

use crate::catalog::CatalogSnapshot;

use super::format::decode_metadata;
use super::{LedgerFailure, LedgerFailureCode, SegmentScope};

impl CatalogSnapshot {
    /// Returns the bounded canonical ledger scopes reachable from this immutable generation.
    pub fn reachable_ledger_scopes(
        &self,
        tenant: TenantId,
        signal: SignalKind,
    ) -> Result<Vec<SegmentScope>, LedgerFailure> {
        let object_count = self.plaintext_object_count();
        let mut scopes = Vec::new();
        scopes
            .try_reserve_exact(object_count)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        for plaintext in self.plaintext_objects() {
            let Some(metadata) = decode_metadata(plaintext)? else {
                continue;
            };
            if metadata.scope.tenant_id() == tenant && metadata.scope.signal_kind() == signal {
                scopes.push(metadata.scope);
            }
        }
        scopes.sort_unstable();
        scopes.dedup();
        Ok(scopes)
    }

    /// Returns the authenticated source identity for one scope's segment
    /// metadata. Maintenance records can advance the Catalog generation
    /// without changing this identity, while any segment publication makes a
    /// saved scrub position explicitly stale.
    pub fn integrity_scope_source_identity(
        &self,
        scope: SegmentScope,
    ) -> Result<[u8; 32], LedgerFailure> {
        let mut digest = Sha256::new();
        digest.update(b"positron/integrity-scope-source/v1");
        for plaintext in self.plaintext_objects() {
            let Some(metadata) = decode_metadata(plaintext)? else {
                continue;
            };
            if metadata.scope == scope {
                digest.update(plaintext);
            }
        }
        Ok(digest.finalize().into())
    }
}
