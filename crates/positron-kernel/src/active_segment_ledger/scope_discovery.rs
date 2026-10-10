use positron_domain::identity::TenantId;
use positron_domain::routing::SignalKind;
use sha2::{Digest, Sha256};

use crate::catalog::CatalogSnapshot;

use super::format::{SegmentState, decode_metadata};
use super::{LedgerFailure, LedgerFailureCode, SegmentScope};

impl CatalogSnapshot {
    /// Reports the existing authenticated active publication for one scope.
    pub fn has_active_ledger_scope(&self, scope: SegmentScope) -> Result<bool, LedgerFailure> {
        let mut found = false;
        for plaintext in self.plaintext_objects() {
            let Some(metadata) = decode_metadata(plaintext)? else {
                continue;
            };
            if metadata.scope == scope && metadata.state == SegmentState::Active {
                if found {
                    return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                }
                found = true;
            }
        }
        Ok(found)
    }
    /// Selects one authenticated active scope without allocating a scope inventory.
    pub fn next_active_ledger_scope(
        &self,
        tenant: TenantId,
    ) -> Result<Option<SegmentScope>, LedgerFailure> {
        let mut selected = None;
        let mut matching = 0_usize;
        for plaintext in self.plaintext_objects() {
            let Some(metadata) = decode_metadata(plaintext)? else {
                continue;
            };
            if metadata.scope.tenant_id() != tenant || metadata.state != SegmentState::Active {
                continue;
            }
            if selected.is_none_or(|scope| metadata.scope < scope) {
                selected = Some(metadata.scope);
                matching = 1;
            } else if selected == Some(metadata.scope) {
                matching = matching
                    .checked_add(1)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            }
        }
        if matching > 1 {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        Ok(selected)
    }
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
        for finding in crate::integrity_abandonment_findings(self)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
        {
            if finding.scope().tenant_id() == tenant && finding.scope().signal_kind() == signal {
                scopes.push(finding.scope());
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
