use super::*;
use crate::active_segment_ledger::envelope_overlay;
impl LedgerStorage {
    pub(in crate::active_segment_ledger) fn successor_envelope(
        &self,
        metadata: SegmentMetadata,
        protection: &SegmentProtectionKey,
        instance: crate::InstanceId,
        basis: &crate::CatalogSnapshot,
    ) -> Result<(Vec<u8>, bool), LedgerFailure> {
        let directory = if super::entry_exists(&self.active, &segment_name(metadata.id))? {
            &self.active
        } else {
            &self.sealed
        };
        let mut file = open_regular(directory, &segment_name(metadata.id), false)?;
        let mut bytes = [0_u8; 512];
        let read = file.read(&mut bytes).map_err(map_io_error)?;
        let header = bytes
            .get(..read)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))?;
        let decoded = decode_header(header)?;
        // Authenticate the original route and encrypted metadata before adding
        // an alternate route; a Catalog row cannot legitimize substituted bytes.
        let key = envelope_overlay::open_key(
            Some(basis),
            metadata,
            instance,
            protection,
            &decoded,
            header,
        )?;
        let object = object_context(metadata.scope, metadata.id)?;
        let context = object
            .frame(SegmentFramePurpose::SegmentMetadata, FrameSequence::new(0))
            .map_err(map_frame_failure)?;
        let opened = DataProtection::open_frame(
            &key,
            context,
            decoded.encrypted_metadata,
            FrameLimits::new(256).map_err(map_frame_failure)?,
        )
        .map_err(map_frame_failure)?;
        let physical = decode_metadata(opened.as_plaintext())?
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::AuthenticationFailed))?;
        if physical.scope != metadata.scope
            || physical.id != metadata.id
            || physical.state != SegmentState::Active
            || physical.base_position != metadata.base_position
        {
            return Err(LedgerFailure::new(LedgerFailureCode::AuthenticationFailed));
        }
        let wrapped = DataProtection::wrap_segment_key_with_route(
            &*protection.key_for_route(protection.route)?,
            &key,
            instance.to_bytes(),
            protection.route,
        )
        .map_err(map_frame_failure)?;
        let digest = DataProtection::hash(
            header
                .get(..decoded.encoded_bytes)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))?,
        )
        .map_err(map_frame_failure)?;
        let migrated = decoded.route != protection.route;
        let encoded =
            envelope_overlay::encode(metadata, instance, protection.route, digest, &wrapped)?;
        Ok((encoded, migrated))
    }
}
