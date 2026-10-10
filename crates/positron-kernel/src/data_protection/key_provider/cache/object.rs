use super::{EnvelopeContext, KeyProviderFailure, KeyScope, SecretKeyBytes};

fn segment_route(
    parent: EnvelopeContext,
) -> Result<crate::data_protection::SegmentEnvelopeRoute, KeyProviderFailure> {
    // The immutable KEK ID and epoch bind the object envelope to its admitted lease.
    let digest = crate::data_protection::DataProtection::hash(&parent.key_id)
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    let reference = digest
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(KeyProviderFailure::ContextMismatch)?;
    crate::data_protection::SegmentEnvelopeRoute::new(1, reference, parent.epoch)
        .map_err(|_| KeyProviderFailure::ContextMismatch)
}
fn object_binding(
    parent: EnvelopeContext,
    object: crate::data_protection::FrameObjectContext,
) -> Result<Option<crate::data_protection::WrappedKeyContext>, KeyProviderFailure> {
    use crate::data_protection::{
        DataProtection, FrameObjectClass, FrameScope, FrameSequence, WrappedKeyContext,
    };
    match (parent.scope, object.scope, object.class) {
        (
            KeyScope::Tenant(expected),
            FrameScope::Tenant(actual),
            FrameObjectClass::Segment { .. },
        ) if expected == actual => Ok(None),
        (KeyScope::System, FrameScope::System, FrameObjectClass::System(kind)) => {
            let frame = object
                .system_frame(FrameSequence::new(0))
                .map_err(|_| KeyProviderFailure::ContextMismatch)?;
            let binding = crate::data_protection::encode_associated_data(&[], frame);
            let digest =
                DataProtection::hash(&binding).map_err(|_| KeyProviderFailure::ContextMismatch)?;
            let mut id = [0; 32];
            id.get_mut(..16)
                .ok_or(KeyProviderFailure::ContextMismatch)?
                .copy_from_slice(&object.object_id.0);
            WrappedKeyContext::system(parent.instance, kind, id, object.key_epoch.0, digest)
                .map(Some)
                .map_err(|_| KeyProviderFailure::ContextMismatch)
        },
        _ => Err(KeyProviderFailure::ContextMismatch),
    }
}
pub(super) fn wrap_object(
    wrapping: &SecretKeyBytes,
    parent: EnvelopeContext,
    key: &crate::data_protection::ObjectDataKey,
) -> Result<Vec<u8>, KeyProviderFailure> {
    use crate::data_protection::DataProtection;
    match object_binding(parent, key.object)? {
        Some(context) => DataProtection::wrap_key_payload(wrapping, key, context),
        None => DataProtection::wrap_segment_key_with_route(
            wrapping,
            key,
            parent.instance,
            segment_route(parent)?,
        ),
    }
    .map_err(|_| KeyProviderFailure::ContextMismatch)
}
pub(super) fn open_object(
    wrapping: &SecretKeyBytes,
    parent: EnvelopeContext,
    ciphertext: &[u8],
    object: crate::data_protection::FrameObjectContext,
) -> Result<crate::data_protection::ObjectDataKey, KeyProviderFailure> {
    use crate::data_protection::DataProtection;
    match object_binding(parent, object)? {
        Some(context) => DataProtection::unwrap_key_payload(wrapping, ciphertext, context, object),
        None => DataProtection::unwrap_segment_key_with_route(
            wrapping,
            ciphertext,
            parent.instance,
            object,
            segment_route(parent)?,
        ),
    }
    .map_err(|_| KeyProviderFailure::ContextMismatch)
}
