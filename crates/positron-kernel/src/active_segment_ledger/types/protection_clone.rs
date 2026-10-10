use super::SegmentProtectionKey;
use crate::data_protection::SecretKeyBytes;

impl Clone for SegmentProtectionKey {
    fn clone(&self) -> Self {
        Self {
            key: self
                .key
                .as_ref()
                .map(|key| SecretKeyBytes::from_owned(Box::new(*key.expose_to_backend()))),
            local_source: self.local_source.clone(),
            route: self.route,
            retained: self
                .retained
                .iter()
                .map(|(route, key)| {
                    (
                        *route,
                        SecretKeyBytes::from_owned(Box::new(*key.expose_to_backend())),
                    )
                })
                .collect(),
            capacity: None,
        }
    }
}
