//! Bounded journal decoder corpus; opaque bytes never authorize a provider.
use super::*;
use positron_kernel::key_provider::{EnvelopeContext, KeyScope, WrappingAlgorithm};

pub(crate) fn run(data: &[u8]) {
    let bounded = data
        .get(..data.len().min(PROVIDER_MAXIMUM + 1))
        .unwrap_or_default();
    check(bounded);
    let instance = positron_kernel::InstanceId::new([1; 16]).expect("fixed instance");
    let anchor = BootstrapKeyIdentity::from_parts([2; 16], [3; 32], 1).expect("fixed anchor");
    let context = EnvelopeContext::new(instance.to_bytes(), KeyScope::System, [4; 32], 1, 1)
        .expect("fixed context");
    let source = ProviderKeyUri::new(ProviderFamily::LocalFile, "migration-decoder-corpus", "v1")
        .expect("fixed local identity");
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        "kmip://localhost:5696/objects/immutable-id",
        "sha256:0606060606060606060606060606060606060606060606060606060606060606",
    )
    .expect("fixed immutable identity");
    let source_route = Route {
        epoch: 1,
        identity: anchor,
        envelope: KeyEnvelope::from_provider_response(
            source.clone(),
            context,
            WrappingAlgorithm::Aes256Kwp,
            vec![0; 8],
        )
        .expect("opaque local envelope")
        .encode(),
    };
    let target_route = Route {
        epoch: 2,
        identity: BootstrapKeyIdentity::from_parts([5; 16], [6; 32], 0).expect("fixed successor"),
        envelope: KeyEnvelope::from_provider_response(
            target,
            context,
            WrappingAlgorithm::Aes256Kwp,
            vec![0; 8],
        )
        .expect("opaque native envelope")
        .encode(),
    };
    for phase in 0..7 {
        let state = State {
            instance,
            transaction: TransactionId::new([7; 16]).expect("fixed transaction"),
            anchor,
            active: if phase < 3 {
                source_route.clone()
            } else {
                target_route.clone()
            },
            successor: (phase == 1 || phase == 2).then(|| target_route.clone()),
            predecessor: (phase == 3 || phase == 4 || phase == 5).then(|| source_route.clone()),
            retiring: phase == 5,
            cancelled: phase == 2 || phase == 4,
            provider_format: phase != 0,
            migration_source: (phase != 0).then(|| source.clone()),
        };
        let mut encoded = state.encode().expect("valid fixed phase corpus");
        assert_eq!(
            State::decode(&encoded).expect("canonical phase").status(),
            state.status()
        );
        for operation in bounded.chunks(3).take(256) {
            let Some((kind, rest)) = operation.split_first() else {
                continue;
            };
            let position = usize::from(rest.first().copied().unwrap_or_default());
            let value = rest.get(1).copied().unwrap_or_default();
            match kind % 3 {
                0 => {
                    if !encoded.is_empty() {
                        let length = encoded.len();
                        if let Some(byte) = encoded.get_mut(position % length) {
                            *byte ^= value;
                        }
                    }
                },
                1 => encoded.truncate(position.min(encoded.len())),
                _ => {
                    if encoded.len() <= PROVIDER_MAXIMUM {
                        encoded.push(value);
                    }
                },
            }
            check(&encoded);
        }
    }
}
fn check(bytes: &[u8]) {
    if let Ok(state) = State::decode(bytes) {
        let canonical = state.encode().expect("accepted journal encodes");
        assert_eq!(canonical, bytes);
        assert_eq!(
            State::decode(&canonical)
                .expect("accepted canonical journal")
                .status(),
            state.status()
        );
    }
}
#[test]
fn canonical_migration_phases_and_mutated_journals_are_bounded() {
    for data in [
        &[][..],
        &[0, 0, 255],
        &[1, 0, 0],
        &[2, 1, 255],
        &[0; 1_024],
        &[255; 20_000],
    ] {
        run(data);
    }
}
