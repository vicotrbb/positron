use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(super) const PIN: &str =
    "sha256:0606060606060606060606060606060606060606060606060606060606060606";
const CA: &[u8] = include_bytes!("../../../../tests/native_transport/fixtures/mtls-ca-cert.pem");
const CLIENT_CERT: &[u8] =
    include_bytes!("../../../../tests/native_transport/fixtures/mtls-client-cert.pem");
const CLIENT_KEY: &[u8] =
    include_bytes!("../../../../tests/native_transport/fixtures/mtls-client-key.pem");
const SERVER_CERT: &[u8] =
    include_bytes!("../../../../tests/native_transport/fixtures/mtls-server-cert.pem");
const SERVER_KEY: &[u8] =
    include_bytes!("../../../../tests/native_transport/fixtures/mtls-server-key.pem");
pub(super) fn model(
    root: &std::path::Path,
) -> Result<ProviderCredentialModel, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    for (name, bytes) in [("cert", CLIENT_CERT), ("key", CLIENT_KEY), ("ca", CA)] {
        std::fs::write(root.join(name), bytes)?;
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(ProviderCredentialModel::KmipMutualTls {
        certificate: CredentialFileReference::new(&root.join("cert"))?,
        private_key: CredentialFileReference::new(&root.join("key"))?,
        trust_roots: CredentialFileReference::new(&root.join("ca"))?,
    })
}
pub(super) async fn transcript_transport(
    build: impl FnOnce(u16) -> Vec<Vec<Vec<u8>>>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<
    (
        u16,
        tokio::task::JoinHandle<Vec<zeroize::Zeroizing<Vec<u8>>>>,
    ),
    Box<dyn std::error::Error>,
> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let replies = build(port)
        .into_iter()
        .map(|connection| {
            connection
                .into_iter()
                .map(zeroize::Zeroizing::new)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(CA) {
        roots.add(cert?)?;
    }
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        crypto.clone(),
    )
    .build()?;
    let server = rustls::ServerConfig::builder_with_provider(crypto)
        .with_protocol_versions(versions)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            CertificateDer::pem_slice_iter(SERVER_CERT).collect::<Result<Vec<_>, _>>()?,
            PrivateKeyDer::from_pem_slice(SERVER_KEY)?,
        )?;
    let server = Arc::new(server);
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for replies in replies {
            let (socket, _) = listener.accept().await.expect("fixture connection");
            let mut socket = match tokio_rustls::TlsAcceptor::from(server.clone())
                .accept(socket)
                .await
            {
                Ok(socket) => socket,
                Err(_) => {
                    assert!(replies.is_empty());
                    continue;
                },
            };
            assert!(
                socket
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|c| !c.is_empty())
            );
            for reply in replies {
                let mut header = [0; 8];
                socket
                    .read_exact(&mut header)
                    .await
                    .expect("request header");
                let length =
                    u32::from_be_bytes(header[4..8].try_into().expect("fixed length")) as usize;
                assert!(length <= 8192);
                let mut body = zeroize::Zeroizing::new(vec![0; length]);
                socket.read_exact(&mut body).await.expect("request body");
                requests.push(body);
                socket
                    .write_all(&reply)
                    .await
                    .expect("immutable wire reply");
                socket.flush().await.expect("reply flush");
            }
        }
        requests
    });
    Ok((port, task))
}
pub(super) fn field(tag: u32, kind: u8, value: &[u8]) -> Vec<u8> {
    let mut result = tag.to_be_bytes()[1..].to_vec();
    result.push(kind);
    result.extend_from_slice(&(value.len() as u32).to_be_bytes());
    result.extend_from_slice(value);
    result.resize(result.len().div_ceil(8) * 8, 0);
    result
}
pub(super) fn number(tag: u32, kind: u8, value: u32) -> Vec<u8> {
    field(tag, kind, &value.to_be_bytes())
}
pub(super) fn response(operation: u32, status: u32, payload: &[u8]) -> Vec<u8> {
    response_extra(operation, status, payload, &[])
}
pub(super) fn response_extra(operation: u32, status: u32, payload: &[u8], extra: &[u8]) -> Vec<u8> {
    let version = field(
        0x420069,
        1,
        &[number(0x42006a, 2, 2), number(0x42006b, 2, 1)].concat(),
    );
    let header = field(
        0x42007a,
        1,
        &[
            version,
            field(0x420092, 9, &1u64.to_be_bytes()),
            number(0x42000d, 2, 1),
        ]
        .concat(),
    );
    let payload = if status == 0 {
        field(0x42007c, 1, payload)
    } else {
        payload.to_vec()
    };
    let batch = field(
        0x42000f,
        1,
        &[
            number(0x42005c, 5, operation),
            number(0x42007f, 5, status),
            extra.to_vec(),
            payload,
        ]
        .concat(),
    );
    field(0x42007b, 1, &[header, batch].concat())
}
pub(super) fn discover() -> Vec<u8> {
    response(
        0x1e,
        0,
        &field(
            0x420069,
            1,
            &[number(0x42006a, 2, 2), number(0x42006b, 2, 1)].concat(),
        ),
    )
}
pub(super) fn digest(algorithm: u32, format: u32, value: &[u8]) -> Vec<u8> {
    field(
        0x420034,
        1,
        &[
            number(0x420038, 5, algorithm),
            number(0x420042, 5, format),
            field(0x420035, 8, value),
        ]
        .concat(),
    )
}
pub(super) fn metadata(id: &str) -> Vec<u8> {
    response(
        0x0b,
        0,
        &[
            field(0x420094, 7, id.as_bytes()),
            field(
                0x420125,
                1,
                &[
                    number(0x420057, 5, 2),
                    number(0x420028, 5, 3),
                    number(0x42002a, 2, 256),
                    number(0x42002c, 2, 12),
                    number(0x42008d, 5, 2),
                    digest(6, 1, &[6; 32]),
                ]
                .concat(),
            ),
        ]
        .concat(),
    )
}

pub(super) fn migration_replies(
    instance: &crate::InitializedInstance,
    port: u16,
    id: &str,
    verifications: usize,
) -> Vec<Vec<Vec<u8>>> {
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/{id}"),
        PIN,
    )
    .expect("fixture target");
    instance
        .with_native_migration_fixture_payload(&target, |payload| {
            let encrypted = response(
                0x1f,
                0,
                &[
                    field(0x420094, 7, id.as_bytes()),
                    field(0x4200c2, 8, &vec![0x55; payload.len()]),
                    field(0x42003d, 8, &[4; 12]),
                    field(0x4200ff, 8, &[5; 16]),
                ]
                .concat(),
            );
            let plaintext = response(
                0x20,
                0,
                &[
                    field(0x420094, 7, id.as_bytes()),
                    field(0x4200c2, 8, payload),
                ]
                .concat(),
            );
            let mut sequence = vec![
                vec![discover(), metadata(id)],
                vec![discover(), metadata(id), encrypted],
            ];
            for _ in 0..verifications {
                sequence.push(vec![discover(), metadata(id)]);
                sequence.push(vec![discover(), metadata(id), plaintext.clone()]);
            }
            sequence
        })
        .expect("bound fixture")
}
