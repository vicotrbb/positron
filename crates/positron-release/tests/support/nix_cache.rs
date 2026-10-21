use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

pub const NAME: &str = "positron-qualification-1";
pub fn pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[18; 32]).unwrap()
}
pub fn key() -> [u8; 32] {
    pair().public_key().as_ref().try_into().unwrap()
}
pub fn hint() -> String {
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend(key());
    hex(&Sha256::digest(spki))
}
pub fn proof(artifact: &Artifact, inventory: &ReleaseInventory) -> serde_json::Value {
    let identity = &inventory.file(&artifact.file).unwrap().identity;
    let alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
    let bits: Vec<bool> = identity
        .sha256
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| byte & (1 << bit) != 0))
        .collect();
    let hash: String = bits
        .chunks(5)
        .rev()
        .map(|chunk| {
            let value = chunk
                .iter()
                .enumerate()
                .fold(0, |value, (bit, set)| value | (usize::from(*set) << bit));
            char::from(alphabet[value])
        })
        .collect();
    let path = &artifact.publication.native_subject;
    let hash = format!("sha256:{hash}");
    let fingerprint = format!("1;{path};{hash};{};", identity.size);
    json!({"narinfo":format!("StorePath: {path}\nURL: nar/positron.nar\nCompression: none\nNarHash: {hash}\nNarSize: {}\nReferences: \nSig: {NAME}:{}\n",identity.size,STANDARD.encode(pair().sign(fingerprint.as_bytes()).as_ref()))})
}
