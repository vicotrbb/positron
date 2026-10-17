use positron_release::verify_transparency_inclusion;
fn hash(value: &str) -> [u8; 32] {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
// Independent RFC 6962 vectors from transparency-dev/merkle/testonly/constants.go.
// https://github.com/transparency-dev/merkle/blob/main/testonly/constants.go
#[test]
fn official_balanced_and_unbalanced_tree_vectors_verify_and_reject_truncation() {
    let cases = [
        (
            vec![],
            0,
            8,
            vec![
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ),
        (
            vec![0x30, 0x31],
            4,
            5,
            vec!["d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"],
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        ),
        (
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            6,
            7,
            vec![
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        ),
        (
            vec![0x10],
            2,
            3,
            vec!["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        ),
    ];
    for (leaf, index, size, siblings, root) in cases {
        let mut siblings: Vec<_> = siblings.into_iter().map(hash).collect();
        verify_transparency_inclusion(&leaf, index, size, &siblings, hash(root)).unwrap();
        siblings.pop();
        assert!(verify_transparency_inclusion(&leaf, index, size, &siblings, hash(root)).is_err());
    }
}
