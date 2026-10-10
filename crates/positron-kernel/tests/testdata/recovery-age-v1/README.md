These public known-answer vectors are the `x25519` and `scrypt` fixtures
published by the age-format testkit and shipped unchanged in age 0.11.5
(`tests/testdata/testkit`). The metadata retains only the published test credential
and expected SHA-256, excluding the testkit's raw file key. These credentials
are public test vectors, never an operator's recovery identity or Root KEK.

Source: the published `age` crate version 0.11.5,
`tests/testdata/testkit/{x25519,scrypt}` (https://crates.io/crates/age/0.11.5).
