The RSA key pair is the published 2048-bit example from ring 0.17.14,
`src/rsa/signature_rsa_example_{private,public}_key.der`, used in the upstream
signature documentation with the message `hello, world`. These are public
test keys and must never be used for custody or authentication.

The private DER file was converted to unencrypted PKCS#8 PEM with
`openssl pkcs8 -topk8 -nocrypt -inform DER`; no new key was generated. The
backend signs the documented message using RSA PKCS#1 v1.5 with SHA-256, and
the published public key verifies it with the independent ring verifier.

Source: https://github.com/briansmith/ring/tree/0.17.14/src/rsa

Copyright 2015-2016 Brian Smith.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
