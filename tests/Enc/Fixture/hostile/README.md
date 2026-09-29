# Hostile corpus

One fixture per case of spec/enc.md section 9.2, each a variant of the vector
`../vectors/response-encrypted-assertion-aes256-gcm.xml` with the one change its name says and nothing else,
decrypted with the test key of `../keys/`; the test that reads it asserts the named exception and its message.

The fixtures the reading model refuses (rows 1 to 18, and the structural cases with no row) are derived by
`derive.php`, run from this directory, which refuses to write a fixture when the text it replaces is not found exactly
once in the vector. The fixtures the decryptor refuses (rows 19 to 30) are made from the same vector: by `derive-decryptor.php`, run from
this directory, which re-encrypts the plaintext of the vector under session keys derived from each fixture's name
and alters the vector's values byte by byte; or by xmlsec1, as named below.

| Fixture | Made with | Serves |
|---|---|---|
| `encrypted-under-the-stranger-certificate-refused.xml` | xmlsec1, the command of `../vectors/README.md` with `--pubkey-cert-pem keys/stranger-certificate.pem` | row 19, the one failure (E-3) |
| `plaintext-without-its-namespace-declaration-refused.xml` | xmlsec1, the same command on the data file with the `xmlns:saml` of the assertion removed, which xmlsec1 encrypts without it (section 13) | row 30, a plaintext that does not parse on its own (E-9) |
| `key-wrapped-under-pkcs1-v1-5-refused.xml` | `derive-decryptor.php`: a fresh session key wrapped under PKCS#1 v1.5 padding, the method still naming `rsa-oaep-mgf1p` | row 20, the one failure (E-3), "One Bad Apple" |
| `wrapped-key-altered-refused.xml` | `derive-decryptor.php`: the last byte of the vector's wrapped key flipped | row 21 |
| `session-key-32-bytes-declared-aes128-gcm-refused.xml`, `session-key-16-bytes-declared-aes256-gcm-refused.xml` | `derive-decryptor.php`: a session key of the other length, wrapped under RSA-OAEP, the content declared under the method it does not fit | rows 22 and 23, the length before the primitive (E-2) |
| `tag-truncated-refused.xml` | `derive-decryptor.php`: the vector's data cipher value shortened by one byte | row 24, CVE-2026-32313 and CVE-2026-32600 |
| `tag-altered-refused.xml`, `ciphertext-altered-refused.xml`, `iv-altered-refused.xml` | `derive-decryptor.php`: one byte of the tag, of the ciphertext, of the IV flipped | row 25 |
| `plaintext-with-doctype-refused.xml`, `plaintext-with-two-roots-refused.xml`, `plaintext-not-xml-refused.xml` | `derive-decryptor.php`: an authentic ciphertext whose plaintext holds a DOCTYPE, two root elements, or no XML at all | rows 27 and 28, what `Core` refuses of the plaintext (E-4) |

## The adversarial pass

The `adversarial-*-refused.xml` files are the attempts of spec/enc.md section 9.7 the namespace refuses, derived by
`derive-adversarial.php` from the same vector: algorithm URIs that differ by case, a slash or a fragment, or are
surrounded by spaces; a `Type` in another case or with a trailing space; padding inside the cipher value, the URL-safe
alphabet, extra padding; the `EncryptedKey` moved next to the `EncryptedData` with a `RetrievalMethod` in its place,
the sibling form of section 12; the cipher value shortened and lengthened around the IV and the tag; a wrapped key
of the modulus length filled with zeros, with ones, and equal to the modulus; an `Id` equal to the response's; an
`EncryptedData` in a namespace that is almost the right one; an `MGF` and a `DigestMethod` in the xmlenc namespace;
an element inside the `CipherValue`. `AdversarialTest` asserts each with the exception and the message it got, and
the one message of E-3 for every failure. The attempts that decrypt are under `../behaviour/`.
