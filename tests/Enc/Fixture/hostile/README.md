# Hostile corpus

One fixture per case of spec/enc.md section 9.2, each a variant of the vector
`../vectors/response-encrypted-assertion-aes256-gcm.xml` with the one change its name says and nothing else,
decrypted with the test key of `../keys/`; the test that reads it asserts the named exception and its message.

The fixtures the reading model refuses (rows 1 to 18, and the structural cases with no row) are derived by
`derive.php`, run from this directory, which refuses to write a fixture when the text it replaces is not found exactly
once in the vector. The fixtures the decryptor refuses (rows 19 to 33) are made from the same vector with the tools
named next to each one below.

| Fixture | Made with | Serves |
|---|---|---|
| `encrypted-under-the-stranger-certificate-refused.xml` | xmlsec1, the command of `../vectors/README.md` with `--pubkey-cert-pem keys/stranger-certificate.pem` | row 19, the one failure (E-3) |
| `plaintext-without-its-namespace-declaration-refused.xml` | xmlsec1, the same command on the data file with the `xmlns:saml` of the assertion removed, which xmlsec1 encrypts without it (section 13) | row 30, a plaintext that does not parse on its own (E-9) |
