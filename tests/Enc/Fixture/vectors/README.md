# Vectors

The valid encryptions the decryptor must accept (spec/enc.md section 9.1), produced by an implementation that is not
this one: xmlsec1 1.3.7 on OpenSSL, in Alpine 3.22 (`apk add xmlsec`). Each vector is the output of xmlsec1 byte for
byte; nothing reformats it afterwards. A template (`*.template.xml`) is a standalone `xenc:EncryptedData` whose empty
`X509Certificate` and `CipherValue` elements xmlsec1 fills; a data file (`*.data.xml`) is a SAML response whose
`EncryptedAssertion` holds the plain assertion, the element `--node-id` names. xmlsec1 encrypts that element, replaces
it with the filled template, and writes the data file so changed: the vector.

The command, run in `tests/Enc/Fixture/` with the keys of `keys/`; `--lax-key-search` is what xmlsec1 1.3 needs when
the template's `KeyInfo` does not name the key:

```
xmlsec1 --encrypt --lax-key-search --pubkey-cert-pem keys/test-signing-certificate.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --node-id _assertion-d4e5f6 \
    --session-key aes-256-gcm --xml-data vectors/response-assertion.data.xml \
    --output vectors/response-encrypted-assertion-aes256-gcm.xml vectors/encrypted-data-aes256-gcm.template.xml
```

And the check that xmlsec1 decrypts what it produced to the bytes of the data file:

```
xmlsec1 --decrypt --lax-key-search --privkey-pem keys/test-signing-key.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    vectors/response-encrypted-assertion-aes256-gcm.xml | diff vectors/response-assertion.data.xml -
```

The plaintext xmlsec1 encrypts is the assertion element dumped with the namespace declarations it carries itself and
none it inherits (spec/enc.md section 13), so every data file declares `xmlns:saml` on the assertion and the plaintext
parses on its own (E-9). The same assertion without its own declaration, nested under a response that declares it, is
`../hostile/plaintext-without-its-namespace-declaration-refused.xml`.

| Vector | Data and template | Encrypted with |
|---|---|---|
| `response-encrypted-assertion-aes256-gcm.xml` | `response-assertion.data.xml`, `encrypted-data-aes256-gcm.template.xml` | `aes256-gcm`, the session key under `rsa-oaep-mgf1p`, the test certificate in the key's `KeyInfo` |
| `response-encrypted-assertion-aes128-gcm.xml` | the same data, `encrypted-data-aes128-gcm.template.xml`, `--session-key aes-128-gcm` | `aes128-gcm` |
| `response-encrypted-assertion-keyinfo-absent.xml` | the same data, `encrypted-data-keyinfo-absent.template.xml` | the key's `KeyInfo` absent, which the decryptor never reads (E-6) |
| `response-encrypted-assertion-mgf1p-digest-sha1.xml` | the same data, `encrypted-data-mgf1p-digest-sha1.template.xml` | `rsa-oaep-mgf1p` with the `DigestMethod` of SHA-1 that Shibboleth and ADFS write under it |
| `response-encrypted-assertion-rsa-oaep-sha256.xml` | the same data, `encrypted-data-rsa-oaep-sha256.template.xml` | `rsa-oaep` of XML Encryption 1.1 with a `DigestMethod` of `sha256` and an `MGF` of `mgf1sha256` |
| `response-encrypted-signed-assertion.xml` | `response-signed-assertion.data.xml`, the `aes256-gcm` template | the signed assertion of `../../Dsig/Fixture/vectors/response-assertion-rsa-sha256.xml`, wrapped in an `EncryptedAssertion` with `xmlns:saml` declared on it, which leaves its exclusive canonical form and so its signature unchanged: xmlsec1 verifies the data file and the decrypted output alike |
| `response-encrypted-assertion-with-comment.xml` | `response-assertion-with-comment.data.xml`, the `aes256-gcm` template | a comment inside the `NameID`, kept in the plaintext |

`../hostile/encrypted-under-the-stranger-certificate-refused.xml` is the first data file encrypted the same way to
`keys/stranger-certificate.pem`: the test key cannot unwrap its session key, and the decryptor refuses it with the one
message of E-3, which is the point.
