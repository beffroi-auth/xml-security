# Behaviour fixtures

Documents the model reads or the verifier accepts, each named `<case>-loads.xml` or `<case>-verifies.xml`, and
the documents the signer produced, pinned byte for byte because a PKCS#1 v1.5 signature is deterministic:
the test of the signer builds the same document through `tests/Dsig/Support/Built.php`, signs it with the test key
and asserts the same bytes, so that a change of the signer's output is a change someone sees.

The three `signed-by-the-signer-*.xml` files were produced on 27 September 2026 in the phpqa image (PHP 8.5.10,
OpenSSL 3.5.7) and verified by xmlsec1 1.3.7 in Alpine 3.22, the implementation that is not this one
(spec/dsig.md section 9.1). The check, run in `tests/Dsig/Fixture/`, or `castor xmlsec <file>` from the root, with
`--xpath` for a `Signature` that carries no `Id`:

```
I="--id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor"
xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/test-signing-certificate.pem $I behaviour/signed-by-the-signer-assertion-rsa-sha256.xml
xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/test-signing-certificate.pem $I behaviour/signed-by-the-signer-entity-rsa-sha512.xml
xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/test-signing-certificate.pem $I --node-xpath '/*/*[local-name()="Signature"]' behaviour/signed-by-the-signer-both-rsa-sha256.xml
xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/test-signing-certificate.pem $I --node-xpath '/*/*[local-name()="Assertion"]/*[local-name()="Signature"]' behaviour/signed-by-the-signer-both-rsa-sha256.xml
```

| File | Built by | Signed with |
|---|---|---|
| `signed-by-the-signer-assertion-rsa-sha256.xml` | `Built::responseWithAssertion()` | the assertion, rsa-sha256 and sha256, the `Signature` after its `Issuer`, the test certificate in `KeyInfo` |
| `signed-by-the-signer-both-rsa-sha256.xml` | the same, signed twice | the assertion as above, then the response over bytes that hold the assertion's `Signature` |
| `signed-by-the-signer-entity-rsa-sha512.xml` | `Built::entityDescriptor()` | rsa-sha512 and sha512, the `Signature` first, the test certificate in `KeyInfo` |
