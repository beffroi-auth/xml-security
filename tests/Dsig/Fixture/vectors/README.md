# Vectors

The valid signatures the verifier must accept (spec/dsig.md section 9.1), produced by an implementation that is not
this one: xmlsec1 1.3.7 on OpenSSL, in Alpine 3.22 (`apk add xmlsec`). Each vector is the output of xmlsec1 byte for
byte; nothing reformats it afterwards. The templates carry empty `DigestValue`, `SignatureValue` and
`X509Certificate` elements that xmlsec1 fills.

The command, run in `tests/Dsig/Fixture/` with the keys of `../keys/`; `--lax-key-search` is what xmlsec1 1.3
needs when the template's `KeyInfo` does not name the key:

```
xmlsec1 --sign --lax-key-search --privkey-pem keys/test-signing-key.pem,keys/test-signing-certificate.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    --output vectors/response-assertion-rsa-sha256.xml vectors/response-assertion.template.xml
```

And the check that xmlsec1 verifies what it produced:

```
xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/test-signing-certificate.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion vectors/response-assertion-rsa-sha256.xml
```

| Vector | Template | Signed with |
|---|---|---|
| `response-assertion-rsa-sha256.xml` | `response-assertion.template.xml`, a SAML response holding one assertion whose `Signature` follows its `Issuer` | rsa-sha256, exclusive canonicalization, the enveloped transform then exclusive canonicalization, a sha256 digest |
