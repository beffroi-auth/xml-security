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
| `response-assertion-rsa-sha384.xml`, `-sha512.xml` | their own templates, the signature and digest methods changed | rsa-sha384 with sha384, rsa-sha512 with sha512 |
| `response-assertion-rsa-pss-sha256.xml`, `-sha384.xml`, `-sha512.xml` | their own templates | RSASSA-PSS with MGF1 (`http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1` and its siblings), which xmlsec1 1.3 signs with a salt of the digest's length |
| `response-assertion-with-comments.xml` | its own template, both canonicalizations `#WithComments`, a comment inside the signed `NameID` | exclusive canonicalization with comments |
| `response-assertion-prefixlist.xml` | its own template, an `InclusiveNamespaces PrefixList="#default saml ds"` on the canonicalization transform | the prefix list rendered as an inclusive form would |
| `entity-descriptor-rsa-sha256.xml` | `entity-descriptor.template.xml`, the `Signature` as the first child, the test certificate in the key descriptor | the shape of signed metadata, `--id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor` |
| `response-and-assertion-both-signed.xml` | `response-and-assertion-both-signed.template.xml`, the assertion's `Signature` with `Id="_sig-assertion"` and a response `Signature` with `Id="_sig-response"` after the response's `Issuer` | two enveloped signatures, the assertion signed first, then the response over bytes that hold the assertion's `Signature` |

The doubly signed vector takes two runs, each naming the `Signature` to fill by its `Id`, registered as an ID
attribute like the SAML ones:

```
I="--id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response --id-attr:Id http://www.w3.org/2000/09/xmldsig#:Signature"
xmlsec1 --sign --lax-key-search --privkey-pem keys/test-signing-key.pem,keys/test-signing-certificate.pem $I \
    --node-id _sig-assertion --output step-1.xml vectors/response-and-assertion-both-signed.template.xml
xmlsec1 --sign --lax-key-search --privkey-pem keys/test-signing-key.pem,keys/test-signing-certificate.pem $I \
    --node-id _sig-response --output vectors/response-and-assertion-both-signed.xml step-1.xml
```

`../hostile/resigned-with-a-stranger-key-refused.xml` is the first template signed the same way with the stranger
key pair of `../keys/README.md`: xmlsec1 verifies it with the stranger's certificate, and this namespace refuses it
with the test certificate as the trusted key, which is the point.
