# Hostile fixtures

Documents the model or the verifier refuses, each named `<case>-refused.xml` and derived from a vector of
`../vectors/` by the one change its name says; the tests assert the exception and the message of each
(spec/dsig.md section 9.2).

Three of them carry a signature that is valid, made with another scheme than the one `SignatureMethod` claims, so
that the verifier refuses them for the confusion of schemes and for nothing else. Each was built on 29 September
2026 in the phpqa image (PHP 8.5.10, OpenSSL 3.5.7): `SignatureMethod` changed in the vector, `SignedInfo`
canonicalized as its `CanonicalizationMethod` says with `Core`'s `Canonicalizer` into `si.bin`, those bytes signed
with the test key under the real scheme, and the signature checked before it replaced `SignatureValue`:

```
openssl dgst -sha256 -sign keys/test-signing-key.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out si.sig si.bin
openssl dgst -sha256 -sign keys/test-signing-key.pem -out si.sig si.bin
openssl dgst -sha256 -verify public.pem [the same -sigopt] -signature si.sig si.bin
```

| File | `SignatureMethod` claims | Signed with |
|---|---|---|
| `pss-signature-claimed-as-pkcs1-refused.xml` | `rsa-sha256` | RSASSA-PSS, SHA-256, a salt of 32 bytes |
| `pkcs1-signature-claimed-as-pss-refused.xml` | `sha256-rsa-MGF1` | RSASSA-PKCS1-v1_5, SHA-256 |
| `sha256-signature-claimed-as-sha512-refused.xml` | `rsa-sha512` | RSASSA-PKCS1-v1_5, SHA-256 |
