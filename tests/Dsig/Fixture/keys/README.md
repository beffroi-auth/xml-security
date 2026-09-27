# Test keys

A key pair for the tests of the `Dsig` namespace and nothing else: the private key is public by construction, in
this repository, and signs no real document anywhere. It is an RSA-2048 key with a self-signed certificate valid
twenty years from its generation, made in Alpine 3.22 with OpenSSL 3.5.8 on 27 September 2026:

```
openssl req -x509 -newkey rsa:2048 -nodes -keyout test-signing-key.pem -out test-signing-certificate.pem \
    -days 7300 -subj "/CN=xml-security test signing key, not a secret"
```

`test-signing-certificate.pem` is the trusted key every vector of `../vectors/` verifies against, and the
certificate the signer writes into `KeyInfo` when a test asks for one.
