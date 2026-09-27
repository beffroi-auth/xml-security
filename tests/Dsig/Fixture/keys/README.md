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

The other files serve the refusals and the second-key cases, made the same day the same way:

| File | Made with | Serves |
|---|---|---|
| `stranger-certificate.pem` | `openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=xml-security test stranger key, not a secret"`, its private key kept out of the repository after signing `../hostile/resigned-with-a-stranger-key-refused.xml` | a trusted key that is not the signer's (D-7), the second-key cases |
| `weak-rsa-1024-certificate.pem`, `weak-rsa-1024-key.pem` | `openssl req -x509 -newkey rsa:1024 -nodes`, `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024` | the refusal of a key under 2048 bits (D-16) |
| `ec-p256-certificate.pem`, `ec-p256-key.pem` | `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes`, `openssl ecparam -name prime256v1 -genkey` | the refusal of a key that is not RSA (D-16) |
| `dsa-2048-key.pem` | `openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048`, then `openssl genpkey -paramfile` | the refusal of a DSA signing key (D-16) |
| `encrypted-rsa-2048-key.pem` | `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -pass pass:test-passphrase` | a passphrase-protected PEM, passphrase `test-passphrase`, and the refusal of a wrong one |
