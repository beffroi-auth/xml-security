# Behaviour fixtures

The documents the encryptor produced, decrypted by xmlsec1 1.3.7 in Alpine 3.22, the implementation that is not
this one (spec/enc.md section 9.3, row 10). An AES-GCM ciphertext is fresh on every call (E-8), so nothing pins
these bytes: the test of the encryptor builds the same response through `tests/Enc/Support/Built.php`, encrypts
its assertion, and checks that the decryptor reads its output and reads these files alike.

The two files were produced on 27 September 2026 with PHP 8.4.25 and OpenSSL 3.5.7 by `Encryptor::encrypt()` over
the assertion of `Built::responseWithAssertion()`, the test certificate in the key's `KeyInfo`, the result put under
an `EncryptedAssertion` in place of the assertion and serialized by `Core`. The check, run from the root with
`castor xmlsec-decrypt <file>`, or in `tests/Enc/Fixture/`:

```
xmlsec1 --decrypt --lax-key-search --privkey-pem keys/test-signing-key.pem behaviour/encrypted-by-the-encryptor-aes256-gcm.xml
xmlsec1 --decrypt --lax-key-search --privkey-pem keys/test-signing-key.pem behaviour/encrypted-by-the-encryptor-aes128-gcm.xml
```

Each prints the response with the assertion back in place, `xmlns:saml` declared on it, its ID and its `NameID`
as built.

| File | Encrypted with |
|---|---|
| `encrypted-by-the-encryptor-aes256-gcm.xml` | `aes256-gcm`, the session key under `rsa-oaep-mgf1p` |
| `encrypted-by-the-encryptor-aes128-gcm.xml` | `aes128-gcm`, the same transport |
