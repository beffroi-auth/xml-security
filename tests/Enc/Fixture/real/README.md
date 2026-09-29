# Real documents

Section 9.4 of spec/enc.md: encryptions produced by other implementations, decrypted here with the test key, bytes
as received, disposable identities.

## SimpleSAMLphp

The judge of sub-spike 8e says: SimpleSAMLphp decrypts what this namespace encrypts, and the reverse. What encrypts
and decrypts inside SimpleSAMLphp is its library `simplesamlphp/saml2`, on `robrichards/xmlseclibs`; the exchange
below ran it directly, in a container, on 27 September 2026 with `simplesamlphp/saml2` 4.20.3 and `xmlseclibs`
3.1.5 (PHP 8.4.25). Nothing of it is a dependency of this package: `simplesamlphp/` holds a throwaway Composer
project and the two scripts, run from the root of the repository so that the fixtures of `tests/Enc/Fixture/` are
mounted:

```
docker run --rm -it -v "$PWD/tests/Enc/Fixture/real/simplesamlphp:/app" -v "$PWD/tests/Enc/Fixture:/fixtures:ro" \
    -v "$PWD/tests/Enc/Fixture/real:/out" -w /app ghcr.io/spomky-labs/phpqa:8.4 \
    sh -c 'composer install -n --no-progress && php encrypt-theirs.php && php decrypt-ours.php'
```

`encrypt-theirs.php` encrypts the assertion of `../vectors/response-assertion.data.xml` with `XMLSecEnc`, the
library under `saml2`, called directly: `encryptKey()` under `rsa-oaep-mgf1p` to the test certificate, then
`encryptNode()` under `aes256-gcm` and again under `aes128-gcm`, the `EncryptedKey` inside a `dsig:KeyInfo` with
no hint. Those are `simplesamlphp-xmlseclibs-3.1.5-response-encrypted-aes256-gcm-2026-09-27.xml` and its `aes128-gcm`
sibling, which `RealDocumentsTest` decrypts with the test key. The library is called directly because `saml2`'s own
`EncryptedAssertion::setAssertion()` picks AES-128-CBC whenever the key it is given is an RSA key: the script runs
it too, and its output, `simplesamlphp-saml2-4.20.3-response-encrypted-assertion-default-2026-09-27.xml`, `aes128-cbc`
under `rsa-oaep-mgf1p`, is what a SimpleSAMLphp identity provider sends and what the decryptor refuses by name (E-1,
the trade-off of section 12).

`decrypt-ours.php` loads what the encryptor of this namespace produced (`../behaviour/encrypted-by-the-encryptor-*.xml`)
and two xmlsec1 vectors with `SAML2\Message::fromXML()` and decrypts the assertion with
`EncryptedAssertion::getAssertion()` under the test key. On 27 September 2026 both of ours and the `aes256-gcm`
vector decrypted to the assertion, its issuer and its attribute; the `rsa-oaep` vector with SHA-256 raised "Failed
to decrypt XML element", the library unwrapping under SHA-1 only; and the fixture with the truncated tag raised the
same, the check of CVE-2026-32313 in place.

A SimpleSAMLphp installation as an IdP and an SP remains to be done when the SAML layers exist (`Core` #15); the
library is what such an installation runs to encrypt and decrypt.
