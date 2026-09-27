# Real documents

Section 9.4 of spec/dsig.md: signatures produced by other implementations, verified here with the key their
producer published, bytes as received, disposable identities.

## Entra

The common federation metadata of `Core` (`tests/Core/Fixture/real/`), signed by Microsoft; the test passes the
certificate of the `Signature`'s own `KeyInfo` as the trusted key, which proves the signature, not the trust.

## SimpleSAMLphp

The judge of sub-spike 8a says: SimpleSAMLphp verifies what this namespace signs, and the reverse. What signs and
verifies inside SimpleSAMLphp is its library `simplesamlphp/saml2`, on `robrichards/xmlseclibs`; the exchange below
ran it directly, in a container, on 27 September 2026 with `simplesamlphp/saml2` 4.20.3 and `xmlseclibs` 3.1.5
(PHP 8.4.25). Nothing of it is a dependency of this package: `simplesamlphp/` holds a throwaway Composer project
and the two scripts, run from the root of the repository so that the fixtures of `tests/Dsig/Fixture/` are mounted:

```
docker run --rm -it -v "$PWD/tests/Dsig/Fixture/real/simplesamlphp:/app" -v "$PWD/tests/Dsig/Fixture:/fixtures:ro" \
    -v "$PWD/tests/Dsig/Fixture/real:/out" -w /app ghcr.io/spomky-labs/phpqa:8.4 \
    sh -c 'composer install -n --no-progress && php verify-ours.php && php sign-theirs.php'
```

`verify-ours.php` loads what the signer of this namespace produced (`../behaviour/signed-by-the-signer-*.xml`)
and the first xmlsec1 vector with `SAML2\Message::fromXML()` and validates the assertion, and the response where
it is signed, with `Assertion::validate()` and `Response::validate()` under the test certificate; it also checks
that a tampered element fails there. On 27 September 2026 every one validated and the tampered one raised
"Reference validation failed".

`sign-theirs.php` builds a response holding one assertion with the library, signs the assertion with the test key
(`setSignatureKey()`, `setCertificates()`), writes it as `simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-27.xml`,
then signs the response as well and writes `simplesamlphp-saml2-4.20.3-response-signed-both-2026-09-27.xml`.
The library signs as this namespace expects: exclusive canonicalization, rsa-sha256, the enveloped transform then
exclusive canonicalization, a sha256 digest, no prefix list, the `Signature` after the `Issuer`, the certificate in
`KeyInfo`. The tests of `RealDocumentsTest` verify both files with the test certificate.

A SimpleSAMLphp installation as an IdP and an SP, with metadata, an `AuthnRequest` and a `LogoutRequest` captured
from a browser flow, remains to be done when the SAML layers exist (`Core` #15); the library is what such an
installation would run to sign and verify.
