<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Dom\Element;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Fixtures as CoreFixtures;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 9.4: the real documents, verified with the key their producer published; the signature is proven, not
 * the trust, which is the metadata layer's business.
 */
final class RealDocumentsTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * §9.4, section 13: Entra's common federation metadata of 23 September 2026, signed with rsa-sha256, exclusive
     * canonicalization, the enveloped transform then exclusive canonicalization, a sha256 digest, one reference to
     * the root's ID; the trusted key is the certificate of the Signature's own KeyInfo.
     */
    #[Test]
    public function itVerifiesEntrasFederationMetadata(): void
    {
        // Given
        $document = Loaded::document(CoreFixtures::bytes('real/entra-common-federation-metadata-2026-09-23.xml'));
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([$this->certificateOf($document->root())]);

        // When
        $verified = $verifier->verify($document->root(), $keys);

        // Then
        static::assertSame('EntityDescriptor', $verified->document->root()->localName);
        static::assertSame('_2cac9ed1-b223-4fb8-83bd-03d6f59d682d', $verified->document->root()->getAttribute('ID'));
        static::assertSame(SignatureAlgorithm::RsaSha256, $verified->algorithm);
        static::assertSame([], Children::named($verified->document->root(), new Name(self::DSIG, 'Signature')));
        static::assertGreaterThan(25_000, strlen($verified->canonical->bytes));
    }

    /**
     * §9.4: the canonical form is stable across two runs.
     */
    #[Test]
    public function itVerifiesEntrasFederationMetadataToTheSameBytesTwice(): void
    {
        // Given
        $document = Loaded::document(CoreFixtures::bytes('real/entra-common-federation-metadata-2026-09-23.xml'));
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([$this->certificateOf($document->root())]);

        // When
        $first = $verifier->verify($document->root(), $keys);
        $second = $verifier->verify($document->root(), $keys);

        // Then
        static::assertSame($first->canonical->bytes, $second->canonical->bytes);
    }

    /**
     * §9.4, the judge of sub-spike 8a: the response SimpleSAMLphp's own library signed (simplesamlphp/saml2 4.20.3
     * on xmlseclibs 3.1.5, 27 September 2026) verifies with the test certificate; the reverse is in
     * tests/Dsig/Fixture/real/README.md.
     */
    #[Test]
    public function itVerifiesTheAssertionSimpleSamlPhpSigned(): void
    {
        // Given
        $document = Loaded::fixture('real/simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-27.xml');
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // When
        $verified = $verifier->verify($document->elementById('_ssp-assertion-p1q2r3'), $keys);

        // Then
        static::assertSame('Assertion', $verified->document->root()->localName);
        static::assertSame(SignatureAlgorithm::RsaSha256, $verified->algorithm);
        static::assertStringContainsString('user-0001', $verified->canonical->bytes);
    }

    /**
     * §9.4: the response SimpleSAMLphp's library signed over its signed assertion, both signatures verified.
     */
    #[Test]
    public function itVerifiesTheResponseAndTheAssertionSimpleSamlPhpSigned(): void
    {
        // Given
        $document = Loaded::fixture('real/simplesamlphp-saml2-4.20.3-response-signed-both-2026-09-27.xml');
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // When
        $response = $verifier->verify($document->elementById('_ssp-response-s4t5u6'), $keys);
        $assertion = $verifier->verify($document->elementById('_ssp-assertion-p1q2r3'), $keys);

        // Then
        static::assertSame('Response', $response->document->root()->localName);
        static::assertStringContainsString('<ds:Signature', $response->canonical->bytes);
        static::assertSame('Assertion', $assertion->document->root()->localName);
    }

    /**
     * The certificate the Signature's KeyInfo carries, read with Core's readers: a hint the test takes as the
     * trusted key, which the metadata layer never does.
     */
    private function certificateOf(Element $signed): VerificationKey
    {
        $signature = Children::one($signed, new Name(self::DSIG, 'Signature'));
        $keyInfo = Children::one($signature, new Name(self::DSIG, 'KeyInfo'));
        $data = Children::one($keyInfo, new Name(self::DSIG, 'X509Data'));

        return VerificationKey::fromCertificateBase64(
            Text::of(Children::one($data, new Name(self::DSIG, 'X509Certificate'))),
        );
    }
}
