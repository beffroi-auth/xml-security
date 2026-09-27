<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Core\CanonicalXml;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\Verified;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.4, D-10: what a verification hands to the consumer, four values and nothing computed.
 */
final class VerifiedTest extends TestCase
{
    #[Test]
    public function itHoldsWhatTheVerifierGivesIt(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x" ID="_a"/>');
        $canonical = new CanonicalXml('<a xmlns="urn:x" ID="_a"></a>');
        $key = VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));

        // When
        $verified = new Verified($document, $canonical, SignatureAlgorithm::RsaSha256, $key);

        // Then
        static::assertSame($document, $verified->document);
        static::assertSame($canonical, $verified->canonical);
        static::assertSame(SignatureAlgorithm::RsaSha256, $verified->algorithm);
        static::assertSame($key, $verified->key);
    }
}
