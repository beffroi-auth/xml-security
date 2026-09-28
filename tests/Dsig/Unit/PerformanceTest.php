<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Fixtures as CoreFixtures;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use function hrtime;
use PHPUnit\Framework\Attributes\RequiresEnvironmentVariable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.5: a soft assertion, run in CI only, where the machine is known.
 */
#[RequiresEnvironmentVariable('CI')]
final class PerformanceTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Section 9.5: verifying Entra's metadata, the reload included, takes less than 20 ms.
     */
    #[Test]
    public function itVerifiesEntrasMetadataInLessThanTwentyMilliseconds(): void
    {
        // Given
        $document = Loaded::document(CoreFixtures::bytes('real/entra-common-federation-metadata-2026-09-23.xml'));
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $signature = Children::one($document->root(), new Name(self::DSIG, 'Signature'));
        $data = Children::one(
            Children::one($signature, new Name(self::DSIG, 'KeyInfo')),
            new Name(self::DSIG, 'X509Data'),
        );
        $keys = new VerificationKeys([VerificationKey::fromCertificateBase64(
            Text::of(Children::one($data, new Name(self::DSIG, 'X509Certificate'))),
        )]);

        // When
        $start = hrtime(true);
        $verifier->verify($document->root(), $keys);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertLessThan(20, $milliseconds);
    }
}
