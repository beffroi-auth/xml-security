<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
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
    /**
     * Section 9.5: decrypting the assertion SimpleSAMLphp's library encrypted, the load included, takes less than
     * 10 ms.
     */
    #[Test]
    public function itDecryptsSimpleSamlPhpsAssertionInLessThanTenMilliseconds(): void
    {
        // Given
        $bytes = Fixtures::bytes('real/simplesamlphp-xmlseclibs-3.1.5-response-encrypted-aes256-gcm-2026-09-27.xml');
        $key = PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
        $decryptor = new Decryptor(new Loader(Stack::idAttributes()));

        // When
        $start = hrtime(true);
        $document = Loaded::document($bytes);
        $decrypted = $decryptor->decrypt(Encrypted::dataOf($document), $key);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertLessThan(10, $milliseconds);
        static::assertSame('Assertion', $decrypted->root()->localName);
    }
}
