<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Internal;

use Beffroi\Xml\Enc\Internal\Pem;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use function base64_decode;
use function count;
use function explode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function strlen;

/**
 * E-11, E-14: one PEM block in memory, read strictly, and written again from its bytes.
 */
final class PemTest extends TestCase
{
    #[Test]
    public function itReadsTheBytesOfOneBlock(): void
    {
        // Given
        $pem = Fixtures::bytes('keys/test-signing-certificate.pem');
        $body = preg_replace('~-----[A-Z ]+-----|\s~', '', $pem) ?? '';

        // When
        $bytes = Pem::block("\n  " . $pem . "\n\n", 'CERTIFICATE');

        // Then
        static::assertSame(base64_decode($body, true), $bytes);
    }

    /**
     * E-11: a block of another type, two blocks, text around the block, no content, content that is not base64.
     */
    #[Test]
    #[TestWith(["-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"], 'another type')]
    #[TestWith(
        [
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ],
        'two blocks',
    )]
    #[TestWith(["x-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"], 'text before')]
    #[TestWith(["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\nx"], 'text after')]
    #[TestWith(["-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"], 'no content')]
    #[TestWith(["-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----\n"], 'content that is not base64')]
    #[TestWith(['file:///etc/ssl/cert.pem'], 'a path')]
    public function itReadsNothingButOneBlockOfTheTypeAsked(string $pem): void
    {
        // When
        $bytes = Pem::block($pem, 'CERTIFICATE');

        // Then
        static::assertNull($bytes);
    }

    #[Test]
    public function itWritesTheBlockAgainInLinesOf64Characters(): void
    {
        // Given
        $bytes = Pem::block(Fixtures::bytes('keys/test-signing-certificate.pem'), 'CERTIFICATE');
        static::assertNotNull($bytes);

        // When
        $pem = Pem::armour($bytes, 'CERTIFICATE');

        // Then
        $lines = explode("\n", $pem);
        static::assertSame('-----BEGIN CERTIFICATE-----', $lines[0]);
        static::assertSame(64, strlen($lines[1]));
        static::assertSame(['-----END CERTIFICATE-----', ''], [$lines[count($lines) - 2], $lines[count($lines) - 1]]);
        static::assertSame($bytes, Pem::block($pem, 'CERTIFICATE'));
    }
}
