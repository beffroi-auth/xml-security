<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.1, E-1: the closed list of content encryption methods, and what each case knows of itself.
 */
final class ContentAlgorithmTest extends TestCase
{
    /**
     * §9.3 row 12: each case round-trips through fromUri().
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function itRoundTripsEachCaseThroughItsUri(ContentAlgorithm $algorithm): void
    {
        // When / Then
        static::assertSame($algorithm, ContentAlgorithm::fromUri($algorithm->value));
    }

    /**
     * @return iterable<string, array{ContentAlgorithm}>
     */
    public static function provideCases(): iterable
    {
        foreach (ContentAlgorithm::cases() as $case) {
            yield $case->name => [$case];
        }
    }

    /**
     * §9.2 rows 1 and 2, E-1: the CBC modes, 3DES, aes192-gcm and every unknown URI are refused by name, before
     * anything is decoded.
     */
    #[Test]
    #[DataProvider('provideRefusedUris')]
    public function itRefusesEveryOtherUri(string $uri): void
    {
        // Then
        $this->expectException(UnknownContentAlgorithm::class);
        $this->expectExceptionMessageIs('The content algorithm is not AES-128-GCM or AES-256-GCM (E-1).');

        // When
        ContentAlgorithm::fromUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedUris(): iterable
    {
        yield 'aes128-cbc' => ['http://www.w3.org/2001/04/xmlenc#aes128-cbc'];
        yield 'aes192-cbc' => ['http://www.w3.org/2001/04/xmlenc#aes192-cbc'];
        yield 'aes256-cbc' => ['http://www.w3.org/2001/04/xmlenc#aes256-cbc'];
        yield 'tripledes-cbc' => ['http://www.w3.org/2001/04/xmlenc#tripledes-cbc'];
        yield 'aes192-gcm' => ['http://www.w3.org/2009/xmlenc11#aes192-gcm'];
        yield 'a key transport as the content method' => ['http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'];
        yield 'a case that differs' => ['http://www.w3.org/2009/xmlenc11#AES256-GCM'];
        yield 'a trailing character' => ['http://www.w3.org/2009/xmlenc11#aes256-gcm/'];
        yield 'the 1.0 namespace for a GCM name' => ['http://www.w3.org/2001/04/xmlenc#aes256-gcm'];
        yield 'empty' => [''];
    }

    /**
     * E-2: the one length of the session key each case accepts.
     */
    #[Test]
    public function itKnowsTheLengthOfItsKey(): void
    {
        // When / Then
        static::assertSame(16, ContentAlgorithm::Aes128Gcm->keyBytes());
        static::assertSame(32, ContentAlgorithm::Aes256Gcm->keyBytes());
    }

    /**
     * Section 5.1: what the two OpenSSL functions take.
     */
    #[Test]
    public function itKnowsItsOpensslCipher(): void
    {
        // When / Then
        static::assertSame('aes-128-gcm', ContentAlgorithm::Aes128Gcm->cipher());
        static::assertSame('aes-256-gcm', ContentAlgorithm::Aes256Gcm->cipher());
    }
}
