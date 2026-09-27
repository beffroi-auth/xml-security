<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use function defined;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.1, E-1: the hash of RSA-OAEP, for the OAEP mask and for MGF1 alike, and what each case knows of itself.
 */
final class OaepHashTest extends TestCase
{
    /**
     * §9.3 row 12: each case round-trips through fromDigestUri().
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function itRoundTripsEachCaseThroughItsDigestUri(OaepHash $hash): void
    {
        // When / Then
        static::assertSame($hash, OaepHash::fromDigestUri($hash->value));
    }

    /**
     * Section 5.1: each case round-trips through its MGF URI of XML Encryption 1.1 §5.5.2.
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function itRoundTripsEachCaseThroughItsMgfUri(OaepHash $hash): void
    {
        // When / Then
        static::assertSame($hash, OaepHash::fromMgfUri($hash->mgfUri()));
    }

    /**
     * @return iterable<string, array{OaepHash}>
     */
    public static function provideCases(): iterable
    {
        foreach (OaepHash::cases() as $case) {
            yield $case->name => [$case];
        }
    }

    /**
     * Section 5.1: the MGF URIs, written as XML Encryption 1.1 §5.5.2 spells them.
     */
    #[Test]
    public function itSpellsTheMgfUris(): void
    {
        // When / Then
        static::assertSame('http://www.w3.org/2009/xmlenc11#mgf1sha1', OaepHash::Sha1->mgfUri());
        static::assertSame('http://www.w3.org/2009/xmlenc11#mgf1sha256', OaepHash::Sha256->mgfUri());
        static::assertSame('http://www.w3.org/2009/xmlenc11#mgf1sha384', OaepHash::Sha384->mgfUri());
        static::assertSame('http://www.w3.org/2009/xmlenc11#mgf1sha512', OaepHash::Sha512->mgfUri());
    }

    /**
     * E-1: every other digest URI is refused by name.
     */
    #[Test]
    #[DataProvider('provideRefusedDigestUris')]
    public function itRefusesEveryOtherDigestUri(string $uri): void
    {
        // Then
        $this->expectException(UnknownKeyTransport::class);
        $this->expectExceptionMessageIs('The DigestMethod of a key transport is not SHA-1, SHA-256, SHA-384 or SHA-512 (E-1).');

        // When
        OaepHash::fromDigestUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedDigestUris(): iterable
    {
        yield 'md5' => ['http://www.w3.org/2001/04/xmldsig-more#md5'];
        yield 'sha224' => ['http://www.w3.org/2001/04/xmldsig-more#sha224'];
        yield 'ripemd160' => ['http://www.w3.org/2001/04/xmlenc#ripemd160'];
        yield 'an MGF URI as a digest' => ['http://www.w3.org/2009/xmlenc11#mgf1sha256'];
        yield 'a case that differs' => ['http://www.w3.org/2001/04/xmlenc#SHA256'];
        yield 'a trailing character' => ['http://www.w3.org/2001/04/xmlenc#sha256/'];
        yield 'empty' => [''];
    }

    /**
     * E-1: every other MGF URI is refused by name.
     */
    #[Test]
    #[DataProvider('provideRefusedMgfUris')]
    public function itRefusesEveryOtherMgfUri(string $uri): void
    {
        // Then
        $this->expectException(UnknownKeyTransport::class);
        $this->expectExceptionMessageIs('The MGF of a key transport is not MGF1 with SHA-1, SHA-256, SHA-384 or SHA-512 (E-1).');

        // When
        OaepHash::fromMgfUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedMgfUris(): iterable
    {
        yield 'mgf1md5' => ['http://www.w3.org/2009/xmlenc11#mgf1md5'];
        yield 'mgf1sha224' => ['http://www.w3.org/2009/xmlenc11#mgf1sha224'];
        yield 'a digest URI as an MGF' => ['http://www.w3.org/2001/04/xmlenc#sha256'];
        yield 'a case that differs' => ['http://www.w3.org/2009/xmlenc11#MGF1SHA256'];
        yield 'a trailing character' => ['http://www.w3.org/2009/xmlenc11#mgf1sha256/'];
        yield 'empty' => [''];
    }

    /**
     * Section 5.1: what the digest parameter of the two RSA functions takes on PHP 8.5.
     */
    #[Test]
    public function itKnowsItsOpensslName(): void
    {
        // When / Then
        static::assertSame('sha1', OaepHash::Sha1->openssl());
        static::assertSame('sha256', OaepHash::Sha256->openssl());
        static::assertSame('sha384', OaepHash::Sha384->openssl());
        static::assertSame('sha512', OaepHash::Sha512->openssl());
    }

    /**
     * §9.3 row 14, section 13: SHA-1 is available on every build, the others where the RSA functions take a digest,
     * PHP 8.5, the release that also defined OPENSSL_PKCS1_PSS_PADDING.
     */
    #[Test]
    public function itIsAvailableWhereTheBuildTakesADigest(): void
    {
        // When / Then
        static::assertTrue(OaepHash::Sha1->isAvailable());
        static::assertSame(defined('OPENSSL_PKCS1_PSS_PADDING'), OaepHash::Sha256->isAvailable());
        static::assertSame(defined('OPENSSL_PKCS1_PSS_PADDING'), OaepHash::Sha384->isAvailable());
        static::assertSame(defined('OPENSSL_PKCS1_PSS_PADDING'), OaepHash::Sha512->isAvailable());
    }
}
