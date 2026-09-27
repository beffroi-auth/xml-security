<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Dsig\DigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use function defined;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.1, D-5: the closed list of signature methods, and what each case knows of itself.
 */
final class SignatureAlgorithmTest extends TestCase
{
    /**
     * §9.3 row 13: each case round-trips through fromUri().
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function itRoundTripsEachCaseThroughItsUri(SignatureAlgorithm $algorithm): void
    {
        // When / Then
        static::assertSame($algorithm, SignatureAlgorithm::fromUri($algorithm->value));
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm}>
     */
    public static function provideCases(): iterable
    {
        foreach (SignatureAlgorithm::cases() as $case) {
            yield $case->name => [$case];
        }
    }

    /**
     * §9.2 rows 18, 19 and 20, D-5: SHA-1, HMAC, DSA, ECDSA and every unknown URI are refused by name.
     */
    #[Test]
    #[DataProvider('provideRefusedUris')]
    public function itRefusesEveryOtherUri(string $uri): void
    {
        // Then
        $this->expectException(UnknownSignatureAlgorithm::class);
        $this->expectExceptionMessageIs('The signature algorithm is not one of the six RSA schemes the namespace verifies (D-5).');

        // When
        SignatureAlgorithm::fromUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedUris(): iterable
    {
        yield 'rsa-sha1' => ['http://www.w3.org/2000/09/xmldsig#rsa-sha1'];
        yield 'hmac-sha256' => ['http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'];
        yield 'hmac-sha1' => ['http://www.w3.org/2000/09/xmldsig#hmac-sha1'];
        yield 'dsa-sha256' => ['http://www.w3.org/2009/xmldsig11#dsa-sha256'];
        yield 'dsa-sha1' => ['http://www.w3.org/2000/09/xmldsig#dsa-sha1'];
        yield 'ecdsa-sha256' => ['http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'];
        yield 'rsa-md5' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-md5'];
        yield 'a case that differs' => ['http://www.w3.org/2001/04/xmldsig-more#RSA-SHA256'];
        yield 'a trailing character' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256/'];
        yield 'empty' => [''];
    }

    /**
     * §9.3 row 14: the hash of the scheme.
     */
    #[Test]
    #[DataProvider('provideDigests')]
    public function itKnowsTheDigestOfItsScheme(SignatureAlgorithm $algorithm, DigestAlgorithm $digest): void
    {
        // When / Then
        static::assertSame($digest, $algorithm->digest());
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm, DigestAlgorithm}>
     */
    public static function provideDigests(): iterable
    {
        yield 'rsa-sha256' => [SignatureAlgorithm::RsaSha256, DigestAlgorithm::Sha256];
        yield 'rsa-sha384' => [SignatureAlgorithm::RsaSha384, DigestAlgorithm::Sha384];
        yield 'rsa-sha512' => [SignatureAlgorithm::RsaSha512, DigestAlgorithm::Sha512];
        yield 'pss sha256' => [SignatureAlgorithm::RsaPssSha256, DigestAlgorithm::Sha256];
        yield 'pss sha384' => [SignatureAlgorithm::RsaPssSha384, DigestAlgorithm::Sha384];
        yield 'pss sha512' => [SignatureAlgorithm::RsaPssSha512, DigestAlgorithm::Sha512];
    }

    #[Test]
    #[DataProvider('providePss')]
    public function itKnowsWhetherItIsPss(SignatureAlgorithm $algorithm, bool $pss): void
    {
        // When / Then
        static::assertSame($pss, $algorithm->isPss());
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm, bool}>
     */
    public static function providePss(): iterable
    {
        yield 'rsa-sha256' => [SignatureAlgorithm::RsaSha256, false];
        yield 'rsa-sha384' => [SignatureAlgorithm::RsaSha384, false];
        yield 'rsa-sha512' => [SignatureAlgorithm::RsaSha512, false];
        yield 'pss sha256' => [SignatureAlgorithm::RsaPssSha256, true];
        yield 'pss sha384' => [SignatureAlgorithm::RsaPssSha384, true];
        yield 'pss sha512' => [SignatureAlgorithm::RsaPssSha512, true];
    }

    /**
     * §9.3 row 15: the PKCS#1 v1.5 schemes are available everywhere.
     */
    #[Test]
    #[DataProvider('providePkcs1Cases')]
    public function itsPkcs1SchemesAreAvailableOnEveryBuild(SignatureAlgorithm $algorithm): void
    {
        // When / Then
        static::assertTrue($algorithm->isAvailable());
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm}>
     */
    public static function providePkcs1Cases(): iterable
    {
        yield 'rsa-sha256' => [SignatureAlgorithm::RsaSha256];
        yield 'rsa-sha384' => [SignatureAlgorithm::RsaSha384];
        yield 'rsa-sha512' => [SignatureAlgorithm::RsaSha512];
    }

    /**
     * §9.3 row 15, section 13: the PSS schemes are available where OPENSSL_PKCS1_PSS_PADDING is defined, PHP 8.5,
     * and not on 8.4.
     */
    #[Test]
    public function itsPssSchemesAreAvailableWhereTheBuildDefinesThePadding(): void
    {
        // When / Then
        static::assertSame(defined('OPENSSL_PKCS1_PSS_PADDING'), SignatureAlgorithm::RsaPssSha256->isAvailable());
        static::assertSame(defined('OPENSSL_PKCS1_PSS_PADDING'), SignatureAlgorithm::RsaPssSha384->isAvailable());
        static::assertSame(defined('OPENSSL_PKCS1_PSS_PADDING'), SignatureAlgorithm::RsaPssSha512->isAvailable());
    }
}
