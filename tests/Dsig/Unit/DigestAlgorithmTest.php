<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Dsig\DigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\UnknownDigestAlgorithm;
use function hash;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 5.1, D-5: the closed list of digest methods, their raw digests and their lengths.
 */
final class DigestAlgorithmTest extends TestCase
{
    /**
     * §9.3 row 13: each case round-trips through fromUri().
     */
    #[Test]
    #[DataProvider('provideCases')]
    public function itRoundTripsEachCaseThroughItsUri(DigestAlgorithm $algorithm): void
    {
        // When / Then
        static::assertSame($algorithm, DigestAlgorithm::fromUri($algorithm->value));
    }

    /**
     * @return iterable<string, array{DigestAlgorithm}>
     */
    public static function provideCases(): iterable
    {
        foreach (DigestAlgorithm::cases() as $case) {
            yield $case->name => [$case];
        }
    }

    /**
     * §9.2 row 21, D-5: SHA-1, MD5 and every unknown URI are refused by name.
     */
    #[Test]
    #[DataProvider('provideRefusedUris')]
    public function itRefusesEveryOtherUri(string $uri): void
    {
        // Then
        $this->expectException(UnknownDigestAlgorithm::class);
        $this->expectExceptionMessageIs('The digest algorithm is not SHA-256, SHA-384 or SHA-512 (D-5).');

        // When
        DigestAlgorithm::fromUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedUris(): iterable
    {
        yield 'sha1' => ['http://www.w3.org/2000/09/xmldsig#sha1'];
        yield 'md5' => ['http://www.w3.org/2001/04/xmldsig-more#md5'];
        yield 'sha224' => ['http://www.w3.org/2001/04/xmldsig-more#sha224'];
        yield 'a case that differs' => ['http://www.w3.org/2001/04/xmlenc#SHA256'];
        yield 'empty' => [''];
    }

    /**
     * The raw digest, as hash() gives it with its binary flag, and its length.
     */
    #[Test]
    #[DataProvider('provideHashes')]
    public function itHashesWithItsFunctionAndKnowsItsLength(
        DigestAlgorithm $algorithm,
        string $name,
        int $length,
    ): void {
        // When
        $digest = $algorithm->hash('signed bytes');

        // Then
        static::assertSame(hash($name, 'signed bytes', true), $digest);
        static::assertSame($length, strlen($digest));
        static::assertSame($length, $algorithm->length());
    }

    /**
     * @return iterable<string, array{DigestAlgorithm, string, int}>
     */
    public static function provideHashes(): iterable
    {
        yield 'sha256' => [DigestAlgorithm::Sha256, 'sha256', 32];
        yield 'sha384' => [DigestAlgorithm::Sha384, 'sha384', 48];
        yield 'sha512' => [DigestAlgorithm::Sha512, 'sha512', 64];
    }
}
