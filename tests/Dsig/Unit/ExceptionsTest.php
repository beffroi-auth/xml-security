<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureRefused;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Exception\UnknownDigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use function class_parents;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Section 5.6: every refusal is a SignatureRefused, which is a RefusedXml of Core, so that a consumer catching that
 * base class catches everything the package refuses; a SigningFailed is never input.
 */
final class ExceptionsTest extends TestCase
{
    /**
     * @param class-string $exception
     */
    #[Test]
    #[DataProvider('provideRefusals')]
    public function itsRefusalsAreRefusedXml(string $exception): void
    {
        // When
        $parents = class_parents($exception);

        // Then
        static::assertNotFalse($parents);
        static::assertArrayHasKey(SignatureRefused::class, $parents);
        static::assertArrayHasKey(RefusedXml::class, $parents);
    }

    /**
     * @return iterable<string, array{class-string}>
     */
    public static function provideRefusals(): iterable
    {
        foreach ([
            MalformedSignature::class,
            UnknownSignatureAlgorithm::class,
            UnknownDigestAlgorithm::class,
            AlgorithmUnavailable::class,
            WrongReference::class,
            SignatureMismatch::class,
            DigestMismatch::class,
            InvalidKey::class,
            LimitExceeded::class,
        ] as $exception) {
            yield $exception => [$exception];
        }
    }

    #[Test]
    public function itsSigningFailureIsNeverInput(): void
    {
        // When
        $parents = class_parents(SigningFailed::class);

        // Then
        static::assertNotFalse($parents);
        static::assertArrayHasKey(RuntimeException::class, $parents);
        static::assertArrayNotHasKey(RefusedXml::class, $parents);
    }
}
