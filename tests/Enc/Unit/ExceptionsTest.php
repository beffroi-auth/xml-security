<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\EncryptionFailed;
use Beffroi\Xml\Enc\Exception\EncryptionRefused;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;
use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use function class_parents;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Section 5.6: every refusal is an EncryptionRefused, which is a RefusedXml of Core, so that a consumer catching
 * that base class catches everything the package refuses; the one failure carries the one message (E-3); an
 * EncryptionFailed is never input.
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
        static::assertArrayHasKey(EncryptionRefused::class, $parents);
        static::assertArrayHasKey(RefusedXml::class, $parents);
    }

    /**
     * @return iterable<string, array{class-string}>
     */
    public static function provideRefusals(): iterable
    {
        foreach ([
            MalformedEncryption::class,
            UnknownContentAlgorithm::class,
            UnknownKeyTransport::class,
            AlgorithmUnavailable::class,
            DecryptionFailed::class,
            InvalidKey::class,
            LimitExceeded::class,
        ] as $exception) {
            yield $exception => [$exception];
        }
    }

    /**
     * §9.2 row 33, E-3: the one failure carries the one message and nothing else, by construction.
     */
    #[Test]
    public function itsOneFailureCarriesTheOneMessage(): void
    {
        // When
        $failure = new DecryptionFailed();

        // Then
        static::assertSame('The data could not be decrypted (E-3).', $failure->getMessage());
        static::assertSame(DecryptionFailed::MESSAGE, $failure->getMessage());
        static::assertSame(0, $failure->getCode());
        static::assertNull($failure->getPrevious());
    }

    #[Test]
    public function itsEncryptionFailureIsNeverInput(): void
    {
        // When
        $parents = class_parents(EncryptionFailed::class);

        // Then
        static::assertNotFalse($parents);
        static::assertArrayHasKey(RuntimeException::class, $parents);
        static::assertArrayNotHasKey(RefusedXml::class, $parents);
    }
}
