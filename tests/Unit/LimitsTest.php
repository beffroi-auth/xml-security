<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\Limits;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * I-7 and section 7: six bounds, each with a default and a ceiling, never a switch that removes a check.
 */
final class LimitsTest extends TestCase
{
    /**
     * Section 7: the defaults.
     */
    #[Test]
    public function itHoldsTheDefaultsOfSection7(): void
    {
        // When
        $limits = new Limits();

        // Then
        static::assertSame(1_048_576, $limits->maxBytes);
        static::assertSame(64, $limits->maxDepth);
        static::assertSame(10_000, $limits->maxElements);
        static::assertSame(32, $limits->maxAttributesPerElement);
        static::assertSame(512, $limits->maxNamespaceDeclarations);
        static::assertSame(128, $limits->maxIdLength);
    }

    /**
     * Section 7: a bound may be raised up to its ceiling.
     */
    #[Test]
    #[DataProvider('provideCeilings')]
    public function itAcceptsABoundAtItsCeiling(string $bound, int $ceiling): void
    {
        // When
        $limits = new Limits(...[$bound => $ceiling]);

        // Then
        static::assertSame($ceiling, $this->read($limits, $bound));
    }

    /**
     * Section 5.2: a value over the ceiling is a programming error.
     */
    #[Test]
    #[DataProvider('provideCeilings')]
    public function itRefusesABoundOverItsCeiling(string $bound, int $ceiling): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('%s must be between 1 and %d (section 7).', $bound, $ceiling));

        // When
        new Limits(...[$bound => $ceiling + 1]);
    }

    /**
     * Section 5.2: a value under 1 is a programming error, and never a switch that removes the check.
     */
    #[Test]
    #[DataProvider('provideCeilings')]
    public function itRefusesABoundUnderOne(string $bound, int $ceiling): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('%s must be between 1 and %d (section 7).', $bound, $ceiling));

        // When
        new Limits(...[$bound => 0]);
    }

    private function read(Limits $limits, string $bound): int
    {
        return match ($bound) {
            'maxBytes' => $limits->maxBytes,
            'maxDepth' => $limits->maxDepth,
            'maxElements' => $limits->maxElements,
            'maxAttributesPerElement' => $limits->maxAttributesPerElement,
            'maxNamespaceDeclarations' => $limits->maxNamespaceDeclarations,
            'maxIdLength' => $limits->maxIdLength,
            default => throw new InvalidArgumentException(sprintf('%s is not a bound.', $bound)),
        };
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideCeilings(): iterable
    {
        yield 'maxBytes' => ['maxBytes', 8_388_608];
        yield 'maxDepth' => ['maxDepth', 200];
        yield 'maxElements' => ['maxElements', 1_000_000];
        yield 'maxAttributesPerElement' => ['maxAttributesPerElement', 1_000];
        yield 'maxNamespaceDeclarations' => ['maxNamespaceDeclarations', 10_000];
        yield 'maxIdLength' => ['maxIdLength', 1_024];
    }
}
