<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Stack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, the silent first match: getElementById() returns the first of two elements sharing an ID and says
 * nothing (measured, section 13). The rule: it is never called, and the brick's own index refuses duplicates
 * (I-8, I-14).
 */
final class SilentFirstMatchTest extends TestCase
{
    /**
     * I-8: two elements sharing an ID, under one attribute or two, refuse the whole document; no first match.
     */
    #[Test]
    #[DataProvider('provideDuplicates')]
    public function aDuplicateIdRefusesTheWholeDocument(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDuplicates(): iterable
    {
        yield 'two assertions with the same ID' => ['hostile/id-duplicate-assertion-refused.xml'];
        yield 'an assertion ID equal to a signature Id' => ['hostile/id-duplicate-across-attributes-refused.xml'];
    }
}
