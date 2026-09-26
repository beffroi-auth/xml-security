<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Core\InclusiveNamespaces;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.4: the prefixes of an InclusiveNamespaces PrefixList (Exclusive XML Canonicalization §4).
 */
final class InclusiveNamespacesTest extends TestCase
{
    #[Test]
    public function itHoldsThePrefixes(): void
    {
        // When
        $namespaces = new InclusiveNamespaces(['ds', '#default']);

        // Then
        static::assertSame(['ds', '#default'], $namespaces->prefixes);
    }

    #[Test]
    public function noneHoldsNoPrefix(): void
    {
        // When / Then
        static::assertSame([], InclusiveNamespaces::none()->prefixes);
    }

    /**
     * Section 5.4: whitespace-separated, as the PrefixList attribute carries it.
     *
     * @param list<string> $prefixes
     */
    #[Test]
    #[DataProvider('providePrefixLists')]
    public function itSplitsAPrefixListOnWhitespace(string $prefixList, array $prefixes): void
    {
        // When / Then
        static::assertSame($prefixes, InclusiveNamespaces::fromPrefixList($prefixList)->prefixes);
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function providePrefixLists(): iterable
    {
        yield 'one prefix' => ['ds', ['ds']];
        yield 'two prefixes' => ['ds saml', ['ds', 'saml']];
        yield '#default among them' => ['#default xs', ['#default', 'xs']];
        yield 'several spaces, tabs and line feeds' => ["ds  \t saml\nxs", ['ds', 'saml', 'xs']];
        yield 'leading and trailing whitespace' => ['  ds ', ['ds']];
        yield 'empty' => ['', []];
        yield 'whitespace only' => ["  \t", []];
    }
}
