<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Regression;

use Beffroi\Xml\Core\Exception\UnknownId;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, XPath injection: xmlseclibs built XPath expressions from the reference URI (GHSA-2g98-f9jv-w8c5,
 * 20 May 2024). The rule: no XPath expression exists anywhere in the brick, and an ID is looked up in the index
 * built at load (I-9, I-14).
 */
final class XpathInjectionTest extends TestCase
{
    /**
     * GHSA-2g98-f9jv-w8c5, I-9: a reference identifier crafted as an XPath fragment is compared as a string and
     * matches nothing; nothing is evaluated.
     */
    #[Test]
    #[DataProvider('provideCraftedIdentifiers')]
    public function ghsa2g98f9jvw8c5ACraftedIdentifierIsLookedUpNeverEvaluated(string $identifier): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');
        static::assertFalse($document->hasId($identifier));

        // Then
        $this->expectException(UnknownId::class);
        $this->expectExceptionMessageIs('No element carries that ID (section 6.2).');

        // When
        $document->elementById($identifier);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCraftedIdentifiers(): iterable
    {
        yield 'a predicate closing and reopening' => ["_assertion')] | //*[@ID='_response"];
        yield 'an alternative node set' => ['_assertion | //saml:Assertion'];
        yield 'a quote' => ["'"];
        yield 'an id() call' => ["xpointer(id('_assertion'))"];
        yield 'a fragment sign' => ['#_assertion'];
    }
}
