<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Exception\MissingAttribute;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.4: attributes read with getAttributeNS(), null for an absent one, matched on namespace URI and local
 * name (I-10).
 */
final class AttributesTest extends TestCase
{
    /**
     * §9.3 row 10: optional() on an absent attribute is null, not ''.
     */
    #[Test]
    public function optionalIsNullForAnAbsentAttribute(): void
    {
        // Given
        $document = Loaded::document('<a x=""/>');

        // When / Then
        static::assertNull(Attributes::optional($document->root(), new Name(null, 'y')));
    }

    /**
     * Section 6.4: an attribute that is present and empty reads as '', which is not absent.
     */
    #[Test]
    public function optionalReadsAnEmptyAttributeAsEmpty(): void
    {
        // Given
        $document = Loaded::document('<a x=""/>');

        // When / Then
        static::assertSame('', Attributes::optional($document->root(), new Name(null, 'x')));
    }

    #[Test]
    public function requiredReadsAPresentAttribute(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');

        // When / Then
        static::assertSame('2.0', Attributes::required($document->root(), new Name(null, 'Version')));
    }

    /**
     * Section 6.4, I-16: required() on an absent attribute refuses, naming the attribute asked for.
     */
    #[Test]
    public function requiredRefusesAnAbsentAttribute(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');

        // Then
        $this->expectException(MissingAttribute::class);
        $this->expectExceptionMessageIs('The element has no attribute named Destination (section 6.4).');

        // When
        Attributes::required($document->root(), new Name(null, 'Destination'));
    }

    /**
     * I-10: a namespaced attribute, xml:lang here, is read by its namespace URI and local name.
     */
    #[Test]
    public function itReadsANamespacedAttribute(): void
    {
        // Given
        $document = Loaded::document('<a xml:lang="fr" xmlns:p="urn:p" p:lang="de"/>');
        $root = $document->root();

        // When / Then
        static::assertSame('fr', Attributes::required($root, new Name('http://www.w3.org/XML/1998/namespace', 'lang')));
        static::assertSame('de', Attributes::optional($root, new Name('urn:p', 'lang')));
        static::assertNull(Attributes::optional($root, new Name(null, 'lang')));
    }

    /**
     * Section 6.4, I-16: a namespaced attribute asked for is named in Clark notation in the refusal.
     */
    #[Test]
    public function requiredNamesANamespacedAttributeInClarkNotation(): void
    {
        // Given
        $document = Loaded::document('<a/>');

        // Then
        $this->expectException(MissingAttribute::class);
        $this->expectExceptionMessageIs('The element has no attribute named {http://www.w3.org/XML/1998/namespace}lang (section 6.4).');

        // When
        Attributes::required($document->root(), new Name('http://www.w3.org/XML/1998/namespace', 'lang'));
    }
}
