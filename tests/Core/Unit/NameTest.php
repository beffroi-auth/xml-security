<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Beffroi\Xml\Tests\Core\Support\Stack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * I-10: names are namespace URI and local name; a prefix is never compared. Section 5.1.
 */
final class NameTest extends TestCase
{
    /**
     * Section 5.1: a null namespace is a node in no namespace.
     */
    #[Test]
    public function itHoldsTheNamespaceAndTheLocalName(): void
    {
        // When
        $name = new Name(Stack::SAML_ASSERTION, 'Assertion');

        // Then
        static::assertSame(Stack::SAML_ASSERTION, $name->namespace);
        static::assertSame('Assertion', $name->local);
    }

    /**
     * Section 5.1: of() reads (namespaceURI, localName) of an element, not its prefix.
     */
    #[Test]
    public function itReadsTheNamespaceUriAndTheLocalNameOfAnElement(): void
    {
        // Given
        $element = Loaded::document('<x:Assertion xmlns:x="urn:oasis:names:tc:SAML:2.0:assertion"/>')->root();

        // When
        $name = Name::of($element);

        // Then
        static::assertTrue($name->equals(new Name(Stack::SAML_ASSERTION, 'Assertion')));
    }

    /**
     * Section 5.1: an unprefixed attribute is in no namespace, whatever the default namespace of its element.
     */
    #[Test]
    public function itReadsAnUnprefixedAttributeAsInNoNamespace(): void
    {
        // Given
        $element = Loaded::document('<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"/>')->root();
        $attribute = $element->getAttributeNodeNS(null, 'ID');
        static::assertNotNull($attribute);

        // When
        $name = Name::of($attribute);

        // Then
        static::assertTrue($name->equals(new Name(null, 'ID')));
    }

    /**
     * I-10, §9.3 row 9: same namespace, other prefix, matched.
     */
    #[Test]
    public function itMatchesAnElementOnNamespaceUriAndLocalNameNeverThePrefix(): void
    {
        // Given
        $element = Loaded::document('<x:Assertion xmlns:x="urn:oasis:names:tc:SAML:2.0:assertion"/>')->root();

        // When / Then
        static::assertTrue(new Name(Stack::SAML_ASSERTION, 'Assertion')->matches($element));
    }

    /**
     * I-10, §9.3 row 8: same local name, other namespace, not matched.
     */
    #[Test]
    public function itDoesNotMatchTheSameLocalNameInAnotherNamespace(): void
    {
        // Given
        $element = Loaded::document('<evil:Assertion xmlns:evil="urn:evil"/>')->root();

        // When / Then
        static::assertFalse(new Name(Stack::SAML_ASSERTION, 'Assertion')->matches($element));
    }

    /**
     * I-10: same namespace, other local name, not matched.
     */
    #[Test]
    public function itDoesNotMatchAnotherLocalNameInTheSameNamespace(): void
    {
        // Given
        $element = Loaded::document('<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>')->root();

        // When / Then
        static::assertFalse(new Name(Stack::SAML_ASSERTION, 'Assertion')->matches($element));
    }

    /**
     * I-10: an attribute matches on its namespace URI and local name too.
     */
    #[Test]
    public function itMatchesAnAttribute(): void
    {
        // Given
        $element = Loaded::document('<a xmlns:p="urn:p" p:lang="fr"/>')->root();
        $attribute = $element->getAttributeNodeNS('urn:p', 'lang');
        static::assertNotNull($attribute);

        // When / Then
        static::assertTrue(new Name('urn:p', 'lang')->matches($attribute));
    }

    /**
     * Section 5.1: equality is the pair (namespace, local), null namespace included.
     */
    #[Test]
    #[DataProvider('provideNamePairs')]
    public function itComparesTwoNamesOnBothParts(Name $left, Name $right, bool $equal): void
    {
        // When / Then
        static::assertSame($equal, $left->equals($right));
    }

    /**
     * @return iterable<string, array{Name, Name, bool}>
     */
    public static function provideNamePairs(): iterable
    {
        yield 'same namespace, same local' => [new Name('urn:a', 'x'), new Name('urn:a', 'x'), true];
        yield 'both in no namespace' => [new Name(null, 'x'), new Name(null, 'x'), true];
        yield 'other namespace' => [new Name('urn:a', 'x'), new Name('urn:b', 'x'), false];
        yield 'other local' => [new Name('urn:a', 'x'), new Name('urn:a', 'y'), false];
        yield 'namespace against none' => [new Name('urn:a', 'x'), new Name(null, 'x'), false];
        yield 'case of the local name' => [new Name('urn:a', 'x'), new Name('urn:a', 'X'), false];
    }
}
