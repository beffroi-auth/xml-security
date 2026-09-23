<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Internal;

use function array_map;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\NamespaceRefused;
use Beffroi\Xml\Core\Exception\XmlVersionRefused;
use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\IdAttributes;
use Beffroi\Xml\Core\Internal\Inspector;
use Beffroi\Xml\Core\Limits;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Tests\Support\Foreign;
use Beffroi\Xml\Core\Tests\Support\Stack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 6.1 steps 5 and 6 on documents parsed outside the loader: the rules I-1 and I-3 stop earlier through
 * load() are reached here, so that every branch of the second layer is tested (section 10).
 */
final class InspectorTest extends TestCase
{
    private Inspector $inspector;

    protected function setUp(): void
    {
        $this->inspector = new Inspector(Stack::idAttributes(), new Limits());
    }

    /**
     * I-1: a parsed document whose doctype is not null is refused, whatever the byte scan missed.
     */
    #[Test]
    public function itRefusesADoctypeNode(): void
    {
        // Given
        $document = Foreign::parse('<!DOCTYPE doc [<!ENTITY x "y">]><doc>text</doc>');

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The document has a document type declaration (I-1).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-1: an entity reference node is refused, here with the doctype node removed from the tree.
     */
    #[Test]
    public function itRefusesAnEntityReferenceNode(): void
    {
        // Given
        $document = Foreign::parse('<!DOCTYPE doc [<!ENTITY x "y">]><doc>&x;</doc>');
        $doctype = $document->doctype;
        static::assertNotNull($doctype);
        $document->removeChild($doctype);

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The document contains a node only a DTD can produce, of type 5 (I-1).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-5, §9.2 row 13: XML 1.1, once libxml's warning is out of the way.
     */
    #[Test]
    public function itRefusesAnXmlVersionOtherThan10(): void
    {
        // Given
        $document = Foreign::parse('<?xml version="1.1"?><doc/>');

        // Then
        $this->expectException(XmlVersionRefused::class);
        $this->expectExceptionMessageIs('The XML version is not 1.0 (I-5).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-5: a declared encoding other than UTF-8, compared case-insensitively.
     */
    #[Test]
    public function itRefusesADeclaredEncodingOtherThanUtf8(): void
    {
        // Given
        $document = Foreign::parse('<?xml version="1.0" encoding="ISO-8859-1"?><doc/>');

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The declared encoding is not UTF-8 (I-5).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-5, section 6.1 step 5: an absent declaration reads as UTF-8, a lowercase utf-8 declaration passes.
     */
    #[Test]
    #[DataProvider('provideUtf8Declarations')]
    public function itAcceptsAUtf8DeclarationInAnyCaseOrNone(string $bytes): void
    {
        // Given
        $document = Foreign::parse($bytes);

        // When
        $inspected = $this->inspector->inspect($document);

        // Then
        static::assertSame('doc', $inspected->root()->localName);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUtf8Declarations(): iterable
    {
        yield 'no declaration' => ['<doc/>'];
        yield 'UTF-8' => ['<?xml version="1.0" encoding="UTF-8"?><doc/>'];
        yield 'utf-8, what Entra emits' => ['<?xml version="1.0" encoding="utf-8"?><doc/>'];
    }

    /**
     * Section 6.1: a document without a root element cannot be the brick's.
     */
    #[Test]
    public function itRefusesADocumentWithoutARootElement(): void
    {
        // Given
        $document = Foreign::parse('<doc/>');
        $root = $document->documentElement;
        static::assertNotNull($root);
        $document->removeChild($root);

        // Then
        $this->expectException(MalformedXml::class);
        $this->expectExceptionMessageIs('The document has no root element (I-3).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-6: the parser keeps a prefix it could not bind inside the local name of an element (section 13).
     */
    #[Test]
    public function itRefusesAnElementWhosePrefixIsUnbound(): void
    {
        // Given
        $document = Foreign::parse('<x:doc/>');

        // Then
        $this->expectException(NamespaceRefused::class);
        $this->expectExceptionMessageIs('A prefixed name has no namespace (I-6).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-6: the same for an attribute.
     */
    #[Test]
    public function itRefusesAnAttributeWhosePrefixIsUnbound(): void
    {
        // Given
        $document = Foreign::parse('<doc x:a="1"/>');

        // Then
        $this->expectException(NamespaceRefused::class);
        $this->expectExceptionMessageIs('A prefixed name has no namespace (I-6).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-6, section 6.1: an empty namespace is allowed for xmlns itself only; the parser drops xmlns:x="" with a
     * diagnostic, so the declaration is added to the tree here.
     */
    #[Test]
    public function itRefusesAPrefixBoundToAnEmptyNamespace(): void
    {
        // Given
        $document = Foreign::parse('<doc/>');
        $root = $document->documentElement;
        static::assertNotNull($root);
        $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:x', '');

        // Then
        $this->expectException(NamespaceRefused::class);
        $this->expectExceptionMessageIs('A namespace declaration is not an absolute URI (I-6).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * I-6: a namespace name is an absolute URI, a scheme followed by a colon (RFC 3986 §3.1).
     */
    #[Test]
    #[DataProvider('provideRelativeNamespaces')]
    public function itRefusesANamespaceThatIsNotAnAbsoluteUri(string $namespace): void
    {
        // Given
        $document = Foreign::parse(sprintf('<doc xmlns:x="%s"><x:a/></doc>', $namespace));

        // Then
        $this->expectException(NamespaceRefused::class);
        $this->expectExceptionMessageIs('A namespace declaration is not an absolute URI (I-6).');

        // When
        $this->inspector->inspect($document);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRelativeNamespaces(): iterable
    {
        yield 'a word' => ['relative'];
        yield 'a path' => ['/path/to/schema'];
        yield 'a scheme starting with a digit' => ['1urn:x'];
        yield 'a colon first' => [':x'];
        yield 'a space before the colon' => ['urn x:y'];
    }

    /**
     * I-6: the empty undeclaration of the default namespace is accepted; a scheme with digits, plus, dot and
     * hyphen is absolute.
     */
    #[Test]
    #[DataProvider('provideAcceptedNamespaces')]
    public function itAcceptsAnAbsoluteNamespaceOrTheEmptyDefault(string $bytes): void
    {
        // Given
        $document = Foreign::parse($bytes);

        // When
        $inspected = $this->inspector->inspect($document);

        // Then
        static::assertSame('doc', $inspected->root()->localName);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedNamespaces(): iterable
    {
        yield 'xmlns="" undeclares the default namespace' => ['<doc xmlns="urn:d"><a xmlns=""/></doc>'];
        yield 'urn' => ['<doc xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>'];
        yield 'http' => ['<doc xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'];
        yield 'a scheme with plus, dot, hyphen and digits' => ['<doc xmlns:x="a+b.c-1:rest"/>'];
    }

    /**
     * I-8, section 6.2: a registered attribute with a null element namespace applies to any element.
     */
    #[Test]
    public function itIndexesARegisteredAttributeOnAnyElementWhenNoNamespaceIsGiven(): void
    {
        // Given
        $inspector = new Inspector(new IdAttributes([new IdAttribute(new Name(null, 'id'))]), new Limits());
        $document = Foreign::parse('<doc xmlns="urn:a"><a id="one"/><b xmlns="urn:b" id="two"/></doc>');

        // When
        $inspected = $inspector->inspect($document);

        // Then
        static::assertSame('a', $inspected->elementById('one')->localName);
        static::assertSame('b', $inspected->elementById('two')->localName);
    }

    /**
     * Section 5.3: a namespaced ID attribute such as xml:id gets the same index once registered.
     */
    #[Test]
    public function itIndexesANamespacedAttributeOnceRegistered(): void
    {
        // Given
        $xmlId = new IdAttribute(new Name('http://www.w3.org/XML/1998/namespace', 'id'));
        $inspector = new Inspector(new IdAttributes([$xmlId]), new Limits());
        $document = Foreign::parse('<doc><a xml:id="one"/><b id="two"/></doc>');

        // When
        $inspected = $inspector->inspect($document);

        // Then
        static::assertTrue($inspected->hasId('one'));
        static::assertFalse($inspected->hasId('two'));
    }

    /**
     * Section 5.3: a registered attribute applies to the elements of its namespace only.
     */
    #[Test]
    public function itIgnoresARegisteredAttributeOnAnElementOfAnotherNamespace(): void
    {
        // Given
        $document = Foreign::parse('<doc xmlns="urn:other" ID="one"><a xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="two"/></doc>');

        // When
        $inspected = $this->inspector->inspect($document);

        // Then
        static::assertFalse($inspected->hasId('one'));
        static::assertTrue($inspected->hasId('two'));
    }

    /**
     * Section 6.1: the traversal is in document order, so the index maps a value to the element that carries it.
     */
    #[Test]
    public function itMapsEachIdToItsElementInDocumentOrder(): void
    {
        // Given
        $inspector = new Inspector(new IdAttributes([new IdAttribute(new Name(null, 'id'))]), new Limits());
        $document = Foreign::parse('<doc id="r"><a id="a"><b id="b"/></a><c id="c"/><!--c--><?pi?>text</doc>');

        // When
        $inspected = $inspector->inspect($document);

        // Then
        static::assertSame(['doc', 'a', 'b', 'c'], array_map(
            static fn (string $id): string => $inspected->elementById($id)->localName,
            ['r', 'a', 'b', 'c'],
        ));
    }

    /**
     * Section 5.3, §9.2 row 24: an ID attribute nobody registered is not an ID.
     */
    #[Test]
    public function itIndexesNothingWhenNothingIsRegistered(): void
    {
        // Given
        $inspector = new Inspector(IdAttributes::none(), new Limits());
        $document = Foreign::parse('<doc xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="one"/>');

        // When
        $inspected = $inspector->inspect($document);

        // Then
        static::assertFalse($inspected->hasId('one'));
    }
}
