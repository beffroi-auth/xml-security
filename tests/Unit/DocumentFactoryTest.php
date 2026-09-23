<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Name;
use Dom\XMLDocument;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.5: a new XML 1.0, UTF-8 document whose root is created with createElementNS(), registered so that the
 * brick recognises what a consumer builds under it.
 */
final class DocumentFactoryTest extends TestCase
{
    private DocumentFactory $factory;

    protected function setUp(): void
    {
        $this->factory = new DocumentFactory();
    }

    #[Test]
    public function itCreatesADocumentWhoseRootCarriesTheNameAndThePrefix(): void
    {
        // When
        $document = $this->factory->create(new Name('urn:oasis:names:tc:SAML:2.0:protocol', 'AuthnRequest'), 'samlp');

        // Then
        $root = $document->root();
        static::assertSame('AuthnRequest', $root->localName);
        static::assertSame('urn:oasis:names:tc:SAML:2.0:protocol', $root->namespaceURI);
        static::assertSame('samlp', $root->prefix);
        static::assertSame('samlp:AuthnRequest', $root->tagName);
    }

    #[Test]
    public function itCreatesARootWithoutAPrefixByDefault(): void
    {
        // When
        $root = $this->factory->create(new Name('urn:a', 'a'))->root();

        // Then
        static::assertNull($root->prefix);
        static::assertSame('urn:a', $root->namespaceURI);
    }

    #[Test]
    public function itCreatesARootInNoNamespace(): void
    {
        // When
        $root = $this->factory->create(new Name(null, 'a'))->root();

        // Then
        static::assertNull($root->namespaceURI);
        static::assertSame('a', $root->tagName);
    }

    /**
     * Section 6.5: XML 1.0, UTF-8, formatOutput false.
     */
    #[Test]
    public function itCreatesAnXml10Utf8Document(): void
    {
        // When
        $xml = $this->factory->create(new Name('urn:a', 'a'))->root()->ownerDocument;

        // Then
        static::assertInstanceOf(XMLDocument::class, $xml);
        static::assertSame('1.0', $xml->xmlVersion);
        static::assertSame('UTF-8', $xml->xmlEncoding);
    }

    /**
     * Section 6.2: a created document has an empty index; what a consumer builds, it holds by reference.
     */
    #[Test]
    public function itCreatesADocumentWithAnEmptyIndex(): void
    {
        // When
        $document = $this->factory->create(new Name('urn:a', 'a'));

        // Then
        static::assertFalse($document->hasId('_x'));
    }

    /**
     * §9.3 row 14, I-4: owning() on a node of a created document, and on what a consumer builds under its root.
     */
    #[Test]
    public function itsDocumentOwnsWhatAConsumerBuildsUnderTheRoot(): void
    {
        // Given
        $document = $this->factory->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);

        // When
        $child = $root->appendChild($xml->createElementNS('urn:a', 'b'));

        // Then
        static::assertSame($document, Document::owning($root));
        static::assertSame($document, Document::owning($child));
    }

    /**
     * Section 6.5: each call is a new document, recognised on its own.
     */
    #[Test]
    public function itCreatesADistinctDocumentEachTime(): void
    {
        // When
        $first = $this->factory->create(new Name('urn:a', 'a'));
        $second = $this->factory->create(new Name('urn:a', 'a'));

        // Then
        static::assertNotSame($first, $second);
        static::assertSame($first, Document::owning($first->root()));
        static::assertSame($second, Document::owning($second->root()));
    }
}
