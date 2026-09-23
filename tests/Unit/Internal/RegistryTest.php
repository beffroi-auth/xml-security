<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Internal;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Internal\Registry;
use Beffroi\Xml\Core\Tests\Support\Foreign;
use Dom\XMLDocument;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 7: the weak maps that make Document::owning() recognise every node of a document the brick
 * produced (I-4), give Serializer its Dom\XMLDocument, and forget a document the caller drops.
 */
final class RegistryTest extends TestCase
{
    #[Test]
    public function itRecognisesARegisteredDocument(): void
    {
        // Given
        $xml = Foreign::parse('<a/>');
        $root = $xml->documentElement;
        static::assertNotNull($root);
        $document = new Document($root, []);

        // When
        $registered = Registry::register($xml, $document);

        // Then
        static::assertSame($document, $registered);
        static::assertSame($document, Registry::owning($xml));
        static::assertSame($xml, Registry::xmlOf($document));
    }

    #[Test]
    public function itDoesNotRecogniseADocumentNobodyRegistered(): void
    {
        // Given
        $xml = Foreign::parse('<a/>');

        // When / Then
        static::assertNull(Registry::owning($xml));
    }

    /**
     * I-4: a Document built by hand around a parsed root has no Dom\XMLDocument for the brick.
     */
    #[Test]
    public function itRefusesToGiveTheXmlOfADocumentBuiltByHand(): void
    {
        // Given
        $root = Foreign::parse('<a/>')->documentElement;
        static::assertNotNull($root);
        $document = new Document($root, []);

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The document is not one the brick produced (I-4).');

        // When
        Registry::xmlOf($document);
    }

    /**
     * Section 6.1 step 7: the entry keeps the Dom\XMLDocument object alive as long as the Document is held, so
     * that ownerDocument yields the very object the entry is keyed by; a node object alone does not keep it.
     */
    #[Test]
    public function itKeepsTheXmlDocumentAliveWhileTheDocumentIsHeld(): void
    {
        // Given
        $xml = Foreign::parse('<a><b/></a>');
        $root = $xml->documentElement;
        static::assertNotNull($root);
        $document = Registry::register($xml, new Document($root, []));
        $child = $root->firstElementChild;
        static::assertNotNull($child);

        // When
        unset($xml, $root);

        // Then
        $owner = $child->ownerDocument;
        static::assertInstanceOf(XMLDocument::class, $owner);
        static::assertSame($document, Registry::owning($owner));
    }

    /**
     * §9.3 row 15: a Document dropped by the caller, the WeakMap entry is gone, whatever nodes are still held.
     */
    #[Test]
    public function itForgetsADocumentTheCallerDrops(): void
    {
        // Given
        $before = Registry::count();
        $xml = Foreign::parse('<a/>');
        $root = $xml->documentElement;
        static::assertNotNull($root);
        $document = Registry::register($xml, new Document($root, []));
        static::assertSame($before + 1, Registry::count());

        // When
        unset($document, $xml);

        // Then
        static::assertSame($before, Registry::count());
        static::assertSame('a', $root->localName);
    }
}
