<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\UnknownId;
use Beffroi\Xml\Core\Tests\Support\Foreign;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use Dom\HTMLDocument;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.2 and 6.2: the root, the ID index built at load, and the recognition of the brick's own nodes (I-4, I-9).
 */
final class DocumentTest extends TestCase
{
    #[Test]
    public function itGivesItsRoot(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');

        // When
        $root = $document->root();

        // Then
        static::assertSame('Response', $root->localName);
        static::assertSame('urn:oasis:names:tc:SAML:2.0:protocol', $root->namespaceURI);
    }

    /**
     * I-9, section 6.2: the index built at load, compared exactly.
     */
    #[Test]
    public function itFindsAnElementByItsId(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');

        // When
        $assertion = $document->elementById('_assertion');

        // Then
        static::assertSame('Assertion', $assertion->localName);
        static::assertSame('_assertion', $assertion->getAttributeNS(null, 'ID'));
    }

    /**
     * Section 6.2: an absent value throws UnknownId, and the message carries no input (I-16).
     */
    #[Test]
    public function itRefusesAnUnknownId(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');

        // Then
        $this->expectException(UnknownId::class);
        $this->expectExceptionMessageIs('No element carries that ID (section 6.2).');

        // When
        $document->elementById('_nobody');
    }

    /**
     * Section 6.2: the comparison is exact, never a prefix, never a case fold.
     */
    #[Test]
    public function itComparesAnIdExactly(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');

        // When / Then
        static::assertTrue($document->hasId('_assertion'));
        static::assertFalse($document->hasId('_ASSERTION'));
        static::assertFalse($document->hasId('_assertio'));
        static::assertFalse($document->hasId(''));
    }

    /**
     * §9.3 row 14: owning() on a node of a loaded document.
     */
    #[Test]
    public function itIsTheOwnerOfEveryNodeOfALoadedDocument(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');
        $assertion = $document->elementById('_assertion');
        $attribute = $assertion->getAttributeNodeNS(null, 'ID');
        static::assertNotNull($attribute);
        $text = $assertion->firstChild;
        static::assertNotNull($text);

        // When / Then
        static::assertSame($document, Document::owning($document->root()));
        static::assertSame($document, Document::owning($assertion));
        static::assertSame($document, Document::owning($attribute));
        static::assertSame($document, Document::owning($text));
    }

    /**
     * §9.3 row 14, section 6.6: owning() on the root of a re-loaded canonical form is the new Document, not the
     * document the form was rendered from.
     */
    #[Test]
    public function itIsTheOwnerOfTheRootOfAReloadedCanonicalForm(): void
    {
        // Given
        $original = Loaded::fixture('behaviour/response-with-assertion.xml');
        $canonical = new Canonicalizer()->canonicalize(
            $original->elementById('_assertion'),
            CanonicalizationMethod::Exclusive,
        );

        // When
        $reloaded = Loaded::document($canonical->bytes);

        // Then
        static::assertSame($reloaded, Document::owning($reloaded->root()));
        static::assertNotSame($original, Document::owning($reloaded->root()));
        static::assertSame('Assertion', $reloaded->root()->localName);
    }

    /**
     * I-4: the document node itself is recognised too.
     */
    #[Test]
    public function itIsTheOwnerOfItsOwnDocumentNode(): void
    {
        // Given
        $document = Loaded::document('<a/>');
        $xml = $document->root()->ownerDocument;
        static::assertNotNull($xml);

        // When / Then
        static::assertSame($document, Document::owning($xml));
    }

    /**
     * §9.2 row 26, I-4: a document from a direct createFromString() call that bypassed the Loader.
     */
    #[Test]
    public function itRefusesANodeOfADocumentParsedOutsideTheLoader(): void
    {
        // Given
        $foreign = Foreign::parse('<a/>');
        $root = $foreign->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The node belongs to a document the brick did not produce (I-4).');

        // When
        Document::owning($root);
    }

    /**
     * I-4: a node that belongs to no XML document at all, an HTML document here.
     */
    #[Test]
    public function itRefusesANodeOfAnHtmlDocument(): void
    {
        // Given
        $html = HTMLDocument::createFromString('<!DOCTYPE html><title>t</title>');

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The node belongs to a document the brick did not produce (I-4).');

        // When
        Document::owning($html);
    }

    /**
     * I-4: a Document built by hand around a foreign root is not the brick's; the registry is the truth.
     */
    #[Test]
    public function itRefusesTheRootOfADocumentBuiltByHand(): void
    {
        // Given
        $root = Foreign::parse('<a/>')->documentElement;
        static::assertNotNull($root);
        $byHand = new Document($root, []);
        static::assertSame($root, $byHand->root());

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The node belongs to a document the brick did not produce (I-4).');

        // When
        Document::owning($root);
    }
}
