<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use function basename;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Tests\Support\Fixtures;
use Beffroi\Xml\Core\Tests\Support\Foreign;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use Dom\XMLDocument;
use function filesize;
use function glob;
use function in_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function sort;
use function str_ends_with;
use function substr;

/**
 * Section 6.5, I-15: the whole document, formatOutput false, an XML declaration and UTF-8, whitespace kept, nothing
 * reformatted afterwards.
 */
final class SerializerTest extends TestCase
{
    private Serializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new Serializer();
    }

    /**
     * §9.3 row 16: the declaration on the first line, the root with its namespace declaration on the second, no
     * indentation.
     */
    #[Test]
    public function itSerializesACreatedDocumentWithTheDeclarationThenTheRoot(): void
    {
        // Given
        $document = new DocumentFactory()->create(
            new Name('urn:oasis:names:tc:SAML:2.0:protocol', 'AuthnRequest'),
            'samlp',
        );
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:Issuer',
        ))->appendChild($xml->createTextNode('https://sp.example.org'));

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.org</saml:Issuer>'
            . '</samlp:AuthnRequest>',
            $bytes,
        );
    }

    /**
     * §9.3 row 11, I-15: a loaded document with whitespace between elements, serialized, is the same bytes, the
     * declaration aside and the line feed after the root aside, which the parser never kept.
     */
    #[Test]
    public function itSerializesALoadedDocumentByteForByteDeclarationAside(): void
    {
        // Given
        $bytes = Fixtures::bytes('behaviour/response-with-assertion.xml');
        $document = Loaded::document($bytes);

        // When
        $serialized = $this->serializer->serialize($document);

        // Then
        static::assertSame("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" . substr($bytes, 0, -1), $serialized);
    }

    /**
     * I-15: formatOutput stays false, whatever a consumer set on the Dom\XMLDocument it can reach.
     */
    #[Test]
    public function itNeverPrettyPrints(): void
    {
        // Given
        $document = Loaded::document('<a><b/></a>');
        $xml = $document->root()->ownerDocument;
        static::assertInstanceOf(XMLDocument::class, $xml);
        $xml->formatOutput = true;

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a><b/></a>", $bytes);
    }

    /**
     * §9.2 row 26, I-4: a Document built by hand around a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesADocumentTheBrickDidNotProduce(): void
    {
        // Given
        $root = Foreign::parse('<a/>')->documentElement;
        static::assertNotNull($root);
        $document = new Document($root, []);

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The document is not one the brick produced (I-4).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * §9.3 row 17: every serialized document of the fixtures loads again through the Loader without refusal, and
     * canonicalizes to the same bytes as before serialization.
     */
    #[Test]
    #[DataProvider('provideLoadableFixtures')]
    public function itsOutputLoadsAgainAndCanonicalizesToTheSameBytes(string $fixture): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $document = Loaded::fixture($fixture);
        $before = $canonicalizer->canonicalize($document->root(), CanonicalizationMethod::InclusiveWithComments)->bytes;

        // When
        $reloaded = Loaded::document($this->serializer->serialize($document));

        // Then
        static::assertSame(
            $before,
            $canonicalizer->canonicalize($reloaded->root(), CanonicalizationMethod::InclusiveWithComments)->bytes,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLoadableFixtures(): iterable
    {
        $paths = [];
        foreach (['canonical', 'behaviour', 'real', 'hostile'] as $directory) {
            $found = glob(__DIR__ . '/../Fixture/' . $directory . '/*.xml');
            if ($found === false) {
                throw new RuntimeException('The fixtures cannot be listed.');
            }
            foreach ($found as $path) {
                $name = basename($path);
                if ($directory === 'hostile' && ! str_ends_with($name, '-loads.xml')) {
                    continue;
                }
                // the one fixture that does not round-trip: a carriage return in a text node (section 6.5)
                if ($name === 'c14n-3.4-derived-character-references.xml') {
                    continue;
                }
                // 512 declarations over 10 000 elements: seconds of inclusive canonicalization (section 13),
                // round-tripped exclusively in its own test
                if ($name === 'at-the-six-default-bounds-loads.xml') {
                    continue;
                }
                // the other fixtures that do not round-trip, each pinned in its own test (section 6.5): a prefix
                // bound to the in-scope default namespace, which the namespace fix-up of saveXml() drops; adjacent
                // CDATA sections that saveXml() merges into one holding "]]>"; an ampersand in a namespace name that
                // saveXml() escapes twice
                if (in_array(
                    $name,
                    [
                        'entra-common-federation-metadata-2026-09-23.xml',
                        'adversarial-cdata-nested-marker-loads.xml',
                        'adversarial-xmlns-attribute-value-with-entity-amp-loads.xml',
                    ],
                    true,
                )) {
                    continue;
                }
                // at the byte bound: the declaration the serializer adds pushes them over maxBytes on the way back
                if (filesize($path) > (1_048_576 - 40)) {
                    continue;
                }
                $paths[] = $directory . '/' . $name;
            }
        }
        sort($paths);
        foreach ($paths as $path) {
            yield $path => [$path];
        }
    }

    /**
     * §9.3 row 17, section 7: the document at the six default bounds round-trips too, exclusively, since its
     * inclusive canonical form costs seconds with 512 declarations in scope over 10 000 elements (section 13).
     */
    #[Test]
    public function itsOutputOfTheDocumentAtTheSixBoundsLoadsAgainAndCanonicalizesToTheSameBytes(): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $document = Loaded::fixture('behaviour/at-the-six-default-bounds-loads.xml');
        $before = $canonicalizer->canonicalize($document->root(), CanonicalizationMethod::Exclusive)->bytes;

        // When
        $reloaded = Loaded::document($this->serializer->serialize($document));

        // Then
        static::assertSame(
            $before,
            $canonicalizer->canonicalize($reloaded->root(), CanonicalizationMethod::Exclusive)->bytes,
        );
    }

    /**
     * Section 6.5, I-15, measured: saveXml() applies the namespace fix-up of the DOM Parsing and Serialization
     * specification and writes an element whose prefix is bound to the URI of the in-scope default namespace
     * without its prefix, which changes its canonical form. Entra's federation metadata carries the shape.
     */
    #[Test]
    public function itDropsAPrefixBoundToTheInScopeDefaultNamespace(): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $document = Loaded::document('<a xmlns="urn:x"><p:b xmlns:p="urn:x"><p:c/></p:b></a>');
        static::assertSame(
            '<a xmlns="urn:x"><p:b xmlns:p="urn:x"><p:c></p:c></p:b></a>',
            $canonicalizer->canonicalize($document->root(), CanonicalizationMethod::Exclusive)->bytes,
        );

        // When
        $serialized = $this->serializer->serialize($document);

        // Then
        static::assertSame(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a xmlns=\"urn:x\"><b xmlns:p=\"urn:x\"><c/></b></a>",
            $serialized,
        );
        $reloaded = Loaded::document($serialized);
        static::assertSame(
            '<a xmlns="urn:x"><b><c></c></b></a>',
            $canonicalizer->canonicalize(
                $reloaded->root(),
                CanonicalizationMethod::Exclusive,
            )->bytes,
        );
    }

    /**
     * Section 6.5, section 13, measured: saveXml() merges adjacent CDATA sections into one, and the junction of
     * "a]]" and ">b" is a CDATA section holding "]]>", which no parser accepts; the canonical form, which folds the
     * sections, is right. A consumer builds no adjacent CDATA sections.
     */
    #[Test]
    public function itCannotRoundTripAdjacentCdataSectionsWhoseJunctionIsACdataEndMarker(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/adversarial-cdata-nested-marker-loads.xml');
        static::assertSame(
            '<doc>a]]&gt;b</doc>',
            new Canonicalizer()->canonicalize($document->root(), CanonicalizationMethod::Inclusive)->bytes,
        );

        // When
        $serialized = $this->serializer->serialize($document);

        // Then
        static::assertSame("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<doc><![CDATA[a]]>b]]></doc>", $serialized);
        $this->expectException(MalformedXml::class);
        Loaded::document($serialized);
    }

    /**
     * Section 6.5, section 13, measured: saveXml() escapes an ampersand of a namespace name twice, so the name
     * changes on the way back and libxml reports it; the canonical form writes it once. A namespace name holds no
     * ampersand in the stack.
     */
    #[Test]
    public function itCannotRoundTripAnAmpersandInANamespaceName(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/adversarial-xmlns-attribute-value-with-entity-amp-loads.xml');
        static::assertSame(
            '<doc xmlns:x="urn:x?a=1&#38;b=2"><x:e></x:e></doc>',
            new Canonicalizer()->canonicalize($document->root(), CanonicalizationMethod::Inclusive)->bytes,
        );

        // When
        $serialized = $this->serializer->serialize($document);

        // Then
        static::assertSame(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<doc xmlns:x=\"urn:x?a=1&amp;#38;b=2\"><x:e/></doc>",
            $serialized,
        );
        $this->expectException(ParserDiagnostic::class);
        Loaded::document($serialized);
    }

    /**
     * Section 6.5, measured: a carriage return in a text node does not survive a round trip. saveXml() writes the
     * byte as it is, and the parser normalises it to a line feed (XML 1.0 §2.11), so the canonical form of what
     * was serialized is not the canonical form of what was loaded. The vector of Canonical XML 1.0 §3.4 carries one.
     */
    #[Test]
    public function itCannotRoundTripACarriageReturnInATextNode(): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $document = Loaded::fixture('canonical/c14n-3.4-derived-character-references.xml');
        static::assertStringContainsString(
            "First line&#xD;\nSecond line",
            $canonicalizer->canonicalize($document->root(), CanonicalizationMethod::Inclusive)->bytes,
        );

        // When
        $reloaded = Loaded::document($this->serializer->serialize($document));

        // Then
        static::assertStringContainsString(
            "First line\nSecond line",
            $canonicalizer->canonicalize($reloaded->root(), CanonicalizationMethod::Inclusive)->bytes,
        );
    }
}
