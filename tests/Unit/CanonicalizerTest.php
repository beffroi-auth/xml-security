<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use function array_pop;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\CanonicalizationFailed;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Tests\Support\Fixtures;
use Beffroi\Xml\Core\Tests\Support\Foreign;
use Beffroi\Xml\Core\Tests\Support\Libxml;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use Beffroi\Xml\Core\Tests\Support\Nodes;
use Dom\Element;
use InvalidArgumentException;
use function libxml_use_internal_errors;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.3 and the vectors of section 9.1: the mapping of methods to flags, the subtree exclusion, the prefix
 * list handling and the guards, on outputs the recommendations fix. Every test byte-compares the serialized document
 * before and after the call (I-14).
 */
final class CanonicalizerTest extends TestCase
{
    private Canonicalizer $canonicalizer;

    private Serializer $serializer;

    protected function setUp(): void
    {
        $this->canonicalizer = new Canonicalizer();
        $this->serializer = new Serializer();
    }

    /**
     * Section 9.1: the vectors of Canonical XML 1.0 §3 and Exclusive XML Canonicalization §2, the four measured
     * cases of section 13 and the text rows of section 9.3 (rows 1 and 2), byte for byte.
     *
     * @param list<string> $prefixes
     */
    #[Test]
    #[DataProvider('provideVectors')]
    public function itRendersAVectorByteForByte(
        string $fixture,
        ?string $apexName,
        CanonicalizationMethod $method,
        array $prefixes,
        string $expected,
    ): void {
        // Given
        $document = Loaded::fixture($fixture);
        $apex = $apexName === null ? $document->root() : Nodes::childNamed($document->root(), $apexName);
        $before = $this->serializer->serialize($document);

        // When
        $canonical = $this->canonicalizer->canonicalize($apex, $method, new InclusiveNamespaces($prefixes));

        // Then
        static::assertSame(Fixtures::bytes($expected), $canonical->bytes);
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * @return iterable<string, array{string, ?string, CanonicalizationMethod, list<string>, string}>
     */
    public static function provideVectors(): iterable
    {
        $inclusive = CanonicalizationMethod::Inclusive;
        $inclusiveWithComments = CanonicalizationMethod::InclusiveWithComments;
        $exclusive = CanonicalizationMethod::Exclusive;
        $c = 'canonical/';
        $b = 'behaviour/';

        yield 'C14N §3.1 A, outside nodes, inclusive' => [
            $c . 'c14n-3.1-derived-a-outside-nodes.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.1-derived-a-outside-nodes.inclusive.c14n',
        ];
        yield 'C14N §3.1 A, outside nodes, with comments' => [
            $c . 'c14n-3.1-derived-a-outside-nodes.xml',
            null,
            $inclusiveWithComments,
            [],
            $c . 'c14n-3.1-derived-a-outside-nodes.inclusive-with-comments.c14n',
        ];
        yield 'C14N §3.1 B, nodes inside doc, inclusive' => [
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.inclusive.c14n',
        ];
        yield 'C14N §3.1 B, nodes inside doc, with comments' => [
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.xml',
            null,
            $inclusiveWithComments,
            [],
            $c . 'c14n-3.1-derived-b-nodes-inside-doc.inclusive-with-comments.c14n',
        ];
        yield 'C14N §3.2 whitespace in document content' => [
            $c . 'c14n-3.2-whitespace-in-content.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.2-whitespace-in-content.inclusive.c14n',
        ];
        yield 'C14N §3.3 start and end tags' => [
            $c . 'c14n-3.3-derived-start-and-end-tags.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.3-derived-start-and-end-tags.inclusive.c14n',
        ];
        yield 'C14N §3.4 character modifications and character references' => [
            $c . 'c14n-3.4-derived-character-references.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.4-derived-character-references.inclusive.c14n',
        ];
        yield 'C14N §3.6 UTF-8 encoding' => [
            $c . 'c14n-3.6-derived-utf-8.xml',
            null,
            $inclusive,
            [],
            $c . 'c14n-3.6-derived-utf-8.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.1, elem1 in pdu, inclusive' => [
            $c . 'exc-c14n-2.1-elem1-in-pdu.xml',
            'elem1',
            $inclusive,
            [],
            $c . 'exc-c14n-2.1-elem1-in-pdu.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.1, elem1 in pdu, exclusive' => [
            $c . 'exc-c14n-2.1-elem1-in-pdu.xml',
            'elem1',
            $exclusive,
            [],
            $c . 'exc-c14n-2.1-elem1-in-pdu.exclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 in local, inclusive' => [
            $c . 'exc-c14n-2.2-elem2-in-local.xml',
            'elem2',
            $inclusive,
            [],
            $c . 'exc-c14n-2.2-elem2-in-local.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 in local, exclusive' => [
            $c . 'exc-c14n-2.2-elem2-in-local.xml',
            'elem2',
            $exclusive,
            [],
            $c . 'exc-c14n-2.2-elem2-in-local.exclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 re-enveloped, inclusive' => [
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.xml',
            'elem2',
            $inclusive,
            [],
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.inclusive.c14n',
        ];
        yield 'Exclusive C14N §2.2, elem2 re-enveloped, exclusive' => [
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.xml',
            'elem2',
            $exclusive,
            [],
            $c . 'exc-c14n-2.2-derived-elem2-re-enveloped.exclusive.c14n',
        ];
        yield 'measured, inclusive renders everything in scope and the inherited xml:lang' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $inclusive,
            [],
            $c . 'measured-apex-under-ancestors.inclusive.c14n',
        ];
        yield 'measured, exclusive renders the visibly utilised namespaces only' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            [],
            $c . 'measured-apex-under-ancestors.exclusive.c14n',
        ];
        yield 'measured, exclusive with PrefixList="unused"' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            ['unused'],
            $c . 'measured-apex-under-ancestors.exclusive-prefixlist-unused.c14n',
        ];
        yield 'measured, exclusive with PrefixList="#default"' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            ['#default'],
            $c . 'measured-apex-under-ancestors.exclusive-prefixlist-default.c14n',
        ];
        yield 'measured, exclusive with an unknown prefix changes nothing' => [
            $c . 'measured-apex-under-ancestors.xml',
            'a',
            $exclusive,
            ['nope'],
            $c . 'measured-apex-under-ancestors.exclusive.c14n',
        ];
        yield '§9.3 row 1, comment-split NameID without comments' => [
            $b . 'nameid-comment-split.xml',
            null,
            $inclusive,
            [],
            $b . 'nameid-comment-split.inclusive.c14n',
        ];
        yield '§9.3 row 1, comment-split NameID with comments' => [
            $b . 'nameid-comment-split.xml',
            null,
            $inclusiveWithComments,
            [],
            $b . 'nameid-comment-split.inclusive-with-comments.c14n',
        ];
        yield '§9.3 row 2, CDATA folded' => [
            $b . 'cdata-in-text.xml',
            null,
            $inclusive,
            [],
            $b . 'cdata-in-text.inclusive.c14n',
        ];
    }

    /**
     * §9.3 row 12, I-14: the enveloped exclusion of ds:Signature gives the bytes of the XPath node-set form the
     * fixture carries, computed outside the repository; the excluded element in the middle, first, last, and two
     * of them; the document unchanged afterwards.
     */
    #[Test]
    #[DataProvider('provideEnvelopedCases')]
    public function itExcludesASubtreeAsTheXpathNodeSetWould(
        string $fixture,
        CanonicalizationMethod $method,
        string $expected,
    ): void {
        // Given
        $document = Loaded::fixture($fixture);
        $before = $this->serializer->serialize($document);
        $signatures = $this->signaturesOf($document);

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $document->root(),
            $method,
            InclusiveNamespaces::none(),
            $signatures,
        );

        // Then
        static::assertSame(Fixtures::bytes($expected), $canonical->bytes);
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * @return iterable<string, array{string, CanonicalizationMethod, string}>
     */
    public static function provideEnvelopedCases(): iterable
    {
        foreach ([
            'enveloped-signature-under-root',
            'enveloped-signature-first-child',
            'enveloped-signature-last-child',
            'enveloped-two-signatures',
        ] as $case) {
            yield $case . ', inclusive' => [
                'behaviour/' . $case . '.xml',
                CanonicalizationMethod::Inclusive,
                'behaviour/' . $case . '.inclusive.c14n',
            ];
            yield $case . ', exclusive' => [
                'behaviour/' . $case . '.xml',
                CanonicalizationMethod::Exclusive,
                'behaviour/' . $case . '.exclusive.c14n',
            ];
        }
    }

    /**
     * Section 6.3 step 3: the excluded elements are reinserted at their position whatever the order they were
     * listed in, two adjacent siblings included.
     */
    #[Test]
    public function itReinsertsAdjacentExclusionsWhateverTheirOrder(): void
    {
        // Given
        $document = Loaded::document('<r><a/><b/><c/></r>');
        $root = $document->root();
        $before = $this->serializer->serialize($document);

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [Nodes::childNamed($root, 'b'), Nodes::childNamed($root, 'a')],
        );

        // Then
        static::assertSame('<r><c></c></r>', $canonical->bytes);
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * Section 6.3 step 2: a nested exclusion, the inner one listed first, is detached and put back inside its
     * parent, itself detached and put back.
     */
    #[Test]
    public function itReinsertsANestedExclusion(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a><c/></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');
        $before = $this->serializer->serialize($document);

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [Nodes::childNamed($a, 'b'), $a],
        );

        // Then
        static::assertSame('<r><c></c></r>', $canonical->bytes);
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * §9.3 row 13, I-14: a failing canonicalization with exclusions leaves the excluded elements back in place.
     */
    #[Test]
    public function itPutsTheExclusionsBackWhenTheCanonicalizationFails(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/enveloped-signature-under-root.xml');
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('relative', 'x:b'));
        $before = $this->serializer->serialize($document);

        // When
        try {
            $this->canonicalizer->canonicalize(
                $root,
                CanonicalizationMethod::Exclusive,
                InclusiveNamespaces::none(),
                $this->signaturesOf($document),
            );
        } catch (CanonicalizationFailed) {
        }

        // Then
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * §9.2 row 28, I-13: a relative namespace on a document of the brick makes libxml return false; the refusal
     * carries libxml's error code and never its message, which quotes the URI (I-16).
     */
    #[Test]
    public function itRefusesARelativeNamespaceLibxmlCannotCanonicalize(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('relative', 'x:b'));

        // Then
        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessageIs('libxml could not canonicalize the apex: error 1955 (I-13).');

        // When
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);
    }

    /**
     * §9.2 row 25, I-4: a document from a direct createFromString() call that bypassed the Loader.
     */
    #[Test]
    public function itRefusesAForeignApex(): void
    {
        // Given
        $root = Foreign::parse('<a/>')->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The node belongs to a document the brick did not produce (I-4).');

        // When
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);
    }

    /**
     * §9.2 row 26, section 6.3 step 1: an apex removed from its parent is a programming error.
     */
    #[Test]
    public function itRefusesAnApexThatIsNotConnected(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');
        $root->removeChild($a);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The apex is not connected to its document (section 6.3).');

        // When
        $this->canonicalizer->canonicalize(
            $a,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [Nodes::childNamed($a, 'b')],
        );
    }

    /**
     * §9.2 row 26: the check runs before any exclusion is detached.
     */
    #[Test]
    public function itDetachesNothingWhenTheApexIsNotConnected(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');
        $b = Nodes::childNamed($a, 'b');
        $root->removeChild($a);

        // When
        try {
            $this->canonicalizer->canonicalize(
                $a,
                CanonicalizationMethod::Inclusive,
                InclusiveNamespaces::none(),
                [$b],
            );
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame($a, $b->parentNode);
    }

    /**
     * §9.2 row 27, section 6.3 step 2: an excluded element that is not a strict descendant of the apex.
     */
    #[Test]
    #[DataProvider('provideNonDescendants')]
    public function itRefusesAnExclusionThatIsNotAStrictDescendant(string $which): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a><c/></r>');
        $other = Loaded::document('<o/>');
        $apex = Nodes::childNamed($document->root(), 'a');
        $excluded = match ($which) {
            'the apex itself' => $apex,
            'a sibling of the apex' => Nodes::childNamed($document->root(), 'c'),
            'the parent of the apex' => $document->root(),
            default => $other->root(),
        };

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An excluded element is not a strict descendant of the apex (section 6.3).');

        // When
        $this->canonicalizer->canonicalize(
            $apex,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [$excluded],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNonDescendants(): iterable
    {
        foreach ([
            'the apex itself',
            'a sibling of the apex',
            'the parent of the apex',
            'the root of another document',
        ] as $which) {
            yield $which => [$which];
        }
    }

    /**
     * §9.2 row 27, I-14: the document is unchanged after the refusal, since nothing was detached.
     */
    #[Test]
    public function itLeavesTheDocumentUnchangedAfterRefusingAnExclusion(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a><c/></r>');
        $root = $document->root();
        $before = $this->serializer->serialize($document);

        // When
        try {
            $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive, InclusiveNamespaces::none(), [
                Nodes::childNamed($root, 'c'),
                $root,
            ]);
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertSame($before, $this->serializer->serialize($document));
    }

    /**
     * Section 6.3 step 2: an element listed twice would be detached twice; refused before anything is detached.
     */
    #[Test]
    public function itRefusesAnElementExcludedTwice(): void
    {
        // Given
        $document = Loaded::document('<r><a/></r>');
        $root = $document->root();
        $a = Nodes::childNamed($root, 'a');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An element is excluded twice (section 6.3).');

        // When
        $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::Inclusive,
            InclusiveNamespaces::none(),
            [$a, $a],
        );
    }

    /**
     * §9.2 row 30, section 6.3: inclusive canonicalization renders every in-scope namespace already.
     */
    #[Test]
    #[DataProvider('provideInclusiveMethods')]
    public function itRefusesInclusiveNamespacesWithAnInclusiveMethod(CanonicalizationMethod $method): void
    {
        // Given
        $document = Loaded::document('<r xmlns:x="urn:x"/>');
        $root = $document->root();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Inclusive namespaces apply to exclusive canonicalization only (section 6.3).');

        // When
        $this->canonicalizer->canonicalize($root, $method, new InclusiveNamespaces(['x']));
    }

    /**
     * @return iterable<string, array{CanonicalizationMethod}>
     */
    public static function provideInclusiveMethods(): iterable
    {
        yield 'inclusive' => [CanonicalizationMethod::Inclusive];
        yield 'inclusive with comments' => [CanonicalizationMethod::InclusiveWithComments];
    }

    /**
     * Section 6.3 step 3: an empty prefix list with an exclusive method renders the visibly utilised namespaces.
     */
    #[Test]
    public function itAcceptsAnEmptyPrefixListWithAnExclusiveMethod(): void
    {
        // Given
        $document = Loaded::document('<r xmlns:x="urn:x"><x:a/></r>');
        $root = $document->root();

        // When
        $canonical = $this->canonicalizer->canonicalize(
            $root,
            CanonicalizationMethod::ExclusiveWithComments,
            InclusiveNamespaces::none(),
        );

        // Then
        static::assertSame('<r><x:a xmlns:x="urn:x"></x:a></r>', $canonical->bytes);
    }

    /**
     * Section 6.3 step 4: libxml's internal-errors mode is restored after a canonicalization, on the success path.
     */
    #[Test]
    public function itRestoresAnInternalErrorsModeOfFalseAfterACanonicalization(): void
    {
        // Given
        $document = Loaded::document('<r/>');
        $root = $document->root();
        libxml_use_internal_errors(false);

        // When
        $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);

        // Then
        static::assertFalse(Libxml::mode());
    }

    /**
     * Section 6.3 step 4: the mode is restored and the buffer emptied after a refusal, the diagnostic of libxml
     * not left behind.
     */
    #[Test]
    public function itEmptiesTheBufferAndRestoresTheModeAfterARefusal(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('relative', 'x:b'));
        Libxml::fillBuffer();

        // When
        try {
            $this->canonicalizer->canonicalize($root, CanonicalizationMethod::Inclusive);
        } catch (CanonicalizationFailed) {
        }

        // Then
        static::assertSame([], Libxml::buffer());
        static::assertTrue(Libxml::mode());
    }

    /**
     * Section 6.6: the canonical bytes load again through the Loader, with every namespace declaration and every
     * inherited xml attribute the form rendered; the re-parsed root is what a consumer receives.
     */
    #[Test]
    public function itsCanonicalFormLoadsAgainAsOneRootWithItsInheritedContext(): void
    {
        // Given
        $document = Loaded::fixture('canonical/measured-apex-under-ancestors.xml');
        $apex = Nodes::childNamed($document->root(), 'a');

        // When
        $reloaded = Loaded::document($this->canonicalizer->canonicalize(
            $apex,
            CanonicalizationMethod::Inclusive,
        )->bytes);

        // Then
        static::assertSame('a', $reloaded->root()->localName);
        static::assertSame('urn:s', $reloaded->root()->namespaceURI);
        static::assertSame('fr', $reloaded->root()->getAttributeNS('http://www.w3.org/XML/1998/namespace', 'lang'));
        static::assertSame('1', $reloaded->root()->getAttributeNS('urn:x', 'attr'));
        static::assertNull($reloaded->root()->parentElement);
    }

    /**
     * Every ds:Signature element of the document, by direct navigation, in document order.
     *
     * @return list<Element>
     */
    private function signaturesOf(Document $document): array
    {
        $signatures = [];
        $stack = [$document->root()];
        while ($stack !== []) {
            $element = array_pop($stack);
            if (
                $element->namespaceURI === 'http://www.w3.org/2000/09/xmldsig#'
                && $element->localName === 'Signature'
            ) {
                $signatures[] = $element;
                continue;
            }
            for ($child = $element->lastElementChild; $child !== null; $child = $child->previousElementSibling) {
                $stack[] = $child;
            }
        }

        return $signatures;
    }
}
