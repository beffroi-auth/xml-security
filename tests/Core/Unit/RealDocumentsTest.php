<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use function array_pop;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Dom\Comment;
use Dom\Element;
use Dom\Node;
use Dom\ProcessingInstruction;
use Dom\XMLDocument;
use function max;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_starts_with;
use function strlen;

/**
 * Section 9.4: the real documents under tests/Core/Fixture/real/, each loading without refusal with the SAML stack's
 * IdAttributes and the default Limits, its IDs indexed, its exclusive canonical form stable across two runs. A
 * real document the loader refuses is a finding.
 */
final class RealDocumentsTest extends TestCase
{
    private const string ENTRA = 'real/entra-common-federation-metadata-2026-09-23.xml';

    /**
     * Section 9.4: every real document loads.
     */
    #[Test]
    #[DataProvider('provideRealDocuments')]
    public function itLoadsWithTheStacksIdAttributesAndTheDefaultLimits(string $fixture): void
    {
        // When
        $document = Loaded::fixture($fixture);

        // Then
        static::assertSame($document, Document::owning($document->root()));
    }

    /**
     * Section 9.4: the exclusive canonical form is the same bytes on two runs, two loads apart.
     */
    #[Test]
    #[DataProvider('provideRealDocuments')]
    public function itsExclusiveCanonicalFormIsStableAcrossTwoRuns(string $fixture): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $firstRun = Loaded::fixture($fixture);
        $secondRun = Loaded::fixture($fixture);

        // When
        $first = $canonicalizer->canonicalize($firstRun->root(), CanonicalizationMethod::Exclusive)->bytes;
        $second = $canonicalizer->canonicalize($secondRun->root(), CanonicalizationMethod::Exclusive)->bytes;

        // Then
        static::assertSame($first, $second);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRealDocuments(): iterable
    {
        yield 'Entra, common federation metadata, 2026-09-23' => [self::ENTRA];
    }

    /**
     * Section 9.4, section 13: Entra's common federation metadata, its one ID indexed under the root.
     */
    #[Test]
    public function entrasMetadataHasItsOneIdIndexed(): void
    {
        // When
        $document = Loaded::fixture(self::ENTRA);

        // Then
        static::assertSame('EntityDescriptor', $document->root()->localName);
        static::assertSame('urn:oasis:names:tc:SAML:2.0:metadata', $document->root()->namespaceURI);
        static::assertSame($document->root(), $document->elementById('_2cac9ed1-b223-4fb8-83bd-03d6f59d682d'));
    }

    /**
     * Section 13, measured on 23 September 2026: the figures of the specification, pinned so that a re-capture
     * that moves them is seen.
     */
    #[Test]
    public function entrasMetadataMatchesTheMeasurementsOfSection13(): void
    {
        // Given
        $bytes = Fixtures::bytes(self::ENTRA);
        $document = Loaded::document($bytes);
        $xml = $document->root()->ownerDocument;
        static::assertInstanceOf(XMLDocument::class, $xml);

        // When
        $counts = self::measure($document->root());

        // Then
        static::assertSame(31_752, strlen($bytes));
        static::assertTrue(str_starts_with($bytes, "\xEF\xBB\xBF"));
        static::assertSame('utf-8', $xml->xmlEncoding);
        static::assertSame(
            [
                'elements' => 166,
                'depth' => 6,
                'declarations' => 49,
                'attributes' => 2,
                'comments' => 0,
                'instructions' => 0,
            ],
            $counts,
        );
        static::assertSame(
            32_095,
            strlen(new Canonicalizer()->canonicalize($document->root(), CanonicalizationMethod::Exclusive)->bytes),
        );
    }

    /**
     * @return array{elements: int, depth: int, declarations: int, attributes: int, comments: int, instructions: int}
     */
    private static function measure(Element $root): array
    {
        $counts = [
            'elements' => 0,
            'depth' => 0,
            'declarations' => 0,
            'attributes' => 0,
            'comments' => 0,
            'instructions' => 0,
        ];
        /** @var list<array{Node, int}> $stack */
        $stack = [[$root, 1]];
        while ($stack !== []) {
            [$node, $depth] = array_pop($stack);
            if ($node instanceof Comment) {
                ++$counts['comments'];
            }
            if ($node instanceof ProcessingInstruction) {
                ++$counts['instructions'];
            }
            if (! $node instanceof Element) {
                continue;
            }
            ++$counts['elements'];
            $counts['depth'] = max($counts['depth'], $depth);
            $attributes = 0;
            foreach ($node->attributes as $attribute) {
                if ($attribute->namespaceURI === 'http://www.w3.org/2000/xmlns/') {
                    ++$counts['declarations'];
                    continue;
                }
                ++$attributes;
            }
            $counts['attributes'] = max($counts['attributes'], $attributes);
            for ($child = $node->lastChild; $child instanceof Node; $child = $child->previousSibling) {
                $stack[] = [$child, $depth + 1];
            }
        }

        return $counts;
    }
}
