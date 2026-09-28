<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\DigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Reference;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 5.3, D-2, D-3, D-5, D-8, D-14: the one reference read strictly.
 */
final class ReferenceTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    #[Test]
    public function itReadsTheReferenceOfTheVector(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');

        // When
        $reference = Reference::of($this->referenceOf($document->elementById('_assertion-d4e5f6')));

        // Then
        static::assertSame('_assertion-d4e5f6', $reference->id);
        static::assertSame(CanonicalizationMethod::Exclusive, $reference->canonicalization);
        static::assertSame([], $reference->inclusiveNamespaces->prefixes);
        static::assertSame(DigestAlgorithm::Sha256, $reference->digestMethod);
        static::assertSame(32, strlen($reference->digestValue));
    }

    /**
     * §9.2 rows 7, 8 and 9, D-2: the URI is "#" and an NCName, nothing else.
     */
    #[Test]
    #[TestWith(['reference-uri-empty-refused.xml'], 'empty')]
    #[TestWith(['reference-uri-xpointer-refused.xml'], 'xpointer')]
    #[TestWith(['reference-uri-external-refused.xml'], 'external')]
    public function itRefusesAUriThatIsNotAHashAndAnNcName(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = $this->referenceOf($document->elementById('_assertion-d4e5f6'));

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('A Reference names the claimed element by its ID, "#" followed by an NCName (D-2).');

        // When
        Reference::of($element);
    }

    /**
     * §9.2 row 10, D-2: a Type, whatever it names.
     */
    #[Test]
    public function itRefusesAType(): void
    {
        // Given
        $document = Loaded::fixture('hostile/reference-type-refused.xml');
        $element = $this->referenceOf($document->elementById('_assertion-d4e5f6'));

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('A Reference carries no Type (D-2).');

        // When
        Reference::of($element);
    }

    /**
     * §9.2 row 28, D-14: the prefixes of a PrefixList are bounded.
     */
    #[Test]
    public function itRefusesAPrefixListOverTheBound(): void
    {
        // Given
        $document = Loaded::fixture('hostile/prefixlist-33-refused.xml');
        $element = $this->referenceOf($document->elementById('_assertion-d4e5f6'));

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A PrefixList holds more prefixes than maxPrefixes, 32 (D-14).');

        // When
        Reference::of($element);
    }

    /**
     * Core I-4: an element of a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesAnElementOfAForeignDocument(): void
    {
        // Given
        $root = Foreign::parse('<ds:Reference xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>')->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        Reference::of($root);
    }

    private function referenceOf(Element $signed): Element
    {
        return Children::one(
            Children::one(
                Children::one($signed, new Name(self::DSIG, 'Signature')),
                new Name(self::DSIG, 'SignedInfo'),
            ),
            new Name(self::DSIG, 'Reference'),
        );
    }
}
