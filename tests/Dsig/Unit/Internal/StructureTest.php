<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Internal;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Internal\Structure;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * D-9: the structure read strictly, direct children only, counted, the unexpected refused with the message the
 * caller gives.
 */
final class StructureTest extends TestCase
{
    #[Test]
    public function itAcceptsChildrenOfTheAllowedNames(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/><b/><c/></a>');

        // When
        Structure::refuseOtherChildren($document->root(), [new Name('urn:x', 'b'), new Name('urn:x', 'c')], 'unused');

        // Then
        static::assertCount(3, Children::all($document->root()));
    }

    #[Test]
    public function itRefusesAChildOfAnotherName(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/><c/></a>');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('the message of the caller (D-9).');

        // When
        Structure::refuseOtherChildren($document->root(), [new Name('urn:x', 'b')], 'the message of the caller (D-9).');
    }

    #[Test]
    public function itReadsExactlyOneChild(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/><c/></a>');

        // When
        $child = Structure::one($document->root(), new Name('urn:x', 'c'), 'unused');

        // Then
        static::assertSame('c', $child->localName);
    }

    #[Test]
    public function itRefusesTwoChildrenWhereItReadsOne(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/><b/></a>');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('exactly one (D-9).');

        // When
        Structure::one($document->root(), new Name('urn:x', 'b'), 'exactly one (D-9).');
    }

    #[Test]
    public function itRefusesNoChildWhereItReadsOne(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/></a>');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('exactly one (D-9).');

        // When
        Structure::one($document->root(), new Name('urn:x', 'c'), 'exactly one (D-9).');
    }

    #[Test]
    public function itReadsAnOptionalChildOrNull(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/></a>');

        // When
        $present = Structure::optional($document->root(), new Name('urn:x', 'b'), 'unused');
        $absent = Structure::optional($document->root(), new Name('urn:x', 'c'), 'unused');

        // Then
        static::assertNotNull($present);
        static::assertSame('b', $present->localName);
        static::assertNull($absent);
    }

    #[Test]
    public function itRefusesTwoChildrenWhereItReadsAtMostOne(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/><b/></a>');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('at most one (D-9).');

        // When
        Structure::optional($document->root(), new Name('urn:x', 'b'), 'at most one (D-9).');
    }

    #[Test]
    public function itAcceptsAnElementWithoutElementChildren(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x">text<!--comment--></a>');

        // When
        Structure::none($document->root(), 'unused');

        // Then
        static::assertSame([], Children::all($document->root()));
    }

    #[Test]
    public function itRefusesAnElementChildWhereNoneIsAllowed(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b/></a>');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('no child (D-9).');

        // When
        Structure::none($document->root(), 'no child (D-9).');
    }

    /**
     * D-9, Core I-12: the text of an element, read through Text::of(), a comment skipped.
     */
    #[Test]
    public function itReadsTheTextOfAnElement(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x">te<!--comment-->xt</a>');

        // When
        $text = Structure::text($document->root(), 'unused');

        // Then
        static::assertSame('text', $text);
    }

    /**
     * D-9: an element inside a text is refused under the rule of the namespace, never with Core's MixedContent.
     */
    #[Test]
    public function itRefusesAnElementInsideTheText(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x">te<b/>xt</a>');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('nothing but text (D-9).');

        // When
        Structure::text($document->root(), 'nothing but text (D-9).');
    }

    /**
     * D-1, D-9: direct children only; a grandchild of the name is not found.
     */
    #[Test]
    public function itNeverSearchesDescendants(): void
    {
        // Given
        $document = Loaded::document('<a xmlns="urn:x"><b><c/></b></a>');

        // When
        $child = Structure::optional($document->root(), new Name('urn:x', 'c'), 'unused');

        // Then
        static::assertNull($child);
    }
}
