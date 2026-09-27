<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Internal;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Internal\Structure;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * E-5: the structure read strictly, direct children only, counted, every other child refused.
 */
final class StructureTest extends TestCase
{
    private const string NS = 'urn:test';

    #[Test]
    public function itAcceptsChildrenOfTheAllowedNames(): void
    {
        // Given
        $document = $this->document('<t:b/><t:b/><t:c/>');

        // When
        Structure::refuseOtherChildren($document->root(), [$this->named('b'), $this->named('c')], 'never');

        // Then
        static::assertCount(3, Children::all($document->root()));
    }

    #[Test]
    public function itRefusesAChildOfAnotherName(): void
    {
        // Given
        $document = $this->document('<t:b/><t:d/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('another name (E-5).');

        // When
        Structure::refuseOtherChildren($document->root(), [$this->named('b')], 'another name (E-5).');
    }

    #[Test]
    public function itRefusesAChildOfTheSameLocalNameInAnotherNamespace(): void
    {
        // Given
        $document = $this->document('<b xmlns="urn:other"/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('another namespace (E-5).');

        // When
        Structure::refuseOtherChildren($document->root(), [$this->named('b')], 'another namespace (E-5).');
    }

    #[Test]
    public function itFindsExactlyOneChild(): void
    {
        // Given
        $document = $this->document('<t:b/><t:c/>');

        // When
        $child = Structure::one($document->root(), $this->named('c'), 'never');

        // Then
        static::assertSame('c', $child->localName);
    }

    #[Test]
    public function itRefusesTwoChildrenWhereOneIsExpected(): void
    {
        // Given
        $document = $this->document('<t:b/><t:b/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('two (E-5).');

        // When
        Structure::one($document->root(), $this->named('b'), 'two (E-5).');
    }

    #[Test]
    public function itRefusesNoChildWhereOneIsExpected(): void
    {
        // Given
        $document = $this->document('<t:c/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('none (E-5).');

        // When
        Structure::one($document->root(), $this->named('b'), 'none (E-5).');
    }

    #[Test]
    public function itFindsAnOptionalChildOrNothing(): void
    {
        // Given
        $document = $this->document('<t:b/>');

        // When / Then
        static::assertSame('b', Structure::optional($document->root(), $this->named('b'), 'never')?->localName);
        static::assertNull(Structure::optional($document->root(), $this->named('c'), 'never'));
    }

    #[Test]
    public function itRefusesTwoChildrenWhereAtMostOneIsExpected(): void
    {
        // Given
        $document = $this->document('<t:b/><t:b/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('two (E-5).');

        // When
        Structure::optional($document->root(), $this->named('b'), 'two (E-5).');
    }

    #[Test]
    public function itAcceptsNoChildWhereNoneIsExpected(): void
    {
        // Given
        $document = $this->document('text <!-- and a comment -->');

        // When
        Structure::none($document->root(), 'never');

        // Then
        static::assertSame([], Children::all($document->root()));
    }

    #[Test]
    public function itRefusesAChildWhereNoneIsExpected(): void
    {
        // Given
        $document = $this->document('<t:b/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('a child (E-5).');

        // When
        Structure::none($document->root(), 'a child (E-5).');
    }

    private function document(string $children): Document
    {
        return Loaded::document('<t:a xmlns:t="' . self::NS . '">' . $children . '</t:a>');
    }

    private function named(string $local): Name
    {
        return new Name(self::NS, $local);
    }
}
