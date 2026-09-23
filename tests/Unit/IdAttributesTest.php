<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\IdAttributes;
use Beffroi\Xml\Core\Name;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: what a consumer registers; the index of I-8 is built over every registered attribute at once.
 */
final class IdAttributesTest extends TestCase
{
    #[Test]
    public function itHoldsTheRegisteredAttributes(): void
    {
        // Given
        $id = new IdAttribute(new Name(null, 'ID'));

        // When
        $attributes = new IdAttributes([$id]);

        // Then
        static::assertSame([$id], $attributes->attributes);
    }

    #[Test]
    public function noneRegistersNothing(): void
    {
        // When / Then
        static::assertSame([], IdAttributes::none()->attributes);
    }

    /**
     * Section 5.3: a value object; withAttribute() returns a new set and leaves the original as it was.
     */
    #[Test]
    public function withAttributeAppendsToANewSet(): void
    {
        // Given
        $first = new IdAttribute(new Name(null, 'ID'));
        $second = new IdAttribute(new Name(null, 'Id'), 'http://www.w3.org/2000/09/xmldsig#');
        $original = new IdAttributes([$first]);

        // When
        $extended = $original->withAttribute($second);

        // Then
        static::assertSame([$first, $second], $extended->attributes);
        static::assertSame([$first], $original->attributes);
    }
}
