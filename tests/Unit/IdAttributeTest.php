<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\Name;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: an attribute whose values identify elements, on the elements of one namespace or of any.
 */
final class IdAttributeTest extends TestCase
{
    #[Test]
    public function itAppliesToTheElementsOfANamespace(): void
    {
        // When
        $attribute = new IdAttribute(new Name(null, 'ID'), 'urn:oasis:names:tc:SAML:2.0:assertion');

        // Then
        static::assertTrue($attribute->attribute->equals(new Name(null, 'ID')));
        static::assertSame('urn:oasis:names:tc:SAML:2.0:assertion', $attribute->elementNamespace);
    }

    /**
     * Section 5.3: null for any element, the way xml:id would be registered.
     */
    #[Test]
    public function itAppliesToAnyElementByDefault(): void
    {
        // When
        $attribute = new IdAttribute(new Name('http://www.w3.org/XML/1998/namespace', 'id'));

        // Then
        static::assertNull($attribute->elementNamespace);
    }
}
