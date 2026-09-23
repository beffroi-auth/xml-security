<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\CanonicalXml;
use Beffroi\Xml\Core\Exception\CanonicalizationFailed;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * I-13: nothing canonicalizes to nothing. CVE-2025-66578 hashed the empty string libxml returned.
 */
final class CanonicalXmlTest extends TestCase
{
    #[Test]
    public function itHoldsTheCanonicalBytes(): void
    {
        // When
        $canonical = new CanonicalXml('<a></a>');

        // Then
        static::assertSame('<a></a>', $canonical->bytes);
    }

    /**
     * §9.2 row 29, I-13: the empty string is refused in the constructor, whatever produced it.
     */
    #[Test]
    public function itRefusesTheEmptyString(): void
    {
        // Then
        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessageIs('The canonical form is empty (I-13).');

        // When
        new CanonicalXml('');
    }
}
