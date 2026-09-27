<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Internal;

use Beffroi\Xml\Dsig\Internal\Names;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Core I-10: the names of the model match on namespace URI and local name, never on a prefix.
 */
final class NamesTest extends TestCase
{
    #[Test]
    public function itsElementNamesAreInTheSignatureNamespaceWhateverThePrefix(): void
    {
        // Given
        $document = Loaded::document('<x:Signature xmlns:x="http://www.w3.org/2000/09/xmldsig#"/>');

        // When / Then
        static::assertTrue(Names::dsig('Signature')->matches($document->root()));
        static::assertFalse(Names::dsig('SignedInfo')->matches($document->root()));
    }

    #[Test]
    public function itsAttributeNamesAreInNoNamespace(): void
    {
        // When / Then
        static::assertNull(Names::attribute('URI')->namespace);
        static::assertSame('URI', Names::attribute('URI')->local);
    }

    #[Test]
    public function itsInclusiveNamespacesNameIsTheOneOfExclusiveCanonicalization(): void
    {
        // When / Then
        static::assertSame('http://www.w3.org/2001/10/xml-exc-c14n#', Names::inclusiveNamespaces()->namespace);
        static::assertSame('InclusiveNamespaces', Names::inclusiveNamespaces()->local);
    }
}
