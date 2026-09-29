<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Internal;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Internal\CipherData;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * E-5, E-7: one CipherValue, decoded strictly, never a CipherReference.
 */
final class CipherDataTest extends TestCase
{
    #[Test]
    public function itDecodesTheOneCipherValue(): void
    {
        // Given
        $document = $this->cipherData("<xenc:CipherValue>AA\nEC</xenc:CipherValue>");

        // When / Then
        static::assertSame("\x00\x01\x02", CipherData::valueOf($document->root()));
    }

    /**
     * E-7: a value split by a comment reads as one value, Text::of() concatenating.
     */
    #[Test]
    public function itDecodesAValueSplitByAComment(): void
    {
        // Given
        $document = $this->cipherData('<xenc:CipherValue>AA<!-- split -->EC</xenc:CipherValue>');

        // When / Then
        static::assertSame("\x00\x01\x02", CipherData::valueOf($document->root()));
    }

    /**
     * §9.2 row 11, E-5: a CipherReference, alone or next to a value.
     */
    #[Test]
    public function itRefusesACipherReference(): void
    {
        // Given
        $document = $this->cipherData('<xenc:CipherReference URI="#cipher"/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('A CipherData holds nothing but a CipherValue, never a CipherReference (E-5).');

        // When
        CipherData::valueOf($document->root());
    }

    #[Test]
    public function itRefusesTwoCipherValues(): void
    {
        // Given
        $document = $this->cipherData('<xenc:CipherValue>AAEC</xenc:CipherValue><xenc:CipherValue>AAEC</xenc:CipherValue>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('A CipherData holds exactly one CipherValue (E-5).');

        // When
        CipherData::valueOf($document->root());
    }

    #[Test]
    public function itRefusesNoCipherValue(): void
    {
        // Given
        $document = $this->cipherData('');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('A CipherData holds exactly one CipherValue (E-5).');

        // When
        CipherData::valueOf($document->root());
    }

    /**
     * §9.2 row 36, E-5: a CipherValue with an element child is refused by the model, never with Core's MixedContent,
     * since nothing was decrypted.
     */
    #[Test]
    public function itRefusesACipherValueHoldingAnElement(): void
    {
        // Given
        $document = $this->cipherData('<xenc:CipherValue>AA<xenc:Foo/>EC</xenc:CipherValue>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('A CipherValue holds nothing but text (E-5).');

        // When
        CipherData::valueOf($document->root());
    }

    private function cipherData(string $children): Document
    {
        return Loaded::document('<xenc:CipherData xmlns:xenc="'
        . Names::XMLENC
        . '">'
        . $children
        . '</xenc:CipherData>');
    }
}
