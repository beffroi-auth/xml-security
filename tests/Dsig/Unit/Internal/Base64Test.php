<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Internal;

use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Internal\Base64;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * D-8, D-14: base64 decoded strictly after whitespace removal, the text bounded before anything is decoded.
 */
final class Base64Test extends TestCase
{
    #[Test]
    #[TestWith(['AAEC'], 'plain')]
    #[TestWith(["AA\nEC\n"], 'line feeds, as XML Signature writes them')]
    #[TestWith([" AA\r\n\tEC "], 'every whitespace character')]
    public function itDecodesAfterWhitespaceRemoval(string $text): void
    {
        // When / Then
        static::assertSame("\x00\x01\x02", Base64::decode($text));
    }

    /**
     * §9.2 rows 30 and 32, D-8: a character outside the alphabet, padding out of place, or nothing at all.
     */
    #[Test]
    #[TestWith(['AA!C'], 'a character outside the alphabet')]
    #[TestWith(['AA=A'], 'a padding character before the end')]
    #[TestWith(['A'], 'a lone character')]
    #[TestWith([''], 'empty')]
    #[TestWith(["\n"], 'whitespace only')]
    public function itRefusesWhatIsNotBase64(string $text): void
    {
        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('A base64 value holds a character outside the alphabet or is empty (D-8).');

        // When
        Base64::decode($text);
    }

    /**
     * §9.2 row 33, D-14: the text is bounded before it is decoded.
     */
    #[Test]
    public function itRefusesATextOverTheBound(): void
    {
        // Given
        $text = str_repeat('A', 4097);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A base64 value is longer than maxBase64Bytes, 4096 bytes (D-14).');

        // When
        Base64::decode($text);
    }

    /**
     * D-14: a text of exactly the bound decodes.
     */
    #[Test]
    public function itDecodesATextAtTheBound(): void
    {
        // Given
        $text = str_repeat('A', 4096);

        // When / Then
        static::assertSame(str_repeat("\x00", 3072), Base64::decode($text));
    }
}
