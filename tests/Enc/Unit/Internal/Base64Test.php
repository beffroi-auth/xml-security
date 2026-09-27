<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Internal;

use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Internal\Base64;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * E-7, E-13: base64 decoded strictly after whitespace removal, the text bounded before anything is decoded.
 */
final class Base64Test extends TestCase
{
    #[Test]
    #[TestWith(['AAEC'], 'plain')]
    #[TestWith(["AA\nEC\n"], 'line feeds, as XML Encryption writes them')]
    #[TestWith([" AA\r\n\tEC "], 'every whitespace character')]
    public function itDecodesAfterWhitespaceRemoval(string $text): void
    {
        // When / Then
        static::assertSame("\x00\x01\x02", Base64::decode($text));
    }

    /**
     * §9.2 row 15, E-7: a character outside the alphabet, padding out of place, or nothing at all.
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
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('A CipherValue holds a character outside the base64 alphabet or is empty (E-7).');

        // When
        Base64::decode($text);
    }

    /**
     * §9.2 row 16, E-13: the text is bounded before it is decoded.
     */
    #[Test]
    public function itRefusesATextOverTheBound(): void
    {
        // Given
        $text = str_repeat('A', 2_097_153);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A CipherValue is longer than maxCipherValueBytes, 2097152 bytes of text (E-13).');

        // When
        Base64::decode($text);
    }

    /**
     * E-13: a text of exactly the bound decodes.
     */
    #[Test]
    public function itDecodesATextAtTheBound(): void
    {
        // Given
        $text = str_repeat('A', 2_097_152);

        // When / Then
        static::assertSame(str_repeat("\x00", 1_572_864), Base64::decode($text));
    }
}
