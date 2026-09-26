<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Stack;
use function iconv;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, encoding tricks: UTF-16 with a byte order mark is accepted by libxml and then reported as UTF-8, so
 * what the bytes say and what the DOM says differ. The rule: valid UTF-8, no UTF-16 or UTF-32 mark, checked before
 * parsing; a declared encoding is UTF-8 (I-5).
 */
final class EncodingTricksTest extends TestCase
{
    /**
     * I-5: a UTF-16 response with a byte order mark, which libxml would parse and call UTF-8, is refused before
     * parsing.
     */
    #[Test]
    public function aUtf16ResponseWithAByteOrderMarkIsRefused(): void
    {
        // Given
        $bytes = "\xFF\xFE"
        . iconv(
            'UTF-8',
            'UTF-16LE',
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"/>',
        );

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The input starts with a UTF-16 or UTF-32 byte order mark (I-5).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }

    /**
     * I-5: a declared single-byte encoding, which libxml converts silently, is refused after parsing.
     */
    #[Test]
    public function aDeclaredSingleByteEncodingIsRefused(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/declared-iso-8859-1-refused.xml');

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The declared encoding is not UTF-8 (I-5).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }
}
