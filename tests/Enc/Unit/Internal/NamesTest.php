<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Internal;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Core I-10: the names the model matches, on namespace URI and local name, never a prefix.
 */
final class NamesTest extends TestCase
{
    #[Test]
    public function itNamesTheElementsOfTheVector(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-rsa-oaep-sha256.xml');
        $data = Encrypted::dataOf($document);
        $key = Encrypted::keyOf($document);

        // When / Then
        static::assertTrue(Names::xenc('EncryptedData')->matches($data));
        static::assertFalse(Names::xenc('EncryptedKey')->matches($data));
        static::assertTrue(Names::xenc('EncryptedKey')->matches($key));
        static::assertTrue(Names::dsig('KeyInfo')->matches($key->parentElement ?? $data));
        static::assertSame(Names::TYPE_ELEMENT, Attributes::optional($data, Names::attribute('Type')));
    }

    #[Test]
    public function itNamesTheMgfOfXmlEncryption11(): void
    {
        // Given
        $document = Loaded::document('<m xmlns:xenc11="'
        . Names::XMLENC11
        . '"><xenc11:MGF Algorithm="'
        . Names::XMLENC11
        . 'mgf1sha256"/></m>');
        $mgf = $document->root()->firstElementChild;
        static::assertNotNull($mgf);

        // When / Then
        static::assertTrue(Names::xenc11('MGF')->matches($mgf));
        static::assertFalse(Names::xenc('MGF')->matches($mgf));
        static::assertNull(Names::attribute('Algorithm')->namespace);
    }
}
