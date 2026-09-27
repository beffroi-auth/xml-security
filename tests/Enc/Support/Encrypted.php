<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Dom\Element;

/**
 * Where the vectors and the hostile fixtures keep their encrypted assertion: a SAML response whose
 * EncryptedAssertion holds the xenc:EncryptedData, the element a consumer hands to the decryptor.
 */
final class Encrypted
{
    public static function dataOf(Document $document): Element
    {
        return Children::one(
            Children::one($document->root(), new Name(Stack::SAML_ASSERTION, 'EncryptedAssertion')),
            new Name(Stack::XMLENC, 'EncryptedData'),
        );
    }

    /**
     * The xenc:EncryptedKey inside the KeyInfo of that EncryptedData.
     */
    public static function keyOf(Document $document): Element
    {
        return Children::one(
            Children::one(self::dataOf($document), new Name(Stack::XMLDSIG, 'KeyInfo')),
            new Name(Stack::XMLENC, 'EncryptedKey'),
        );
    }
}
