<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use Beffroi\Xml\Core\Name;

/**
 * The names the reading model matches, on namespace URI and local name, never a prefix (Core I-10).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Names
{
    public const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';

    public const string XMLENC11 = 'http://www.w3.org/2009/xmlenc11#';

    public const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * The Type of an EncryptedData whose plaintext is a whole element, the only one the namespace reads (E-5).
     */
    public const string TYPE_ELEMENT = 'http://www.w3.org/2001/04/xmlenc#Element';

    /**
     * An element of the XML Encryption namespace.
     */
    public static function xenc(string $local): Name
    {
        return new Name(self::XMLENC, $local);
    }

    /**
     * An element of the XML Encryption 1.1 namespace: the MGF of an rsa-oaep method.
     */
    public static function xenc11(string $local): Name
    {
        return new Name(self::XMLENC11, $local);
    }

    /**
     * An element of the XML Signature namespace: the KeyInfo that holds an EncryptedKey, the DigestMethod of a key
     * transport.
     */
    public static function dsig(string $local): Name
    {
        return new Name(self::DSIG, $local);
    }

    /**
     * An attribute in no namespace, as every attribute of the xenc:* elements is.
     */
    public static function attribute(string $local): Name
    {
        return new Name(null, $local);
    }
}
