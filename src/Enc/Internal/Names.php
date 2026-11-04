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

    public const string TYPE_ELEMENT = 'http://www.w3.org/2001/04/xmlenc#Element';

    public static function xenc(string $local): Name
    {
        return new Name(self::XMLENC, $local);
    }

    public static function xenc11(string $local): Name
    {
        return new Name(self::XMLENC11, $local);
    }

    public static function dsig(string $local): Name
    {
        return new Name(self::DSIG, $local);
    }

    public static function attribute(string $local): Name
    {
        return new Name(null, $local);
    }
}
