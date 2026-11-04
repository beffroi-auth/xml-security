<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Internal;

use Beffroi\Xml\Core\Name;

/**
 * @internal outside the compatibility promise of section 5
 */
final readonly class Names
{
    public const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public const string ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    public static function dsig(string $local): Name
    {
        return new Name(self::DSIG, $local);
    }

    public static function attribute(string $local): Name
    {
        return new Name(null, $local);
    }

    /**
     * Exclusive XML Canonicalization §4
     */
    public static function inclusiveNamespaces(): Name
    {
        return new Name(self::EXC_C14N, 'InclusiveNamespaces');
    }
}
