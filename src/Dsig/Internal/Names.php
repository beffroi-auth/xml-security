<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Internal;

use Beffroi\Xml\Core\Name;

/**
 * The names the reading model matches, on namespace URI and local name, never a prefix (Core I-10).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Names
{
    public const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public const string ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * An element of the XML Signature namespace.
     */
    public static function dsig(string $local): Name
    {
        return new Name(self::DSIG, $local);
    }

    /**
     * An attribute in no namespace, as every attribute of the ds:* elements is.
     */
    public static function attribute(string $local): Name
    {
        return new Name(null, $local);
    }

    /**
     * The InclusiveNamespaces element of Exclusive XML Canonicalization §4, child of a canonicalization method or
     * transform, whose PrefixList attribute names the prefixes rendered as an inclusive form would.
     */
    public static function inclusiveNamespaces(): Name
    {
        return new Name(self::EXC_C14N, 'InclusiveNamespaces');
    }
}
