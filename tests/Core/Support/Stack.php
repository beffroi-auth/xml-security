<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Support;

use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\IdAttributes;
use Beffroi\Xml\Core\Name;

/**
 * What the SAML stack registers, for the record and for the tests of this brick (specification, section 5.3).
 */
final class Stack
{
    public const string XMLDSIG = 'http://www.w3.org/2000/09/xmldsig#';
    public const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';
    public const string SAML_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';
    public const string SAML_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';
    public const string SAML_METADATA = 'urn:oasis:names:tc:SAML:2.0:metadata';

    public static function idAttributes(): IdAttributes
    {
        return new IdAttributes([
            new IdAttribute(new Name(null, 'Id'), self::XMLDSIG),
            new IdAttribute(new Name(null, 'Id'), self::XMLENC),
            new IdAttribute(new Name(null, 'ID'), self::SAML_ASSERTION),
            new IdAttribute(new Name(null, 'ID'), self::SAML_PROTOCOL),
            new IdAttribute(new Name(null, 'ID'), self::SAML_METADATA),
        ]);
    }
}
