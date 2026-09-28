<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Stack;

/**
 * A document loaded through Core, with the SAML stack's ID attributes and the default limits: the way every test
 * of Dsig obtains a signed element. A test holds the Document it reads nodes from (core.md section 6.1 step 7).
 */
final class Loaded
{
    public static function document(string $bytes): Document
    {
        return new Loader(Stack::idAttributes())->load($bytes);
    }

    public static function fixture(string $path): Document
    {
        return self::document(Fixtures::bytes($path));
    }
}
