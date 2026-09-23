<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Support;

use Dom\Element;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Loader;

/**
 * A document loaded through the brick, with the SAML stack's ID attributes and the default limits: the way every
 * test obtains a node unless it needs a foreign one.
 */
final class Loaded
{
    public static function document(string $bytes): Document
    {
        return new Loader(Stack::idAttributes())->load($bytes);
    }

    public static function root(string $bytes): Element
    {
        return self::document($bytes)->root();
    }

    public static function fixture(string $path): Document
    {
        return self::document(Fixtures::bytes($path));
    }
}
