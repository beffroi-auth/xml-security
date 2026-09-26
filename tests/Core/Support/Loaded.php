<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Loader;

/**
 * A document loaded through the brick, with the SAML stack's ID attributes and the default limits: the way every
 * test obtains a node unless it needs a foreign one. A test holds the Document it reads nodes from: a node alone
 * does not keep its document recognised (section 6.1 step 7).
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
