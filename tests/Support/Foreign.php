<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Support;

use Dom\XMLDocument;
use function libxml_clear_errors;
use const LIBXML_NONET;
use function libxml_use_internal_errors;

/**
 * A document parsed outside the loader: what Internal\Inspector is fed to reach the rules I-1 and I-3 stop earlier,
 * and what Canonicalizer and Serializer refuse as foreign (I-4). The diagnostics of the parse are discarded here
 * on purpose.
 */
final class Foreign
{
    public static function parse(string $bytes): XMLDocument
    {
        $previous = libxml_use_internal_errors(true);
        try {
            return XMLDocument::createFromString($bytes, LIBXML_NONET);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }
}
