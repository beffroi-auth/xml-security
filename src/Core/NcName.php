<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use function preg_match;

/**
 * Namespaces in XML 1.0 §3, production NCName, over the character classes of XML 1.0 fifth edition §2.3: what an
 * ID is (I-8), and what a reference of Dsig names after its "#" (spec/dsig.md D-2).
 */
final readonly class NcName
{
    private const string PATTERN = '~^[A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}][A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}\-.0-9\x{B7}\x{300}-\x{36F}\x{203F}-\x{2040}]*\z~u';

    public static function is(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
