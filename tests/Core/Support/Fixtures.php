<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Support;

use function file_get_contents;
use RuntimeException;
use function sprintf;

/**
 * The corpus of section 9: files, one case per file, under tests/Fixture/{canonical,hostile,behaviour,real}/.
 */
final class Fixtures
{
    public static function bytes(string $path): string
    {
        $bytes = file_get_contents(self::path($path));
        if ($bytes === false) {
            throw new RuntimeException(sprintf('The fixture %s cannot be read.', $path));
        }

        return $bytes;
    }

    public static function path(string $path): string
    {
        return __DIR__ . '/../Fixture/' . $path;
    }
}
