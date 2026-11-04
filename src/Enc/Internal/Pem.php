<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use function base64_decode;
use function base64_encode;
use function chunk_split;
use function preg_match;
use function preg_replace;

/**
 * E-11, E-14: OpenSSL gets the block armoured again from the decoded bytes, never a path or a bundle it would open.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Pem
{
    /**
     * @param 'CERTIFICATE'|'PUBLIC KEY' $type
     *
     * @return ?non-empty-string
     */
    public static function block(string $pem, string $type): ?string
    {
        $matches = [];
        if (
            preg_match(
                '~\A\s*-----BEGIN ' . $type . '-----([A-Za-z0-9+/=\s]+)-----END ' . $type . '-----\s*\z~',
                $pem,
                $matches,
            ) !== 1
        ) {
            return null;
        }
        $bytes = base64_decode(preg_replace('~\s+~', '', $matches[1]) ?? '', true);

        return $bytes === false || $bytes === '' ? null : $bytes;
    }

    /**
     * @param 'CERTIFICATE'|'PUBLIC KEY' $type
     */
    public static function armour(string $bytes, string $type): string
    {
        return '-----BEGIN ' . $type . "-----\n" . chunk_split(base64_encode($bytes), 64, "\n") . '-----END ' . $type . "-----\n";
    }
}
