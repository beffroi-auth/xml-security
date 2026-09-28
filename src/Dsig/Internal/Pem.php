<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Internal;

use function base64_decode;
use function base64_encode;
use function chunk_split;
use function preg_match;
use function preg_replace;

/**
 * One PEM block in memory, read strictly (D-16): exactly one block of the type asked, its content strict base64,
 * nothing around it but whitespace. What is anything else, a path OpenSSL would open or a bundle among them, never
 * reaches OpenSSL, which is handed the block written again from the decoded bytes.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Pem
{
    /**
     * The decoded bytes of the one block of $type that $pem is, or null.
     *
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
     * The block of $type around $bytes, in lines of 64 characters.
     *
     * @param 'CERTIFICATE'|'PUBLIC KEY' $type
     */
    public static function armour(string $bytes, string $type): string
    {
        return (
            '-----BEGIN '
            . $type
            . "-----\n"
            . chunk_split(base64_encode($bytes), 64, "\n")
            . '-----END '
            . $type
            . "-----\n"
        );
    }
}
