<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Internal;

use function base64_decode;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use function preg_replace;
use function sprintf;
use function strlen;

/**
 * Decoded strictly after whitespace removal: a character outside the alphabet is refused, never skipped (D-8).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Base64
{
    /**
     * Section 7: whitespace included.
     */
    public const int MAX_TEXT_BYTES = 4096;

    /**
     * @throws LimitExceeded
     * @throws MalformedSignature
     */
    public static function decode(string $text): string
    {
        if (strlen($text) > self::MAX_TEXT_BYTES) {
            throw new LimitExceeded(sprintf(
                'A base64 value is longer than maxBase64Bytes, %d bytes (D-14).',
                self::MAX_TEXT_BYTES,
            ));
        }
        $bytes = base64_decode(preg_replace('~[ \t\r\n]+~', '', $text) ?? '', true);
        if ($bytes === false || $bytes === '') {
            throw new MalformedSignature('A base64 value holds a character outside the alphabet or is empty (D-8).');
        }

        return $bytes;
    }
}
