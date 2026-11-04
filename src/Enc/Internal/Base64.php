<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use function base64_decode;
use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use function preg_replace;
use function sprintf;
use function strlen;

/**
 * The base64 of a CipherValue, bounded first (E-13), then decoded strictly once whitespace is removed (E-7).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Base64
{
    /**
     * Section 7: the text of a CipherValue, whitespace included.
     */
    public const int MAX_TEXT_BYTES = 2_097_152;

    /**
     * @param positive-int $maxTextBytes
     *
     * @throws LimitExceeded
     * @throws MalformedEncryption
     */
    public static function decode(
        string $text,
        int $maxTextBytes = self::MAX_TEXT_BYTES,
        string $bound = 'maxCipherValueBytes',
    ): string {
        if (strlen($text) > $maxTextBytes) {
            throw new LimitExceeded(sprintf(
                'A CipherValue is longer than %s, %d bytes of text (E-13).',
                $bound,
                $maxTextBytes,
            ));
        }
        $bytes = base64_decode(preg_replace('~[ \t\r\n]+~', '', $text) ?? '', true);
        if ($bytes === false || $bytes === '') {
            throw new MalformedEncryption('A CipherValue holds a character outside the base64 alphabet or is empty (E-7).');
        }

        return $bytes;
    }
}
