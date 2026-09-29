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
 * The base64 of a CipherValue, decoded strictly after whitespace removal (E-7), the text bounded before anything is
 * decoded (E-13). XML Encryption writes base64 with line breaks every 76 characters; a character outside the
 * alphabet, padding out of place, or an empty value is a refusal, never a byte skipped.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Base64
{
    /**
     * Section 7: the text of a CipherValue, whitespace included, before decoding.
     */
    public const int MAX_TEXT_BYTES = 2_097_152;

    /**
     * @param positive-int $maxTextBytes the bound of section 7 the text is held to, before anything is decoded
     * @param string $bound the name section 7 gives it
     *
     * @throws LimitExceeded when the text is longer than $maxTextBytes
     * @throws MalformedEncryption when the text holds a character outside the alphabet or is empty
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
