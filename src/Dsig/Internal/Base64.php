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
 * The base64 of a SignatureValue or a DigestValue, decoded strictly after whitespace removal (D-8), the text bounded
 * before anything is decoded (D-14). XML Signature writes base64 with line breaks every 76 characters; a character
 * outside the alphabet, padding out of place, or an empty value is a refusal, never a byte skipped.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Base64
{
    /**
     * Section 7: the text of a base64 value, whitespace included, before decoding.
     */
    public const int MAX_TEXT_BYTES = 4096;

    /**
     * @throws LimitExceeded when the text is longer than MAX_TEXT_BYTES
     * @throws MalformedSignature when the text holds a character outside the alphabet or is empty
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
