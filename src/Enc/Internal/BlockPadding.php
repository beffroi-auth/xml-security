<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use Beffroi\Xml\Enc\CbcContentAlgorithm;
use function ord;
use function substr;

/**
 * The padding of a block cipher in XML Encryption 1.1 §5.2: arbitrary octets ended by their count, from 1 to a block.
 * xmlsec1 fills them at random, xmlseclibs repeats the count, and PKCS#7, which OpenSSL checks, refuses the first: the
 * count is read here, and nothing else of the padding (E-16).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class BlockPadding
{
    /**
     * The plaintext of $padded, its padding removed, or null when the count, its last octet, is not 1 to BLOCK_BYTES.
     */
    public static function strip(string $padded): ?string
    {
        $count = ord(substr($padded, -1));

        // one comparison: count - 1 holds no bit above those of 0 to 15 for a count of 1 to 16 only
        return (($count - 1) & ~(CbcContentAlgorithm::BLOCK_BYTES - 1)) === 0 ? substr($padded, 0, -$count) : null;
    }
}
