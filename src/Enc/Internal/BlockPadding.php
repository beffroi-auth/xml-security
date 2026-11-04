<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use Beffroi\Xml\Enc\CbcContentAlgorithm;
use function ord;
use function substr;

/**
 * XML Encryption 1.1 §5.2, E-16: only the count is read, as xmlsec1 pads with random octets that PKCS#7 refuses.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class BlockPadding
{
    public static function strip(string $padded): ?string
    {
        $count = ord(substr($padded, -1));

        // One comparison: count - 1 has no bit above those of 0 to 15 only for a count of 1 to 16.
        return (($count - 1) & ~(CbcContentAlgorithm::BLOCK_BYTES - 1)) === 0 ? substr($padded, 0, -$count) : null;
    }
}
