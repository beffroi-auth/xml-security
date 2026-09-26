<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Exception\CanonicalizationFailed;

/**
 * The bytes a canonicalization produced: what a consumer hashes, and what it loads again to see what was signed
 * (section 6.6). Nothing canonicalizes to nothing (I-13): the empty string is refused here, whatever produced it.
 */
final readonly class CanonicalXml
{
    /**
     * @throws CanonicalizationFailed on ''
     */
    public function __construct(
        public string $bytes,
    ) {
        if ($bytes === '') {
            throw new CanonicalizationFailed('The canonical form is empty (I-13).');
        }
    }
}
