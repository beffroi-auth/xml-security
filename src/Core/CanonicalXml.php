<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Exception\CanonicalizationFailed;

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
