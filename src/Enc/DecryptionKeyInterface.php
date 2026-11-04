<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;

interface DecryptionKeyInterface
{
    /**
     * Under RSA-OAEP with $hash for the mask and for MGF1. Null when it does not unwrap, never why, so that the port
     * cannot become the oracle (E-3, E-6).
     *
     * @throws AlgorithmUnavailable
     */
    public function unwrap(string $wrapped, OaepHash $hash): ?string;
}
