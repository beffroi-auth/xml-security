<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\SigningFailed;

interface SigningKeyInterface
{
    /**
     * The raw signature of $bytes.
     *
     * @throws AlgorithmUnavailable
     * @throws SigningFailed
     */
    public function sign(string $bytes, SignatureAlgorithm $algorithm): string;
}
