<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Document;

/**
 * E-15
 *
 * The namespace does not check where the proof comes from: the consumer builds it from a verification and from
 * nothing else.
 */
interface CoveringSignatureInterface
{
    /**
     * The re-parse of the very bytes its digest matched (dsig.md D-10), so that every node of it is what was signed.
     */
    public function document(): Document;
}
