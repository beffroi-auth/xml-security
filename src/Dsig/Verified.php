<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\CanonicalXml;
use Beffroi\Xml\Core\Document;

/**
 * The consumer reads $document->root(), the reload of the hashed bytes, and nothing of the element it passed in
 * (D-10).
 */
final readonly class Verified
{
    public function __construct(
        public Document $document,
        public CanonicalXml $canonical,
        public SignatureAlgorithm $algorithm,
        public VerificationKey $key,
    ) {
    }
}
