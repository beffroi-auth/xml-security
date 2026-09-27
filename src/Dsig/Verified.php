<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\CanonicalXml;
use Beffroi\Xml\Core\Document;

/**
 * What a verification hands to the consumer (D-10): the Document its Loader built from the very bytes the digest
 * matched, one root, the signed element without its Signature, no sibling, no ancestor, no wrapper; the bytes
 * themselves; the algorithm; the trusted key that verified. The consumer reads $document->root() and nothing of
 * the element it passed in.
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
