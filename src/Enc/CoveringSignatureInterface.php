<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Document;

/**
 * The proof Decryptor::decryptCovered() asks for before it opens AES-CBC (E-15, section 5.2): that a signature,
 * verified under a key the consumer trusts for the peer, covers the encrypted element. The namespace never reaches
 * Dsig (decision 0015), so it checks what the proof covers, the encrypted element being a node of its document, and
 * not where the proof comes from: the consumer builds it from a verification and from nothing else, as saml2-model
 * builds it from the Verified of the response's signature.
 */
interface CoveringSignatureInterface
{
    /**
     * The document the signature covers: the re-parse of the very bytes its digest matched (dsig.md D-10), so that
     * every node of it is what was signed.
     */
    public function document(): Document;
}
