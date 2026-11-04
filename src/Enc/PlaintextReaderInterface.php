<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * Section 5.2, E-4, E-16: run inside the decryption, where under AES-CBC each of its refusals becomes the one
 * DecryptionFailed.
 *
 * @template-covariant T
 */
interface PlaintextReaderInterface
{
    /**
     * @return T
     *
     * @throws RefusedXml
     */
    public function read(Document $plaintext): mixed;
}
