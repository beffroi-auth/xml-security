<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * The consumer's reading of a plaintext, which Decryptor::decryptCovered() runs inside the decryption before it
 * answers (section 5.2, E-16): under AES-CBC, every refusal of it is the one DecryptionFailed, raised from the one place
 * of the decryptor, so that nothing the consumer says after a decryption splits a plaintext that parses from one that
 * does not; under AES-GCM, whose tag authenticated the plaintext, its refusals pass as they are (E-4).
 *
 * @template-covariant T
 */
interface PlaintextReaderInterface
{
    /**
     * What the consumer reads of the plaintext the decryption loaded.
     *
     * @return T
     *
     * @throws RefusedXml what the consumer refuses of it
     */
    public function read(Document $plaintext): mixed;
}
