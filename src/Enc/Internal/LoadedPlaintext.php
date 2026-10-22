<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Enc\PlaintextReaderInterface;

/**
 * The reading of Decryptor::decrypt(), which reads nothing: the plaintext as Core loaded it is what it answers (E-4).
 *
 * @internal outside the compatibility promise of section 5
 *
 * @implements PlaintextReaderInterface<Document>
 */
final readonly class LoadedPlaintext implements PlaintextReaderInterface
{
    public function read(Document $plaintext): Document
    {
        return $plaintext;
    }
}
