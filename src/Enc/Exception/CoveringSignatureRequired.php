<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-15: AES-CBC without a verified signature that covers the encrypted element, given to Decryptor::decrypt(), or to
 * Decryptor::decryptCovered() under a signature whose document does not hold the element. Refused by name, before any
 * key is touched: CBC authenticates nothing, and only the signature keeps an altered ciphertext from the decryptor.
 */
final class CoveringSignatureRequired extends EncryptionRefused
{
}
