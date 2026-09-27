<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-11: a key that is not RSA of at least 2048 bits, a PEM that holds no key, or a passphrase that does not open it.
 */
final class InvalidKey extends EncryptionRefused
{
}
