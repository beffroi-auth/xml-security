<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

use RuntimeException;

/**
 * A primitive failed while encrypting, with a key the constructor accepted and randomness PHP drew: a failure of the
 * build or of OpenSSL, never input, which is why it is not an EncryptionRefused.
 */
final class EncryptionFailed extends RuntimeException
{
}
