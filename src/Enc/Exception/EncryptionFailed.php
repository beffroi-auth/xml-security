<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

use RuntimeException;

/**
 * A failure of the build or of OpenSSL, never of input, hence not an EncryptionRefused.
 */
final class EncryptionFailed extends RuntimeException
{
}
