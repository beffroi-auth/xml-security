<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

use RuntimeException;

/**
 * The primitive failed while signing: never input, so not a SignatureRefused.
 */
final class SigningFailed extends RuntimeException
{
}
