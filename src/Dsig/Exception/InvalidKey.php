<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * Not RSA of at least 2048 bits, or no key in the PEM (D-16).
 */
final class InvalidKey extends SignatureRefused
{
}
