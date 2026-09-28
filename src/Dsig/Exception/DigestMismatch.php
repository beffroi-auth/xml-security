<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * The element is not what was signed (D-8).
 */
final class DigestMismatch extends SignatureRefused
{
}
