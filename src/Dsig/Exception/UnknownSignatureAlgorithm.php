<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * D-5: a signature method outside the closed list.
 */
final class UnknownSignatureAlgorithm extends SignatureRefused
{
}
