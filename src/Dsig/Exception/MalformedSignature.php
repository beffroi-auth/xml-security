<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * D-1, D-2, D-3, D-4, D-9: the structure is not the one of section 5.3 of the specification.
 */
final class MalformedSignature extends SignatureRefused
{
}
