<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * D-2: the reference does not name the claimed element.
 */
final class WrongReference extends SignatureRefused
{
}
