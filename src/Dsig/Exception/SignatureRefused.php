<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * Messages name the rule, never the input and never a key (D-13).
 */
abstract class SignatureRefused extends RefusedXml
{
}
