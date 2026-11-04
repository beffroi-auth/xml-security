<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * E-12: a refusal names the rule, never the input and never a key.
 */
abstract class EncryptionRefused extends RefusedXml
{
}
