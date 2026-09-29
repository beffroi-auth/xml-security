<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * Input the Enc namespace refuses: it extends the base class of Core, so that a consumer catching RefusedXml
 * catches everything the package refuses. A refusal of the reading model names the rule, never the input and never
 * a key (E-12); the one failure of decryption names nothing at all (E-3).
 */
abstract class EncryptionRefused extends RefusedXml
{
}
