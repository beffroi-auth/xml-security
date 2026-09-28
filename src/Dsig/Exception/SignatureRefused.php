<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * Input the Dsig namespace refuses: it extends the base class of Core, so that a consumer catching RefusedXml
 * catches everything the package refuses. Messages name the rule, never the input and never a key (D-13).
 */
abstract class SignatureRefused extends RefusedXml
{
}
