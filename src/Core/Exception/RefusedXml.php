<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

use RuntimeException;

/**
 * Input the brick refuses: the message names the rule and never carries the input (I-16).
 */
abstract class RefusedXml extends RuntimeException
{
}
