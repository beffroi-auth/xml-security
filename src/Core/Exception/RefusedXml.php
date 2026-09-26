<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

use RuntimeException;

/**
 * Input the brick refuses (section 5.7). A consumer catches this class when it does not care which rule fired.
 * The message names the rule and, when libxml gives them, its error code, the line and the column; it never
 * carries the input (I-16).
 */
abstract class RefusedXml extends RuntimeException
{
}
