<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * An ID value that is not an NCName, or is longer than the bound (I-8).
 */
final class InvalidId extends RefusedXml
{
}
