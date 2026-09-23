<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * No element of the document carries the ID (section 6.2).
 */
final class UnknownId extends RefusedXml
{
}
