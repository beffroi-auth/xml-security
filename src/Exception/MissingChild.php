<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * No direct child of the parent carries the name (section 6.4).
 */
final class MissingChild extends RefusedXml
{
}
