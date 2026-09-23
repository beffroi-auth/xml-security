<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * Two or more direct children of the parent carry the name (section 6.4).
 */
final class AmbiguousChild extends RefusedXml
{
}
