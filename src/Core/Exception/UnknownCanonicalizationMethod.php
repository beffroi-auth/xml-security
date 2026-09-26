<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * A canonicalization URI that is none of the four of section 5.4, Canonical XML 1.1 included.
 */
final class UnknownCanonicalizationMethod extends RefusedXml
{
}
