<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * libxml returned false, or the canonical form is the empty string (I-13).
 */
final class CanonicalizationFailed extends RefusedXml
{
}
