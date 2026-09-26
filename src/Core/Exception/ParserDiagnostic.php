<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * libxml parsed but reported something, whatever its level: its code, level, line and column (I-3).
 */
final class ParserDiagnostic extends RefusedXml
{
}
