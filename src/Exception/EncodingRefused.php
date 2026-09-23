<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * Not UTF-8, a UTF-16 or UTF-32 byte order mark, or a declared encoding other than UTF-8 (I-5).
 */
final class EncodingRefused extends RefusedXml
{
}
