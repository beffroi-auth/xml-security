<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * An element whose text cannot be read whole: a child element, or a child of another type (I-12).
 */
final class MixedContent extends RefusedXml
{
}
