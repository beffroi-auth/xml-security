<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * <!DOCTYPE in the bytes, a doctype node, an entity reference node, or any node only a DTD can produce (I-1).
 */
final class DoctypeRefused extends RefusedXml
{
}
