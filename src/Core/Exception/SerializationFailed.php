<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * The document holds a shape the serializer refuses, or saveXml() returned false (section 6.5).
 */
final class SerializationFailed extends RefusedXml
{
}
