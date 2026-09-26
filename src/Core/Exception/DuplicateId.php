<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Exception;

/**
 * An ID value that appears twice in the document, under one registered attribute or two (I-8).
 */
final class DuplicateId extends RefusedXml
{
}
