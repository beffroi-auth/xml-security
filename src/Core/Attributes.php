<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Exception\MissingAttribute;
use Dom\Element;
use function sprintf;

/**
 * The Dom API's getAttributeNS() returns null for an absent attribute and '' for an empty one.
 */
final class Attributes
{
    /**
     * @throws MissingAttribute
     */
    public static function required(Element $element, Name $name): string
    {
        return (
            $element->getAttributeNS($name->namespace, $name->local) ?? throw new MissingAttribute(sprintf(
                'The element has no attribute named %s (section 6.4).',
                $name->namespace === null ? $name->local : sprintf('{%s}%s', $name->namespace, $name->local),
            ))
        );
    }

    public static function optional(Element $element, Name $name): ?string
    {
        return $element->getAttributeNS($name->namespace, $name->local);
    }
}
