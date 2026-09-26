<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Support;

use Dom\Element;
use RuntimeException;
use function sprintf;

/**
 * Direct navigation for the tests, by local name only: what a test needs to reach an apex or an element to exclude.
 */
final class Nodes
{
    public static function childNamed(Element $parent, string $local): Element
    {
        for ($child = $parent->firstElementChild; $child instanceof Element; $child = $child->nextElementSibling) {
            if ($child->localName === $local) {
                return $child;
            }
        }

        throw new RuntimeException(sprintf('No child named %s.', $local));
    }
}
