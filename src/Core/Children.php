<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use function array_filter;
use function array_values;
use Beffroi\Xml\Core\Exception\AmbiguousChild;
use Beffroi\Xml\Core\Exception\MissingChild;
use function count;
use Dom\Element;
use function sprintf;

/**
 * Direct children only, never a search of descendants, which is what a signature wrapping relies on (I-11).
 */
final class Children
{
    /**
     * @return list<Element> in document order
     */
    public static function all(Element $parent): array
    {
        $children = [];
        for ($child = $parent->firstElementChild; $child instanceof Element; $child = $child->nextElementSibling) {
            $children[] = $child;
        }

        return $children;
    }

    /**
     * @return list<Element>
     */
    public static function named(Element $parent, Name $name): array
    {
        return array_values(array_filter(self::all($parent), $name->matches(...)));
    }

    /**
     * @throws MissingChild
     * @throws AmbiguousChild
     */
    public static function one(Element $parent, Name $name): Element
    {
        $children = self::named($parent, $name);

        return match (count($children)) {
            0 => throw new MissingChild(sprintf(
                'The element has no child named %s (section 6.4).',
                self::describe($name),
            )),
            1 => $children[0],
            default => throw new AmbiguousChild(sprintf(
                'The element has more than one child named %s (section 6.4).',
                self::describe($name),
            )),
        };
    }

    /**
     * @throws AmbiguousChild
     */
    public static function optional(Element $parent, Name $name): ?Element
    {
        $children = self::named($parent, $name);
        if (count($children) > 1) {
            throw new AmbiguousChild(sprintf(
                'The element has more than one child named %s (section 6.4).',
                self::describe($name),
            ));
        }

        return $children[0] ?? null;
    }

    private static function describe(Name $name): string
    {
        return $name->namespace === null ? $name->local : sprintf('{%s}%s', $name->namespace, $name->local);
    }
}
